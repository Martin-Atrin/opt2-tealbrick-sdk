// defineApp / startApp (SDK-API §3): the manifest is the only source; the app registers handlers by operation id and
// the SDK derives routes, validation, OpenAPI, status and standard ops. startApp refuses to boot on an invalid
// manifest, handler set or migration set.
import { readFileSync } from "node:fs";
import type { Server } from "node:http";
import { keySetFrom, manifestDigest, memoryReplayGuard, sdkMajorOf, ulid, validateManifest, withStandardOps } from "@opt2-tealbrick/manifest";
import type { Ed25519PublicJwk, InstanceId, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { App, AppDefinition, HealthStatus, HoldDecideInput, OperationView, PersonPrincipal, Receipt, RunningApp, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import { createAppSecrets } from "./app-secrets.ts";
import { createAuditLog } from "./audit.ts";
import { createBackupApi, restoreAtBoot } from "./backup.ts";
import { BridgeClient } from "./bridge-client.ts";
import type { SdkAppDefinition } from "./context.ts";
import { readEnv } from "./env.ts";
import { TbError } from "./errors.ts";
import { createKeys } from "./keys.ts";
import { BridgeLink } from "./link.ts";
import { createLogger, SecretRegistry } from "./log.ts";
import { decide } from "./ops.ts";
import { createPersonAuth } from "./person.ts";
import { dropPrivileges, type PrivilegeProc } from "./privilege.ts";
import { Receipts } from "./receipts.ts";
import type { Runtime } from "./runtime.ts";
import { createScopeStore } from "./scopes.ts";
import { createSealer, loadInstanceKey, resolveKeks } from "./secrets.ts";
import { createHttpServer } from "./server.ts";
import { createServiceHelperCaller } from "./service-helper.ts";
import { appDb, metaGet, metaSet, openStore, type Row, runAppMigrations } from "./store.ts";
import { TrustState } from "./trust.ts";

export const SDK_VERSION: string = (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;
/**
 * SDK major the manifest `sdkMajor` must equal. SPEC-GAP: the schema requires `sdkMajor ≥ 1` while the SDK ships as
 * 0.x during the opt2 build; 0.x is treated as major 1.
 */
export const SDK_MAJOR: number = sdkMajorOf(SDK_VERSION);

const SWEEP_MS = 60_000;
const definitions = new WeakMap<App, SdkAppDefinition<string>>();
let current: Runtime | null = null;

/** Registers handlers by operation id. Validation happens in startApp (boot refuses on error). */
export function defineApp<A extends string = never>(def: SdkAppDefinition<A>): App {
  const manifest = def.manifest;
  let digest: `sha256:${string}`;
  let operations: OperationView[];
  try {
    digest = manifestDigest(manifest);
    operations = withStandardOps(manifest);
  } catch {
    throw new TbError("manifest_invalid", "manifest is not a manifest object", 500);
  }
  const app: App = Object.freeze({ manifest, digest, operations: Object.freeze(operations) });
  definitions.set(app, def as SdkAppDefinition<string>);
  return app;
}

/** Boot checks of the handler set against the manifest (SDK-API §3): exactly one handler per non-dynamic op, etc. */
function checkDefinition(def: AppDefinition<string>, m: Manifest): string[] {
  const problems: string[] = [];
  const ops = new Map(m.operations.map((o) => [o.id, o]));
  for (const o of m.operations) {
    const h = def.handlers[o.id];
    if (o.dynamic) {
      if (h) problems.push(`handler for dynamic operation ${o.id} (use dynamic.${o.id})`);
      if (!def.dynamic?.[o.id]) problems.push(`missing dynamic handlers for ${o.id}`);
      continue;
    }
    if (!h) problems.push(`missing handler for operation ${o.id}`);
    else if (o.scopeType && (typeof h === "function" || typeof h.scope !== "function")) problems.push(`operation ${o.id} has scopeType ${o.scopeType} and needs a scope() function`);
    else if (typeof h !== "function" && typeof h.run !== "function") problems.push(`handler for ${o.id} has no run()`);
  }
  for (const id of Object.keys(def.handlers)) if (!ops.has(id)) problems.push(`extra handler ${id} (not a manifest operation)`);
  for (const id of Object.keys(def.dynamic ?? {})) if (!ops.get(id)?.dynamic) problems.push(`extra dynamic handlers ${id}`);
  const hooks = new Set((m.hooks ?? []).map((h) => h.id));
  for (const id of hooks) if (typeof def.hooks?.[id] !== "function") problems.push(`missing hook handler ${id}`);
  for (const id of Object.keys(def.hooks ?? {})) if (!hooks.has(id)) problems.push(`extra hook handler ${id}`);
  const routes = new Set((m.publicRoutes ?? []).map((r) => r.path));
  for (const p of routes) if (typeof def.publicRoutes?.[p] !== "function") problems.push(`missing public route handler ${p}`);
  for (const p of Object.keys(def.publicRoutes ?? {})) if (!routes.has(p)) problems.push(`extra public route handler ${p}`);
  if (typeof def.migrations !== "string" || def.migrations === "") problems.push("migrations directory is required");
  for (const a of def.auditActions ?? []) if (!/^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$/.test(a)) problems.push(`audit action ${a} must look like noun.verb`);
  return problems;
}

function listen(server: Server, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, () => {
      server.off("error", reject);
      resolve();
    });
  });
}

/** Reads only the TB_* names of `env`; refuses to boot on an invalid manifest, handler set or migration set. */
/**
 * `harness` is for test harnesses only, never read from env and never set by Portal: `privilegeProc` (not part of
 * types/sdk.ts) replaces the real process facade of the privilege drop so a root test runner is not dropped to uid 1000
 * by an app it starts in-process; `portalRootKeys` (types/sdk.ts v0.1.11 `StartHooks`, C63) replaces the build-pinned
 * Portal Root Keys so a conformance start module can sign key-set statements with a test root pair. Production never
 * passes it.
 */
export async function startApp(
  app: App,
  env: Record<string, string | undefined>,
  harness?: { privilegeProc?: PrivilegeProc; portalRootKeys?: Ed25519PublicJwk[] },
): Promise<RunningApp> {
  const def = definitions.get(app);
  if (!def) throw new TbError("app_invalid", "startApp needs the value returned by defineApp", 500);
  const v = validateManifest(def.manifest);
  if (!v.ok) throw new TbError("manifest_invalid", "manifest does not validate", 500, { errors: v.errors });
  const manifest = v.manifest;
  if (manifest.sdkMajor !== SDK_MAJOR) throw new TbError("sdk_major_unsupported", `manifest sdkMajor ${manifest.sdkMajor} differs from SDK major ${SDK_MAJOR}`, 500);
  const problems = checkDefinition(def, manifest);
  if (problems.length) throw new TbError("handlers_invalid", problems.join("; "), 500, { problems });

  const cfg = readEnv(env);
  const secrets = new SecretRegistry();
  const log = createLogger(cfg.logLevel, secrets, { product: manifest.id });
  for (const name of cfg.unknown) log.warn("env_unknown", { name });
  if (!cfg.standalone && (!cfg.instanceId || !cfg.bridgeUrl || !cfg.portalKeys))
    throw new TbError("env_invalid", "TB_INSTANCE_ID, TB_BRIDGE_URL and TB_PORTAL_KEYS are required unless TB_STANDALONE=1", 500);

  // C53 / BSA-05: started as root → hand the volumes to uid 1000 and drop before any file, key or listener opens.
  if (dropPrivileges(cfg, harness?.privilegeProc)) log.info("privileges_dropped", { uid: 1000 });

  const sealer = createSealer(resolveKeks(cfg.dataDir, cfg.kek, cfg.kekPrevious));
  await restoreAtBoot(
    { manifest, dataDir: cfg.dataDir, backupDir: cfg.backupDir, instanceId: cfg.instanceId ?? "", sdkVersion: SDK_VERSION, log, hooks: def.backup, env, instanceKey: () => loadInstanceKey(cfg.dataDir, sealer), bridgeId: () => null },
    cfg.restoreFrom,
  );
  const db = openStore(cfg.dataDir);
  const closeOnFail = <T>(fn: () => T): T => {
    try {
      return fn();
    } catch (e) {
      db.close();
      throw e;
    }
  };
  let migrated: { version: number; name: string }[];
  try {
    migrated = await runAppMigrations(db, def.migrations);
  } catch (e) {
    db.close();
    throw e;
  }
  const audit = createAuditLog(db, def.auditActions ?? []);
  for (const m of migrated) await audit.record({ actor: "system", action: "migration.apply", target: `${String(m.version).padStart(4, "0")}_${m.name}`, detail: null });

  // reseal app-own keys after a KEK rotation (CREDENTIALS §9.1)
  closeOnFail(() => {
    for (const r of db.prepare("SELECT name, sealed FROM tb_keys").all() as Row[]) {
      if (!sealer.stale(String(r.sealed))) continue;
      const value = sealer.unsealText("app-key", String(r.name), String(r.sealed));
      db.prepare("UPDATE tb_keys SET sealed = ? WHERE name = ?").run(sealer.sealText("app-key", String(r.name), value), String(r.name));
    }
  });

  // identity: TB_INSTANCE_ID, or (app-alone) an ins_/ws_ pair generated at first boot
  let instanceId: InstanceId;
  let aloneWs: WorkspaceId | null = null;
  if (cfg.standalone) {
    const id = metaGet<{ ins: InstanceId; ws: WorkspaceId }>(db, "standalone_identity") ?? { ins: `ins_${ulid()}` as InstanceId, ws: `ws_${ulid()}` as WorkspaceId };
    metaSet(db, "standalone_identity", id);
    instanceId = id.ins;
    aloneWs = id.ws;
  } else instanceId = cfg.instanceId as InstanceId;
  const instanceKey = await loadInstanceKey(cfg.dataDir, sealer);
  const trust = new TrustState(db, instanceId, {
    bootstrap: cfg.portalKeys ? keySetFrom(cfg.portalKeys, "tb:portal") : null,
    ...(aloneWs ? { alone: { ws: aloneWs, ownKey: instanceKey.publicJwk } } : {}),
    ...(harness?.portalRootKeys ? { roots: harness.portalRootKeys } : {}),
    warn: (msg, fields) => log.warn(msg, fields),
  });

  const ops = new Map(withStandardOps(manifest).map((o) => [o.id, o]));
  const state = { claimed: false, failed: false, restoring: false, stopping: false };
  let link: BridgeLink | null = null;
  const bridge = cfg.standalone || !cfg.bridgeUrl ? null : new BridgeClient({ baseUrl: cfg.bridgeUrl, instanceId, key: instanceKey, bridgeId: () => trust.bridgeId });
  const receipts = new Receipts(db);
  const kick = () => link?.kick();
  const scopes = createScopeStore(db, manifest, audit, kick);
  const appHandle = appDb(db);
  const appSecrets = createAppSecrets(db, sealer, secrets);
  closeOnFail(() => appSecrets.reseal());
  const keys = createKeys({
    db,
    manifest,
    env,
    sealer,
    secrets,
    audit,
    log,
    bridge: () => (state.claimed ? bridge : null),
    emit: async (names) => {
      try {
        await def.events?.keysChanged?.(names, { log });
      } catch (e) {
        log.warn("keysChanged failed", { error: e instanceof Error ? e.message : "unknown" });
      }
    },
  });
  const person = createPersonAuth({ db, product: manifest.id, launchPath: manifest.ui?.launchPath ?? "/", trust, audit, log, instanceKey, standalone: cfg.standalone,
    idempotencyRequired: manifest.operations.filter((o) => o.audience === "person" && o.idempotency === "required").map((o) => o.id),
  });
  const backup = createBackupApi({
    manifest,
    dataDir: cfg.dataDir,
    backupDir: cfg.backupDir,
    instanceId,
    sdkVersion: SDK_VERSION,
    log,
    hooks: def.backup,
    env,
    instanceKey: async () => instanceKey,
    bridgeId: () => trust.bridgeId,
    db,
    audit,
  });
  const helper = createServiceHelperCaller({ manifest, env, instanceId, instanceKey, bridgeId: () => trust.bridgeId });
  let onStartRan = false;

  const rt: Runtime = {
    def,
    manifest,
    product: manifest.id,
    digest: v.digest,
    ops,
    sdkVersion: SDK_VERSION,
    cfg,
    env,
    db,
    appDb: appHandle,
    log,
    secrets,
    sealer,
    instanceId,
    instanceKey,
    trust,
    receipts,
    scopes,
    keys,
    audit,
    person,
    secretsStore: appSecrets,
    backups: backup.api,
    bridge,
    replay: memoryReplayGuard(),
    state,
    health(): HealthStatus {
      if (state.failed) return "failed";
      if (state.restoring) return "restoring";
      if (!cfg.standalone) {
        if (!state.claimed) return "needs_claim";
        if (trust.stale(Date.now())) return "slice_stale";
      }
      return keys.needsKeys() ? "needs_keys" : "ok";
    },
    extras() {
      const slice = trust.slice;
      return {
        publicUrl: (slice?.bridge as { publicUrl?: unknown } | undefined)?.publicUrl?.toString() ?? null,
        workspace: (() => {
          // spec 0.1.3 (C31): non-null; before the first verified slice there is no workspace to give
          if (!trust.ws) throw new TbError("workspace_unknown", "the workspace is not known yet (no verified slice)", 503);
          return trust.ws;
        })(),
        scopes: { instances: scopes.instances },
        secrets: appSecrets,
      };
    },
    kickStatus: kick,
    onClaimed() {
      if (onStartRan || !def.onStart) return;
      onStartRan = true;
      def.onStart({ db: appHandle, log, scopes, secrets: appSecrets, getKey: (n) => keys.getKey(n), callServiceHelper: helper }).catch((e) =>
        log.error("onStart failed", { error: e instanceof Error ? e.message : "unknown" }),
      );
    },
    async refreshSlice() {
      await link?.refreshNow();
    },
    async ensureAgent(agent: SliceAgent) {
      const seen = db.prepare("SELECT in_slice FROM tb_agents WHERE agent = ?").get(agent.id) as Row | undefined;
      const inSlice = trust.agent(agent.id) ? 1 : 0;
      if (seen) {
        if (Number(seen.in_slice) !== inSlice) db.prepare("UPDATE tb_agents SET in_slice = ?, name = ? WHERE agent = ?").run(inSlice, agent.name, agent.id);
        return;
      }
      db.prepare("INSERT OR IGNORE INTO tb_agents (agent, name, first_seen, in_slice) VALUES (?, ?, ?, ?)").run(agent.id, agent.name, Date.now(), inSlice);
      try {
        await def.events?.agentAdded?.(agent, { db: appHandle, scopes, log });
      } catch (e) {
        log.warn("agentAdded failed", { agent: agent.id, error: e instanceof Error ? e.message : "unknown" });
      }
      await scopes.applyDefaults(agent);
    },
    async callApp(product, op, input, opts) {
      if (!link) throw new TbError("no_bridge", "companion calls need the bridge", 503);
      return link.call(product, op, input, opts);
    },
    callServiceHelper: helper,
  };

  // claim record → bridge known; slice from the DB is already installed in TrustState
  if (!cfg.standalone && bridge) {
    const record = BridgeLink.record(rt);
    if (record) {
      if (record.ins !== instanceId) {
        db.close();
        throw new TbError("instance_mismatch", "stored claim names another instance than TB_INSTANCE_ID", 500);
      }
      trust.setBridge(record.bridge.id);
      state.claimed = true;
    }
    link = new BridgeLink(rt, bridge);
  } else person.standaloneBoot(cfg.standaloneReset);

  const server = createHttpServer(rt);
  try {
    await listen(server, manifest.runtime.port);
  } catch (e) {
    db.close();
    throw new TbError("listen_failed", `cannot listen on port ${manifest.runtime.port}: ${e instanceof Error ? e.message : "error"}`, 500);
  }
  if (cfg.standalone || state.claimed) rt.onClaimed();
  link?.start();
  const sweep = setInterval(() => {
    try {
      const now = Date.now();
      if (receipts.sweep(now).expired > 0) kick();
      person.sweep(now);
    } catch (e) {
      log.warn("sweep failed", { error: e instanceof Error ? e.message : "unknown" });
    }
  }, SWEEP_MS);
  sweep.unref();

  let stopped: Promise<void> | null = null;
  const stop = (): Promise<void> => {
    stopped ??= (async () => {
      state.stopping = true;
      process.off("SIGTERM", onSignal);
      process.off("SIGINT", onSignal);
      clearInterval(sweep);
      backup.stop();
      await link?.stop();
      await new Promise<void>((resolve) => {
        server.close(() => resolve());
        server.closeIdleConnections();
        setTimeout(() => server.closeAllConnections(), 10_000).unref();
      });
      if (current === rt) current = null;
      db.close();
    })();
    return stopped;
  };
  const onSignal = () => {
    void stop();
  };
  process.once("SIGTERM", onSignal);
  process.once("SIGINT", onSignal);
  current = rt;
  log.info("app started", { port: manifest.runtime.port, instance: instanceId, standalone: cfg.standalone, status: rt.health() });

  return {
    status: () => rt.health(),
    receipts,
    scopes,
    keys,
    audit,
    backups: backup.api,
    stop,
  };
}

function running(): Runtime {
  if (!current) throw new TbError("app_not_running", "no app is running (call startApp first)", 500);
  return current;
}

/** Person only (tb.holds_decide, SDK-API §4.5). */
export function decideHold(principal: PersonPrincipal, input: HoldDecideInput): Promise<Receipt> {
  return decide(running(), principal, input);
}

/** App-own value > workspace default (SDK-API §8). */
export function getKey(name: string): Promise<string | null> {
  return running().keys.getKey(name);
}

export function onKeysChanged(cb: (names: string[]) => void): () => void {
  return running().keys.onKeysChanged(cb);
}

