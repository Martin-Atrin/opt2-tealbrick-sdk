// tb-exec orchestration (SDK-API §11, C2, C6, C33): claim as service → fetch declared keys → start helper, helper proxy,
// control port and the upstream child → status long-poll (BRIDGE §10.3) → restart the child when key values change →
// exit with the child's code.
import { createHash } from "node:crypto";
import type { Server } from "node:http";
import { conditionHolds, settingsFromEnv } from "@opt2-tealbrick/manifest";
import type { AppStatus } from "@opt2-tealbrick/spec/bridge";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "../server/errors.ts";
import { createLogger, type LogSink, SecretRegistry } from "../server/log.ts";
import { dropPrivileges, type PrivilegeProc } from "../server/privilege.ts";
import { TB_EXEC_CONTROL_PORT } from "../server/service-helper.ts";
import { parseArgs } from "./args.ts";
import { ServiceBridge } from "./bridge.ts";
import { HelperProcess, Upstream } from "./child.ts";
import { childEnv, type ExecConfig, loadExecConfig, SDK_VERSION } from "./config.ts";
import { type ClaimRecord, claimOrLoad, loadServiceKey, retryable } from "./identity.ts";
import { startControlServer, startHelperProxy } from "./servers.ts";
import { signalExitCode, sleep } from "./util.ts";
import { appAssertionVerifier } from "./verify.ts";

export const STOP_SIGNALS: readonly NodeJS.Signals[] = ["SIGTERM", "SIGINT", "SIGQUIT"];
export const FORWARDED_SIGNALS: readonly NodeJS.Signals[] = [...STOP_SIGNALS, "SIGHUP", "SIGUSR1", "SIGUSR2"];

export interface TbExecOptions {
  /** tests only: injected process facade for the privilege drop (default: the real process) */
  privilegeProc?: PrivilegeProc;
  argv: readonly string[];
  env: Record<string, string | undefined>;
  /** listen address of the helper proxy and control port (default all interfaces of the private network) */
  host?: string;
  /** default 7077; tests override */
  controlPort?: number;
  logSink?: LogSink;
}

export interface TbExecHandle {
  /** tb-exec's exit code: the child's code, 128 + n when stopped by a signal before start, 2 usage, 1 failure */
  exited: Promise<number>;
  signal(sig: NodeJS.Signals): void;
}

interface FetchedKeys {
  /** env name → value (memory only) */
  values: Map<string, string>;
  missing: string[];
  rev: number;
  /** digest of the values, to restart only on a real change */
  fingerprint: string;
}

/** C54: tb-exec drops privileges for a companion service only when `runtime.services[].dropPrivileges === true`. */
export function shouldDropForService(service: { dropPrivileges?: boolean }): boolean {
  return service.dropPrivileges === true;
}

/**
 * The bridge's `serviceKeys` list is authoritative, but a key whose manifest `when` is false for the settings this
 * service can see is dropped (ONE evaluation: manifest `conditionHolds` / `settingsFromEnv`). Only settings carried in
 * this service's env are judged; a key whose condition references a setting the env does not carry is kept.
 */
export function keysInForce(
  manifest: Manifest,
  serviceId: string,
  listed: { name: string; env: string }[],
  env: Record<string, string | undefined>,
  log?: Logger,
): { name: string; env: string }[] {
  const carried = new Set((manifest.runtime.env ?? []).filter((e) => "setting" in e && typeof e.setting === "string" && env[e.name] !== undefined).map((e) => e.setting as string));
  const settings = settingsFromEnv(manifest, env);
  const reqs = new Map((manifest.settings?.keys ?? []).filter((k) => k.usedBy.includes(serviceId)).map((k) => [k.name, k]));
  return listed.filter((k) => {
    const req = reqs.get(k.name);
    if (!req?.when) return true;
    if (!Object.keys(req.when).every((s) => carried.has(s))) return true;
    const ok = conditionHolds(req.when, settings);
    if (!ok) log?.info("key not in force", { key: k.name });
    return ok;
  });
}

async function fetchKeys(rec: ClaimRecord, bridge: ServiceBridge, secrets: SecretRegistry, log: Logger, signal: AbortSignal): Promise<FetchedKeys> {
  const values = new Map<string, string>();
  const missing: string[] = [];
  let rev = 0;
  const fp = createHash("sha256");
  for (const k of rec.serviceKeys) {
    let delay = 1000;
    for (;;) {
      try {
        const r = await bridge.fetchKey(k.name, signal);
        if (r) {
          secrets.add(r.value);
          values.set(k.env, r.value);
          rev = Math.max(rev, r.keysRev);
          fp.update(`${k.env}\0${createHash("sha256").update(r.value, "utf8").digest("hex")}\0`);
        } else missing.push(k.name);
        break;
      } catch (e) {
        if (signal.aborted) throw e;
        if (!retryable(e)) {
          log.warn("key not delivered", { key: k.name, code: e instanceof TbError ? e.code : "key_fetch_failed" });
          missing.push(k.name);
          break;
        }
        await sleep(delay, signal);
        delay = Math.min(delay * 2, 30_000);
      }
    }
  }
  return { values, missing, rev, fingerprint: fp.digest("hex") };
}

async function closeAll(servers: Server[]): Promise<void> {
  await Promise.all(
    servers.map(
      (s) =>
        new Promise<void>((r) => {
          s.close(() => r());
          s.closeAllConnections();
        }),
    ),
  );
}

function checkHelperFlags(cfg: ExecConfig, helperCmd: string | null): void {
  if (cfg.service.helper && helperCmd === null) throw new TbError("helper_flags_required", "the service declares a helper: pass --helper-cmd and --helper-target", 500);
  if (!cfg.service.helper && helperCmd !== null) throw new TbError("helper_undeclared", "--helper-cmd given but the service declares no helper", 500);
}

export function startTbExec(o: TbExecOptions): TbExecHandle {
  const secrets = new SecretRegistry();
  let log = createLogger("info", secrets, { component: "tb-exec" }, o.logSink);
  const startup = new AbortController();
  let stopSignal: NodeJS.Signals | null = null;
  let upstream: Upstream | null = null;
  let helper: HelperProcess | null = null;

  async function main(): Promise<number> {
    const args = parseArgs(o.argv);
    const cfg = loadExecConfig(o.env, args.manifestPath);
    log = createLogger(cfg.env.logLevel, secrets, { component: "tb-exec", svc: cfg.service.id }, o.logSink);
    for (const name of cfg.env.unknown) log.warn("env_unknown", { name });
    checkHelperFlags(cfg, args.helperCmd);
    // C53 / BSA-05: started as root → hand the volumes to uid 1000 and drop before the key, any listener or the
    // children (the upstream and helper inherit uid/gid 1000).
    // C54: companions drop only when the manifest opts in (upstream images such as Postgres switch users themselves).
    if (shouldDropForService(cfg.service) && dropPrivileges(cfg.env, o.privilegeProc)) log.info("privileges_dropped", { uid: 1000 });
    const key = await loadServiceKey(cfg);
    const bridge = new ServiceBridge({ baseUrl: cfg.bridgeUrl, instanceId: cfg.instanceId, service: cfg.service.id, key });
    const claimed = await claimOrLoad(cfg, key, bridge, log, startup.signal);
    const rec = { ...claimed, serviceKeys: keysInForce(cfg.manifest, cfg.service.id, claimed.serviceKeys, o.env, log) };
    let keys = await fetchKeys(rec, bridge, secrets, log, startup.signal);
    if (keys.missing.length > 0) log.warn("needs_keys", { missing: keys.missing });
    if (startup.signal.aborted) throw new TbError("stopped", "stopped before start", 500);

    const verify = appAssertionVerifier(rec);
    const host = o.host ?? "0.0.0.0";
    const servers: Server[] = [];
    const up = new Upstream(args.command, log);
    upstream = up;
    try {
      if (cfg.service.helper && args.helperTarget && args.helperCmd) {
        helper = new HelperProcess(args.helperCmd, childEnv(o.env, new Map()), log);
        helper.start();
        servers.push(await startHelperProxy({ port: cfg.service.helper.port, host, paths: cfg.service.helper.paths, target: args.helperTarget, verify, log }));
      }
      if (cfg.service.backup) servers.push(await startControlServer({ port: o.controlPort ?? TB_EXEC_CONTROL_PORT, host, backup: cfg.service.backup, verify, env: () => childEnv(o.env, keys.values), log }));
    } catch (e) {
      await helper?.stop();
      await closeAll(servers);
      throw e;
    }
    if (stopSignal) {
      await helper?.stop();
      await closeAll(servers);
      return signalExitCode(stopSignal);
    }
    up.start(childEnv(o.env, keys.values));

    // Status long-poll: echo the bridge's slice revision, act on a new keysRev (restart only when values changed).
    const polling = new AbortController();
    let sliceRevision = 0;
    const loop = (async () => {
      let delay = 1000;
      while (!polling.signal.aborted) {
        const body: AppStatus = {
          readiness: keys.missing.length > 0 ? "needs_keys" : "ready",
          version: cfg.manifest.version,
          sdkVersion: SDK_VERSION,
          scopesRev: 0,
          sliceRevision,
          keysRev: keys.rev,
          pendingHolds: 0,
        };
        try {
          const r = await bridge.status(body, polling.signal);
          delay = 1000;
          if (!r) continue;
          const changed = r.sliceRevision !== sliceRevision || r.keysRev !== keys.rev;
          sliceRevision = r.sliceRevision;
          if (r.keysRev !== keys.rev) {
            const next = await fetchKeys(rec, bridge, secrets, log, polling.signal);
            next.rev = Math.max(next.rev, r.keysRev);
            const restart = next.fingerprint !== keys.fingerprint;
            keys = next;
            if (restart && !polling.signal.aborted) await up.restart(childEnv(o.env, keys.values));
          }
          if (!changed) await sleep(1000, polling.signal); // a bridge answering 200 without a change must not spin
        } catch (e) {
          if (polling.signal.aborted) break;
          log.warn("status retry", { code: e instanceof TbError ? e.code : "status_failed", inMs: delay });
          await sleep(delay, polling.signal);
          delay = Math.min(delay * 2, 30_000);
        }
      }
    })();

    const code = await up.exited;
    polling.abort();
    await loop;
    await helper?.stop();
    await closeAll(servers);
    return code;
  }

  const exited = main().catch((e: unknown) => {
    if (stopSignal) return signalExitCode(stopSignal);
    const err = e instanceof TbError ? e : new TbError("internal_error", e instanceof Error ? e.message : "internal error", 500);
    log.error("tb-exec failed", { code: err.code, message: err.message });
    return err.code === "usage" ? 2 : 1;
  });

  return {
    exited,
    signal(sig) {
      if (STOP_SIGNALS.includes(sig) && !stopSignal) stopSignal = sig;
      if (upstream) {
        upstream.signal(sig);
        helper?.signal(sig);
      } else if (STOP_SIGNALS.includes(sig)) startup.abort();
    },
  };
}
