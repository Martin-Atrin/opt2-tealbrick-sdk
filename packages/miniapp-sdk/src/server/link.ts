// The instance ↔ bridge link (SDK-API §9, BRIDGE §8.3, §10): ONE claim path, the status push + slice/keys long-poll,
// and companion calls. One credential: the instance key K8 (instance assertions in TB-Assert).
import {
  type AppStatus,
  type AppStatusResponse,
  BRIDGE_HEADERS,
  BRIDGE_INTERNAL_PATHS,
  type CallEnvelope,
  type ClaimResponse,
  type OpResult,
} from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, Ed25519PublicJwk, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { CompanionResult, HealthStatus, Json, Logger } from "@opt2-tealbrick/spec/sdk";
import type { BridgeClient } from "./bridge-client.ts";
import { errorFrom } from "./bridge-client.ts";
import { TbError } from "./errors.ts";
import { peekClaims } from "./ops.ts";
import type { Runtime } from "./runtime.ts";
import { metaGet, metaSet } from "./store.ts";

export interface ClaimRecord {
  ins: InstanceId;
  bridge: { id: BridgeId; publicKey: Ed25519PublicJwk; internalUrl: string };
  claimedAt: number;
}

const BACKOFF_MIN_MS = 1000;
const BACKOFF_MAX_MS = 60_000;
const STATUS_WAIT_S = 60;

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    if (signal.aborted) return resolve();
    const t = setTimeout(resolve, ms);
    t.unref();
    signal.addEventListener(
      "abort",
      () => {
        clearTimeout(t);
        resolve();
      },
      { once: true },
    );
  });

export function readiness(h: HealthStatus): AppStatus["readiness"] {
  return h === "ok" ? "ready" : h === "needs_keys" ? "needs_keys" : "degraded";
}

export class BridgeLink {
  readonly #rt: Runtime;
  readonly #client: BridgeClient;
  readonly #log: Logger;
  readonly #stop = new AbortController();
  #poll: AbortController | null = null;
  #dirty = false;
  #running: Promise<void> | null = null;

  constructor(rt: Runtime, client: BridgeClient) {
    this.#rt = rt;
    this.#client = client;
    this.#log = rt.log;
  }

  static record(rt: Runtime): ClaimRecord | null {
    return metaGet<ClaimRecord>(rt.db, "claim");
  }

  start(): void {
    this.#running = this.#loop().catch((e) => this.#log.error("bridge link stopped", { error: e instanceof Error ? e.message : "unknown" }));
  }

  async stop(): Promise<void> {
    this.#stop.abort();
    this.#poll?.abort();
    await this.#running;
  }

  /** Sends a status report at once (pendingHolds / scopesRev changed, C16 S2). */
  kick(): void {
    this.#dirty = true;
    this.#poll?.abort();
  }

  /** One status exchange without waiting (companion `grant_stale` → re-read the slice once). */
  async refreshNow(): Promise<void> {
    const r = await this.#client.request("POST", `${BRIDGE_INTERNAL_PATHS.status}?wait=0`, this.#status());
    if (r.status === 200) await this.#apply(r.body as AppStatusResponse);
  }

  #status(): AppStatus {
    const rt = this.#rt;
    return {
      readiness: readiness(rt.health()),
      version: rt.manifest.version,
      sdkVersion: rt.sdkVersion,
      scopesRev: rt.scopes.rev(),
      sliceRevision: rt.trust.slice?.rev ?? 0,
      keysRev: rt.keys.keysRev(),
      pendingHolds: rt.receipts.pendingCount(),
    };
  }

  async #apply(r: AppStatusResponse): Promise<void> {
    if (typeof r?.slice === "string") await installSlice(this.#rt, r.slice);
    if (typeof r?.keysRev === "number") await this.#rt.keys.onKeysRev(r.keysRev);
  }

  async #claim(): Promise<boolean> {
    const rt = this.#rt;
    const code = rt.cfg.enrolCode;
    if (!code) {
      this.#log.error("TB_ENROL_CODE missing and no claim record: issue a new enrolment code in Portal");
      return false;
    }
    const r = await this.#client.claim(
      { code, instancePublicKey: rt.instanceKey.publicJwk, manifestDigest: rt.digest, version: rt.manifest.version, sdkVersion: rt.sdkVersion },
      this.#stop.signal,
    );
    if (r.status !== 200) throw errorFrom(r, "claim_failed");
    const body = r.body as ClaimResponse;
    if (body?.ins !== rt.instanceId) {
      rt.state.failed = true;
      throw new TbError("instance_mismatch", "claim response names another instance than TB_INSTANCE_ID", 500);
    }
    const record: ClaimRecord = { ins: body.ins, bridge: body.bridge, claimedAt: Date.now() };
    metaSet(rt.db, "claim", record);
    rt.trust.setBridge(body.bridge.id);
    rt.state.claimed = true;
    await rt.audit.record({ actor: "system", action: "claim.complete", target: rt.instanceId, detail: { bridge: body.bridge.id } });
    if (typeof body.slice === "string") await installSlice(rt, body.slice);
    rt.onClaimed();
    return true;
  }

  async #loop(): Promise<void> {
    const rt = this.#rt;
    let backoff = BACKOFF_MIN_MS;
    while (!this.#stop.signal.aborted && !rt.state.failed) {
      try {
        if (!rt.state.claimed) {
          if (!(await this.#claim())) {
            await sleep(BACKOFF_MAX_MS, this.#stop.signal);
            continue;
          }
          void rt.keys.refresh();
        }
        this.#poll = new AbortController();
        const wait = this.#dirty ? 0 : STATUS_WAIT_S;
        this.#dirty = false;
        const sentAt = Date.now();
        const r = await this.#client.request(
          "POST",
          `${BRIDGE_INTERNAL_PATHS.status}?wait=${wait}`,
          this.#status(),
          {},
          AbortSignal.any([this.#stop.signal, this.#poll.signal]),
        );
        if (r.status === 200) await this.#apply(r.body as AppStatusResponse);
        else if (r.status !== 204) throw errorFrom(r, "status_failed");
        backoff = BACKOFF_MIN_MS;
        // a bridge that answers a long-poll at once with 204 must not turn this loop into a busy loop
        if (wait > 0 && r.status === 204 && Date.now() - sentAt < BACKOFF_MIN_MS) await sleep(BACKOFF_MIN_MS, this.#stop.signal);
      } catch (e) {
        if (this.#stop.signal.aborted) break;
        if (this.#poll?.signal.aborted) continue; // kicked: report again at once
        this.#log.warn("bridge exchange failed", { code: e instanceof TbError ? e.code : "error" });
        if (rt.state.failed) break;
        await sleep(backoff + Math.floor(Math.random() * 250), this.#stop.signal);
        backoff = Math.min(BACKOFF_MAX_MS, backoff * 2);
      }
    }
  }

  /** Companion call `POST /tb/v1/call` with TB-Assert + TB-Grant (SDK-API §9, BRIDGE §8.3). */
  async call<O = Json>(product: string, op: string, input: Json, opts: { idempotencyKey?: string; parentCall: string | null }): Promise<CompanionResult<O>> {
    const rt = this.#rt;
    const declared = rt.manifest.companions?.find((c) => c.product === product);
    if (!declared?.operations.includes(op)) throw new TbError("companion_undeclared", `companion operation not declared: ${product}.${op}`, 500);
    const p = rt.trust.paused(null);
    if (p.workspace || p.instance) throw new TbError("paused", "this instance is paused", 403);
    const envelope: CallEnvelope = {
      target: product,
      op,
      input,
      ...(opts.idempotencyKey ? { idempotencyKey: opts.idempotencyKey } : {}),
      ...(opts.parentCall ? { parentCall: opts.parentCall as CallEnvelope["parentCall"] } : {}),
    };
    for (let attempt = 0; ; attempt++) {
      const grant = companionGrant(rt, declared.operations);
      if (!grant) throw new TbError("no_grant", `no companion grant for ${product} in the slice`, 403);
      const r = await this.#client.request("POST", BRIDGE_INTERNAL_PATHS.call, envelope, { [BRIDGE_HEADERS.companionGrant]: grant });
      if (r.status === 200 || r.status === 202) return r.body as OpResult<O>;
      const err = errorFrom(r, "app_error");
      if (attempt === 0 && (err.code === "grant_stale" || err.code === "grant_expired")) {
        await this.refreshNow();
        continue;
      }
      throw err;
    }
  }
}

/**
 * The slice's `grants` carry no product label. SPEC-GAP: the SDK picks the grant whose `wf` equals the manifest-declared
 * companion operations for that product (I8: companion grants carry `wf` = those operations); the bridge verifies it.
 */
function companionGrant(rt: Runtime, ops: readonly string[]): string | null {
  const want = [...ops].sort().join(",");
  for (const g of rt.trust.slice?.grants ?? []) {
    const c = peekClaims(g);
    if (Array.isArray(c?.wf) && [...(c.wf as string[])].sort().join(",") === want && c.sub === rt.trust.self) return g;
  }
  return null;
}

/** Verifies + installs a slice, then runs the side effects: first sight (§7.2), agentRemoved, pause → drop key cache. */
export async function installSlice(rt: Runtime, token: string): Promise<boolean> {
  const r = rt.trust.install(token, Date.now());
  if (!r.ok) {
    rt.log.warn("slice rejected", { code: r.code });
    return false;
  }
  const slice = rt.trust.slice;
  if (!r.changed || !slice) return true;
  for (const a of slice.agents) await rt.ensureAgent(a);
  for (const a of r.changed.removed) {
    rt.db.prepare("UPDATE tb_agents SET in_slice = 0 WHERE agent = ?").run(a.id);
    try {
      await rt.def.events?.agentRemoved?.(a, { db: rt.appDb, log: rt.log });
    } catch (e) {
      rt.log.warn("agentRemoved failed", { agent: a.id, error: e instanceof Error ? e.message : "unknown" });
    }
  }
  const p = rt.trust.paused(null);
  if (p.workspace || p.instance) rt.keys.dropCache();
  return true;
}
