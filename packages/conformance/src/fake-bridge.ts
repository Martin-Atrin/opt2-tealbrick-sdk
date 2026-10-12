// Fake bridge (CONFORMANCE §3): the bridge internal surface an app talks to — `/tb/v1/claim`, `/tb/v1/status`
// (long-poll), `/tb/v1/keys/<name>`, `/tb/v1/call` — exactly per BRIDGE §8.3, §9.4, §10, plus a programmatic control
// API and a client that drives an app the way the bridge does (CORE §8). It holds a fake Portal key set and a bridge
// key, issues enrolment codes and signs slices / grants / proofs / tickets with the @opt2-tealbrick/manifest signers.
// Unknown routes → 404 (default deny). Every request and answer is captured for the payload scans (C4, C8).
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import {
  assertPublicJwk,
  digestEqual,
  type Ed25519KeyPair,
  gate,
  generateKeyPair,
  keySetFrom,
  keySetFromPortalKeys,
  manifestDigest,
  memoryReplayGuard,
  opaqueDigest,
  opaqueValue,
  sdkMajorOf,
  signSlice,
  TYP,
  verifyAssertion,
} from "@opt2-tealbrick/manifest";
import {
  type AppStatus,
  type AppStatusResponse,
  BRIDGE_HEADERS,
  BRIDGE_INTERNAL_PATHS,
  type CallEnvelope,
  type ClaimRequest,
  type ClaimResponse,
  type InstanceSlice,
  type KeyFetchResponse,
  type OpResult,
} from "@opt2-tealbrick/spec/bridge";
import type {
  AgentId,
  BridgeId,
  Ed25519PublicJwk,
  InstanceId,
  PersonId,
  PortalKeyEntry,
  Sha256Digest,
  WorkspaceId,
} from "@opt2-tealbrick/spec/credentials";
import type { AgentMode, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { OperationView } from "@opt2-tealbrick/spec/sdk";
import { AppClient } from "./app-client.ts";
import { closeServer, HttpError, header, listen, parseJson, readRaw, sendError, sendJson } from "./http.ts";
import { Mint, newId, nowS, peek } from "./tokens.ts";

export interface FakeAgent {
  id: AgentId;
  name: string;
  mode: AgentMode;
}

export interface FakeBridgeOptions {
  /** manifest of the app under test (key declarations, companions, expected digest) */
  manifest: Manifest;
  instanceId?: InstanceId;
  /** agents with an edge to the app (default: two free agents and one bound agent) */
  agents?: FakeAgent[];
  /** SDK majors served (default: manifest.sdkMajor and the one before, CONFORMANCE §5) */
  sdkMajors?: number[];
  /** claims are accepted but the key is listed (and the slice returned) only after `control.bind()` */
  deferBinding?: boolean;
  /** cap for status long-polls in seconds (default 60, BRIDGE §10.3) */
  maxWaitS?: number;
  port?: number;
}

export interface CapturedPayload {
  /** `bridge-in`: request the app sent to the fake; `app-out`: request the fake sent to the app; `app-in`: the app's answer */
  dir: "bridge-in" | "app-out" | "app-in";
  method: string;
  path: string;
  headers: Record<string, string>;
  body: string;
  at: number;
}

export interface ClaimSeen {
  request: ClaimRequest;
  codeDigest: Sha256Digest;
  at: number;
}
export interface StatusSeen {
  status: AppStatus;
  ins: InstanceId;
  assertion: { iat: number; exp: number; kid: string };
  at: number;
}
export interface Violation {
  route: string;
  code: string;
  detail: string;
  at: number;
}

type HookBehaviour = "deny" | "error" | "timeout";
type CompanionResponder = (env: CallEnvelope, caller: InstanceId) => OpResult | Promise<OpResult>;

interface PortalKeyState {
  key: Ed25519KeyPair;
  status: PortalKeyEntry["status"];
}

export interface FakeBridgeIds {
  ws: WorkspaceId;
  bridge: BridgeId;
  ins: InstanceId;
  person: PersonId;
  agents: FakeAgent[];
  /** a fake target instance per companion product */
  peers: Record<string, InstanceId>;
}

export class FakeBridge {
  readonly ids: FakeBridgeIds;
  readonly manifest: Manifest;
  readonly mint: Mint;
  readonly control: FakeBridgeControl;
  readonly captured: CapturedPayload[] = [];
  readonly claims: ClaimSeen[] = [];
  readonly statuses: StatusSeen[] = [];
  readonly keyFetches: { name: string; ins: InstanceId; at: number }[] = [];
  readonly violations: Violation[] = [];
  readonly companionCalls: { envelope: CallEnvelope; caller: InstanceId; answer: number; at: number }[] = [];
  /** the first K6 for the app instance (`TB_ENROL_CODE`) */
  readonly enrolCode: string;
  url = "";

  // state (internal)
  portalKeys: PortalKeyState[];
  bridgeKeys: Ed25519KeyPair[];
  stranger: Ed25519KeyPair;
  readonly sdkMajors: number[];
  readonly expectedDigest: Sha256Digest;
  readonly enrolCodes = new Map<string, { ins: InstanceId; svc?: string; exp: number; used: boolean }>();
  readonly instanceKeys = new Map<string, Ed25519PublicJwk>();
  readonly pending = new Map<string, Ed25519PublicJwk>();
  pause = { workspace: false, agents: new Set<AgentId>(), instances: new Set<InstanceId>() };
  revoked: { jti: string; exp: number }[] = [];
  personNbf = 0;
  sliceRev = 0;
  slice: string | null = null;
  keysRev = 0;
  readonly keyValues = new Map<string, string>();
  configExpired = false;
  hooks: { phase: "before" | "context"; behaviour: HookBehaviour }[] = [];
  companionResponder: CompanionResponder = () => ({ status: "ok", output: {} });
  readonly #replay = memoryReplayGuard();
  readonly #waiters = new Set<() => void>();
  readonly #statusWaiters = new Set<() => void>();
  readonly #server = createServer((req, res) => void this.#handle(req, res));
  readonly #opts: FakeBridgeOptions;
  #closed = false;

  private constructor(opts: FakeBridgeOptions, keys: { portal: Ed25519KeyPair; bridge: Ed25519KeyPair; stranger: Ed25519KeyPair }) {
    this.#opts = opts;
    this.manifest = opts.manifest;
    const agents = opts.agents ?? [
      { id: newId("agt") as AgentId, name: "Conformance agent A", mode: "free" },
      { id: newId("agt") as AgentId, name: "Conformance agent B", mode: "free" },
      { id: newId("agt") as AgentId, name: "Conformance agent C", mode: "bound" },
    ];
    const peers: Record<string, InstanceId> = {};
    for (const c of opts.manifest.companions ?? []) peers[c.product] = newId("ins") as InstanceId;
    this.ids = {
      ws: newId("ws") as WorkspaceId,
      bridge: newId("brg") as BridgeId,
      ins: opts.instanceId ?? (newId("ins") as InstanceId),
      person: newId("per") as PersonId,
      agents,
      peers,
    };
    this.portalKeys = [{ key: keys.portal, status: "active" }];
    this.bridgeKeys = [keys.bridge];
    this.stranger = keys.stranger;
    this.sdkMajors = opts.sdkMajors ?? [opts.manifest.sdkMajor, opts.manifest.sdkMajor - 1].filter((m) => m >= 0);
    this.expectedDigest = manifestDigest(opts.manifest);
    this.mint = new Mint({
      ws: this.ids.ws,
      bridge: this.ids.bridge,
      portalKey: () => this.activePortalKey(),
      bridgeKey: () => this.bridgeKeys[0],
      stranger: keys.stranger,
    });
    this.enrolCode = this.issueEnrolCode(this.ids.ins);
    this.control = new FakeBridgeControl(this);
  }

  static async create(opts: FakeBridgeOptions): Promise<FakeBridge> {
    const [portal, bridge, stranger] = await Promise.all([generateKeyPair(), generateKeyPair(), generateKeyPair()]);
    const fb = new FakeBridge(opts, { portal, bridge, stranger });
    fb.url = await listen(fb.#server, opts.port ?? 0);
    await fb.rebuildSlice();
    return fb;
  }

  /** `TB_PORTAL_KEYS` value (public JWKS, bootstrap trust). */
  portalJwks(): { keys: Ed25519PublicJwk[] } {
    return { keys: this.portalKeys.filter((k) => k.status !== "pending").map((k) => k.key.publicJwk) };
  }

  activePortalKey(): Ed25519KeyPair {
    const a = this.portalKeys.find((k) => k.status === "active");
    if (!a) throw new Error("fake bridge: no active Portal key");
    return a.key;
  }

  issueEnrolCode(ins: InstanceId, svc?: string): string {
    const code = opaqueValue("tbe_");
    this.enrolCodes.set(opaqueDigest(code), { ins, ...(svc ? { svc } : {}), exp: nowS() + 86400, used: false });
    return code;
  }

  /** Client that drives the app at `appUrl` like the bridge does (op calls, hooks, bridge ops, person launch). */
  client(appUrl: string): AppClient {
    return new AppClient(this, appUrl.replace(/\/$/, ""));
  }

  capture(p: Omit<CapturedPayload, "at">): void {
    if (this.captured.length < 20_000) this.captured.push({ ...p, at: Date.now() });
  }

  async close(): Promise<void> {
    if (this.#closed) return;
    this.#closed = true;
    for (const w of this.#waiters) w();
    for (const w of this.#statusWaiters) w();
    await closeServer(this.#server);
  }

  // ── slice ─────────────────────────────────────────────────────────────────
  agentEntries(): InstanceSlice["agents"] {
    return this.ids.agents.map((a) => ({ id: a.id, name: a.name, mode: a.mode, status: this.pause.agents.has(a.id) ? "paused" : "active" }));
  }

  async companionGrants(): Promise<string[]> {
    const out: string[] = [];
    for (const c of this.manifest.companions ?? []) {
      out.push(
        await this.mint.grant({
          sub: `tb:ins:${this.ids.ins}`,
          aud: `tb:ins:${this.ids.peers[c.product]}`,
          crud: c.crud,
          mode: "bound",
          held: ["destructive", "money"],
          caps: {},
          wf: c.operations,
        }),
      );
    }
    return out;
  }

  /** Signs a new slice (`rev` + 1) with the active Portal key and wakes the status long-polls. */
  async rebuildSlice(): Promise<number> {
    this.sliceRev++;
    const now = nowS();
    this.revoked = this.revoked.filter((r) => r.exp > now);
    const body = {
      v: 1 as const,
      iss: "tb:portal" as const,
      sub: `tb:ins:${this.ids.ins}` as const,
      aud: `tb:ins:${this.ids.ins}` as const,
      iat: now,
      ws: this.ids.ws,
      rev: this.sliceRev,
      ins: this.ids.ins,
      product: this.manifest.id,
      portalKeys: this.portalKeys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })),
      bridge: { id: this.ids.bridge, keys: this.bridgeKeys.slice(0, 4).map((k) => k.publicJwk) },
      pause: { workspace: this.pause.workspace, agents: [...this.pause.agents], instances: [...this.pause.instances] },
      revoked: { jtis: this.revoked.map((r) => ({ jti: r.jti, exp: r.exp })) },
      personNbf: this.personNbf,
      grants: await this.companionGrants(),
      agents: this.agentEntries(),
    };
    this.slice = await signSlice(body, this.activePortalKey());
    this.wake();
    return this.sliceRev;
  }

  wake(): void {
    for (const w of [...this.#waiters]) w();
  }

  /** Resolves when `pred` holds for a recorded status push (checked on every push) or rejects after `timeoutMs`. */
  waitForStatus(pred: (s: StatusSeen) => boolean, timeoutMs: number): Promise<StatusSeen> {
    const hit = this.statuses.findLast(pred);
    if (hit) return Promise.resolve(hit);
    return new Promise((resolve, reject) => {
      const done = () => {
        const s = this.statuses.findLast(pred);
        if (s) {
          clearTimeout(t);
          this.#statusWaiters.delete(done);
          resolve(s);
        } else if (this.#closed) {
          clearTimeout(t);
          this.#statusWaiters.delete(done);
          reject(new Error("fake bridge closed"));
        }
      };
      const t = setTimeout(() => {
        this.#statusWaiters.delete(done);
        reject(new Error(`timeout after ${timeoutMs} ms waiting for an app status push`));
      }, timeoutMs);
      this.#statusWaiters.add(done);
    });
  }

  /** Resolves with the latest claim (at once if one was seen) or rejects after `timeoutMs`. */
  waitForClaim(timeoutMs: number): Promise<ClaimSeen> {
    const deadline = Date.now() + timeoutMs;
    return new Promise((resolve, reject) => {
      const tick = () => {
        const c = this.claims.at(-1);
        if (c) return resolve(c);
        if (this.#closed || Date.now() > deadline) return reject(new Error(`no claim within ${timeoutMs} ms`));
        setTimeout(tick, 50).unref();
      };
      tick();
    });
  }

  // ── HTTP ──────────────────────────────────────────────────────────────────
  async #handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const pathAndQuery = req.url ?? "/";
    const path = pathAndQuery.split("?")[0];
    let raw: Buffer = Buffer.alloc(0);
    try {
      raw = await readRaw(req);
      this.capture({ dir: "bridge-in", method: req.method ?? "GET", path: pathAndQuery, headers: flatHeaders(req), body: raw.toString("utf8") });
      if (req.method === "POST" && path === BRIDGE_INTERNAL_PATHS.claim) return await this.#claim(raw, res);
      if (req.method === "POST" && path === BRIDGE_INTERNAL_PATHS.status) return await this.#status(req, pathAndQuery, raw, res);
      if (req.method === "GET" && path.startsWith("/tb/v1/keys/")) return this.#keys(req, pathAndQuery, path, res);
      if (req.method === "POST" && path === BRIDGE_INTERNAL_PATHS.call) return await this.#call(req, pathAndQuery, raw, res);
      if (req.method === "GET" && path === BRIDGE_INTERNAL_PATHS.metrics) {
        res.writeHead(200, { "content-type": "text/plain" });
        return void res.end(`tb_fake_bridge_requests_total ${this.captured.filter((c) => c.dir === "bridge-in").length}\n`);
      }
      throw new HttpError(404, "not_found", "no such route");
    } catch (e) {
      const err = e instanceof HttpError ? e : new HttpError(500, "internal", "fake bridge error");
      if (err.status !== 404 && path !== BRIDGE_INTERNAL_PATHS.status) this.violations.push({ route: path, code: err.code, detail: err.message, at: Date.now() });
      sendError(res, err.status, err.code, err.message);
    }
  }

  /** TB-Assert check (CREDENTIALS §10): `kid` ∈ claimed keys for (ins, svc), htm/htu/bd bound, ≤ 60 s, replay set. */
  #verifyInstance(req: IncomingMessage, pathAndQuery: string, raw: Buffer): { ins: InstanceId; svc?: string; iat: number; exp: number; kid: string } {
    const token = header(req, BRIDGE_HEADERS.assertion) ?? "";
    const c = peek(token);
    const iss = typeof c?.iss === "string" ? c.iss : "";
    const ins = iss.startsWith("tb:ins:") ? (iss.slice(7) as InstanceId) : null;
    const svc = typeof c?.svc === "string" ? c.svc : undefined;
    const jwk = ins ? this.instanceKeys.get(svc ? `${ins}/${svc}` : ins) : undefined;
    if (!ins || !jwk) throw new HttpError(401, "unauthenticated", "instance assertion missing or key unknown");
    const r = verifyAssertion(token, keySetFrom({ keys: [jwk] }, `tb:ins:${ins}`), {
      typ: TYP.instanceAssertion,
      aud: `tb:brg:${this.ids.bridge}`,
      now: nowS(),
      method: req.method ?? "GET",
      pathAndQuery,
      body: raw.length > 0 ? new Uint8Array(raw) : undefined,
      replay: this.#replay,
    });
    if (!r.ok) throw new HttpError(401, "unauthenticated", `instance assertion refused (${r.reason})`);
    return { ins, ...(svc ? { svc } : {}), iat: r.claims.iat, exp: r.claims.exp, kid: r.header.kid };
  }

  async #claim(raw: Buffer, res: ServerResponse): Promise<void> {
    const b = parseJson(raw) as Partial<ClaimRequest> | undefined;
    if (!b || typeof b.code !== "string" || typeof b.manifestDigest !== "string" || typeof b.sdkVersion !== "string" || typeof b.version !== "string") {
      throw new HttpError(400, "input_invalid", "ClaimRequest shape");
    }
    const d = opaqueDigest(b.code);
    let entry: { ins: InstanceId; svc?: string; exp: number; used: boolean } | undefined;
    for (const [k, v] of this.enrolCodes) if (digestEqual(k, d)) entry = v;
    if (!entry || entry.used || entry.exp < nowS()) throw new HttpError(403, "code_invalid", "enrolment code unknown, used or expired");
    if ((b.service ?? undefined) !== entry.svc) throw new HttpError(403, "code_invalid", "code bound to another target");
    let major = Number.NaN;
    try {
      major = sdkMajorOf(b.sdkVersion);
    } catch {
      throw new HttpError(400, "sdk_major_unsupported", "sdkVersion is not semver");
    }
    if (!this.sdkMajors.includes(major)) throw new HttpError(400, "sdk_major_unsupported", `SDK major ${major} not served`);
    if (b.manifestDigest !== this.expectedDigest) throw new HttpError(409, "manifest_mismatch", "manifestDigest differs from the deployed manifest");
    try {
      assertPublicJwk(b.instancePublicKey);
    } catch {
      throw new HttpError(400, "input_invalid", "instancePublicKey is not an Ed25519 public JWK");
    }
    entry.used = true;
    const slot = entry.svc ? `${entry.ins}/${entry.svc}` : entry.ins;
    this.claims.push({ request: b as ClaimRequest, codeDigest: d, at: Date.now() });
    if (this.#opts.deferBinding) this.pending.set(slot, b.instancePublicKey as Ed25519PublicJwk);
    else this.instanceKeys.set(slot, b.instancePublicKey as Ed25519PublicJwk);
    const body: ClaimResponse = {
      ins: entry.ins,
      bridge: { id: this.ids.bridge, publicKey: this.bridgeKeys[0].publicJwk, internalUrl: this.url },
      ...(this.#opts.deferBinding || !this.slice ? {} : { slice: this.slice }),
    };
    sendJson(res, 200, body);
  }

  async #status(req: IncomingMessage, pathAndQuery: string, raw: Buffer, res: ServerResponse): Promise<void> {
    const who = this.#verifyInstance(req, pathAndQuery, raw);
    const s = parseJson(raw) as Partial<AppStatus> | undefined;
    const nums = ["scopesRev", "sliceRevision", "keysRev", "pendingHolds"] as const;
    if (!s || !["ready", "needs_keys", "degraded"].includes(String(s.readiness)) || nums.some((k) => !Number.isInteger(s[k]))) {
      throw new HttpError(400, "input_invalid", "AppStatus shape");
    }
    this.statuses.push({ status: s as AppStatus, ins: who.ins, assertion: { iat: who.iat, exp: who.exp, kid: who.kid }, at: Date.now() });
    for (const w of [...this.#statusWaiters]) w();
    const wait = Math.max(0, Math.min(this.#opts.maxWaitS ?? 60, Number(new URL(pathAndQuery, "http://x").searchParams.get("wait") ?? "0") || 0));
    const changed = () => this.slice !== null && (s.sliceRevision !== this.sliceRev || s.keysRev !== this.keysRev);
    if (!changed() && wait > 0 && !this.#closed) {
      await new Promise<void>((resolve) => {
        const done = () => {
          clearTimeout(t);
          this.#waiters.delete(done);
          resolve();
        };
        const t = setTimeout(done, wait * 1000);
        this.#waiters.add(done);
        req.once("close", done);
      });
    }
    if (res.destroyed) return;
    if (changed() && this.slice) {
      const body: AppStatusResponse = { slice: this.slice, sliceRevision: this.sliceRev, keysRev: this.keysRev };
      return sendJson(res, 200, body);
    }
    res.writeHead(204).end();
  }

  #keys(req: IncomingMessage, pathAndQuery: string, path: string, res: ServerResponse): void {
    const who = this.#verifyInstance(req, pathAndQuery, Buffer.alloc(0));
    const name = decodeURIComponent(path.slice("/tb/v1/keys/".length));
    if (this.pause.workspace || this.pause.instances.has(who.ins)) throw new HttpError(403, "paused", "workspace or instance paused");
    const declared = (this.manifest.settings?.keys ?? []).find((k) => k.name === name && k.source === "account_default" && k.usedBy.includes(who.svc ?? "app"));
    if (!declared) throw new HttpError(403, "key_not_declared", "key not declared for this caller");
    this.keyFetches.push({ name, ins: who.ins, at: Date.now() });
    const value = this.keyValues.get(name);
    if (value === undefined) throw new HttpError(404, "key_not_set", "key not set on the key page");
    const body: KeyFetchResponse = { name, value, keysRev: this.keysRev };
    sendJson(res, 200, body, { "cache-control": "no-store" });
  }

  async #call(req: IncomingMessage, pathAndQuery: string, raw: Buffer, res: ServerResponse): Promise<void> {
    const who = this.#verifyInstance(req, pathAndQuery, raw);
    const env = parseJson(raw) as Partial<CallEnvelope> | undefined;
    if (!env || typeof env.target !== "string" || typeof env.op !== "string" || !("input" in env)) throw new HttpError(400, "input_invalid", "CallEnvelope shape");
    const target = this.ids.peers[env.target];
    const declared = (this.manifest.companions ?? []).find((c) => c.product === env.target);
    if (!target || !declared) throw new HttpError(404, "unknown_tool", "no such companion target");
    if (this.configExpired) throw new HttpError(503, "config_expired", "signed config older than 12 h");
    const grant = header(req, BRIDGE_HEADERS.companionGrant) ?? "";
    if (peek(grant)?.sub !== `tb:ins:${who.ins}`) throw new HttpError(403, "grant_invalid", "companion grant subject is not the asserting instance");
    const op: OperationView = {
      standard: false,
      id: env.op,
      title: env.op,
      description: "companion target operation (fake)",
      crud: declared.crud,
      effect: "read",
      idempotency: "none",
      receipt: false,
      audience: "agent",
    };
    const g = gate({
      paused: { workspace: this.pause.workspace, agent: false, connection: false, instance: this.pause.instances.has(who.ins) || this.pause.instances.has(target) },
      grant,
      trust: {
        now: nowS(),
        self: `tb:ins:${target}`,
        ws: this.ids.ws,
        bridge: this.ids.bridge,
        issuers: keySetFromPortalKeys(this.portalKeys.map((k) => ({ jwk: k.key.publicJwk, status: k.status }))),
        bridgeKeys: keySetFrom({ keys: this.bridgeKeys.map((k) => k.publicJwk) }, `tb:brg:${this.ids.bridge}`),
        revokedJtis: new Set(this.revoked.map((r) => r.jti)),
      },
      op,
      declaredScopeTypes: [],
    });
    if (g.decision === "refuse") throw new HttpError(403, g.reason, "refused by gate()");
    for (const h of this.hooks) {
      if (h.behaviour === "deny") throw new HttpError(403, "hook_denied", `${h.phase} hook denied the call`);
      if (h.behaviour === "timeout") await new Promise((r) => setTimeout(r, 2100));
      throw new HttpError(502, "hook_failed", `${h.phase} hook failed (fail closed)`);
    }
    const answer = await this.companionResponder(env as CallEnvelope, who.ins);
    this.companionCalls.push({ envelope: env as CallEnvelope, caller: who.ins, answer: answer.status === "held" ? 202 : 200, at: Date.now() });
    sendJson(res, answer.status === "held" ? 202 : 200, answer);
  }
}

function flatHeaders(req: IncomingMessage): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers)) if (v !== undefined) out[k] = Array.isArray(v) ? v.join(", ") : v;
  return out;
}

/** Test control API (CONFORMANCE §3): pause, rotate, revoke, expire, set keys, inject hooks, wait for the app. */
export class FakeBridgeControl {
  readonly #b: FakeBridge;
  constructor(b: FakeBridge) {
    this.#b = b;
  }

  get sliceRevision(): number {
    return this.#b.sliceRev;
  }
  get keysRev(): number {
    return this.#b.keysRev;
  }

  /** Lists a deferred claim's key (Core binding) and publishes a new slice. */
  async bind(): Promise<number> {
    for (const [slot, jwk] of this.#b.pending) this.#b.instanceKeys.set(slot, jwk);
    this.#b.pending.clear();
    return this.#b.rebuildSlice();
  }
  issueEnrolCode(svc?: string): string {
    return this.#b.issueEnrolCode(this.#b.ids.ins, svc);
  }
  pauseWorkspace(on: boolean): Promise<number> {
    this.#b.pause.workspace = on;
    return this.#b.rebuildSlice();
  }
  pauseAgent(agent: AgentId, on: boolean): Promise<number> {
    if (on) this.#b.pause.agents.add(agent);
    else this.#b.pause.agents.delete(agent);
    return this.#b.rebuildSlice();
  }
  pauseInstance(on: boolean, ins: InstanceId = this.#b.ids.ins): Promise<number> {
    if (on) this.#b.pause.instances.add(ins);
    else this.#b.pause.instances.delete(ins);
    return this.#b.rebuildSlice();
  }
  /** Withdraws a grant (or other jti) before its `exp` via slice `revoked.jtis`. */
  revokeJti(jti: string, exp: number): Promise<number> {
    this.#b.revoked.push({ jti, exp });
    return this.#b.rebuildSlice();
  }
  /** "Sign out everywhere": app UI sessions created before `at` become invalid. */
  setPersonNbf(at: number): Promise<number> {
    this.#b.personNbf = at;
    return this.#b.rebuildSlice();
  }
  republish(): Promise<number> {
    return this.#b.rebuildSlice();
  }
  /** Portal key rotation (CREDENTIALS §9.2): `announce` adds a pending key; `activate` makes it sign (old → retired); `retire` drops retired keys. */
  async rotatePortalKey(phase: "announce" | "activate" | "retire"): Promise<number> {
    const b = this.#b;
    if (phase === "announce") b.portalKeys.push({ key: await generateKeyPair(), status: "pending" });
    if (phase === "activate") {
      const next = b.portalKeys.find((k) => k.status === "pending");
      if (!next) throw new Error("no pending Portal key to activate");
      for (const k of b.portalKeys) if (k.status === "active") k.status = "retired";
      next.status = "active";
    }
    if (phase === "retire") b.portalKeys = b.portalKeys.filter((k) => k.status !== "retired");
    return b.rebuildSlice();
  }
  /** Re-enrolment of the bridge: new bridge key signs proofs; `keepOld` keeps the old key in slice `bridge.keys`. */
  async rotateBridgeKey(opts: { keepOld?: boolean } = {}): Promise<number> {
    const b = this.#b;
    const next = await generateKeyPair();
    b.bridgeKeys = opts.keepOld ? [next, ...b.bridgeKeys].slice(0, 4) : [next];
    return b.rebuildSlice();
  }
  /** Key page write (BRIDGE §9.3): value stored, `keysRev` bumped, long-polls woken. */
  setKey(name: string, value: string): void {
    this.#b.keyValues.set(name, value);
    this.#b.keysRev++;
    this.#b.wake();
  }
  deleteKey(name: string): void {
    this.#b.keyValues.delete(name);
    this.#b.keysRev++;
    this.#b.wake();
  }
  setConfigExpired(on: boolean): void {
    this.#b.configExpired = on;
  }
  injectHook(phase: "before" | "context", behaviour: HookBehaviour): void {
    this.#b.hooks.push({ phase, behaviour });
  }
  clearHooks(): void {
    this.#b.hooks = [];
  }
  setCompanionResponder(fn: CompanionResponder): void {
    this.#b.companionResponder = fn;
  }
  waitForClaim(timeoutMs = 20_000): Promise<ClaimSeen> {
    return this.#b.waitForClaim(timeoutMs);
  }
  waitForStatus(pred: (s: StatusSeen) => boolean = () => true, timeoutMs = 20_000): Promise<StatusSeen> {
    return this.#b.waitForStatus(pred, timeoutMs);
  }
  /** Resolves once the app reports `sliceRevision ≥ rev` (i.e. it installed that slice). */
  waitForSliceRevision(rev: number, timeoutMs = 20_000): Promise<StatusSeen> {
    return this.#b.waitForStatus((s) => s.status.sliceRevision >= rev, timeoutMs);
  }
}

export async function createFakeBridge(opts: FakeBridgeOptions): Promise<FakeBridge> {
  return FakeBridge.create(opts);
}

export { Mint };
