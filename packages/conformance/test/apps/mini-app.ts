// A tiny app built ONLY on node:http + @opt2-tealbrick/manifest: a minimal correct implementation of the app side of
// the call path (claim, slice long-poll, call proof + grant re-verification, authorize(), holds/receipts, idempotency,
// person launch/session/CSRF, hooks, bridge ops, export, backup/restore). Each `faults` switch breaks exactly one rule
// so the suite's sensitivity can be proven: the faulty variant MUST fail the matching checks.
import { createHash, randomBytes } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import {
  authorize,
  digest,
  type Ed25519KeyPair,
  exportPrivateKey,
  generateKeyPair,
  importKeyPair,
  kekFromEnv,
  keySetFrom,
  keySetFromPortalKeys,
  manifestDigest,
  memoryReplayGuard,
  seal,
  sealAad,
  signInstanceAssertion,
  trustedPortalKeys,
  unseal,
  validateInput,
  verifyBridgeOpProof,
  verifyCallProof,
  verifyGrant,
  verifyHookProof,
  verifySlice,
  verifyTicket,
  withStandardOps,
} from "@opt2-tealbrick/manifest";
import type { InstanceSlice } from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, InstanceId, SealedBlob, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, OperationView, TrustContext } from "@opt2-tealbrick/spec/sdk";
import { readTar } from "../../src/tar.ts";
import { writeTarGz } from "./tar-write.ts";

export interface MiniAppFaults {
  skipProofVerify?: boolean;
  skipGrantVerify?: boolean;
  ignorePause?: boolean;
  ticketReusable?: boolean;
  noIdempotencyConflict?: boolean;
  servesClaimRoute?: boolean;
  standingApproval?: boolean;
  noCsrf?: boolean;
  storesRawInput?: boolean;
  ignorePersonNbf?: boolean;
  newKeyOnRestart?: boolean;
  noProofReplayGuard?: boolean;
  /** companion call: no slice re-read + retry on grant_stale (SDK-API §9) */
  noCompanionRetry?: boolean;
  /** before hook answers an extra key (phase shape, BRIDGE §8.2) */
  badHookShape?: boolean;
  /** ignores portalKeySet: keeps the pre-v0.1.11 rule (portalKeys replace the trusted set; CREDENTIALS §9.5) */
  ignoreKeySet?: boolean;
  /** NOT a fault: a spec-0.1.12 build (statement required for the first slice, C63a) */
  keysetRequired?: boolean;
}

interface Receipt {
  id: string;
  callId: string | null;
  caller: { type: "agent" | "app"; id: string; name: string };
  op: string;
  effect: string;
  holdFamily: string | null;
  status: string;
  inputDigest: string;
  summary: string;
  meta: Json;
  idempotencyKey: string | null;
  view?: string;
  input?: Json;
  createdAt: number;
  decidedAt: number | null;
  expiresAt: number | null;
  decidedBy: string | null;
  consumed?: boolean;
}

interface State {
  claimed: boolean;
  bridgeId: string | null;
  slice: string | null;
  /** v0.1.11: pinned key-set statement + its keys */
  kss?: { seq: number; kss: string; keys: InstanceSlice["portalKeys"] } | null;
  receipts: Receipt[];
  idem: Record<string, { inputDigest: string; kind: "held" | "result"; holdId?: string; output?: Json }>;
  scopes: { agent: string; type: string; instanceId: string; access: string }[];
  defaultsApplied: string[];
  sessions: { digest: string; per: string; createdAt: number; csrf: string; expiresAt: number }[];
  usedJti: string[];
  audit: { id: string; at: number; actor: string; action: string; target: string | null }[];
}

const nowS = () => Math.floor(Date.now() / 1000);
const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const sha = (s: string | Uint8Array) => createHash("sha256").update(s).digest("hex");
const peek = (t: string): Record<string, unknown> => {
  try {
    return JSON.parse(Buffer.from(t.split(".")[1] ?? "", "base64url").toString("utf8")) as Record<string, unknown>;
  } catch {
    return {};
  }
};
class E extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string) {
    super(code);
    this.status = status;
    this.code = code;
  }
}

export async function startMiniApp(manifest: Manifest, env: Record<string, string>, faults: MiniAppFaults = {}, port = 0) {
  const ins = env.TB_INSTANCE_ID as InstanceId;
  const dataDir = env.TB_DATA_DIR;
  const backupDir = env.TB_BACKUP_DIR;
  const bridgeUrl = env.TB_BRIDGE_URL;
  const kek = kekFromEnv(env.TB_KEK);
  const product = manifest.id;
  const mDigest = manifestDigest(manifest);
  const ops = withStandardOps(manifest);
  const replay = memoryReplayGuard();
  const statePath = join(dataDir, "state.json");
  mkdirSync(join(dataDir, "tb"), { recursive: true });

  // restore at boot (before anything else), then load state
  if (env.TB_RESTORE_FROM) {
    const entries = readTar(new Uint8Array(readFileSync(join(backupDir, env.TB_RESTORE_FROM))));
    const meta = JSON.parse(new TextDecoder().decode(entries.find((e) => e.name === "meta.json")?.data)) as { parts: { file: string; sha256: string }[] };
    for (const p of meta.parts) {
      const e = entries.find((x) => x.name === p.file);
      if (!e || sha(e.data) !== p.sha256) throw new Error("restore_failed");
    }
    writeFileSync(statePath, entries.find((e) => e.name === "app.db")?.data ?? "{}");
  }
  const st: State = existsSync(statePath)
    ? (JSON.parse(readFileSync(statePath, "utf8")) as State)
    : { claimed: false, bridgeId: null, slice: null, receipts: [], idem: {}, scopes: [], defaultsApplied: [], sessions: [], usedJti: [], audit: [] };
  const save = () => writeFileSync(statePath, JSON.stringify(st));

  // instance key, sealed on the volume
  const keyPath = join(dataDir, "tb", "instance-key");
  let key: Ed25519KeyPair;
  if (existsSync(keyPath) && !faults.newKeyOnRestart) {
    key = await importKeyPair(unseal(JSON.parse(readFileSync(keyPath, "utf8")) as SealedBlob, { current: kek }, sealAad("instance-key", ins)));
  } else {
    key = await generateKeyPair({ extractable: true });
    writeFileSync(keyPath, JSON.stringify(seal(await exportPrivateKey(key), kek, sealAad("instance-key", ins))));
  }

  let slice: InstanceSlice | null = st.slice ? (peek(st.slice) as unknown as InstanceSlice) : null;
  let keysRev = 0;
  const keyCache = new Map<string, string>();
  const declaredKeys = (manifest.settings?.keys ?? []).filter((k) => k.source === "account_default" && k.usedBy.includes("app"));

  const trust = (): TrustContext | null =>
    slice && st.bridgeId
      ? {
          now: nowS(),
          self: `tb:ins:${ins}`,
          ws: slice.ws as WorkspaceId,
          bridge: st.bridgeId as BridgeId,
          issuers: keySetFromPortalKeys(st.kss ? st.kss.keys : slice.portalKeys),
          bridgeKeys: keySetFrom({ keys: slice.bridge.keys }, `tb:brg:${st.bridgeId as BridgeId}`),
          revokedJtis: new Set(slice.revoked.jtis.map((j) => j.jti)),
        }
      : null;

  const ensureAgent = (agent: string) => {
    for (const sc of manifest.scopes ?? []) {
      const k = `${agent}:${sc.type}`;
      if (st.defaultsApplied.includes(k)) continue;
      st.defaultsApplied.push(k);
      for (const g of sc.defaultGrants) if (g.kind === "own") st.scopes.push({ agent, type: sc.type, instanceId: `${sc.type}-${agent.slice(-8).toLowerCase()}`, access: g.access });
    }
  };

  // v0.1.11 key-set rule (CREDENTIALS §9.5): roots from the harness-only TBCONF_PORTAL_ROOT_KEYS (a test app; the SDK
  // gets them through startApp's harness option)
  const roots = env.TBCONF_PORTAL_ROOT_KEYS ? (JSON.parse(env.TBCONF_PORTAL_ROOT_KEYS) as never[]) : [];
  /** false when the slice was refused */
  function installSlice(token: string): boolean {
    const t = faults.ignoreKeySet ? ({ ok: true, legacy: true } as const) : trustedPortalKeys(peek(token), st.kss ? { seq: st.kss.seq, kss: st.kss.kss } : null, roots, { required: faults.keysetRequired === true });
    if (!t.ok) return false;
    const issuers = !t.legacy ? t.signers : slice ? keySetFromPortalKeys(slice.portalKeys) : keySetFrom(JSON.parse(env.TB_PORTAL_KEYS) as never, "tb:portal");
    const r = verifySlice(token, { now: nowS(), self: `tb:ins:${ins}`, ws: (slice?.ws ?? peek(token).ws) as WorkspaceId, bridge: st.bridgeId as BridgeId, issuers });
    if (!r.ok) return false;
    if (slice && r.slice.rev <= slice.rev) return true;
    if (!t.legacy) st.kss = { seq: t.seq, kss: t.kss, keys: t.keys.keys.map((k) => ({ jwk: k.jwk, status: k.status })) };
    slice = r.slice;
    st.slice = token;
    for (const a of slice.agents) ensureAgent(a.id);
    if (slice.pause.workspace || slice.pause.instances.includes(ins)) keyCache.clear();
    save();
    return true;
  }

  async function bridge(method: "GET" | "POST", path: string, body?: unknown, signal?: AbortSignal, extra: Record<string, string> = {}): Promise<{ status: number; body: unknown }> {
    const bytes = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
    const headers: Record<string, string> = { "content-type": "application/json", ...extra };
    if (st.bridgeId) headers["TB-Assert"] = await signInstanceAssertion({ key, ins, bridge: st.bridgeId as BridgeId, method, pathAndQuery: path, body: bytes, now: nowS() });
    const res = await fetch(bridgeUrl + path, { method, headers, body: bytes, signal });
    const text = await res.text();
    return { status: res.status, body: text ? JSON.parse(text) : null };
  }

  async function fetchKeys(): Promise<void> {
    keyCache.clear();
    for (const k of declaredKeys) {
      const r = await bridge("GET", `/tb/v1/keys/${k.name}`);
      if (r.status === 200 && isObj(r.body)) keyCache.set(k.name, String(r.body.value));
    }
  }

  // claim (once)
  if (!st.claimed) {
    const r = await bridge("POST", "/tb/v1/claim", { code: env.TB_ENROL_CODE, instancePublicKey: key.publicJwk, manifestDigest: mDigest, version: manifest.version, sdkVersion: `${manifest.sdkMajor}.0.0` });
    if (r.status !== 200 || !isObj(r.body) || r.body.ins !== ins) throw new Error(`claim failed: ${r.status}`);
    st.claimed = true;
    st.bridgeId = String((r.body.bridge as Record<string, unknown>).id);
    save();
    if (typeof r.body.slice === "string") installSlice(r.body.slice);
  }

  // status push + long-poll
  const stop = new AbortController();
  const pending = () => st.receipts.filter((x) => x.status === "held").length;
  const loop = (async () => {
    let first = true;
    while (!stop.signal.aborted) {
      try {
        const r = await bridge(
          "POST",
          `/tb/v1/status?wait=${first ? 0 : 60}`,
          { readiness: "ready", version: manifest.version, sdkVersion: `${manifest.sdkMajor}.0.0`, scopesRev: 0, sliceRevision: slice?.rev ?? 0, keysRev, pendingHolds: pending() },
          stop.signal,
        );
        first = false;
        if (r.status === 200 && isObj(r.body)) {
          if (typeof r.body.slice === "string" && !installSlice(r.body.slice)) await new Promise((res) => setTimeout(res, 300));
          if (typeof r.body.keysRev === "number" && r.body.keysRev !== keysRev) {
            keysRev = r.body.keysRev;
            await fetchKeys();
          }
        }
      } catch {
        if (stop.signal.aborted) break;
        await new Promise((res) => setTimeout(res, 200));
      }
    }
  })();

  /** Companion call (SDK-API §9): the slice grant whose `wf` = the declared operations; grant_stale → re-read once, retry. */
  async function callCompanion(parentCall: string | null): Promise<Json> {
    const c = manifest.companions?.[0];
    if (!c) return null;
    const want = [...c.operations].sort().join(",");
    for (let attempt = 0; ; attempt++) {
      const grant = (slice?.grants ?? []).find((g) => [...((peek(g).wf as string[]) ?? [])].sort().join(",") === want);
      if (!grant) throw new E(403, "no_grant");
      const env = { target: c.product, op: c.operations[0], input: {}, ...(parentCall ? { parentCall } : {}) };
      const r = await bridge("POST", "/tb/v1/call", env, undefined, { "TB-Grant": grant });
      if (r.status === 200 || r.status === 202) return r.body as Json;
      const code = String(((r.body as { error?: { code?: string } } | null)?.error?.code) ?? "app_error");
      if (attempt === 0 && code === "grant_stale" && !faults.noCompanionRetry) {
        const s0 = await bridge("POST", "/tb/v1/status?wait=0", { readiness: "ready", version: manifest.version, sdkVersion: `${manifest.sdkMajor}.0.0`, scopesRev: 0, sliceRevision: 0, keysRev, pendingHolds: pending() });
        if (s0.status === 200 && isObj(s0.body) && typeof s0.body.slice === "string") installSlice(s0.body.slice);
        continue;
      }
      throw new E(r.status, code);
    }
  }

  // ── HTTP ──
  const read = async (req: IncomingMessage) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    return Buffer.concat(chunks).toString("utf8");
  };
  const json = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { "content-type": "application/json", ...headers });
    res.end(JSON.stringify(body));
  };
  const fail = (res: ServerResponse, e: E) => json(res, e.status, { error: { code: e.code, message: e.code, requestId: `req_${randomBytes(6).toString("hex")}` } });
  const pausedFor = (agent: string | null) => {
    if (faults.ignorePause || !slice) return { workspace: false, instance: false, agent: false };
    return { workspace: slice.pause.workspace, instance: slice.pause.instances.includes(ins), agent: agent !== null && slice.pause.agents.includes(agent as never) };
  };
  const levelCrud = (type: string, level: string) => manifest.scopes?.find((s) => s.type === type)?.access.find((a) => a.id === level)?.crud ?? [];
  const newId = (p: string) => `${p}_${randomBytes(16).toString("hex").toUpperCase().slice(0, 26)}`;

  async function agentOp(req: IncomingMessage, res: ServerResponse, opId: string, raw: string): Promise<void> {
    const body = JSON.parse(raw || "{}") as { input: Json; context?: Record<string, Json>; idempotencyKey?: string };
    const t = trust();
    if (!t) throw new E(503, "slice_stale");
    const grant = (req.headers.authorization ?? "").replace(/^Bearer /, "");
    const proof = String(req.headers["tb-call"] ?? "");
    const g0 = peek(grant);
    let callId: string | null = null;
    if (!faults.skipProofVerify) {
      const p = verifyCallProof(proof, t, { op: opId, inputDigest: digest(body.input), contextDigest: digest(body.context ?? {}), grantJti: String(g0.jti ?? ""), grantSub: String(g0.sub ?? "") }, faults.noProofReplayGuard ? undefined : replay);
      if (!p.ok) throw new E(401, "call_proof_invalid");
      callId = p.claims.call;
    }
    let callerId: string;
    let held: string[] = [];
    if (!faults.skipGrantVerify) {
      const g = verifyGrant(grant, t);
      if (!g.ok) throw new E(g.code.startsWith("grant_") ? 401 : 403, g.code);
      callerId = g.caller.id;
      held = g.claims.held;
    } else {
      callerId = String(g0.sub ?? "tb:agt:unknown").split(":")[2] ?? "unknown";
    }
    void held;
    const op = ops.find((o) => o.id === opId);
    if (!op) throw new E(404, "unknown_tool");
    if (op.audience !== "agent") throw new E(403, "audience_not_agent");
    if (op.standard) {
      if (op.id !== "tb.hold_status") throw new E(403, "audience_not_agent");
      const h = st.receipts.find((x) => x.id === String((body.input as Record<string, unknown>)?.holdId) && x.caller.id === callerId);
      if (!h) throw new E(404, "hold_not_found");
      return json(res, 200, { status: "ok", output: { status: h.status, expiresAt: h.expiresAt ? new Date(h.expiresAt).toISOString() : null } });
    }
    if (!validateInput(op, body.input).ok) throw new E(400, "input_invalid");
    ensureAgent(callerId);
    const inputDigest = digest(body.input);
    const idemKey = op.idempotency === "none" ? null : (body.idempotencyKey ?? null);
    if (op.idempotency === "required" && !idemKey) throw new E(400, "idempotency_key_required");
    const ik = idemKey ? `${callerId}:${op.id}:${idemKey}` : null;
    const prior = ik ? st.idem[ik] : undefined;
    if (prior && prior.inputDigest !== inputDigest && !faults.noIdempotencyConflict) throw new E(409, "idempotency_conflict");
    if (prior?.kind === "result" && prior.inputDigest === inputDigest) return json(res, 200, { status: "ok", output: prior.output });
    if (prior?.kind === "held" && prior.inputDigest === inputDigest) {
      const h = st.receipts.find((x) => x.id === prior.holdId);
      if (h?.status === "held") return json(res, 202, { status: "held", holdId: h.id, expiresAt: new Date(h.expiresAt ?? 0).toISOString() });
      if (h?.status === "denied") throw new E(403, "hold_denied");
    }
    const scoped = op.standard ? undefined : op.scopeType;
    let access: { level: string; crud: typeof op.crud } | null = null;
    if (scoped) {
      const req0 = (op.standard ? [] : ((op.input?.required as string[]) ?? [])).find((k) => typeof (body.input as Record<string, unknown>)[k] === "string");
      const sid = req0 ? String((body.input as Record<string, unknown>)[req0]) : "";
      const row = st.scopes.find((r) => r.agent === callerId && r.type === scoped && r.instanceId === sid);
      access = row ? { level: row.access, crud: levelCrud(scoped, row.access) } : null;
    }
    const approved = faults.standingApproval
      ? st.receipts.find((x) => x.caller.id === callerId && x.op === op.id && (x.status === "approved" || x.status === "run"))
      : st.receipts.find((x) => x.caller.id === callerId && x.op === op.id && x.inputDigest === inputDigest && x.status === "approved" && !x.consumed);
    const eff = op as Extract<OperationView, { standard: false }>;
    const d = authorize({
      paused: pausedFor(callerId),
      grant,
      trust: t,
      op: { id: op.id, crud: op.crud, effect: op.effect, ...(eff.holdFamily ? { holdFamily: eff.holdFamily } : {}), ...(scoped ? { scopeType: scoped } : {}) },
      access,
      usage: {},
      approval: approved ? "approved" : "none",
    });
    if (faults.skipGrantVerify && d.decision === "refuse" && d.reason.startsWith("grant_")) {
      // a broken app that never verifies the grant runs anyway
    } else if (d.decision === "refuse") throw new E(403, d.reason);
    const base = {
      callId,
      caller: { type: "agent" as const, id: callerId, name: callerId },
      op: op.id,
      effect: op.effect,
      inputDigest,
      summary: op.title,
      meta: null,
      idempotencyKey: idemKey,
      createdAt: Date.now(),
      decidedAt: null,
      decidedBy: null,
      ...(faults.storesRawInput ? { input: body.input } : {}),
    };
    if (d.decision === "hold") {
      const h: Receipt = { ...base, id: newId("hld"), holdFamily: d.holdFamily ?? null, status: "held", expiresAt: Date.now() + 15 * 60_000, view: op.title };
      st.receipts.push(h);
      if (ik) st.idem[ik] = { inputDigest, kind: "held", holdId: h.id };
      save();
      return json(res, 202, { status: "held", holdId: h.id, expiresAt: new Date(h.expiresAt ?? 0).toISOString() });
    }
    // read ops also read the companion product (app→app through the bridge)
    const companion = op.crud.includes("read") ? await callCompanion(callId) : null;
    const output: Json = { ok: true, op: op.id, ...(companion ? { companion } : {}) };
    let receiptId: string | undefined;
    if (approved) {
      approved.status = "run";
      approved.consumed = true; // the receipt keeps the held call's id (accepted rule, SDK-API §4.3)
      receiptId = approved.id;
    } else if (op.receipt) {
      const r: Receipt = { ...base, id: newId("rcp"), holdFamily: null, status: "run", expiresAt: null };
      st.receipts.push(r);
      receiptId = r.id;
    }
    if (ik) st.idem[ik] = { inputDigest, kind: "result", output };
    save();
    json(res, 200, { status: "ok", output, ...(receiptId ? { receiptId } : {}) });
  }

  function session(req: IncomingMessage) {
    const m = /tb_session=([^;]+)/.exec(String(req.headers.cookie ?? ""));
    const s = m ? st.sessions.find((x) => x.digest === sha(m[1])) : undefined;
    if (!s || s.expiresAt < Date.now()) throw new E(401, "session_required");
    if (!faults.ignorePersonNbf && slice && s.createdAt < slice.personNbf * 1000) throw new E(401, "session_required");
    return s;
  }

  async function personOp(req: IncomingMessage, res: ServerResponse, opId: string, raw: string): Promise<void> {
    const s = session(req);
    if (!faults.noCsrf && req.headers["tb-csrf"] !== s.csrf) throw new E(403, "csrf_invalid");
    const input = ((JSON.parse(raw || "{}") as { input?: Record<string, unknown> }).input ?? {}) as Record<string, unknown>;
    const op = ops.find((o) => o.id === opId);
    if (!op) throw new E(404, "unknown_tool");
    if (op.audience !== "person") throw new E(403, "audience_not_person");
    let out: Json;
    switch (opId) {
      case "tb.holds_list":
        out = { items: st.receipts.filter((x) => ["held", "approved", "denied"].includes(x.status)) as unknown as Json, nextCursor: null };
        break;
      case "tb.receipts_list":
        out = { items: st.receipts as unknown as Json, nextCursor: null };
        break;
      case "tb.holds_decide": {
        const h = st.receipts.find((x) => x.id === input.holdId && x.status === "held");
        if (!h) throw new E(404, "hold_not_found");
        h.status = input.decision === "approve" ? "approved" : "denied";
        h.decidedAt = Date.now();
        h.decidedBy = s.per;
        st.audit.push({ id: newId("aud"), at: Date.now(), actor: s.per, action: "hold.decide", target: h.id });
        out = h as unknown as Json;
        break;
      }
      case "tb.agents_list":
        out = { agents: (slice?.agents ?? []).map((a) => ({ ...a, access: st.scopes.filter((r) => r.agent === a.id) })) as unknown as Json };
        break;
      case "tb.scopes_set": {
        st.scopes = st.scopes.filter((r) => !(r.agent === input.agent && r.type === input.type && r.instanceId === input.id));
        if (input.access !== null) st.scopes.push({ agent: String(input.agent), type: String(input.type), instanceId: String(input.id), access: String(input.access) });
        out = { access: input.access as Json };
        break;
      }
      case "tb.export": {
        const files = [
          { file: "receipts.jsonl", data: Buffer.from(st.receipts.map((r) => JSON.stringify(r)).join("\n")) },
          { file: "audit.jsonl", data: Buffer.from(st.audit.map((r) => JSON.stringify(r)).join("\n")) },
        ];
        const meta = { format: "tealbrick.export/1", product, version: manifest.version, instance: ins, sdk: "0.0.0-test", createdAt: new Date().toISOString(), files: files.map((f) => ({ file: f.file, rows: f.data.toString().split("\n").filter(Boolean).length, sha256: sha(f.data) })) };
        const tgz = writeTarGz([{ name: "meta.json", data: Buffer.from(JSON.stringify(meta)) }, ...files.map((f) => ({ name: f.file, data: f.data }))]);
        writeFileSync(join(backupDir, `tb-export-${Date.now()}.tar.gz`), tgz);
        res.writeHead(200, { "content-type": "application/gzip" });
        return void res.end(tgz);
      }
      default:
        out = {};
    }
    save();
    json(res, 200, { status: "ok", output: out });
  }

  async function handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://x");
    const path = url.pathname;
    const raw = await read(req);
    const base = `/a/${product}`;
    try {
      if (req.method === "GET" && path === "/tb/v1/manifest") return json(res, 200, manifest);
      if (req.method === "GET" && path === "/tb/v1/health")
        return json(res, 200, { status: "ok", sdk: "0.0.0-test", version: manifest.version, manifestDigest: mDigest, keys: declaredKeys.map((k) => ({ name: k.name, present: keyCache.has(k.name), source: keyCache.has(k.name) ? "account_default" : null })) });
      if (req.method === "GET" && path === "/tb/v1/openapi.json")
        return json(res, 200, { openapi: "3.1.0", info: { title: manifest.name, version: manifest.version }, paths: Object.fromEntries(ops.filter((o) => o.audience === "agent").map((o) => [`/tb/v1/ops/${o.id}`, { post: {} }])) });
      if (faults.servesClaimRoute && path === "/tb/v1/claim") return json(res, 200, { ok: true });
      if (req.method === "POST" && path.startsWith("/tb/v1/ops/")) return await agentOp(req, res, decodeURIComponent(path.slice(11)), raw);
      if (req.method === "POST" && path.startsWith("/tb/v1/hooks/")) {
        const t = trust();
        if (!t) throw new E(503, "slice_stale");
        const hook = manifest.hooks?.find((h) => h.id === path.slice(13));
        if (!hook) throw new E(404, "unknown_hook");
        const b = JSON.parse(raw) as { phase: string; call: { input?: Json }; context: Json };
        const p = verifyHookProof(String(req.headers["tb-call"] ?? ""), t, { hook: hook.id, phase: hook.phase, contextDigest: digest(b.context), ...(b.call.input !== undefined ? { inputDigest: digest(b.call.input) } : {}) }, replay);
        if (!p.ok) throw new E(401, "call_proof_invalid");
        if (b.phase !== hook.phase) throw new E(400, "input_invalid");
        return json(res, 200, hook.phase === "before" ? { allow: true, ...(faults.badHookShape ? { tb_extra: 1 } : {}) } : hook.phase === "context" ? { add: { [`${product}.seen`]: true } } : {});
      }
      if (req.method === "POST" && path.startsWith("/tb/v1/bridge/")) {
        const t = trust();
        if (!t) throw new E(503, "slice_stale");
        const name = path.slice(14);
        const bop = name === "scope-summary" ? "scope_summary" : name;
        const b = JSON.parse(raw || "{}") as Record<string, Json>;
        const op = typeof b.op === "string" ? b.op : "";
        const bind = bop === "catalog" ? { bop, op } : bop === "resolve" ? { bop, op, inputDigest: digest(b) } : bop === "mark" ? { bop, inputDigest: digest(b) } : { bop };
        const p = verifyBridgeOpProof(String(req.headers["tb-call"] ?? ""), t, bind as never, replay);
        if (!p.ok) throw new E(401, "call_proof_invalid");
        if (bop === "scope_summary") return json(res, 200, (slice?.agents ?? []).map((a) => ({ agent: a.id, label: `${st.scopes.filter((r) => r.agent === a.id).length} spaces` })));
        if (bop === "mark") {
          const r = st.receipts.find((x) => x.callId === b.call);
          if (r) r.status = "after_failed";
          save();
          return json(res, 200, { ok: true, marked: !!r });
        }
        throw new E(404, "unknown_tool");
      }
      if (req.method === "POST" && path === `${base}/tb/launch`) {
        const t = trust();
        if (!t) throw new E(503, "slice_stale");
        const ticket = new URLSearchParams(raw).get("ticket") ?? "";
        const v = verifyTicket(ticket, t);
        if (!v.ok) throw new E(401, "ticket_invalid");
        if (st.usedJti.includes(v.claims.jti) && !faults.ticketReusable) throw new E(401, "ticket_used");
        st.usedJti.push(v.claims.jti);
        const value = randomBytes(32).toString("base64url");
        st.sessions.push({ digest: sha(value), per: v.claims.sub.slice(7), createdAt: Date.now(), csrf: randomBytes(16).toString("base64url"), expiresAt: Date.now() + 8 * 3600_000 });
        save();
        res.writeHead(303, { location: `${base}/`, "set-cookie": `tb_session=${value}; Path=${base}/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800` });
        return void res.end();
      }
      if (req.method === "GET" && path === `${base}/tb/v1/session`) {
        const s = session(req);
        return json(res, 200, { principal: { type: "person", id: s.per, ws: slice?.ws, instance: ins, iss: "tb:portal", sessionExpiresAt: s.expiresAt }, csrf: s.csrf });
      }
      if (req.method === "POST" && path === `${base}/tb/v1/logout`) {
        const s = session(req);
        st.sessions = st.sessions.filter((x) => x !== s);
        save();
        return json(res, 200, { ok: true });
      }
      if (req.method === "POST" && path.startsWith(`${base}/tb/v1/ops/`)) return await personOp(req, res, decodeURIComponent(path.slice(`${base}/tb/v1/ops/`.length)), raw);
      throw new E(404, "not_found");
    } catch (e) {
      fail(res, e instanceof E ? e : new E(500, "app_error"));
    }
  }

  const server = createServer((req, res) => void handle(req, res));
  await new Promise<void>((r) => server.listen(port, "127.0.0.1", () => r()));
  const addr = server.address() as { port: number };
  return {
    url: `http://127.0.0.1:${addr.port}`,
    async stop() {
      stop.abort();
      await loop;
      server.closeAllConnections();
      await new Promise((r) => server.close(r));
    },
    async backupNow() {
      const db = Buffer.from(JSON.stringify(st));
      const meta = { format: "tealbrick.backup/1", product, version: manifest.version, manifestDigest: mDigest, instance: ins, sdk: "0.0.0-test", createdAt: new Date().toISOString(), parts: [{ name: "app.db", file: "app.db", sha256: sha(db), bytes: db.length }] };
      writeFileSync(join(backupDir, `tb-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.tar.gz`), writeTarGz([{ name: "meta.json", data: Buffer.from(JSON.stringify(meta)) }, { name: "app.db", data: db }]));
    },
  };
}
