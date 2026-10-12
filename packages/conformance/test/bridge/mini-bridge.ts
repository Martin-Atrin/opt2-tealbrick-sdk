// Minimal deployed bridge for the bridge target's sensitivity tests (NOT a product bridge): enrolment, signed config
// pull + ack, jwt-bearer K5, MCP initialize / tools/list / tools/call with gate() and forward (grant + call proof).
// Key page on its own origin (BRIDGE §3.1 / §9.3 v0.1.10, C59): keys-ticket POST → form + session, session GET.
// Flags break exactly one rule each so a test can assert the matching check flips from pass to fail.
import { randomUUID } from "node:crypto";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import {
  digest,
  type Ed25519KeyPair,
  gate,
  generateKeyPair,
  keySetFrom,
  keySetFromPortalKeys,
  mcpToolName,
  signAgentSession,
  signAssertion,
  signCallProof,
  ulid,
  validateInput,
  verifyAgentSession,
  verifyAssertion,
  verifyConfig,
  verifyGrant,
  verifyKeysTicket,
  withStandardOps,
} from "@opt2-tealbrick/manifest";
import type { EnrolResponse, WorkspaceConfig } from "@opt2-tealbrick/spec/bridge";
import type { PortalKeyEntry } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";

export interface MiniFlags {
  skipPause?: boolean;
  noProof?: boolean;
  listPerson?: boolean;
  leakToPortal?: boolean;
  acceptPerson?: boolean;
  /** serves /keys on the main origin too (C59) */
  keysOnMain?: boolean;
  /** the keys origin falls through to every main-origin route (C59) */
  keysOriginOpen?: boolean;
  /** key page without Content-Security-Policy (C59) */
  noKeysCsp?: boolean;
  /** answers 404 instead of 503 when TB_KEYS_PUBLIC_URL is unset (C59) */
  noUnset503?: boolean;
}

/** Identity kept across restarts of one mini bridge (same volume): a restart does not enrol again. */
export interface MiniState {
  key?: Ed25519KeyPair;
  enrol?: EnrolResponse;
  usedJtis?: Set<string>;
}

const nowS = () => Math.floor(Date.now() / 1000);
const send = (res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) => {
  res.writeHead(status, { "content-type": "application/json", ...headers });
  res.end(JSON.stringify(body));
};
const read = async (req: IncomingMessage) => {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  return Buffer.concat(chunks);
};
const listen = (srv: Server, port: number) => new Promise<void>((r) => srv.listen(port, "127.0.0.1", () => r()));

export async function startMiniBridge(env: Record<string, string>, flags: MiniFlags = {}, state: MiniState = {}) {
  const key = state.key ?? (await generateKeyPair());
  state.key = key;
  const portal = env.TB_PORTAL_URL as string;
  const pub = env.TB_PUBLIC_URL as string;
  const keysHost = env.TB_KEYS_PUBLIC_URL ? new URL(env.TB_KEYS_PUBLIC_URL).hostname : null;
  const usedJtis = state.usedJtis ?? new Set<string>();
  state.usedJtis = usedJtis;
  const keySessions = new Set<string>();
  const enrol =
    state.enrol ??
    ((await (
      await fetch(`${portal}/api/v1/bridge/enrol`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ code: env.TB_ENROL_CODE, publicKey: key.publicJwk, version: "0.0.0", sdkMajors: [1, 0], form: "deployed", publicOrigin: pub }),
      })
    ).json()) as EnrolResponse);
  state.enrol = enrol;
  const brg = `tb:brg:${enrol.bridgeId}` as const;
  let trusted: PortalKeyEntry[] = enrol.portalKeys;
  let cfg: WorkspaceConfig | null = null;
  const manifests = new Map<string, Manifest>();
  const boot = randomUUID();
  let stopped = false;

  const portalCall = async (method: string, path: string, body?: unknown) => {
    const raw = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
    const assertion = await signAssertion("tb-bridge-assert+jwt", { iss: brg, sub: brg, aud: "tb:portal", iat: nowS() }, key, { method, pathAndQuery: path, body: raw });
    return fetch(`${portal}${path}`, { method, headers: { "content-type": "application/json", "TB-Assert": assertion }, body: raw, signal: AbortSignal.timeout(5000) });
  };
  const ack = (extra: Record<string, unknown> = {}) =>
    cfg &&
    portalCall("POST", enrol.ackPath, {
      rev: cfg.rev,
      appliedAt: new Date().toISOString(),
      bridge: { id: enrol.bridgeId, version: "0.0.0", form: "deployed", boot, sdkMajors: [1, 0], mcpVersions: ["2025-06-18"] },
      portalReachable: true,
      apps: cfg.apps.map((a) => ({ ins: a.ins, state: "ok", version: a.version, sdkVersion: null, manifestDigest: a.manifestDigest, lastSeen: null, pendingHolds: 0 })),
      keys: [],
      scopeSummaries: [],
      connectionsCreated: [],
      connectionsRevoked: [],
      claims: [],
      rejected: [],
      toolsOmitted: [],
      ...extra,
    }).catch(() => undefined);

  void (async () => {
    while (!stopped) {
      try {
        const path = `${enrol.configPath}?after=${cfg?.rev ?? 0}&wait=1`;
        const r = await portalCall("GET", path);
        if (r.status === 200) {
          const v = verifyConfig(await r.text(), { now: nowS(), self: brg, issuers: keySetFromPortalKeys(trusted) });
          const body = v.ok ? (v.body as WorkspaceConfig) : null;
          if (body && body.ws === enrol.workspaceId && (!cfg || body.rev > cfg.rev)) {
            for (const a of body.apps) if (!manifests.has(a.ins)) manifests.set(a.ins, (await (await fetch(`${a.internalUrl}/tb/v1/manifest`)).json()) as Manifest);
            cfg = body;
            trusted = body.portalKeys;
            await ack();
          }
        }
      } catch {
        await new Promise((r) => setTimeout(r, 200));
      }
    }
  })();

  const grantsOf = (agt: string) => {
    const c = cfg as WorkspaceConfig;
    return c.grants.map((g) => verifyGrant(g, { now: nowS(), self: `tb:ins:${JSON.parse(Buffer.from(g.split(".")[1] as string, "base64url").toString()).aud.slice(7)}` as never, ws: c.ws, bridge: enrol.bridgeId, issuers: keySetFromPortalKeys(trusted), bridgeKeys: { keys: [] }, revokedJtis: new Set(c.revoked.jtis.map((j) => j.jti)) })).flatMap((v, i) => (v.ok && v.claims.sub === `tb:agt:${agt}` ? [{ jws: c.grants[i] as string, claims: v.claims }] : []));
  };
  const tools = (agt: string) => {
    const c = cfg as WorkspaceConfig;
    const out: { name: string; ins: string; op: string; inputSchema: unknown }[] = [];
    if (!flags.skipPause && (c.pause.workspace || c.pause.agents.includes(agt as never))) return out;
    for (const g of grantsOf(agt)) {
      const ins = g.claims.aud.slice(7);
      const m = manifests.get(ins);
      if (!m) continue;
      for (const o of withStandardOps(m)) {
        if (o.standard || o.dynamic) continue;
        if (o.audience !== "agent" && !flags.listPerson) continue;
        if (!o.crud.every((x) => g.claims.crud.includes(x)) || (g.claims.mode === "bound" && !g.claims.wf.includes(o.id))) continue;
        out.push({ name: mcpToolName(m.id, o.id), ins, op: o.id, inputSchema: o.input });
      }
      out.push({ name: mcpToolName(m.id, "tb_hold_status"), ins, op: "tb.hold_status", inputSchema: { type: "object" } }, { name: mcpToolName(m.id, "tb_skills"), ins, op: "", inputSchema: { type: "object" } });
    }
    return out;
  };
  const toolError = (code: string) => ({ isError: true, content: [{ type: "text", text: JSON.stringify({ error: { code, message: code, requestId: "req_mini" } }) }], structuredContent: { error: { code, message: code, requestId: "req_mini" } } });

  const callTool = async (agt: string, name: string, args: Json, idem?: string): Promise<unknown> => {
    const c = cfg as WorkspaceConfig;
    const t = tools(agt).find((x) => x.name === name);
    if (!t) return toolError(flags.skipPause ? "unknown_tool" : c.pause.workspace || c.pause.agents.includes(agt as never) ? "paused" : "unknown_tool");
    const m = manifests.get(t.ins) as Manifest;
    const op = withStandardOps(m).find((o) => o.id === t.op);
    const g = grantsOf(agt).find((x) => x.claims.aud === `tb:ins:${t.ins}`);
    if (!op || !g) return toolError("no_grant");
    if (!op.standard && !validateInput(op, args).ok) return toolError("input_invalid");
    if (!op.standard && op.idempotency === "required" && !idem) return toolError("input_invalid");
    const trust = { now: nowS(), self: `tb:ins:${t.ins}` as never, ws: c.ws, bridge: enrol.bridgeId, issuers: keySetFromPortalKeys(trusted), bridgeKeys: { keys: [] }, revokedJtis: new Set(c.revoked.jtis.map((j) => j.jti)) };
    const paused = flags.skipPause ? { workspace: false, agent: false, connection: false, instance: false } : { workspace: c.pause.workspace, agent: c.pause.agents.includes(agt as never), connection: false, instance: c.pause.instances.includes(t.ins as never) };
    const d = gate({ paused, grant: g.jws, trust, op, declaredScopeTypes: (m.scopes ?? []).map((x) => x.type) });
    if (d.decision === "refuse") return toolError(d.reason);
    const context = {};
    const app = c.apps.find((a) => a.ins === t.ins);
    const proof = await signCallProof({ iss: brg, sub: `tb:agt:${agt}` as never, aud: `tb:ins:${t.ins}` as never, call: `call_${ulid()}` as never, gjti: g.claims.jti, op: op.id, in: digest(args), ctx: digest(context), iat: nowS() }, key);
    const r = await fetch(`${app?.internalUrl}/tb/v1/ops/${op.id}`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${g.jws}`, ...(flags.noProof ? {} : { "TB-Call": proof }) },
      body: JSON.stringify({ input: args, context, ...(idem ? { idempotencyKey: idem } : {}) }),
    });
    const body = (await r.json().catch(() => ({}))) as Record<string, unknown>;
    if (flags.leakToPortal) await ack({ lastCall: { name, input: args, output: body } });
    if (r.status === 200) return { content: [{ type: "text", text: JSON.stringify(body.output) }], structuredContent: body.output };
    if (r.status === 202) return { content: [{ type: "text", text: "held" }], structuredContent: { status: "held", holdId: body.holdId, expiresAt: body.expiresAt, checkWith: mcpToolName(m.id, "tb_hold_status") } };
    const code = (body.error as { code?: string } | undefined)?.code ?? "app_error";
    return toolError(code);
  };

  const authAgent = (req: IncomingMessage): string | null => {
    const bearer = /^Bearer (\S+)$/.exec(req.headers.authorization ?? "")?.[1] ?? "";
    const c = cfg;
    if (!c) return null;
    if (flags.acceptPerson && (bearer.startsWith("tbo_") || bearer.split(".").length === 3) && !bearer.startsWith("eyJhbGciOiJFZERTQSI")) return c.connections[0]?.agt ?? null;
    const v = verifyAgentSession(bearer, { now: nowS(), self: brg, ws: c.ws, keys: keySetFrom({ keys: [key.publicJwk] }, brg) });
    if (!v.ok) return null;
    const con = c.connections.find((x) => x.con === v.claims.con && x.status === "active" && x.gen === v.claims.gen && `tb:agt:${x.agt}` === v.claims.sub);
    return con ? con.agt : null;
  };

  const publicServer = createServer((req, res) => {
    handlePublic(req, res).catch((e: unknown) => send(res, 500, { error: { code: "internal", message: String(e), requestId: "req_mini" } }));
  });
  const keyPage = (req: IncomingMessage, res: ServerResponse, raw: Buffer) => {
    const html = (status: number, body: string, extra: Record<string, string> = {}) => {
      res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...(flags.noKeysCsp ? {} : { "content-security-policy": "default-src 'none'; form-action 'self'; frame-ancestors 'none'" }), ...extra });
      res.end(body);
    };
    const page = () => `<!doctype html><form method="post" action="/keys"><input type="hidden" name="csrf" value="${randomUUID()}"><label>MINI_KEY <input name="MINI_KEY"></label></form>`;
    const sid = /(?:^|;\s*)tb_keys=([^;]+)/.exec(req.headers.cookie ?? "")?.[1];
    if (sid && keySessions.has(sid)) return html(200, page());
    const ticket = req.method === "POST" ? new URLSearchParams(raw.toString()).get("ticket") : null;
    if (!ticket) return send(res, 401, { error: { code: "unauthenticated", message: "keys ticket required", requestId: "req_mini" } });
    const v = verifyKeysTicket(ticket, { now: nowS(), self: brg, ws: enrol.workspaceId, issuers: keySetFromPortalKeys(trusted) });
    if (!v.ok || usedJtis.has(v.claims.jti)) return send(res, 400, { error: { code: "ticket_invalid", message: "keys ticket refused", requestId: "req_mini" } });
    usedJtis.add(v.claims.jti);
    const id = randomUUID();
    keySessions.add(id);
    return html(200, page(), { "set-cookie": `tb_keys=${id}; HttpOnly; Secure; SameSite=Strict; Path=/keys` });
  };
  const handlePublic = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    const path = new URL(req.url ?? "/", "http://x").pathname;
    const raw = await read(req);
    if (path === "/healthz" || path === "/readyz") return send(res, 200, { status: "ok" });
    const onKeys = keysHost !== null && (req.headers.host ?? "").replace(/:\d+$/, "").toLowerCase() === keysHost;
    if (onKeys && path === "/keys") return keyPage(req, res, raw);
    if (onKeys && !flags.keysOriginOpen) return send(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_mini" } });
    if (path === "/keys") {
      if (!keysHost && !flags.noUnset503) {
        res.writeHead(503, { "content-type": "text/plain; charset=utf-8" });
        return void res.end("key page not configured");
      }
      if (flags.keysOnMain) return keyPage(req, res, raw);
      return send(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_mini" } });
    }
    if (path === "/oauth/token" && req.method === "POST") {
      const f = new URLSearchParams(raw.toString());
      const a = f.get("assertion") ?? "";
      const claims = (() => {
        try {
          return JSON.parse(Buffer.from(a.split(".")[1] ?? "", "base64url").toString()) as { con?: string };
        } catch {
          return {};
        }
      })();
      const con = cfg?.connections.find((x) => x.con === claims.con && x.status === "active" && x.publicKey);
      const v = con?.publicKey ? verifyAssertion(a, keySetFrom({ keys: [con.publicKey] }, `tb:agt:${con.agt}`), { typ: "tb-agent-assert+jwt", aud: brg, now: nowS() }) : null;
      if (f.get("grant_type") === "refresh_token") return send(res, 400, { error: "invalid_grant" });
      if (f.get("grant_type") !== "urn:ietf:params:oauth:grant-type:jwt-bearer") return send(res, 400, { error: "unsupported_grant_type" });
      if (!con || !v?.ok) return send(res, 400, { error: "invalid_grant", error_description: "connection_unknown" });
      const token = await signAgentSession({ iss: brg, sub: `tb:agt:${con.agt}`, aud: brg, ws: (cfg as WorkspaceConfig).ws, con: con.con, gen: con.gen, iat: nowS() }, key);
      return send(res, 200, { access_token: token, token_type: "Bearer", expires_in: 900 });
    }
    if (path === "/mcp") {
      const agt = authAgent(req);
      if (!agt) return send(res, 401, { error: { code: "unauthenticated", message: "agent session required", requestId: "req_mini" } }, { "www-authenticate": `Bearer resource_metadata="${pub}/.well-known/oauth-protected-resource"` });
      if (req.method !== "POST") return send(res, 405, {});
      const msg = JSON.parse(raw.toString() || "{}") as { id?: unknown; method?: string; params?: Record<string, unknown> };
      if (msg.id === undefined) return void res.writeHead(202).end();
      const c = cfg as WorkspaceConfig;
      let result: unknown = {};
      if (msg.method === "initialize") {
        const paused = c.pause.workspace || c.pause.agents.includes(agt as never);
        return send(res, 200, { jsonrpc: "2.0", id: msg.id, result: { protocolVersion: "2025-06-18", capabilities: { tools: { listChanged: true } }, serverInfo: { name: "mini", version: "0.0.0" }, instructions: paused ? "paused by the owner" : "" } }, { "mcp-session-id": randomUUID() });
      }
      if (msg.method === "tools/list") result = { tools: tools(agt).map((t) => ({ name: t.name, inputSchema: t.inputSchema })) };
      if (msg.method === "tools/call") {
        const meta = msg.params?._meta as Record<string, unknown> | undefined;
        result = await callTool(agt, String(msg.params?.name), (msg.params?.arguments ?? {}) as Json, typeof meta?.["tealbrick/idempotencyKey"] === "string" ? (meta["tealbrick/idempotencyKey"] as string) : undefined);
      }
      return send(res, 200, { jsonrpc: "2.0", id: msg.id, result });
    }
    send(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_mini" } });
  };
  const internalServer = createServer(async (req, res) => {
    await read(req);
    const path = new URL(req.url ?? "/", "http://x").pathname;
    if (path === "/tb/v1/status") return void res.writeHead(204).end();
    // key fetch is not implemented by this minimal bridge: every caller is unauthenticated
    if (path.startsWith("/tb/v1/keys/")) return send(res, 401, { error: { code: "unauthenticated", message: "instance assertion required", requestId: "req_mini" } });
    send(res, 404, { error: { code: "not_found", message: "not found", requestId: "req_mini" } });
  });
  await listen(publicServer, Number(env.PORT));
  await listen(internalServer, Number(env.TB_INTERNAL_PORT));
  return {
    publicUrl: `http://127.0.0.1:${env.PORT}`,
    internalUrl: `http://127.0.0.1:${env.TB_INTERNAL_PORT}`,
    stop: async () => {
      stopped = true;
      publicServer.closeAllConnections();
      internalServer.closeAllConnections();
      await Promise.all([new Promise((r) => publicServer.close(r)), new Promise((r) => internalServer.close(r))]);
    },
  };
}
