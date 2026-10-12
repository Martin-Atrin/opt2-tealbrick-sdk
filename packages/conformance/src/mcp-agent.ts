// Fake agent for the bridge target: K4 key connection (RFC 7523 jwt-bearer → K5), MCP Streamable HTTP client
// (initialize, tools/list, tools/call, resources, GET notification stream) and the OAuth connector path (DCR, PKCE
// S256, authorize page forms, token exchange, refresh). Every answer the bridge gives an agent is captured for the
// person-credential scan (C4). HTML forms are read generically (the spec fixes the flow, not the form field names).
import { createHash, randomBytes } from "node:crypto";
import { type Ed25519KeyPair, signAssertion } from "@opt2-tealbrick/manifest";
import { TOOL_NAME_RULE } from "@opt2-tealbrick/spec/bridge";
import { type AgentId, type BridgeId, type ConnectionId, OAUTH_GRANT_TYPES, TYP } from "@opt2-tealbrick/spec/credentials";
import { errorCode, type HttpAnswer, request } from "./http.ts";
import { nowS } from "./tokens.ts";

export const MCP_PROTOCOL = "2025-06-18";

export interface AgentCapture {
  where: string;
  headers: Record<string, string>;
  body: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function capture(log: AgentCapture[], where: string, a: HttpAnswer): HttpAnswer {
  const headers: Record<string, string> = {};
  a.headers.forEach((v, k) => {
    headers[k] = v;
  });
  log.push({ where, headers, body: a.text });
  return a;
}

/** Parses JSON-RPC messages from a JSON or SSE answer. */
export function rpcMessages(a: { text: string; headers: Headers }): Record<string, unknown>[] {
  const ct = a.headers.get("content-type") ?? "";
  const out: Record<string, unknown>[] = [];
  const push = (v: unknown) => {
    if (Array.isArray(v)) for (const x of v) push(x);
    else if (isObj(v)) out.push(v);
  };
  if (ct.includes("text/event-stream")) {
    for (const block of a.text.split(/\r?\n\r?\n/)) {
      const data = block
        .split(/\r?\n/)
        .filter((l) => l.startsWith("data:"))
        .map((l) => l.slice(5).trimStart())
        .join("\n");
      if (!data) continue;
      try {
        push(JSON.parse(data));
      } catch {
        // not JSON
      }
    }
  } else if (a.text) {
    try {
      push(JSON.parse(a.text));
    } catch {
      // not JSON
    }
  }
  return out;
}

export interface ToolCallResult {
  /** HTTP status of the POST */
  status: number;
  /** JSON-RPC error (protocol level), if any */
  rpcError: { code: number; message: string } | null;
  isError: boolean;
  /** error envelope code inside a tool error result */
  code: string | null;
  structured: Record<string, unknown> | null;
  raw: unknown;
}

export interface Notifications {
  messages: Record<string, unknown>[];
  /** resolves when a message with `method` arrives (true) or after `ms` (false) */
  waitFor(method: string, ms: number): Promise<boolean>;
  close(): void;
}

/** One MCP session at the bridge (`Mcp-Session-Id`), authenticated with a K5 access token. */
export class McpSession {
  readonly url: string;
  token: string;
  sessionId = "";
  instructions = "";
  #id = 0;
  readonly #log: AgentCapture[];

  constructor(publicUrl: string, token: string, log: AgentCapture[]) {
    this.url = `${publicUrl}/mcp`;
    this.token = token;
    this.#log = log;
  }

  #headers(extra: Record<string, string> = {}): Record<string, string> {
    return {
      "content-type": "application/json",
      accept: "application/json, text/event-stream",
      authorization: `Bearer ${this.token}`,
      ...(this.sessionId ? { "mcp-session-id": this.sessionId, "mcp-protocol-version": MCP_PROTOCOL } : {}),
      ...extra,
    };
  }

  /** initialize + notifications/initialized; returns the HTTP answer of initialize. */
  async initialize(): Promise<HttpAnswer> {
    this.sessionId = "";
    const body = { jsonrpc: "2.0", id: ++this.#id, method: "initialize", params: { protocolVersion: MCP_PROTOCOL, capabilities: {}, clientInfo: { name: "tb-conformance", version: "0.1.0" } } };
    const a = capture(this.#log, "mcp initialize", await request(this.url, { method: "POST", headers: this.#headers(), body: JSON.stringify(body), timeoutMs: 20_000 }));
    this.sessionId = a.headers.get("mcp-session-id") ?? "";
    const m = rpcMessages(a).find((x) => x.id === body.id);
    const r = isObj(m?.result) ? m.result : {};
    this.instructions = typeof r.instructions === "string" ? r.instructions : "";
    if (this.sessionId) await request(this.url, { method: "POST", headers: this.#headers(), body: JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) });
    return a;
  }

  /** JSON-RPC request; returns the HTTP answer and the matching response message. */
  async rpc(method: string, params?: Record<string, unknown>, timeoutMs = 40_000): Promise<{ answer: HttpAnswer; message: Record<string, unknown> | null }> {
    const id = ++this.#id;
    const a = capture(this.#log, `mcp ${method}`, await request(this.url, { method: "POST", headers: this.#headers(), body: JSON.stringify({ jsonrpc: "2.0", id, method, ...(params ? { params } : {}) }), timeoutMs }));
    return { answer: a, message: rpcMessages(a).find((x) => x.id === id) ?? null };
  }

  async listTools(): Promise<string[] | null> {
    const { message } = await this.rpc("tools/list");
    const tools = isObj(message?.result) && Array.isArray(message.result.tools) ? (message.result.tools as { name?: unknown }[]) : null;
    return tools ? tools.map((t) => String(t.name)) : null;
  }

  async callTool(name: string, args: Record<string, unknown>, idempotencyKey?: string): Promise<ToolCallResult> {
    const params: Record<string, unknown> = { name, arguments: args };
    if (idempotencyKey !== undefined) params._meta = { [TOOL_NAME_RULE.idempotencyMetaKey]: idempotencyKey };
    const { answer, message } = await this.rpc("tools/call", params);
    const err = isObj(message?.error) ? { code: Number(message.error.code), message: String(message.error.message) } : null;
    const r = isObj(message?.result) ? message.result : null;
    const structured = r && isObj(r.structuredContent) ? r.structuredContent : null;
    let code = structured ? errorCode(structured) : null;
    if (!code && r?.isError === true && Array.isArray(r.content)) {
      for (const c of r.content as { text?: unknown }[]) {
        try {
          code = errorCode(JSON.parse(String(c.text)));
        } catch {
          // plain text content
        }
        if (code) break;
      }
    }
    return { status: answer.status, rpcError: err, isError: r?.isError === true || err !== null, code, structured, raw: message };
  }

  /** Opens the GET notification stream of this session. */
  listen(): Notifications {
    const ctl = new AbortController();
    const messages: Record<string, unknown>[] = [];
    const waiters = new Set<() => void>();
    const log = this.#log;
    void (async () => {
      try {
        const res = await fetch(this.url, { headers: { accept: "text/event-stream", authorization: `Bearer ${this.token}`, "mcp-session-id": this.sessionId, "mcp-protocol-version": MCP_PROTOCOL }, signal: ctl.signal });
        if (!res.body) return;
        let buf = "";
        for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
          buf += Buffer.from(chunk).toString("utf8");
          let i = buf.search(/\r?\n\r?\n/);
          while (i >= 0) {
            const block = buf.slice(0, i);
            buf = buf.slice(i).replace(/^\r?\n\r?\n/, "");
            log.push({ where: "mcp notification stream", headers: {}, body: block });
            for (const m of rpcMessages({ text: `${block}\n\n`, headers: new Headers({ "content-type": "text/event-stream" }) })) messages.push(m);
            for (const w of [...waiters]) w();
            i = buf.search(/\r?\n\r?\n/);
          }
        }
      } catch {
        // closed
      }
    })();
    return {
      messages,
      waitFor(method: string, ms: number): Promise<boolean> {
        return new Promise((resolve) => {
          const check = () => {
            if (messages.some((m) => m.method === method)) {
              clearTimeout(t);
              waiters.delete(check);
              resolve(true);
            }
          };
          const t = setTimeout(() => {
            waiters.delete(check);
            resolve(false);
          }, ms);
          waiters.add(check);
          check();
        });
      },
      close: () => ctl.abort(),
    };
  }

  async end(): Promise<void> {
    if (this.sessionId) await request(this.url, { method: "DELETE", headers: this.#headers() }).catch(() => undefined);
  }
}

/** A key connection (K4): agent assertion → K5 at `/oauth/token`. */
export class KeyAgent {
  readonly agt: AgentId;
  readonly con: ConnectionId;
  readonly key: Ed25519KeyPair;
  readonly #publicUrl: () => string;
  readonly #bridge: BridgeId;
  readonly #log: AgentCapture[];

  constructor(o: { agt: AgentId; con: ConnectionId; key: Ed25519KeyPair; bridge: BridgeId; publicUrl: () => string; log: AgentCapture[] }) {
    this.agt = o.agt;
    this.con = o.con;
    this.key = o.key;
    this.#bridge = o.bridge;
    this.#publicUrl = o.publicUrl;
    this.#log = o.log;
  }

  assertion(over: { aud?: string; con?: string; key?: Ed25519KeyPair } = {}): Promise<string> {
    const ref = `tb:agt:${this.agt}` as const;
    return signAssertion(
      TYP.agentAssertion,
      { iss: ref, sub: ref, aud: (over.aud ?? `tb:brg:${this.#bridge}`) as `tb:brg:${BridgeId}`, iat: nowS(), con: (over.con ?? this.con) as ConnectionId },
      over.key ?? this.key,
    );
  }

  async tokenAnswer(assertion?: string): Promise<HttpAnswer> {
    const a = await request(`${this.#publicUrl()}/oauth/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: OAUTH_GRANT_TYPES.jwtBearer, assertion: assertion ?? (await this.assertion()) }).toString(),
    });
    return capture(this.#log, "oauth token (jwt-bearer)", a);
  }

  /** K5 access token or null. */
  async token(): Promise<string | null> {
    const a = await this.tokenAnswer();
    const t = isObj(a.body) && typeof a.body.access_token === "string" ? a.body.access_token : null;
    return a.status === 200 ? t : null;
  }

  async session(): Promise<McpSession | null> {
    const t = await this.token();
    if (!t) return null;
    const s = new McpSession(this.#publicUrl(), t, this.#log);
    const a = await s.initialize();
    return a.status === 200 && s.sessionId ? s : null;
  }
}

// ── OAuth connector path (BRIDGE §6.2) ───────────────────────────────────────
export interface HtmlForm {
  action: string;
  method: string;
  /** hidden + visible inputs with their current values */
  fields: Record<string, string>;
  /** names of user-fillable inputs (text, password, textarea) */
  visible: string[];
}

const attr = (tag: string, name: string): string | null => {
  const m = new RegExp(`\\s${name}\\s*=\\s*("([^"]*)"|'([^']*)'|([^\\s>]+))`, "i").exec(tag);
  return m ? (m[2] ?? m[3] ?? m[4] ?? "") : null;
};
const unesc = (s: string) => s.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&amp;/g, "&");

/** Every `<form>` of a page with its inputs (generic: the spec fixes the flow, not the field names). */
export function parseForms(html: string): HtmlForm[] {
  const out: HtmlForm[] = [];
  for (const m of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const open = m[1] ?? "";
    const inner = m[2] ?? "";
    const fields: Record<string, string> = {};
    const visible: string[] = [];
    for (const t of inner.matchAll(/<(input|textarea)\b([^>]*)>/gi)) {
      const tag = ` ${t[2] ?? ""}`;
      const name = attr(tag, "name");
      if (!name) continue;
      const type = (attr(tag, "type") ?? (t[1]?.toLowerCase() === "textarea" ? "textarea" : "text")).toLowerCase();
      if (type === "submit" || type === "button") continue;
      fields[name] = unesc(attr(tag, "value") ?? "");
      if (type !== "hidden") visible.push(name);
    }
    out.push({ action: unesc(attr(` ${open}`, "action") ?? ""), method: (attr(` ${open}`, "method") ?? "get").toLowerCase(), fields, visible });
  }
  return out;
}

export async function submitForm(base: string, form: HtmlForm, values: Record<string, string> = {}, headers: Record<string, string> = {}): Promise<HttpAnswer> {
  const target = new URL(form.action || "/", base).toString();
  return request(target, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded", ...headers }, body: new URLSearchParams({ ...form.fields, ...values }).toString() });
}

export function pkcePair(): { verifier: string; challenge: string } {
  const verifier = randomBytes(32).toString("base64url");
  return { verifier, challenge: createHash("sha256").update(verifier).digest("base64url") };
}

/** Query parameters of a redirect answer's Location (code, state, iss, error). */
export function redirectParams(a: HttpAnswer): Record<string, string> | null {
  const loc = a.headers.get("location");
  if (a.status < 300 || a.status >= 400 || !loc) return null;
  try {
    return Object.fromEntries(new URL(loc).searchParams);
  } catch {
    return null;
  }
}

export interface OAuthClient {
  clientId: string;
  redirectUri: string;
  clientName: string;
}

/** OAuth connector flow helpers against one bridge. */
export class OAuthAgent {
  readonly #publicUrl: () => string;
  readonly #advertised: () => string;
  readonly #log: AgentCapture[];

  /** `publicUrl`: origin to connect to; `advertised`: the bridge's public origin (OAuth `resource`, issuer) */
  constructor(publicUrl: () => string, log: AgentCapture[], advertised: () => string = publicUrl) {
    this.#publicUrl = publicUrl;
    this.#advertised = advertised;
    this.#log = log;
  }

  get base(): string {
    return this.#publicUrl();
  }
  get resource(): string {
    return `${this.#advertised()}/mcp`;
  }

  async register(body: Record<string, unknown>): Promise<HttpAnswer> {
    return capture(this.#log, "oauth register", await request(`${this.base}/oauth/register`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) }));
  }

  async client(name = "Conformance connector"): Promise<OAuthClient | null> {
    const redirectUri = "http://127.0.0.1:53682/callback";
    const a = await this.register({ redirect_uris: [redirectUri], client_name: name, token_endpoint_auth_method: "none" });
    const id = isObj(a.body) && typeof a.body.client_id === "string" ? a.body.client_id : null;
    return a.status >= 200 && a.status < 300 && id ? { clientId: id, redirectUri, clientName: name } : null;
  }

  authorizeUrl(c: OAuthClient, p: { challenge: string; state: string; method?: string; resource?: string; omit?: string[] }): string {
    const q = new URLSearchParams({
      response_type: "code",
      client_id: c.clientId,
      redirect_uri: c.redirectUri,
      code_challenge: p.challenge,
      code_challenge_method: p.method ?? "S256",
      state: p.state,
      resource: p.resource ?? this.resource,
    });
    for (const k of p.omit ?? []) q.delete(k);
    return `${this.base}/oauth/authorize?${q}`;
  }

  async authorize(c: OAuthClient, p: Parameters<OAuthAgent["authorizeUrl"]>[1]): Promise<HttpAnswer> {
    return capture(this.#log, "oauth authorize", await request(this.authorizeUrl(c, p)));
  }

  /** Path B: fill the page's paste form (the form with one user-fillable input) with `code`. */
  async paste(page: HttpAnswer, code: string): Promise<HttpAnswer | null> {
    const form = parseForms(page.text).find((f) => f.method === "post" && f.visible.length === 1);
    if (!form) return null;
    return capture(this.#log, "oauth paste", await submitForm(this.base, form, { [form.visible[0] as string]: code }));
  }

  /** Path A: submit the page's "Approve in Portal" form (a POST form without user-fillable inputs). */
  async approveInPortal(page: HttpAnswer): Promise<HttpAnswer | null> {
    const form = parseForms(page.text).find((f) => f.method === "post" && f.visible.length === 0);
    if (!form) return null;
    return capture(this.#log, "oauth approve in portal", await submitForm(this.base, form));
  }

  async callback(ret: string, code: string): Promise<HttpAnswer> {
    return capture(this.#log, "oauth pair callback", await request(ret, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams({ code }).toString() }));
  }

  async token(form: Record<string, string>): Promise<HttpAnswer> {
    return capture(this.#log, "oauth token", await request(`${this.base}/oauth/token`, { method: "POST", headers: { "content-type": "application/x-www-form-urlencoded" }, body: new URLSearchParams(form).toString() }));
  }

  async exchange(c: OAuthClient, code: string, verifier: string): Promise<HttpAnswer> {
    return this.token({ grant_type: OAUTH_GRANT_TYPES.authorizationCode, code, code_verifier: verifier, client_id: c.clientId, redirect_uri: c.redirectUri, resource: this.resource });
  }

  async refresh(refreshToken: string): Promise<HttpAnswer> {
    return this.token({ grant_type: OAUTH_GRANT_TYPES.refreshToken, refresh_token: refreshToken });
  }
}
