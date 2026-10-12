// Same-origin fetch under `/a/<product>/` (SDK-API §5, §14): session cookie (credentials), the ONE CSRF header
// `TB-CSRF` on every non-GET, and the CORE §8 error envelope → TbError. No React here.
import { BRIDGE_HEADERS, type OpResult } from "@opt2-tealbrick/spec/bridge";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "../server/errors.ts";

const PRODUCT_RE = /^[a-z][a-z0-9-]{1,31}$/;
const SAFE_METHODS = new Set(["GET", "HEAD"]);
const IDEM_KEY_RE = /^[A-Za-z0-9._:-]{1,128}$/;

interface ClientState {
  product: string | null;
  csrf: string | null;
  /** loads the session (which sets the CSRF token) when none is cached; set by the session store */
  loadCsrf: (() => Promise<unknown>) | null;
  /** person op ids with `idempotency: "required"` from the session answer; null until a session answer arrived */
  idempotencyRequired: ReadonlySet<string> | null;
}

const state: ClientState = { product: null, csrf: null, loadCsrf: null, idempotencyRequired: null };

/** Sets the product whose base path `/a/<product>/` every request uses (TbProvider calls it). */
export function setProduct(product: string): void {
  if (!PRODUCT_RE.test(product)) throw new TypeError(`invalid product id ${JSON.stringify(product)}`);
  state.product = product;
}

export function setCsrf(token: string | null): void {
  state.csrf = token;
}

/** Set from the session answer's `idempotencyRequired` (an older server without the field → empty list). */
export function setIdempotencyRequired(ops: readonly string[] | null): void {
  state.idempotencyRequired = ops === null ? null : new Set(ops);
}

export function setCsrfLoader(loader: (() => Promise<unknown>) | null): void {
  state.loadCsrf = loader;
}

/** `/a/<product>/`: the configured product, else the one in the current page path. */
export function basePath(): string {
  let product = state.product;
  if (!product) {
    const m = /^\/a\/([a-z][a-z0-9-]{1,31})(?:\/|$)/.exec(globalThis.location?.pathname ?? "");
    product = m?.[1] ?? null;
  }
  if (!product) throw new TypeError("no product: render <TbProvider product> or serve the page under /a/<product>/");
  return `/a/${product}/`;
}

/** `path` is relative to the base path; absolute URLs, protocol-relative paths and `..` segments are refused. */
export function resolvePath(path: string): string {
  if (/^[a-z][a-z0-9+.-]*:/i.test(path) || path.startsWith("//") || path.includes("\\") || path.split(/[/?#]/)[0] === ".." || /(^|\/)\.\.(\/|$|\?|#)/.test(path))
    throw new TypeError(`tbFetch path must stay under the base path: ${JSON.stringify(path)}`);
  return basePath() + path.replace(/^\/+/, "");
}

/** Error envelope (or any non-2xx answer) → TbError with the envelope's code, message and details. */
export async function errorFromResponse(res: Response): Promise<TbError> {
  let body: unknown = null;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  const e = (body as { error?: { code?: unknown; message?: unknown; details?: unknown } } | null)?.error;
  const details = e?.details && typeof e.details === "object" ? (e.details as Record<string, unknown>) : undefined;
  if (typeof e?.code === "string") return new TbError(e.code, typeof e.message === "string" ? e.message : e.code, res.status, details);
  return new TbError("http_error", `request failed with status ${res.status}`, res.status);
}

/** Same-origin fetch under /a/<product>/ with TB-CSRF; CORE error envelope → TbError (types/sdk.ts §C). */
export async function tbFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const url = resolvePath(path);
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (!SAFE_METHODS.has(method)) {
    if (state.csrf === null && state.loadCsrf) await state.loadCsrf();
    const token: string | null = state.csrf;
    if (token === null) throw new TbError("session_required", "sign in first (no session)", 401);
    headers.set(BRIDGE_HEADERS.csrf, token);
  }
  if (!headers.has("accept")) headers.set("accept", "application/json");
  let res: Response;
  try {
    res = await fetch(url, { ...init, method, headers, credentials: "include", redirect: init.redirect ?? "follow" });
  } catch (e) {
    if ((e as { name?: string })?.name === "AbortError") throw e;
    throw new TbError("network_error", "the app cannot be reached", 0);
  }
  if (res.ok) return res;
  const err = await errorFromResponse(res);
  if (err.code === "csrf_invalid" || err.code === "session_required") state.csrf = null;
  throw err;
}

/**
 * Person op via POST /a/<product>/tb/v1/ops/:op (body `{ input, idempotencyKey? }`); returns the op output.
 * C41: `opts.idempotencyKey` (1–128 chars `[A-Za-z0-9._:-]`, SDK-API §4.4) is sent as body field `idempotencyKey`.
 * C53 / BSA-12: for an op the session answer lists in `idempotencyRequired`, a call without a key gets a fresh
 * `crypto.randomUUID()` key. That key is per call: callOp never retries, so a caller that retries the SAME logical
 * call (after a network error, say) must pass its own key to get the server's replay instead of a second effect.
 */
export async function callOp<O = Json>(op: string, input: Json, opts?: { idempotencyKey?: string }): Promise<O> {
  let key = opts?.idempotencyKey;
  if (key !== undefined && !IDEM_KEY_RE.test(key)) throw new TbError("idempotency_key_invalid", "idempotencyKey must be 1-128 chars [A-Za-z0-9._:-]", 400);
  if (key === undefined) {
    if (state.idempotencyRequired === null && state.loadCsrf) {
      await state.loadCsrf();
      if (state.csrf === null) throw new TbError("session_required", "sign in first (no session)", 401);
    }
    if (state.idempotencyRequired?.has(op)) key = globalThis.crypto.randomUUID();
  }
  const body = key === undefined ? { input } : { input, idempotencyKey: key };
  const res = await tbFetch(`tb/v1/ops/${encodeURIComponent(op)}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
  const r = (await res.json()) as OpResult<O>;
  if (r?.status === "ok") return r.output as O;
  throw new TbError("op_not_completed", `operation ${op} did not complete (status ${String((r as { status?: unknown })?.status)})`, 502);
}
