// Viewer route (LA-1 / LA-3c, C232; MANIFEST M-PR-2, BRIDGE v0.1.43 views role). The bridge private views route forwards
// `GET /v/<product>/<rest>` here; the app's `publicRoutes["/v"]` handler (manifest purpose `viewer`) answers it.
// The rules live in @opt2-tealbrick/manifest (viewer.ts, L1); this module only applies them:
//   request  -> the handler sees VIEWER_REQUEST_HEADERS only (no Cookie, Authorization, TB-*, Host, …)
//   response -> VIEWER_HEADER_FLOOR on every response; the handler may replace ONLY Content-Security-Policy; Set-Cookie,
//               Access-Control-*, X-Frame-Options are dropped; a `/_d/` response with an unsafe CSP is refused (502)
import type { IncomingMessage, ServerResponse } from "node:http";
import { Readable } from "node:stream";
import { isViewerDocumentPath, VIEWER_HEADER_FLOOR, VIEWER_REQUEST_HEADERS, viewerDocumentCspOk, viewerResponseHeaderDropped } from "@opt2-tealbrick/manifest";
import type { SdkPublicContext } from "./context.ts";
import { TbError } from "./errors.ts";
import { requestId, sendError } from "./http.ts";
import type { Runtime } from "./runtime.ts";

/** `/v/<product>/…` of this app (the bridge forwards the path unchanged). */
export function isViewerPath(rt: Runtime, path: string): boolean {
  return path === `/v/${rt.product}` || path.startsWith(`/v/${rt.product}/`);
}

/** The manifest's viewer route path (M-PR-2: at most one, `/v`) when the app declared it, else null. */
export function viewerRoutePath(rt: Runtime): string | null {
  return rt.manifest.publicRoutes?.find((r) => r.purpose === "viewer")?.path ?? null;
}

const FLOOR_KEYS = Object.keys(VIEWER_HEADER_FLOOR);

/** The floor as a plain header object (every error the SDK sends on this route carries it too). */
function floor(): Record<string, string> {
  return { ...VIEWER_HEADER_FLOOR };
}

/**
 * Serves one viewer request. Returns false when the app declares no viewer route (the caller answers 404).
 * Errors the SDK itself raises (404 / 405 / 503 / 502 / handler failure) carry the floor headers as well.
 */
export async function handleViewer(rt: Runtime, req: IncomingMessage, res: ServerResponse, url: URL): Promise<boolean> {
  const routePath = viewerRoutePath(rt);
  const handler = routePath === null ? undefined : rt.def.publicRoutes?.[routePath];
  if (routePath === null || !handler) return false;
  const rid = requestId();
  try {
    if (req.method !== "GET") throw new TbError("method_not_allowed", `${routePath} accepts GET`, 405);
    if (url.pathname === `/v/${rt.product}`) throw new TbError("not_found", "not found", 404);
    const paused = rt.trust.paused(null);
    if (paused.workspace || paused.instance) throw new TbError("paused", "this instance is paused", 503);
    const rest = url.pathname.slice(`/v/${rt.product}`.length) || "/";
    // only the allow-listed request headers reach the handler; absent stays absent
    const headers = new Headers();
    for (const name of VIEWER_REQUEST_HEADERS) {
      const v = req.headers[name];
      if (v !== undefined) headers.set(name, Array.isArray(v) ? v.join(", ") : v);
    }
    const request = new Request(`http://${rt.product}.views.internal${rest}${url.search}`, { method: "GET", headers });
    const ctx: SdkPublicContext = { ...rt.extras(), log: rt.log, db: rt.appDb, getKey: (n) => rt.keys.getKey(n) };
    const response = await handler(request, ctx);

    // floor first; the handler's headers are added unless dropped or part of the floor (CSP excepted)
    const out: Record<string, string> = floor();
    response.headers.forEach((v, k) => {
      const name = k.toLowerCase();
      if (viewerResponseHeaderDropped(name)) return;
      if (name === "content-security-policy") out[name] = v;
      else if (!FLOOR_KEYS.includes(name)) out[name] = v;
    });
    // defence in depth (tb-views and the bridge route enforce it too): an untrusted document needs a safe sandbox CSP
    if (isViewerDocumentPath(url.pathname) && !viewerDocumentCspOk([out["content-security-policy"] ?? ""])) {
      await response.body?.cancel();
      rt.log.warn("viewer document refused: unsafe content-security-policy", { product: rt.product });
      throw new TbError("viewer_document_unsafe", "this document's content-security-policy is not a safe sandbox", 502);
    }
    res.writeHead(response.status, out);
    if (response.body) Readable.fromWeb(response.body as import("node:stream/web").ReadableStream).pipe(res);
    else res.end();
  } catch (e) {
    if (!(e instanceof TbError)) rt.log.error("viewer handler failed", { error: e instanceof Error ? e.message : "unknown" });
    sendError(res, rid, e, floor());
  }
  return true;
}
