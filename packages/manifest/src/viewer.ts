// Viewer pages (LA-1, C232; MANIFEST M-PR-2, BRIDGE v0.1.43 views role). ONE implementation for the views service
// (bridge image, TB_ROLE=views), the bridge private views route, the SDK and conformance (L1). Pure, no Node APIs.

/** The response headers every views response carries, even when the app sends none. The app may replace ONLY
 *  `Content-Security-Policy`, and `Cache-Control` on static asset paths (`/v/<product>/_s/…`) with an `immutable` value
 *  (viewerFloorOverride). No X-Frame-Options: framing is controlled by the app's CSP `frame-ancestors <viewUrl> <publicUrl>`
 *  (owner preview from the main origin). */
export const VIEWER_HEADER_FLOOR: Readonly<Record<string, string>> = Object.freeze({
  "x-content-type-options": "nosniff",
  "referrer-policy": "no-referrer",
  "cache-control": "no-store",
  "x-robots-tag": "noindex, nofollow",
  "permissions-policy":
    "accelerometer=(), autoplay=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), encrypted-media=(), fullscreen=(), geolocation=(), gyroscope=(), hid=(), magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), usb=(), xr-spatial-tracking=()",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
  "x-dns-prefetch-control": "off",
  "strict-transport-security": "max-age=31536000",
  "content-security-policy": "default-src 'none'; sandbox",
});

/** Request headers the views service forwards (lower case). Everything else is dropped; absent stays absent. */
export const VIEWER_REQUEST_HEADERS: readonly string[] = Object.freeze(["accept", "sec-fetch-dest", "sec-fetch-mode", "sec-fetch-site", "if-none-match"]);

/** Response headers never passed from the app to a viewer (lower case; `access-control-*` is a prefix). */
export function viewerResponseHeaderDropped(name: string): boolean {
  const n = name.toLowerCase();
  return n === "set-cookie" || n === "set-cookie2" || n.startsWith("access-control-") || n === "x-frame-options";
}

/** Sandbox tokens a `/_d/` document must never get (they would give agent HTML an origin, the top window, popups, forms
 *  or modal dialogs). */
export const VIEWER_DOCUMENT_FORBIDDEN_SANDBOX: readonly string[] = Object.freeze([
  "allow-same-origin",
  "allow-top-navigation",
  "allow-top-navigation-by-user-activation",
  "allow-top-navigation-to-custom-protocols",
  "allow-popups",
  "allow-popups-to-escape-sandbox",
  "allow-forms",
  "allow-modals",
]);

/** True for the reserved untrusted-document path `/v/<product>/_d/…` (M-PR-2). */
export function isViewerDocumentPath(path: string): boolean {
  return /^\/v\/[a-z][a-z0-9-]{1,31}\/_d(\/|$)/.test(path);
}

/**
 * The `_d` gate: every CSP header value of the response (a response may carry several; they are judged together, so a
 * weak one cannot hide behind a strict one). OK only when at least one policy has a `sandbox` directive and NO policy's
 * sandbox lists a forbidden token. Missing CSP → not OK (fail closed).
 */
export function viewerDocumentCspOk(cspHeaderValues: readonly string[]): boolean {
  let sandboxed = false;
  for (const value of cspHeaderValues) {
    // one header value may hold several policies separated by commas
    for (const policy of value.split(",")) {
      for (const directive of policy.split(";")) {
        const parts = directive.trim().toLowerCase().split(/\s+/).filter(Boolean);
        if (parts[0] !== "sandbox") continue;
        sandboxed = true;
        if (parts.slice(1).some((t) => VIEWER_DOCUMENT_FORBIDDEN_SANDBOX.includes(t))) return false;
      }
    }
  }
  return sandboxed;
}

/** True for the reserved static-asset path `/v/<product>/_s/…` (content-hashed shell assets; M-PR-2). */
export function isViewerAssetPath(path: string): boolean {
  return /^\/v\/[a-z][a-z0-9-]{1,31}\/_s\//.test(path);
}

/**
 * May the app's value of a floor header replace the floor's (manifest 0.1.22, one rule for the SDK, tb-views and the
 * bridge)? `content-security-policy`: always (the `_d` gate still applies). `cache-control`: only on a static asset path
 * and only a public, immutable value with a max-age (`public, max-age=<n>, immutable`, any order, no private/no-store/
 * no-cache) — never on a token page, a data answer or a document, which must stay `no-store` so a revoked link is not
 * served from a cache. Every other floor header: never.
 */
export function viewerFloorOverride(name: string, value: string, path: string): boolean {
  const n = name.toLowerCase();
  if (n === "content-security-policy") return true;
  if (n !== "cache-control" || !isViewerAssetPath(path) || isViewerDocumentPath(path)) return false;
  const parts = value.toLowerCase().split(",").map((x) => x.trim()).filter(Boolean);
  if (!parts.includes("immutable") || !parts.some((x) => /^max-age=\d{1,9}$/.test(x))) return false;
  return parts.every((x) => x === "immutable" || x === "public" || /^max-age=\d{1,9}$/.test(x));
}
