// Viewer pages (LA-1, C232; MANIFEST M-PR-2, BRIDGE v0.1.43 views role). ONE implementation for the views service
// (bridge image, TB_ROLE=views), the bridge private views route, the SDK and conformance (L1). Pure, no Node APIs.

/** The response headers every views response carries, even when the app sends none. The app may replace ONLY
 *  `Content-Security-Policy` (and may mark content-hashed assets `Cache-Control: … immutable`). No X-Frame-Options: framing
 *  is controlled by the app's CSP `frame-ancestors <viewUrl> <publicUrl>` (owner preview from the main origin). */
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
