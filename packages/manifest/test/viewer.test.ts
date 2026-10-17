import assert from "node:assert/strict";
import { test } from "node:test";
import { isViewerDocumentPath, VIEWER_HEADER_FLOOR, VIEWER_REQUEST_HEADERS, viewerDocumentCspOk, viewerResponseHeaderDropped } from "../src/index.ts";

test("LA-1: the header floor has the agreed members and no X-Frame-Options (framing is the app's frame-ancestors)", () => {
  for (const k of ["x-content-type-options", "referrer-policy", "cache-control", "x-robots-tag", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy", "x-dns-prefetch-control", "strict-transport-security", "content-security-policy"]) assert.ok(VIEWER_HEADER_FLOOR[k], k);
  assert.equal(VIEWER_HEADER_FLOOR["x-frame-options"], undefined);
  assert.match(VIEWER_HEADER_FLOOR["content-security-policy"] as string, /sandbox/);
  assert.ok(Object.isFrozen(VIEWER_HEADER_FLOOR));
});

test("LA-1 (a): request allow-list forwards Sec-Fetch-Dest and If-None-Match, never cookies or tokens", () => {
  for (const h of ["sec-fetch-dest", "if-none-match", "accept"]) assert.ok(VIEWER_REQUEST_HEADERS.includes(h));
  for (const h of ["cookie", "authorization", "tb-assert", "tb-views-key", "x-forwarded-for"]) assert.ok(!VIEWER_REQUEST_HEADERS.includes(h));
  for (const h of ["Set-Cookie", "access-control-allow-origin", "Access-Control-Allow-Credentials", "X-Frame-Options"]) assert.equal(viewerResponseHeaderDropped(h), true, h);
  for (const h of ["content-type", "etag", "content-security-policy"]) assert.equal(viewerResponseHeaderDropped(h), false, h);
});

test("LA-1 (b): the _d path and the CSP gate — quiet on good, fires on every forbidden token and on a missing CSP (L34)", () => {
  assert.equal(isViewerDocumentPath("/v/live-artifacts/_d/tkt_1"), true);
  assert.equal(isViewerDocumentPath("/v/live-artifacts/_d"), true);
  assert.equal(isViewerDocumentPath("/v/live-artifacts/tbv_x/data"), false);
  assert.equal(isViewerDocumentPath("/v/live-artifacts/_dx/1"), false);
  assert.equal(viewerDocumentCspOk(["default-src 'none'; script-src 'unsafe-inline'; sandbox allow-scripts; frame-ancestors https://v.example https://b.example"]), true);
  assert.equal(viewerDocumentCspOk(["sandbox"]), true);
  assert.equal(viewerDocumentCspOk([]), false);
  assert.equal(viewerDocumentCspOk(["default-src 'none'"]), false);
  for (const t of ["allow-same-origin", "allow-top-navigation", "allow-top-navigation-by-user-activation", "allow-popups", "allow-forms", "allow-modals", "ALLOW-SAME-ORIGIN"]) {
    assert.equal(viewerDocumentCspOk([`sandbox allow-scripts ${t}`]), false, t);
  }
  // a weak policy cannot hide behind a strict one (two headers, or two policies in one header)
  assert.equal(viewerDocumentCspOk(["sandbox allow-scripts", "sandbox allow-scripts allow-same-origin"]), false);
  assert.equal(viewerDocumentCspOk(["sandbox allow-scripts, sandbox allow-popups"]), false);
});
