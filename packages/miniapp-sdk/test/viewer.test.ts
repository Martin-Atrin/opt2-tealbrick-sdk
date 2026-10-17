// v0.1.26 (LA-1 / LA-3c / view_origin_missing, C232): ctx.viewUrl from the slice and the `viewer` prefix route
// GET /v/<product>/<rest> on the app's private listener. Real HTTP, a fake bridge; rules come from @opt2-tealbrick/manifest.
// Alarm tests are quiet on good input and fire on bad (L34).
import assert from "node:assert/strict";
import { after, before, describe, test } from "node:test";
import { VIEWER_DOCUMENT_FORBIDDEN_SANDBOX, VIEWER_HEADER_FLOOR, VIEWER_REQUEST_HEADERS } from "@opt2-tealbrick/manifest";
import type { Json, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, type PublicHandler, requireViewUrl, type SdkOpContext, startApp, TbError, VIEW_ORIGIN_MISSING, viewOriginMissing } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const VIEW = "https://views.example.test";

type Seen = { url: string; headers: Record<string, string>; viewUrl: string | null | undefined };

interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  port: number;
  /** what the viewer handler does next (default: 200 "ok" with no headers) */
  next: { respond: (req: Request) => Response | Promise<Response> };
  seen: Seen[];
  opViewUrl(): Promise<string | null | undefined>;
  cleanup(): Promise<void>;
}

const okText = () => new Response("ok", { headers: { "content-type": "text/plain" } });

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
  const manifest = fixtureManifest(port);
  manifest.publicRoutes = [
    { path: "/v", purpose: "viewer" },
    { path: "/hook-in", purpose: "webhook" },
  ];
  const next: Booted["next"] = { respond: okText };
  const seen: Seen[] = [];
  let opCtx: SdkOpContext | null = null;
  const viewer: PublicHandler = async (req, ctx) => {
    seen.push({ url: req.url, headers: Object.fromEntries(req.headers), viewUrl: ctx.viewUrl });
    return next.respond(req);
  };
  const hook: PublicHandler = async (_req, ctx) => new Response(JSON.stringify({ viewUrl: ctx.viewUrl ?? null }), { headers: { "content-type": "application/json" } });
  const app = defineApp({
    manifest,
    migrations: migrationsDir(t.dir),
    publicRoutes: { "/v": viewer, "/hook-in": hook },
    handlers: {
      note_create: { scope: () => null, run: async () => ({ id: "x" }) },
      note_get: async (_input, ctx) => {
        opCtx = ctx as SdkOpContext;
        return { viewUrl: opCtx.viewUrl } as Json;
      },
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
    },
  });
  const running = await startApp(
    app,
    {
      TB_INSTANCE_ID: w.ins,
      TB_ENROL_CODE: "tbe_test",
      TB_BRIDGE_URL: bridgeUrl,
      TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }),
      TB_DATA_DIR: t.dir,
      TB_DATA_EPHEMERAL: "1",
      TB_LOG_LEVEL: "error",
    },
    testRoots(w),
  );
  return {
    w,
    bridge,
    running,
    port,
    next,
    seen,
    async opViewUrl() {
      const g = await grant(w, w.agents.a);
      const res = await fetch(`http://127.0.0.1:${port}/tb/v1/ops/note_get`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": await callProof(w, g, "note_get", { id: "1" }) },
        body: JSON.stringify({ input: { id: "1" }, context: {} }),
      });
      assert.equal(res.status, 200);
      return ((await res.json()) as { output: { viewUrl: string | null | undefined } }).output.viewUrl;
    },
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

describe("viewer route and ctx.viewUrl", () => {
  let b: Booted;
  const get = (path: string, headers: Record<string, string> = {}) => fetch(`http://127.0.0.1:${b.port}${path}`, { headers });
  before(async () => {
    b = await boot();
    await until(async () => b.running.status() !== "needs_claim" && (await get(`/tb/v1/health`)).ok);
  });
  after(async () => {
    await b.cleanup();
  });

  test("ctx.viewUrl follows the slice: absent -> string -> null, on op, viewer and public contexts", async () => {
    const hookViewUrl = async () => ((await (await fetch(`http://127.0.0.1:${b.port}/hook-in`, { method: "POST", body: "{}" })).json()) as { viewUrl: string | null }).viewUrl;
    // slice 1 carries no viewUrl member at all
    assert.equal(await b.opViewUrl(), null);
    assert.equal(await hookViewUrl(), null);
    assert.equal((await get(`/v/${PRODUCT}/t1`)).status, 200);
    assert.equal(b.seen.at(-1)?.viewUrl, null);
    // slice 2 names the views origin
    b.bridge.push(await slice(b.w, PRODUCT, { viewUrl: VIEW }));
    await until(async () => (await b.opViewUrl()) === VIEW);
    assert.equal(await hookViewUrl(), VIEW);
    await get(`/v/${PRODUCT}/t1`);
    assert.equal(b.seen.at(-1)?.viewUrl, VIEW);
    // slice 3 sets it back to null (Core removed tb-views)
    b.bridge.push(await slice(b.w, PRODUCT, { viewUrl: null }));
    await until(async () => (await b.opViewUrl()) === null);
    assert.equal(await hookViewUrl(), null);
    await get(`/v/${PRODUCT}/t1`);
    assert.equal(b.seen.at(-1)?.viewUrl, null);
  });

  test("view_origin_missing: requireViewUrl returns the origin and throws 409 while it is null", () => {
    assert.equal(requireViewUrl({ viewUrl: VIEW }), VIEW);
    for (const ctx of [{ viewUrl: null }, { viewUrl: undefined }, {}, { viewUrl: "" }]) {
      assert.throws(
        () => requireViewUrl(ctx),
        (e: unknown) => e instanceof TbError && e.code === VIEW_ORIGIN_MISSING && e.code === "view_origin_missing" && e.httpStatus === 409,
      );
    }
    assert.equal(viewOriginMissing().httpStatus, 409);
  });

  test("the handler gets the remaining path and the query; other products, a bare /v/<product> and the exact /v path are 404", async () => {
    b.seen.length = 0;
    assert.equal((await get(`/v/${PRODUCT}/tok123/data?x=1&y=2`)).status, 200);
    const u = new URL(b.seen[0]?.url ?? "http://none");
    assert.equal(u.pathname, "/tok123/data");
    assert.equal(u.search, "?x=1&y=2");
    await get(`/v/${PRODUCT}/`);
    assert.equal(new URL(b.seen[1]?.url ?? "http://none").pathname, "/");
    const before = b.seen.length;
    for (const p of ["/v/other/tok", `/v/${PRODUCT}`, "/v", "/v/"]) assert.equal((await get(p)).status, 404, p);
    assert.equal(b.seen.length, before, "none of them reached the handler");
  });

  test("only GET: HEAD, POST, PUT and DELETE answer 405 with the floor and never reach the handler", async () => {
    const before = b.seen.length;
    for (const method of ["HEAD", "POST", "PUT", "DELETE", "PATCH"]) {
      const res = await fetch(`http://127.0.0.1:${b.port}/v/${PRODUCT}/tok`, { method });
      assert.equal(res.status, 405, method);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff", method);
    }
    assert.equal(b.seen.length, before);
  });

  test("the floor is on a response whose handler set no header; every floor header has its exact value", async () => {
    b.next.respond = okText;
    const res = await get(`/v/${PRODUCT}/tok`);
    assert.equal(res.status, 200);
    assert.equal(await res.text(), "ok");
    for (const [k, v] of Object.entries(VIEWER_HEADER_FLOOR)) assert.equal(res.headers.get(k), v, k);
    assert.equal(res.headers.get("x-frame-options"), null, "the floor has no X-Frame-Options");
    assert.equal(res.headers.get("content-type"), "text/plain");
  });

  test("the handler cannot replace a floor header except the CSP; X-Frame-Options, Set-Cookie and Access-Control-* are dropped", async () => {
    b.next.respond = () => {
      const h = new Headers({
        "content-type": "text/html",
        "content-security-policy": "default-src 'none'; frame-ancestors https://views.example.test; img-src 'self'",
        "cache-control": "public, max-age=600",
        "x-content-type-options": "sniff",
        "referrer-policy": "unsafe-url",
        "strict-transport-security": "max-age=0",
        "permissions-policy": "camera=*",
        "x-frame-options": "SAMEORIGIN",
        "access-control-allow-origin": "*",
        "access-control-allow-credentials": "true",
        etag: '"v1"',
        "x-app": "kept",
      });
      h.append("set-cookie", "sid=abc; Path=/");
      h.append("set-cookie", "other=1");
      return new Response("<p>hi</p>", { headers: h });
    };
    const res = await get(`/v/${PRODUCT}/tok`);
    assert.equal(res.status, 200);
    for (const [k, v] of Object.entries(VIEWER_HEADER_FLOOR)) if (k !== "content-security-policy") assert.equal(res.headers.get(k), v, k);
    assert.equal(res.headers.get("content-security-policy"), "default-src 'none'; frame-ancestors https://views.example.test; img-src 'self'", "the handler's CSP is kept");
    for (const dropped of ["x-frame-options", "set-cookie", "access-control-allow-origin", "access-control-allow-credentials"]) assert.equal(res.headers.get(dropped), null, dropped);
    assert.equal(res.headers.get("etag"), '"v1"');
    assert.equal(res.headers.get("x-app"), "kept");
  });

  test("the handler sees only the allow-listed request headers (no Cookie, Authorization, TB-*); absent stays absent", async () => {
    b.next.respond = okText;
    b.seen.length = 0;
    await get(`/v/${PRODUCT}/tok`, {
      cookie: "tb_session=secret",
      authorization: "Bearer secret",
      "tb-grant": "g",
      "tb-views-key": "k",
      "x-forwarded-for": "1.2.3.4",
      "sec-fetch-dest": "iframe",
      "if-none-match": '"v1"',
      accept: "text/html",
    });
    const h = b.seen[0]?.headers ?? {};
    assert.equal(h["sec-fetch-dest"], "iframe");
    assert.equal(h["if-none-match"], '"v1"');
    assert.equal(h.accept, "text/html");
    for (const name of Object.keys(h)) assert.ok(VIEWER_REQUEST_HEADERS.includes(name), `unexpected request header ${name} reached the handler`);
    for (const name of ["cookie", "authorization", "tb-grant", "tb-views-key", "x-forwarded-for", "host", "user-agent"]) assert.equal(h[name], undefined, name);
    // no Sec-Fetch-Dest sent: none is invented
    b.seen.length = 0;
    await get(`/v/${PRODUCT}/tok`);
    assert.equal(b.seen[0]?.headers["sec-fetch-dest"], undefined);
  });

  test("ETag / 304 round trip: the handler sees If-None-Match and a 304 has no body", async () => {
    b.next.respond = (req) => (req.headers.get("if-none-match") === '"v1"' ? new Response(null, { status: 304, headers: { etag: '"v1"' } }) : new Response("body", { headers: { etag: '"v1"' } }));
    const first = await get(`/v/${PRODUCT}/tok`);
    assert.equal(first.status, 200);
    assert.equal(first.headers.get("etag"), '"v1"');
    await first.text();
    const second = await get(`/v/${PRODUCT}/tok`, { "if-none-match": '"v1"' });
    assert.equal(second.status, 304);
    assert.equal(await second.text(), "");
    assert.equal(second.headers.get("cache-control"), "no-store");
  });

  test("/_d/ documents: a sandbox CSP without the forbidden tokens passes; each forbidden token, a missing sandbox and a hidden second policy answer 502", async () => {
    const csp = (v: string | string[]) => () => {
      const h = new Headers({ "content-type": "text/html" });
      for (const x of [v].flat()) h.append("content-security-policy", x);
      return new Response("<script>1</script>", { headers: h });
    };
    // quiet on good
    for (const good of ["default-src 'none'; sandbox allow-scripts", "sandbox", "default-src 'none'; sandbox allow-scripts allow-downloads"]) {
      b.next.respond = csp(good);
      const res = await get(`/v/${PRODUCT}/_d/ticket1`);
      assert.equal(res.status, 200, good);
      assert.equal(res.headers.get("content-security-policy"), good);
    }
    // fire on bad
    for (const token of VIEWER_DOCUMENT_FORBIDDEN_SANDBOX) {
      b.next.respond = csp(`default-src 'none'; sandbox allow-scripts ${token}`);
      const res = await get(`/v/${PRODUCT}/_d/ticket1`);
      assert.equal(res.status, 502, token);
      assert.equal(((await res.json()) as { error: { code: string } }).error.code, "viewer_document_unsafe", token);
      assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    }
    for (const bad of ["default-src 'none'", "img-src 'self'; sandbox allow-same-origin"]) {
      b.next.respond = csp(bad);
      const res = await get(`/v/${PRODUCT}/_d/ticket1`);
      assert.equal(res.status, 502, bad);
      assert.ok(!(await res.text()).includes("<script>"), "the unsafe body is not sent");
    }
    b.next.respond = csp(["sandbox allow-scripts", "default-src 'none'; sandbox allow-same-origin"]);
    assert.equal((await get(`/v/${PRODUCT}/_d/ticket1`)).status, 502, "the union of the policies is judged");
    // no CSP at all: the floor's sandbox CSP applies, so the document is served sandboxed, not unsandboxed
    b.next.respond = okText;
    const bare = await get(`/v/${PRODUCT}/_d/ticket1`);
    assert.equal(bare.status, 200);
    assert.equal(bare.headers.get("content-security-policy"), VIEWER_HEADER_FLOOR["content-security-policy"]);
    // the gate is for /_d/ only: the same unsafe CSP on another path is the app's own business
    b.next.respond = csp("sandbox allow-same-origin");
    assert.equal((await get(`/v/${PRODUCT}/tok`)).status, 200);
    assert.equal((await get(`/v/${PRODUCT}/x/_d/y`)).status, 200);
  });

  test("a throwing handler answers 500 with the floor and without its message", async () => {
    b.next.respond = () => {
      throw new Error("internal detail");
    };
    const res = await get(`/v/${PRODUCT}/tok`);
    assert.equal(res.status, 500);
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.ok(!(await res.text()).includes("internal detail"));
  });

  test("a paused instance (slice pause) answers 503 paused before the handler; resuming serves again", async () => {
    b.next.respond = okText;
    b.bridge.push(await slice(b.w, PRODUCT, { pause: { workspace: false, agents: [], instances: [b.w.ins] } }));
    await until(async () => (await get(`/v/${PRODUCT}/tok`)).status === 503);
    const before = b.seen.length;
    const res = await get(`/v/${PRODUCT}/tok`);
    assert.equal(res.status, 503);
    assert.equal(((await res.json()) as { error: { code: string } }).error.code, "paused");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
    assert.equal(b.seen.length, before, "the handler was not called");
    // workspace kill switch too
    b.bridge.push(await slice(b.w, PRODUCT, { pause: { workspace: true, agents: [], instances: [] } }));
    await until(async () => (await get(`/v/${PRODUCT}/tok`)).status === 503);
    b.bridge.push(await slice(b.w, PRODUCT));
    await until(async () => (await get(`/v/${PRODUCT}/tok`)).status === 200);
  });
});

describe("an app without a viewer route", () => {
  test("/v/<product>/… is 404 and the exact-path webhook route still works", async () => {
    const w = await world();
    const t = tempDir();
    const port = await freePort();
    const bridge = new FakeBridge(w);
    const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
    const manifest = fixtureManifest(port);
    manifest.publicRoutes = [{ path: "/hook-in", purpose: "webhook" }];
    const app = defineApp({
      manifest,
      migrations: migrationsDir(t.dir),
      publicRoutes: { "/hook-in": async () => new Response("hooked") },
      handlers: { note_create: { scope: () => null, run: async () => ({ id: "x" }) }, note_get: async () => ({}), note_delete: async () => ({}), notebook_rename: async () => ({}) },
    });
    const running = await startApp(
      app,
      { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_test", TB_BRIDGE_URL: bridgeUrl, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" },
      testRoots(w),
    );
    try {
      assert.equal((await fetch(`http://127.0.0.1:${port}/v/${PRODUCT}/tok`)).status, 404);
      const hook = await fetch(`http://127.0.0.1:${port}/hook-in`, { method: "POST", body: "{}" });
      assert.equal(await hook.text(), "hooked");
      assert.equal((await fetch(`http://127.0.0.1:${port}/hook-in`)).status, 405);
    } finally {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    }
  });
});
