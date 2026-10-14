// Spec 0.1.13 SDK additions over real HTTP with a fake bridge: G1 hook hold verdict (`hv` → held receipt, heldBy,
// tb.hold_status family/reason), G4 tb.holds_pending + the SDK decision page /holds/<id>, C85 callApp outside a handler,
// C86 pendingCount / statusChanged / ownerLink, Fleet agentsChanged + widened EventContext, and the spec 0.1.14
// companionTargets addition. Unit tests for the status pacing and the pendingCount wrapper.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { signGrant, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { HookHoldFamily, Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import type { SdkEventContext, SdkOpContext, StartContext } from "../src/server/context.ts";
import { TbError } from "../src/server/errors.ts";
import { defineApp, startApp } from "../src/server/index.ts";
import { createLogger, SecretRegistry } from "../src/server/log.ts";
import { Receipts } from "../src/server/receipts.ts";
import { AttentionReader, PendingCounter, StatusPusher } from "../src/server/status.ts";
import { openStore, SDK_MIGRATIONS } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, nowS, slice, tempDir, testRoots, ticket, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";
const PEER = "peer-app";
/** must never show up in a hold reason (C90): it is in the input and so in the hold view */
const SENTINEL = "SENTINEL-INPUT-9f3a";
const HV = { f: "policy" as HookHoldFamily, r: "Rules <b>policy</b>: needs the owner", by: "rules/check_policy" };

interface Opts {
  noUi?: boolean;
  pendingCount?: (db: unknown) => Promise<number>;
  attention?: (db: unknown) => Promise<{ code: string; reason: string } | null>;
  sliceOver?: Parameters<typeof slice>[2];
  grants?: (w: World) => Promise<string[]>;
}
interface Booted {
  w: World;
  bridge: FakeBridge;
  running: RunningApp;
  base: string;
  port: number;
  dir: string;
  runs: { note_get: number };
  startCtx: StartContext | null;
  agentsChanged: { ids: string[]; ctxKeys: string[] }[];
  agentRemoved: { id: string; ctx: SdkEventContext }[];
  restart(): Promise<void>;
  cleanup(): Promise<void>;
}

function manifest(port: number, noUi: boolean): Manifest {
  const m = fixtureManifest(port);
  if (noUi) {
    // an app without a person UI may not have scopes or app_own keys (M-SC-4, M-ST-5)
    delete m.ui;
    delete m.scopes;
    for (const o of m.operations) delete o.scopeType;
    if (m.settings) m.settings.keys = [];
  }
  m.companions = [
    { product: PEER, operations: ["peer_write"], crud: ["create"], purpose: "Write to the peer." },
    { product: "*", operations: ["tb.holds_pending"], crud: ["read"], purpose: "Show pending approvals of every app." },
  ];
  return m;
}

async function boot(opts: Opts = {}): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const grants = opts.grants ? await opts.grants(w) : [];
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT, { ...opts.sliceOver, grants }));
  const b = {
    w,
    bridge,
    base: `http://127.0.0.1:${port}`,
    port,
    dir: t.dir,
    runs: { note_get: 0 },
    startCtx: null as StartContext | null,
    agentsChanged: [] as { ids: string[]; ctxKeys: string[] }[],
    agentRemoved: [] as { id: string; ctx: SdkEventContext }[],
  } as Booted;
  const start = async () => {
    const app = defineApp({
      manifest: manifest(port, opts.noUi === true),
      migrations: migrationsDir(t.dir),
      handlers: {
        note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: async () => ({ id: "n1" }) },
        note_get: async (_input, ctx) => {
          b.runs.note_get += 1;
          const c = ctx as SdkOpContext;
          return { link: c.ownerLink("/notes/1"), targets: c.companionTargets(), caller: c.caller.name };
        },
        note_delete: async () => ({}),
        notebook_rename: async () => ({}),
      },
      ...(opts.pendingCount ? { pendingCount: opts.pendingCount } : {}),
      ...(opts.attention ? { attention: opts.attention } : {}),
      onStart: async (ctx) => {
        b.startCtx = ctx;
      },
      events: {
        agentsChanged: async (agents: SliceAgent[], ctx) => {
          b.agentsChanged.push({ ids: agents.map((a) => `${a.id}:${a.name}:${a.status}`), ctxKeys: Object.keys(ctx).sort() });
        },
        agentRemoved: async (agent, ctx) => {
          b.agentRemoved.push({ id: agent.id, ctx });
        },
      },
    });
    b.running = await startApp(
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
    await until(async () => b.running.status() === "ok");
  };
  await start();
  b.restart = async () => {
    await b.running.stop();
    b.startCtx = null;
    await start();
  };
  b.cleanup = async () => {
    await b.running.stop();
    await bridge.stop();
    t.cleanup();
  };
  return b;
}

/** Agent (or app, `appIns`) call on /tb/v1/ops/<op>; `hv` adds the bridge-attested hold verdict to the proof. */
async function callOp(b: Booted, op: string, input: Json, opts: { agent?: "a" | "b"; hv?: typeof HV; grantToken?: string } = {}) {
  const g = opts.grantToken ?? (await grant(b.w, b.w.agents[opts.agent ?? "a"]));
  const proof = await callProof(b.w, g, op, input, {}, opts.hv ? { hv: opts.hv } : {});
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {} }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/** Companion grant of another instance (an APP caller) for this app. */
async function appGrant(w: World, wf: string[]): Promise<string> {
  const other = `ins_${ulid()}` as InstanceId;
  return signGrant({ iss: "tb:portal", sub: `tb:ins:${other}`, aud: `tb:ins:${w.ins}`, iat: nowS(), ws: w.ws, cnf: { brg: w.brg }, crud: ["read"], mode: "bound", held: ["money"], caps: {}, wf, polrev: 1 }, w.portal);
}

async function signIn(b: Booted, path = "/"): Promise<{ cookie: string; csrf: string; location: string | null }> {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/launch`, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ticket: await ticket(b.w, path) }),
  });
  assert.equal(res.status, 303);
  const cookie = (res.headers.get("set-cookie") ?? "").split(";")[0] as string;
  const s = (await (await fetch(`${b.base}/a/${PRODUCT}/tb/v1/session`, { headers: { cookie } })).json()) as { csrf: string };
  return { cookie, csrf: s.csrf, location: res.headers.get("location") };
}

async function personOp(b: Booted, s: { cookie: string; csrf: string }, op: string, input: Json) {
  const res = await fetch(`${b.base}/a/${PRODUCT}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", cookie: s.cookie, "tb-csrf": s.csrf, origin: b.base },
    body: JSON.stringify({ input }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

const lastPending = (b: Booted) => (b.bridge.statuses.at(-1) as { pendingHolds?: number } | undefined)?.pendingHolds;

describe("G1 hook hold verdict", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => b.cleanup());

  test("hv → held (family policy, heldBy), status pushed, hold_status family/reason; approval runs once even with hv again", async () => {
    const input = { id: SENTINEL };
    const held = await callOp(b, "note_get", input, { hv: HV });
    assert.equal(held.status, 202, JSON.stringify(held.body));
    assert.equal(held.body.status, "held");
    const holdId = held.body.holdId as string;
    const r = await b.running.receipts.get(holdId as `hld_${string}`);
    assert.equal(r?.status, "held");
    assert.equal(r?.holdFamily, "policy");
    assert.equal(r?.heldBy, HV.by);
    assert.equal(b.runs.note_get, 0);
    // SDK calls statusChanged itself on hold creation (≤ 1 s)
    await until(async () => lastPending(b) === 1, 3000);
    // receipts list carries heldBy
    const list = await b.running.receipts.list({ status: "held" });
    assert.equal(list.items[0]?.heldBy, HV.by);

    const hs = await callOp(b, "tb.hold_status", { holdId });
    assert.equal(hs.status, 200);
    assert.equal(hs.body.output.status, "held");
    assert.equal(hs.body.output.family, "policy");
    assert.equal(hs.body.output.reason, HV.r);
    // C90: the reason is only the verdict reason, never input / view / meta
    assert.ok(!JSON.stringify(hs.body).includes(SENTINEL));

    const s = await signIn(b);
    const d = await personOp(b, s, "tb.holds_decide", { holdId, decision: "approve" });
    assert.equal(d.status, 200, JSON.stringify(d.body));
    assert.equal(d.body.output.heldBy, HV.by);
    await until(async () => lastPending(b) === 0, 3000);

    const retry = await callOp(b, "note_get", input, { hv: HV });
    assert.equal(retry.status, 200, JSON.stringify(retry.body));
    assert.equal(retry.body.receiptId, holdId);
    assert.equal(b.runs.note_get, 1);
    const ran = await b.running.receipts.get(holdId as `hld_${string}`);
    assert.equal(ran?.status, "run");
    assert.equal(ran?.heldBy, HV.by);
    // consumed: the next call with the verdict is held again (one approval runs once)
    const again = await callOp(b, "note_get", input, { hv: HV });
    assert.equal(again.status, 202);
    assert.notEqual(again.body.holdId, holdId);
    assert.equal(b.runs.note_get, 1);
  });

  test("an SDK hold (held family) stores the SDK reason code; heldBy null", async () => {
    const g = await grant(b.w, b.w.agents.a, { held: ["destructive"] });
    const held = await callOp(b, "note_delete", { id: SENTINEL }, { grantToken: g });
    assert.equal(held.status, 202);
    const hs = await callOp(b, "tb.hold_status", { holdId: held.body.holdId });
    assert.equal(hs.body.output.family, "destructive");
    assert.equal(hs.body.output.reason, "held_family");
    assert.ok(!JSON.stringify(hs.body).includes(SENTINEL));
    assert.equal((await b.running.receipts.get(held.body.holdId))?.heldBy, null);
  });
});

describe("G4 tb.holds_pending", () => {
  let b: Booted;
  const ids: string[] = [];
  before(async () => {
    b = await boot();
    for (const [agent, n] of [["a", 1], ["b", 2], ["a", 3]] as const) {
      const r = await callOp(b, "note_get", { id: `${SENTINEL}-${n}` }, { agent, hv: HV });
      assert.equal(r.status, 202);
      ids.push(r.body.holdId);
      await new Promise((res) => setTimeout(res, 3));
    }
  });
  after(async () => b.cleanup());

  test("agent sees only its own pending holds, oldest first, summaries only", async () => {
    const r = await callOp(b, "tb.holds_pending", {}, { agent: "a" });
    assert.equal(r.status, 200, JSON.stringify(r.body));
    assert.equal(r.body.receiptId, undefined);
    const items = r.body.output.items as Record<string, unknown>[];
    assert.deepEqual(
      items.map((i) => i.id),
      [ids[0], ids[2]],
    );
    const it = items[0] as Record<string, any>;
    assert.deepEqual(Object.keys(it).sort(), ["ageS", "caller", "createdAt", "decidePath", "family", "heldBy", "id", "op", "product", "reason", "summary"]);
    assert.equal(it.product, PRODUCT);
    assert.equal(it.op, "note_get");
    assert.equal(it.family, "policy");
    assert.equal(it.reason, HV.r);
    assert.equal(it.heldBy, HV.by);
    assert.equal(it.decidePath, `/holds/${ids[0]}`);
    assert.equal(it.caller.id, b.w.agents.a);
    assert.ok(Number.isInteger(it.ageS) && it.ageS >= 0);
    assert.match(it.createdAt, /^\d{4}-\d{2}-\d{2}T/);
    // C90: never input, view or meta
    assert.ok(!JSON.stringify(r.body).includes(SENTINEL));
    assert.equal(r.body.output.nextCursor, null);
  });

  test("app caller whose grant names tb.holds_pending sees all; pagination; other app grants see only their own", async () => {
    const g = await appGrant(b.w, ["tb.holds_pending"]);
    const p1 = await callOp(b, "tb.holds_pending", { limit: 2 }, { grantToken: g });
    assert.equal(p1.status, 200, JSON.stringify(p1.body));
    assert.deepEqual(
      p1.body.output.items.map((i: { id: string }) => i.id),
      [ids[0], ids[1]],
    );
    assert.ok(typeof p1.body.output.nextCursor === "string");
    const p2 = await callOp(b, "tb.holds_pending", { limit: 2, cursor: p1.body.output.nextCursor }, { grantToken: g });
    assert.deepEqual(
      p2.body.output.items.map((i: { id: string }) => i.id),
      [ids[2]],
    );
    assert.equal(p2.body.output.nextCursor, null);
    const other = await callOp(b, "tb.holds_pending", {}, { grantToken: await appGrant(b.w, ["note_get"]) });
    assert.equal(other.status, 200);
    assert.deepEqual(other.body.output.items, []);
    assert.equal((await callOp(b, "tb.holds_pending", { limit: 0 }, { grantToken: g })).status, 400);
  });
});

describe("/holds/<id> SDK decision page (app without a person UI)", () => {
  let b: Booted;
  before(async () => {
    b = await boot({ noUi: true });
  });
  after(async () => b.cleanup());

  test("shows the hold escaped, decides it with the session CSRF token in a same-origin form POST", async () => {
    const held = await callOp(b, "note_get", { id: SENTINEL }, { hv: HV });
    const holdId = held.body.holdId as string;
    const page = `${b.base}/a/${PRODUCT}/holds/${holdId}`;
    assert.equal((await fetch(page)).status, 401);
    const s = await signIn(b, `/holds/${holdId}`);
    assert.equal(s.location, `/a/${PRODUCT}/holds/${holdId}`);
    const res = await fetch(page, { headers: { cookie: s.cookie } });
    assert.equal(res.status, 200);
    assert.match(res.headers.get("content-security-policy") ?? "", /default-src 'none'/);
    const html = await res.text();
    assert.ok(html.includes("Rules &lt;b&gt;policy&lt;/b&gt;: needs the owner"));
    assert.ok(!html.includes("<b>policy</b>"));
    assert.ok(html.includes(HV.by));
    assert.ok(html.includes(SENTINEL), "the hold view is shown to the owner");
    assert.ok(!/<script/i.test(html));
    const post = (form: Record<string, string>, origin: string | null = b.base) =>
      fetch(page, {
        method: "POST",
        redirect: "manual",
        headers: { "content-type": "application/x-www-form-urlencoded", cookie: s.cookie, ...(origin ? { origin } : {}) },
        body: new URLSearchParams(form),
      });
    assert.equal((await post({ decision: "approve" })).status, 403);
    assert.equal((await post({ decision: "approve", csrf: s.csrf }, "https://evil.example")).status, 403);
    assert.equal((await b.running.receipts.get(holdId as `hld_${string}`))?.status, "held");
    const ok = await post({ decision: "approve", csrf: s.csrf });
    assert.equal(ok.status, 303);
    assert.equal(ok.headers.get("location"), `/a/${PRODUCT}/holds/${holdId}`);
    assert.equal((await b.running.receipts.get(holdId as `hld_${string}`))?.status, "approved");
    const after = await (await fetch(page, { headers: { cookie: s.cookie } })).text();
    assert.ok(!after.includes('name="decision"'));
    assert.equal((await post({ decision: "deny", csrf: s.csrf })).status, 409);
  });

  test("an app WITH a UI routes /holds/<id> itself (no SDK page)", async () => {
    const ui = await boot();
    try {
      const held = await callOp(ui, "note_get", { id: "x" }, { hv: HV });
      const s = await signIn(ui);
      const res = await fetch(`${ui.base}/a/${PRODUCT}/holds/${held.body.holdId}`, { headers: { cookie: s.cookie } });
      // the fixture has no dist/ui: the UI route answers, not the SDK page
      assert.match(res.headers.get("content-type") ?? "", /application\/json/);
      assert.equal(res.status, 404);
    } finally {
      await ui.cleanup();
    }
  });
});

describe("C85 / C86 / Fleet / companionTargets", () => {
  let b: Booted;
  let peerIns: InstanceId;
  let alphaIns: InstanceId;
  let peerGrant: string;
  let alphaGrant: string;
  let counted = 2;
  before(async () => {
    peerIns = `ins_${ulid()}` as InstanceId;
    alphaIns = `ins_${ulid()}` as InstanceId;
    b = await boot({
      pendingCount: async () => counted,
      grants: async (w) => {
        const base = { iss: "tb:portal" as const, sub: `tb:ins:${w.ins}` as const, iat: nowS(), ws: w.ws, cnf: { brg: w.brg }, mode: "bound" as const, held: ["money" as const], caps: {}, polrev: 1 };
        peerGrant = await signGrant({ ...base, aud: `tb:ins:${peerIns}`, crud: ["create"], wf: ["peer_write"] }, w.portal);
        alphaGrant = await signGrant({ ...base, aud: `tb:ins:${alphaIns}`, crud: ["read"], wf: ["tb.holds_pending"] }, w.portal);
        return [peerGrant, alphaGrant];
      },
    });
  });
  after(async () => b.cleanup());

  test("C85: StartContext.callApp after onStart returned (timer): no parentCall, companion grant, one retry on grant_stale", async () => {
    const ctx = b.startCtx;
    assert.ok(ctx);
    let first = true;
    b.bridge.onCall = () => {
      if (first) {
        first = false;
        return { status: 401, body: { error: { code: "grant_stale", message: "stale", requestId: "req_t" } } };
      }
      return { status: 200, body: { status: "ok", output: { done: true } } };
    };
    const out = await new Promise((resolve, reject) => setTimeout(() => ctx.callApp(PEER, "peer_write", { x: 1 }).then(resolve, reject), 30));
    assert.deepEqual(out, { status: "ok", output: { done: true } });
    const calls = b.bridge.calls.slice(-2);
    assert.equal(calls.length, 2);
    for (const c of calls) {
      assert.equal("parentCall" in c.body, false);
      assert.equal(c.body.target, PEER);
      assert.equal(c.grant, peerGrant);
    }
    b.bridge.onCall = () => ({ status: 200, body: { status: "ok", output: { done: true } } });
    await assert.rejects(ctx.callApp(PEER, "peer_other", {}), (e: unknown) => e instanceof TbError && e.code === "companion_undeclared");
  });

  test("C86: pendingHolds = held receipts + pendingCount (clamped); ctx.statusChanged pushes", async () => {
    await until(async () => lastPending(b) === 2, 3000);
    const held = await callOp(b, "note_get", { id: "p" }, { hv: HV });
    assert.equal(held.status, 202);
    await until(async () => lastPending(b) === 3, 3000);
    counted = 50_000;
    b.startCtx?.statusChanged();
    await until(async () => lastPending(b) === 10_001, 3000);
    counted = -4;
    b.startCtx?.statusChanged();
    await until(async () => lastPending(b) === 1, 3000);
  });

  test("ownerLink: null until the slice has portalUrl, path rule enforced (path_invalid); companionTargets from the slice", async () => {
    const ctx = b.startCtx as StartContext;
    assert.equal(ctx.ownerLink("/holds/x"), null);
    assert.deepEqual(ctx.companionTargets(), []);
    assert.equal(ctx.appsPolicy(), null, "v0.1.15 (C105a): no appsPolicy in the slice → null");
    assert.equal(ctx.agentScopeRequest(b.w.agents.a), null, "v0.1.18: no scopeRequest → null");
    for (const bad of ["//evil.example/x", "https://evil.example", "/a/../b", "/a\\b", "relative", ""]) {
      assert.throws(
        () => ctx.ownerLink(bad),
        (e: unknown) => e instanceof TbError && e.code === "path_invalid" && e.httpStatus === 400,
        bad,
      );
    }
    const before = b.agentsChanged.length;
    b.bridge.push(
      await slice(b.w, PRODUCT, {
        grants: [peerGrant, alphaGrant],
        portalUrl: "https://portal.example/",
        appsPolicy: { held: ["destructive", "money", "first_contact"] },
        agents: [
          { id: b.w.agents.a, name: "Agent A", mode: "free", status: "active", scopeRequest: { product: PRODUCT, kind: "connect_inbox", createName: "Team inbox" } },
          { id: b.w.agents.b, name: "Agent B", mode: "free", status: "active", scopeRequest: { product: "other", kind: "buzz_channel", id: "c1" } },
        ],
        companionTargets: [
          { product: "zeta", ins: `ins_${ulid()}` },
          { product: "alpha", ins: alphaIns },
          { product: "zeta", ins: `ins_${ulid()}` },
          { product: PEER, ins: peerIns },
        ],
      }),
    );
    await until(async () => ctx.ownerLink("/x") !== null);
    assert.equal(ctx.ownerLink("/holds/hld_1?tab=a b"), `https://portal.example/w/${b.w.ws}/open?product=${PRODUCT}&path=${encodeURIComponent("/holds/hld_1?tab=a b")}`);
    // v0.1.20: ownerLinkFor builds a link into another app with the same rule
    assert.equal(ctx.ownerLinkFor("sample-caller", "/holds/hld_2"), `https://portal.example/w/${b.w.ws}/open?product=sample-caller&path=${encodeURIComponent("/holds/hld_2")}`);
    assert.throws(() => ctx.ownerLinkFor("Bad Product", "/x"), (e: unknown) => e instanceof TbError && e.code === "product_invalid");
    assert.throws(() => ctx.ownerLinkFor("sample-caller", "//evil.example/x"), (e: unknown) => e instanceof TbError && e.code === "path_invalid");
    assert.deepEqual(ctx.companionTargets(), ["alpha", PEER, "zeta"].sort());
    assert.deepEqual(ctx.appsPolicy(), ["destructive", "money", "first_contact"]);
    // v0.1.18 (C106a, Connect F21): scopeRequest of this product only
    assert.deepEqual(ctx.agentScopeRequest(b.w.agents.a), { product: PRODUCT, kind: "connect_inbox", createName: "Team inbox" });
    assert.equal(ctx.agentScopeRequest(b.w.agents.b), null, "a request for another product is not returned");
    // same agents → no agentsChanged
    assert.equal(b.agentsChanged.length, before);
    // OpContext has both too
    const r = await callOp(b, "note_get", { id: "ctx" });
    assert.equal(r.body.output.link, `https://portal.example/w/${b.w.ws}/open?product=${PRODUCT}&path=%2Fnotes%2F1`);
    assert.deepEqual(r.body.output.targets, ["alpha", PEER, "zeta"].sort());
    // wildcard companion: tb.holds_pending on a target product uses the grant whose aud is that target's instance
    const out = await ctx.callApp("alpha", "tb.holds_pending", {});
    assert.equal(out.status, "ok");
    const call = b.bridge.calls.at(-1);
    assert.equal(call?.grant, alphaGrant);
    assert.equal(call?.body.target, "alpha");
    assert.equal(call && "parentCall" in call.body, false);
    await assert.rejects(ctx.callApp("beta", "tb.holds_pending", {}), (e: unknown) => e instanceof TbError && e.code === "no_grant");
    await assert.rejects(ctx.callApp("alpha", "note_get", {}), (e: unknown) => e instanceof TbError && e.code === "companion_undeclared");
  });

  test("v0.1.14 (C102): an app caller is named from slice companionCallers (verified grant sub); fallback the instance id", async () => {
    const callerIns = `ins_${ulid()}` as InstanceId;
    const g = await signGrant({ iss: "tb:portal", sub: `tb:ins:${callerIns}`, aud: `tb:ins:${b.w.ins}`, iat: nowS(), ws: b.w.ws, cnf: { brg: b.w.brg }, crud: ["read"], mode: "bound", held: ["money"], caps: {}, wf: ["note_get"], polrev: 1 }, b.w.portal);
    const anon = await callOp(b, "note_get", { id: "c102-a" }, { grantToken: g });
    assert.equal(anon.body.output.caller, callerIns, "no companionCallers entry → instance id");
    b.bridge.push(await slice(b.w, PRODUCT, { companionCallers: [{ product: "evolution", ins: callerIns, name: "Evolution" }, { product: "other", ins: `ins_${ulid()}`, name: "Other" }] }));
    await until(async () => (await callOp(b, "note_get", { id: "c102-probe" }, { grantToken: g })).body.output.caller === "Evolution");
    const named = await callOp(b, "note_get", { id: "c102-b" }, { grantToken: g });
    assert.equal(named.body.output.caller, "Evolution");
  });

  test("Fleet: agentsChanged once after boot, on rename/pause/removal only; EventContext is complete; once again after a restart", async () => {
    const ctxKeys = ["agentScopeRequest", "appsPolicy", "callApp", "companionTargets", "db", "log", "ownerLink", "ownerLinkFor", "scopes", "statusChanged"];
    assert.ok(b.agentsChanged.length >= 1);
    assert.deepEqual(b.agentsChanged[0]?.ctxKeys, ctxKeys);
    const n = b.agentsChanged.length;
    const base = { grants: [peerGrant, alphaGrant], portalUrl: "https://portal.example" };
    b.bridge.push(
      await slice(b.w, PRODUCT, {
        ...base,
        agents: [
          { id: b.w.agents.a, name: "Agent A2", mode: "free", status: "active" },
          { id: b.w.agents.b, name: "Agent B", mode: "free", status: "active" },
        ],
      }),
    );
    await until(async () => b.agentsChanged.length === n + 1);
    assert.ok(b.agentsChanged.at(-1)?.ids.includes(`${b.w.agents.a}:Agent A2:active`));
    b.bridge.push(await slice(b.w, PRODUCT, { ...base, agents: [{ id: b.w.agents.a, name: "Agent A2", mode: "free", status: "paused" }] }));
    await until(async () => b.agentsChanged.length === n + 2);
    assert.deepEqual(b.agentsChanged.at(-1)?.ids, [`${b.w.agents.a}:Agent A2:paused`]);
    await until(async () => b.agentRemoved.length === 1);
    const removed = b.agentRemoved[0];
    assert.equal(removed?.id, b.w.agents.b);
    for (const k of ctxKeys) assert.ok(k in (removed?.ctx ?? {}), k);
    assert.equal(typeof removed?.ctx.callApp, "function");

    const total = b.agentsChanged.length;
    await b.restart();
    await until(async () => b.agentsChanged.length === total + 1);
    await new Promise((r) => setTimeout(r, 300));
    assert.equal(b.agentsChanged.length, total + 1);
  });
});

describe("F89 app attention (spec 0.1.28)", () => {
  let b: Booted;
  let current: { code: string; reason: string } | null = null;
  before(async () => {
    b = await boot({ attention: async () => current });
  });
  after(async () => b.cleanup());
  const last = () => b.bridge.statuses.at(-1) as { readiness?: string; attention?: { code: string; reason: string } } | undefined;

  test("quiet: no attention → readiness ready and no attention field; fires: attention → degraded + {code, reason}; cleared → ready again", async () => {
    await until(async () => last()?.readiness === "ready", 3000);
    assert.equal("attention" in (last() ?? {}), false);
    current = { code: "memory_engine_degraded", reason: "Memory engine runs without embeddings (embed_unavailable:provider_error)." };
    b.startCtx?.statusChanged();
    await until(async () => last()?.readiness === "degraded", 3000);
    assert.deepEqual(last()?.attention, current);
    current = null;
    b.startCtx?.statusChanged();
    await until(async () => last()?.readiness === "ready", 3000);
    assert.equal("attention" in (last() ?? {}), false);
  });
});

describe("units", () => {
  test("StatusPusher: coalesces calls, pushes within 1 s and at most once per second", async () => {
    const at: number[] = [];
    const p = new StatusPusher(() => at.push(Date.now()));
    const t0 = Date.now();
    for (let i = 0; i < 5; i++) p.request();
    await until(async () => at.length === 1, 1000);
    assert.ok((at[0] ?? 0) - t0 < 200);
    p.request();
    p.request();
    await until(async () => at.length === 2, 2000);
    assert.ok((at[1] ?? 0) - (at[0] ?? 0) >= 990, "≥ 1 s between pushes");
    p.stop();
    p.request();
    await new Promise((r) => setTimeout(r, 50));
    assert.equal(at.length, 2);
  });

  test("PendingCounter: clamp, error and timeout count 0, warnings rate-limited to 1/min with the suppressed count", async () => {
    const lines: Record<string, unknown>[] = [];
    const log = createLogger("debug", new SecretRegistry(), {}, { write: (_lvl: string, l: string) => void lines.push(JSON.parse(l)) });
    let now = 1_000_000;
    let mode: "n" | "big" | "neg" | "throw" | "slow" | "nan" = "n";
    const fn = async () => {
      if (mode === "throw") throw new Error("app error with DATA-xyz");
      if (mode === "slow") return new Promise<number>((r) => setTimeout(() => r(5), 200).unref());
      return mode === "big" ? 99_999 : mode === "neg" ? -3 : mode === "nan" ? Number.NaN : 7.9;
    };
    const c = new PendingCounter(fn, {} as never, log, { now: () => now, timeoutMs: 50 });
    assert.equal(await c.count(), 7);
    mode = "big";
    assert.equal(await c.count(), 10_000);
    mode = "neg";
    assert.equal(await c.count(), 0);
    assert.equal(lines.length, 0);
    mode = "throw";
    assert.equal(await c.count(), 0);
    mode = "slow";
    assert.equal(await c.count(), 0);
    mode = "nan";
    assert.equal(await c.count(), 0);
    const warns = () => lines.filter((l) => l.msg === "pendingCount failed");
    assert.equal(warns().length, 1);
    assert.equal(warns()[0]?.level, "warn");
    assert.ok(!JSON.stringify(lines).includes("DATA-xyz"));
    now += 60_000;
    mode = "throw";
    assert.equal(await c.count(), 0);
    assert.equal(warns().length, 2);
    assert.equal((warns()[1] as { suppressed?: number }).suppressed, 2);
    assert.equal(await new PendingCounter(undefined, {} as never, log).count(), 0);
  });

  test("migration 3: pre-0.1.13 receipt rows stay readable (heldBy null, reason derived from the family)", () => {
    const t = tempDir();
    try {
      // a 0.1.12 store: SDK migrations 1..2 only, one held row
      const raw = new DatabaseSync(`${t.dir}/app.db`);
      raw.exec("CREATE TABLE tb_migrations (scope TEXT NOT NULL, version INTEGER NOT NULL, name TEXT NOT NULL, sha256 TEXT NOT NULL, applied_at INTEGER NOT NULL, PRIMARY KEY (scope, version)) STRICT");
      for (const m of SDK_MIGRATIONS.slice(0, 2)) {
        raw.exec(m.sql);
        raw.prepare("INSERT INTO tb_migrations VALUES ('sdk', ?, ?, ?, 1)").run(m.version, m.name, createHash("sha256").update(m.sql).digest("hex"));
      }
      raw
        .prepare("INSERT INTO tb_receipts (id, caller_type, caller_id, caller_name, op, effect, hold_family, status, input_digest, summary, meta, created_at, expires_at) VALUES (?, 'agent', 'agt_1', 'A', 'pay', 'money', 'money', 'held', 'sha256:x', 's', 'null', 1, ?)")
        .run(`hld_${ulid()}`, Date.now() + 60_000);
      raw.close();
      const db = openStore(t.dir);
      const rc = new Receipts(db);
      const row = db.prepare("SELECT id FROM tb_receipts").get() as { id: string };
      assert.equal(rc.getSync(row.id)?.heldBy, null);
      assert.equal(rc.holdStatusSync("agt_1", row.id)?.reason, "held_money");
      const p = rc.pending({ caller: null }, Date.now());
      assert.equal(p.items[0]?.reason, "held_money");
      assert.equal(p.items[0]?.heldBy, null);
      db.close();
    } finally {
      t.cleanup();
    }
  });

  test("AttentionReader: valid value passes (reason cleaned and cut); error, timeout and malformed values count as none and warn ≤ 1/min", async () => {
    const lines: { msg: string; fields?: Record<string, unknown> }[] = [];
    const log = { debug() {}, info() {}, warn: (msg: string, fields?: Record<string, unknown>) => lines.push({ msg, fields }), error() {} } as never;
    let now = 0;
    let value: unknown = { code: "engine_down", reason: `  line1\nline2${"x".repeat(300)}` };
    const r = new AttentionReader(async () => value as never, {} as never, log, { now: () => now, timeoutMs: 50 });
    const ok = await r.read();
    assert.equal(ok?.code, "engine_down");
    assert.equal(ok?.reason.length, 200);
    assert.ok(ok?.reason.startsWith("line1 line2"));
    value = null;
    assert.equal(await r.read(), null);
    assert.equal(lines.length, 0, "quiet on the good cases");
    for (const bad of [{ code: "Bad Code", reason: "x" }, { code: "ok_code", reason: "   " }, { code: 5, reason: "x" }]) {
      value = bad;
      assert.equal(await r.read(), null);
    }
    assert.deepEqual(lines.map((l) => l.msg), ["attention failed"], "one warning per minute");
    now += 61_000;
    const slow = new AttentionReader(() => new Promise(() => {}), {} as never, log, { now: () => now, timeoutMs: 20 });
    assert.equal(await slow.read(), null);
    const failing = new AttentionReader(async () => { throw new Error("app secret detail"); }, {} as never, log, { now: () => now, timeoutMs: 20 });
    assert.equal(await failing.read(), null);
    assert.ok(!JSON.stringify(lines).includes("app secret detail"), "never logs the app's error text");
    assert.equal(await new AttentionReader(undefined, {} as never, log).read(), null);
  });
});
