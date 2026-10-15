// Production gate SDK-01 / SDK-02 / SDK-04 / SDK-05 (qa/REVIEW-CODE-QUALITY-2026-10-14): idempotency keys and Free cap
// slots are reserved BEFORE the handler runs (one-wins rows in the app DB), and a grant for an agent that is not in the
// slice is refused. The handler waits on a test gate (no wall-clock race): concurrency is real HTTP on one app.
import assert from "node:assert/strict";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { after, before, describe, test } from "node:test";
import { digest, ulid } from "@opt2-tealbrick/manifest";
import type { FreeCaps } from "@opt2-tealbrick/spec/credentials";
import type { Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, RunningApp } from "@opt2-tealbrick/spec/sdk";
import { defineApp, startApp } from "../src/server/index.ts";
import { Receipts } from "../src/server/receipts.ts";
import { openStore } from "../src/server/store.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, testRoots, until, type World, world } from "./helpers.ts";

const PRODUCT = "jotter";

/** A release-able gate: handlers wait on it while the test sends the concurrent duplicates. */
function gate() {
  let release!: () => void;
  const promise = new Promise<void>((r) => {
    release = r;
  });
  return { promise, release };
}

const tick = (id: string, receipt: boolean): Operation =>
  ({
    id,
    title: `Tick ${id}`,
    description: "Count one write (test op).",
    input: { type: "object", additionalProperties: false, required: ["n"], properties: { n: { type: "string" }, fail: { type: "boolean" } } },
    output: { type: "object", required: ["run"], properties: { run: { type: "number" } } },
    crud: ["update"],
    effect: "write",
    idempotency: "supported",
    receipt,
    audience: "agent",
  }) as Operation;

interface Booted {
  w: World;
  running: RunningApp;
  base: string;
  dataDir: string;
  runs: Record<string, number>;
  state: { gate: ReturnType<typeof gate> | null };
  cleanup(): Promise<void>;
}

async function boot(): Promise<Booted> {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, PRODUCT));
  const runs: Record<string, number> = {};
  const state: Booted["state"] = { gate: null };
  const manifest = fixtureManifest(port);
  manifest.operations.push(tick("tick", false), tick("tick_rcp", true));
  const run = (op: string) => async (input: Json) => {
    runs[op] = (runs[op] ?? 0) + 1;
    const n = runs[op];
    if (state.gate) await state.gate.promise;
    if ((input as { fail?: boolean }).fail) throw new Error("planned failure");
    return { run: n };
  };
  const app = defineApp({ manifest, migrations: migrationsDir(t.dir), handlers: { note_create: { scope: (input) => String((input as { notebook: string }).notebook), run: run("note_create") }, note_get: run("note_get"), note_delete: run("note_delete"), notebook_rename: run("notebook_rename"), tick: run("tick"), tick_rcp: run("tick_rcp") } });
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
  ).catch(async (e) => {
    await bridge.stop();
    t.cleanup();
    throw e;
  });
  await until(async () => running.status() === "ok");
  return {
    w,
    running,
    base: `http://127.0.0.1:${port}`,
    dataDir: t.dir,
    runs,
    state,
    async cleanup() {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    },
  };
}

async function call(b: Booted, op: string, input: Json, opts: { agent?: `agt_${string}`; key?: string; caps?: FreeCaps } = {}) {
  const g = await grant(b.w, opts.agent ?? b.w.agents.a, { caps: opts.caps ?? {} });
  const proof = await callProof(b.w, g, op, input);
  const res = await fetch(`${b.base}/tb/v1/ops/${op}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": proof },
    body: JSON.stringify({ input, context: {}, ...(opts.key ? { idempotencyKey: opts.key } : {}) }),
  });
  return { status: res.status, body: (await res.json()) as Record<string, any> };
}

/**
 * Sends `n` calls at once while the handler waits on a gate. The gate opens when every call has entered the handler
 * (the old, racy behaviour) or after `marginMs` (the fixed behaviour keeps duplicates out of the handler, so the
 * margin only bounds the test; no assertion depends on it).
 */
async function concurrent(b: Booted, op: string, n: number, send: () => Promise<{ status: number; body: Record<string, any> }>, marginMs = 1500) {
  const g = gate();
  b.state.gate = g;
  const before = b.runs[op] ?? 0;
  const answers = Array.from({ length: n }, () => send());
  await until(async () => (b.runs[op] ?? 0) - before >= 1);
  await until(async () => (b.runs[op] ?? 0) - before >= n, marginMs).catch(() => undefined);
  g.release();
  b.state.gate = null;
  const out = await Promise.all(answers);
  return { answers: out, runs: (b.runs[op] ?? 0) - before };
}

describe("SDK-01 idempotency key reserved before the handler", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => {
    await b.cleanup();
  });

  test("two concurrent calls with the same key run the handler ONCE; both get the first result", async () => {
    const r = await concurrent(b, "tick", 2, () => call(b, "tick", { n: "a" }, { key: "race-key-0001" }));
    assert.equal(r.runs, 1, `handler runs = ${r.runs} (SDK-01 reproduced: 2 on miniapp-sdk 0.1.21)`);
    for (const a of r.answers) assert.equal(a.status, 200, JSON.stringify(a.body));
    assert.deepEqual(r.answers[0]?.body.output, r.answers[1]?.body.output);
  });

  test("five concurrent duplicates on a receipt op: one run, one receipt-backed result", async () => {
    const r = await concurrent(b, "tick_rcp", 5, () => call(b, "tick_rcp", { n: "b" }, { key: "race-key-0002" }));
    assert.equal(r.runs, 1);
    const outputs = new Set(r.answers.map((a) => JSON.stringify(a.body.output)));
    assert.equal(outputs.size, 1);
    assert.ok(r.answers.every((a) => a.status === 200));
  });

  test("a duplicate with a different input while the first runs → 409 idempotency_conflict", async () => {
    const g = gate();
    b.state.gate = g;
    const first = call(b, "tick", { n: "c" }, { key: "race-key-0003" });
    await until(async () => (b.runs.tick ?? 0) >= 1);
    const other = await call(b, "tick", { n: "different" }, { key: "race-key-0003" });
    g.release();
    b.state.gate = null;
    assert.equal(other.status, 409);
    assert.equal(other.body.error?.code, "idempotency_conflict");
    assert.equal((await first).status, 200);
  });

  test("a failed first run frees the key: the waiting duplicate runs (a normal retry)", async () => {
    const before = b.runs.tick ?? 0;
    const g = gate();
    b.state.gate = g;
    const first = call(b, "tick", { n: "d", fail: true }, { key: "race-key-0004" });
    await until(async () => (b.runs.tick ?? 0) - before >= 1);
    const second = call(b, "tick", { n: "d", fail: true }, { key: "race-key-0004" });
    g.release();
    b.state.gate = null;
    const [a1, a2] = await Promise.all([first, second]);
    assert.equal(a1.status, 500);
    assert.equal(a2.status, 500);
    assert.equal((b.runs.tick ?? 0) - before, 2, "the key is not kept for a failed run");
  });

  test("a pending key with no live run in this process → 409 idempotency_in_flight, never a second run", async () => {
    // a second connection writes what a crash leaves behind: a pending row with no live run in this process
    const db = new DatabaseSync(join(b.dataDir, "app.db"));
    try {
      db.exec("PRAGMA busy_timeout = 5000");
      const now = Date.now();
      db.prepare("INSERT INTO tb_idempotency (caller_id, op, key, input_digest, kind, output, hold_id, created_at, expires_at) VALUES (?, 'tick', 'race-key-0005', ?, 'pending', NULL, NULL, ?, ?)").run(
        b.w.agents.a,
        digest({ n: "e" }),
        now,
        now + 86_400_000,
      );
    } finally {
      db.close();
    }
    const before = b.runs.tick ?? 0;
    const a = await call(b, "tick", { n: "e" }, { key: "race-key-0005" });
    assert.equal(a.status, 409, JSON.stringify(a.body));
    assert.equal(a.body.error?.code, "idempotency_in_flight");
    assert.equal((b.runs.tick ?? 0) - before, 0);
  });
});

describe("SDK-01 crash recovery (boot)", () => {
  test("pending keys of a dead process become unknown_outcome at boot; they expire with the key (24 h), never re-run", () => {
    const t = tempDir();
    try {
      const db = openStore(t.dir);
      const r = new Receipts(db);
      const now = 1_800_000_000_000;
      assert.equal(r.idemReserve("agt_x", "tick", "crash-key-01", "d1", now).kind, "reserved");
      assert.equal(r.idemRecoverCrashed(now + 1), 1);
      const row = r.idemGet("agt_x", "tick", "crash-key-01", now + 2);
      assert.equal(row?.kind, "unknown");
      // the key's normal 24 h life ends it; the sweep then purges it
      assert.equal(r.idemGet("agt_x", "tick", "crash-key-01", now + 86_400_000 + 1), null);
      r.sweep(now + 86_400_000 + 1);
      assert.equal(r.idemReserve("agt_x", "tick", "crash-key-01", "d1", now + 86_400_000 + 2).kind, "reserved");
      db.close();
    } finally {
      t.cleanup();
    }
  });
});

describe("SDK-02 / SDK-04 caps reserved before the handler, independent of receipts", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => {
    await b.cleanup();
  });
  const caps: FreeCaps = { write: { max: 1, per: "hour" } };

  test("max 1 on a receipt:false write op: the first call runs, the second is held (caps)", async () => {
    const agent = b.w.agents.a;
    const first = await call(b, "tick", { n: "1" }, { agent, caps });
    const second = await call(b, "tick", { n: "2" }, { agent, caps });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(second.status, 202, `second call ${second.status} ${JSON.stringify(second.body)} (SDK-02 reproduced: 200 on miniapp-sdk 0.1.21)`);
    assert.equal(second.body.status, "held");
  });

  test("max 1 on a receipt:true write op: the first call runs, the second is held", async () => {
    // agent B: its own usage window (caps count per caller)
    const agent = b.w.agents.b;
    const first = await call(b, "tick_rcp", { n: "1" }, { agent, caps });
    const second = await call(b, "tick_rcp", { n: "2" }, { agent, caps });
    assert.equal(first.status, 200, JSON.stringify(first.body));
    assert.equal(second.status, 202, JSON.stringify(second.body));
  });
});

describe("SDK-02 concurrent burst and released slots", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => {
    await b.cleanup();
  });

  test("three concurrent calls under max 1: one runs, two are held", async () => {
    let i = 0;
    const r = await concurrent(b, "tick", 3, () => call(b, "tick", { n: `burst-${i++}` }, { caps: { write: { max: 1, per: "hour" } } }));
    assert.equal(r.runs, 1, `handler runs = ${r.runs} (SDK-02 reproduced: 3 on miniapp-sdk 0.1.21)`);
    assert.deepEqual(r.answers.map((a) => a.status).sort(), [200, 202, 202]);
  });

  test("a failed run gives its slot back (spec: failed runs do not count)", async () => {
    const agent = b.w.agents.b;
    const caps: FreeCaps = { write: { max: 1, per: "hour" } };
    const failed = await call(b, "tick", { n: "f", fail: true }, { agent, caps });
    assert.equal(failed.status, 500);
    const ok = await call(b, "tick", { n: "g" }, { agent, caps });
    assert.equal(ok.status, 200, JSON.stringify(ok.body));
    const held = await call(b, "tick", { n: "h" }, { agent, caps });
    assert.equal(held.status, 202);
  });
});

describe("SDK-05 grant for an agent outside the slice", () => {
  let b: Booted;
  before(async () => {
    b = await boot();
  });
  after(async () => {
    await b.cleanup();
  });

  test("a valid grant for an agent not in the slice → 403 agent_unknown; nothing runs, no agent record", async () => {
    const stranger = `agt_${ulid()}` as `agt_${string}`;
    const before = b.runs.note_get ?? 0;
    const a = await call(b, "note_get", { id: "x" }, { agent: stranger });
    assert.equal(a.status, 403, JSON.stringify(a.body));
    assert.equal(a.body.error?.code, "agent_unknown");
    assert.equal((b.runs.note_get ?? 0) - before, 0);
    const db = new DatabaseSync(join(b.dataDir, "app.db"), { readOnly: true });
    try {
      assert.equal(db.prepare("SELECT agent FROM tb_agents WHERE agent = ?").get(stranger), undefined, "no invented agent record");
      assert.equal(Number((db.prepare("SELECT COUNT(*) AS n FROM tb_scope_defaults WHERE agent = ?").get(stranger) as { n: number }).n), 0, "no scope defaults");
    } finally {
      db.close();
    }
    // a listed agent still works
    assert.equal((await call(b, "note_get", { id: "x" })).status, 200);
  });
});
