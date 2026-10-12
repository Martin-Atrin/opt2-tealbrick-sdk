// Report shape (CONFORMANCE §6) and the pending targets.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BRIDGE_CHECKS, buildReport, CORE_CHECKS, exitCode, renderMarkdown, runPendingTarget, Suite, specDigest } from "../src/index.ts";

describe("report", () => {
  it("passes only when every check passes or is not_applicable", async () => {
    const s = new Suite();
    await s.run("X1", "a", "e", () => ({ pass: true, asserted: "ok" }));
    s.record("X2", "b", "e", { status: "not_applicable", asserted: "nothing to test" });
    const r = buildReport({ target: "app", subject: "t", startedAt: new Date(), checks: s.results });
    assert.equal(r.ok, true);
    assert.equal(exitCode(r), 0);
    assert.deepEqual(r.counts, { pass: 1, fail: 0, not_applicable: 1, not_run: 0, not_implemented: 0, waived: 0 });
  });

  for (const status of ["fail", "not_run", "not_implemented"] as const) {
    it(`a ${status} check fails the run`, () => {
      const s = new Suite();
      s.record("X1", "a", "e", { pass: true, asserted: "ok" });
      s.record("X2", "b", "e", { status, asserted: "why" });
      const r = buildReport({ target: "app", subject: "t", startedAt: new Date(), checks: s.results });
      assert.equal(r.ok, false);
      assert.equal(exitCode(r), 1);
    });
  }

  it("a payload finding or an empty check list fails the run", () => {
    const s = new Suite();
    s.record("X1", "a", "e", { pass: true, asserted: "ok" });
    assert.equal(buildReport({ target: "app", subject: "t", startedAt: new Date(), checks: s.results, payloadScan: { payloads: 1, patterns: [], findings: ["x: ticket"] } }).ok, false);
    assert.equal(buildReport({ target: "app", subject: "t", startedAt: new Date(), checks: [] }).ok, false);
  });

  it("a throwing check is recorded as fail with the error", async () => {
    const s = new Suite();
    await s.run("X1", "a", "e", () => {
      throw new Error("boom");
    });
    assert.equal(s.results[0].status, "fail");
    assert.match(s.results[0].asserted, /boom/);
  });

  it("markdown lists every id, the verdict and the not-release-evidence line; spec digest is stable", () => {
    const s = new Suite();
    s.record("A1", "claim", "claimed", { pass: false, asserted: "no | claim" });
    const md = renderMarkdown(buildReport({ target: "app", subject: "t", startedAt: new Date(), checks: s.results, notes: ["n1"] }));
    assert.match(md, /\*\*FAIL\*\*/);
    assert.match(md, /\| A1 claim \| fail \| no \\\| claim \|/);
    assert.match(md, /NOT release evidence/);
    assert.equal(specDigest(), specDigest());
  });

  it("bridge and core targets report every catalogued id as not_implemented and fail", () => {
    const b = runPendingTarget("bridge", "http://x");
    assert.equal(b.checks.length, BRIDGE_CHECKS.length);
    assert.ok(b.checks.every((c) => c.status === "not_implemented"));
    assert.equal(b.ok, false);
    const c = runPendingTarget("core", "http://x");
    assert.equal(c.checks.length, CORE_CHECKS.length);
    assert.equal(exitCode(c), 1);
  });
});

it("result label and exit code: PASS (n not_run) only when nothing failed; --allow-not-run is an explicit opt-in", async () => {
  const { exitCode, resultLabel } = await import("../src/report.ts");
  const base = { ok: false, counts: { pass: 3, fail: 0, not_run: 2, not_applicable: 1, not_implemented: 0 } } as never;
  assert.equal(resultLabel(base), "PASS (2 not_run)");
  assert.equal(exitCode(base), 1, "default: not_run fails the run");
  assert.equal(exitCode(base, { allowNotRun: true }), 0);
  const failed = { ok: false, counts: { pass: 3, fail: 1, not_run: 2, not_applicable: 0, not_implemented: 0 } } as never;
  assert.equal(resultLabel(failed), "FAIL");
  assert.equal(exitCode(failed, { allowNotRun: true }), 1);
  const notImpl = { ok: false, counts: { pass: 3, fail: 0, not_run: 0, not_applicable: 0, not_implemented: 1 } } as never;
  assert.equal(exitCode(notImpl, { allowNotRun: true }), 1);
  assert.equal(resultLabel({ ok: true, counts: { pass: 1 } } as never), "PASS");
});

it("--allow-not-run rewrites the report note so the text matches the exit rule", async () => {
  const { applyAllowNotRun } = await import("../src/report.ts");
  const r = { ok: false, counts: { pass: 3, fail: 0, not_run: 2, not_applicable: 0, not_implemented: 0 }, notes: ["summary: …", "not_run checks fail the run (CONFORMANCE §6: exit 0 only if every check passes)"] } as never as { notes: string[] };
  applyAllowNotRun(r as never);
  assert.equal(r.notes.some((n) => n.startsWith("not_run checks fail the run")), false);
  assert.ok(r.notes.some((n) => n.includes("do not fail this run")));
  const f = { ok: false, counts: { pass: 1, fail: 1, not_run: 1, not_applicable: 0, not_implemented: 0 }, notes: [] } as never as { notes: string[] };
  applyAllowNotRun(f as never);
  assert.ok(f.notes.some((n) => n.includes("still fails")));
});

it("waivers (C89): a not_run / fail check under an active waiver is waived and does not fail the run; expired → ignored + note; passing → unused", async () => {
  const { applyWaivers, compareVersions, renderMarkdown: md } = await import("../src/report.ts");
  assert.equal(compareVersions("0.1.10", "0.1.9"), 1);
  assert.equal(compareVersions("0.1.9", "0.1.9"), 0);
  assert.equal(compareVersions("0.1.9", "0.2.0"), -1);
  const mk = () => {
    const s = new Suite();
    s.record("A1", "a", "e", { pass: true, asserted: "ok" });
    s.record("A7.backup_roundtrip", "b", "e", { status: "not_run", asserted: "needs backupNow" });
    return buildReport({ target: "app", subject: "t", startedAt: new Date(), checks: s.results });
  };
  const r = mk();
  applyWaivers(r, [{ id: "A7.backup_roundtrip", until: "0.2.0", reason: "no backup hook in --cmd mode" }, { id: "A1", until: "0.2.0", reason: "x" }], "0.1.9");
  assert.equal(r.ok, true);
  assert.equal(exitCode(r), 0);
  assert.deepEqual([r.counts.waived, r.counts.not_run], [1, 0]);
  assert.match(r.checks[1]?.asserted ?? "", /^not_run: needs backupNow — waived until 0\.2\.0: no backup hook in --cmd mode$/);
  assert.deepEqual(r.waivers?.map((w) => w.state), ["applied", "unused"]);
  assert.match(md(r), /\| A7\.backup_roundtrip b \| waived \|/);
  const e = mk();
  applyWaivers(e, [{ id: "A7.backup_roundtrip", until: "0.1.9", reason: "late" }], "0.1.9");
  assert.equal(e.ok, false);
  assert.equal(e.checks[1]?.status, "not_run");
  assert.ok(e.notes.some((n) => n.startsWith("waiver A7.backup_roundtrip@0.1.9 ignored")));
});
