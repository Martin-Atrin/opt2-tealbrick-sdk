// App target: a correct mini app passes every check; each deliberately broken variant FAILS the matching checks
// (sensitivity). Ids reported by a run must all be catalogued.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { APP_CHECK_IDS, CHECK_IDS, exitCode, type Report, renderMarkdown, runApp } from "../src/index.ts";
import { freePort } from "./apps/free-port.ts";
import { type MiniAppFaults, startMiniApp } from "./apps/mini-app.ts";

const path = new URL("./fixtures/sample.manifest.json", import.meta.url).pathname;
const manifest = JSON.parse(readFileSync(path, "utf8")) as Manifest;
const template = { services: [{ name: "app", domains: [] }, { name: "bridge", domains: ["bridge.example.org"] }] };

function run(faults: MiniAppFaults = {}, extra: Partial<Parameters<typeof runApp>[0]> = {}): Promise<Report> {
  return runApp({ manifest, manifestPath: path, start: (env) => startMiniApp(manifest, env, faults), deployTemplate: template, timeoutMs: 8000, ...extra });
}
const failing = (r: Report) => r.checks.filter((c) => c.status === "fail" || c.status === "not_run" || c.status === "not_implemented").map((c) => c.id);

describe("app target", () => {
  it("a correct app passes every check; report lists every catalogued app id", async () => {
    const r = await run();
    assert.deepEqual(failing(r), [], renderMarkdown(r));
    assert.equal(r.ok, true);
    assert.equal(exitCode(r), 0);
    const ids = new Set(r.checks.map((c) => c.id));
    for (const id of APP_CHECK_IDS) assert.ok(ids.has(id), `missing ${id}`);
    for (const id of ids) assert.ok(CHECK_IDS.has(id), `uncatalogued ${id}`);
    assert.equal(r.payloadScan.findings.length, 0);
    assert.ok(r.payloadScan.payloads > 50);
    assert.match(r.specDigest, /^sha256:[0-9a-f]{64}$/);
    assert.deepEqual(r.sdk, { majors: [1, 0], reported: "1.0.0" });
  });

  const cases: [string, MiniAppFaults, string[], number?][] = [
    ["skips call-proof verification", { skipProofVerify: true }, ["A2.no_proof", "B8.tampered_input", "A2.proof_op", "C5.proof_unannounced_kid", "C2.proof_aud_foreign", "C3.grant_as_proof", "B13.bridge_op_proof_at_op"]],
    ["skips grant verification", { skipGrantVerify: true }, ["C5.grant_unannounced_kid", "C5.grant_expired", "C2.grant_aud_foreign", "C2.grant_aud_array", "A2.grant_revoked", "A2.grant_cnf"]],
    ["ignores the slice pause", { ignorePause: true }, ["P1.workspace", "P1.agent", "P1.instance", "P1.held_release_paused"]],
    ["accepts a launch ticket twice", { ticketReusable: true }, ["C6.ticket_replay"]],
    ["has no idempotency conflict", { noIdempotencyConflict: true }, ["A5"]],
    ["serves its own claim route", { servesClaimRoute: true }, ["A1.no_claim_route"]],
    ["keeps standing approvals", { standingApproval: true }, ["A10", "A3.no_standing_approval"]],
    ["skips CSRF", { noCsrf: true }, ["A6.csrf"]],
    ["stores raw input in receipts", { storesRawInput: true }, ["A4.receipt_digest"]],
    ["ignores personNbf", { ignorePersonNbf: true }, ["A6.person_nbf"]],
    ["has no proof replay set", { noProofReplayGuard: true }, ["C6.call_proof_replay"]],
    ["does not re-read its slice on a stale companion grant", { noCompanionRetry: true }, ["A12.companion_refresh_retry"]],
    ["answers a hook with a wrong shape", { badHookShape: true }, ["A2.hook_valid"]],
    ["ignores portalKeySet (pre-v0.1.11 trust rule)", { ignoreKeySet: true }, ["A13.portal_keys_ignored", "A13.kss_unknown_root", "A13.kss_rollback", "A13.kss_missing", "A13.kss_compromise"]],
    ["loses its instance key on restart", { newKeyOnRestart: true }, ["A1.key_persisted", "A7.restart"], 2000],
    ["keeps a refused identity although the enrolment code changed", { noReclaim: true }, ["A1.reclaim_on_new_code"]],
    // v0.1.13 (spec 0.1.13, conformance 0.1.9)
    ["ignores the proof's hook hold verdict (hv)", { ignoreHoldVerdict: true }, ["A14.hook_hold"]],
    ["never lets an approval satisfy a hook verdict", { hvIgnoresApproval: true }, ["A14.hold_retry_once"]],
    ["holds on a verdict before the scope checks", { hvBeforeScope: true }, ["A14.scope_wins"]],
    ["shows an agent every pending hold", { holdsPendingAll: true }, ["A15.holds_pending"]],
    ["makes an app-initiated call without its companion grant", { appInitiatedNoGrant: true }, ["A16.call_outside_handler"]],
    ["does not push its status when a hold changes", { noStatusChanged: true }, ["A17.status_changed"]],
    ["reports pendingHolds 0", { pendingHoldsZero: true }, ["A17.pending_count"]],
  ];
  it("--no-test-roots: a strict app refuses every fake-bridge slice, the run fails at boot with the pinned-roots note", async () => {
    const r = await run({}, { testRoots: false, bootTimeoutMs: 3000 });
    assert.equal(r.ok, false);
    assert.equal(exitCode(r), 1);
    assert.match(r.notes.join(" "), /boot failed/);
    assert.ok(
      r.notes.includes("app build pins Portal Root Keys: run with test roots (start module must pass env.TBCONF_PORTAL_ROOT_KEYS to startApp — see create-tealbrick-miniapp conformance.start.ts) (--no-test-roots given)"),
      r.notes.join("\n"),
    );
  });

  it("test roots offered but not pinned (a start module that drops TBCONF_PORTAL_ROOT_KEYS): boot fails with the same note", async () => {
    const r = await runApp({ manifest, manifestPath: path, start: (env) => startMiniApp(manifest, { ...env, TBCONF_PORTAL_ROOT_KEYS: "" }), timeoutMs: 8000, bootTimeoutMs: 3000 });
    assert.equal(r.ok, false);
    assert.match(r.notes.join(" "), /app build pins Portal Root Keys: run with test roots .*the app did not pin them/);
  });

  it("--no-test-roots with a 0.1.11 app (--keyset-transitional): it boots and the A13 key-set checks report not_run", async () => {
    const r = await run({ keysetTransitional: true }, { testRoots: false, keysetRequired: false });
    const a13 = r.checks.filter((c) => c.id.startsWith("A13.") && c.id !== "A13.kss_first_missing");
    assert.equal(a13.length, 7);
    for (const c of a13) assert.equal(c.status, "not_run", `${c.id}: ${c.asserted}`);
    assert.match(a13[0]?.asserted ?? "", /--no-test-roots: the app pins its build's Portal Root Keys/);
    const strict = r.checks.find((c) => c.id === "A13.kss_first_missing");
    assert.equal(strict?.status, "not_applicable");
    assert.match(strict?.asserted ?? "", /--keyset-transitional: 0\.1\.11 transition rules/);
    assert.deepEqual(failing(r).filter((id) => !id.startsWith("A13.")), []);
  });

  it("strict by default (a spec-0.1.12 app passes it in the first test): a 0.1.11 app fails A13.kss_first_missing", async () => {
    const lax = await run({ keysetTransitional: true });
    const l = lax.checks.find((c) => c.id === "A13.kss_first_missing");
    assert.equal(l?.status, "fail", l?.asserted);
  });

  it("an app whose agent ops are ALL read-only passes: the hold chain and its dependants report not_applicable (Fleet)", async () => {
    const ro = structuredClone(manifest) as Manifest;
    ro.operations = ro.operations.map((o) => {
      if (o.audience !== "agent") return o;
      const { holdFamily: _h, ...rest } = o as typeof o & { holdFamily?: string };
      return { ...rest, effect: "read", crud: ["read"], idempotency: "none" } as typeof o;
    });
    const r = await runApp({ manifest: ro, manifestPath: path, start: (env) => startMiniApp(ro, env), deployTemplate: template, timeoutMs: 8000 });
    assert.deepEqual(failing(r), [], renderMarkdown(r));
    for (const id of ["A3.hold", "A4.hold_status", "A4.decide_person_only", "A4.holds_list", "A4.receipt_digest", "A10", "P1.held_release_paused", "A3.no_standing_approval"]) {
      assert.equal(r.checks.find((c) => c.id === id)?.status, "not_applicable", id);
    }
    for (const id of ["P1.workspace", "P1.agent", "P1.instance", "A7.restart", "A1.key_persisted", "A7.backup_roundtrip"]) assert.equal(r.checks.find((c) => c.id === id)?.status, "pass", id);
  });

  it("A5 tampers a free-text field, never an enum first field (Inbox); no receipt op → A4.mark_after_failed not_applicable (Fleet)", async () => {
    const m = structuredClone(manifest) as Manifest;
    for (const o of m.operations) {
      if (o.id !== "item_create") continue;
      const inp = o.input as unknown as { required: string[]; properties: Record<string, unknown> };
      inp.properties = { kind: { type: "string", enum: ["task", "idea"] }, code: { type: "string", pattern: "^[A-Za-z0-9_-]+$" }, ...inp.properties };
      inp.required = ["kind", "code", ...inp.required];
    }
    const r = await runApp({ manifest: m, start: (env) => startMiniApp(m, env), timeoutMs: 8000 });
    const a5 = r.checks.find((c) => c.id === "A5");
    assert.equal(a5?.status, "pass", a5?.asserted);
    assert.match(a5?.asserted ?? "", /other input \(free-text field (title|space)\) 409 idempotency_conflict/);
    const noReceipt = structuredClone(manifest) as Manifest;
    noReceipt.operations = noReceipt.operations.map((o) => {
      if (o.audience !== "agent") return o;
      const { holdFamily: _h, ...rest } = o as typeof o & { holdFamily?: string };
      return { ...rest, effect: "read", crud: ["read"], idempotency: "none", receipt: false } as typeof o;
    });
    const n = await runApp({ manifest: noReceipt, start: (env) => startMiniApp(noReceipt, env), timeoutMs: 8000 });
    const mark = n.checks.find((c) => c.id === "A4.mark_after_failed");
    assert.equal(mark?.status, "not_applicable", mark?.asserted);
    assert.match(mark?.asserted ?? "", /no agent op has receipt: true/);
  });

  for (const [name, faults, expected, timeoutMs] of cases) {
    it(`an app that ${name} fails ${expected.join(", ")}`, async () => {
      const r = await run(faults, timeoutMs ? { timeoutMs } : {});
      const f = failing(r);
      for (const id of expected) assert.ok(f.includes(id), `${id} should fail; failing: ${f.join(", ")}`);
      assert.equal(r.ok, false);
      assert.equal(exitCode(r), 1);
    });
  }

  it("url mode (no restart) reports not_run for the restart / backup checks and fails", async () => {
    const port = await freePort();
    let app: Awaited<ReturnType<typeof startMiniApp>> | null = null;
    let booting: Promise<unknown> = Promise.resolve();
    try {
      const r = await runApp({
        manifest,
        manifestPath: path,
        url: `http://127.0.0.1:${port}`,
        onEnv: (env) => {
          booting = startMiniApp(manifest, env, {}, port).then((a) => {
            app = a;
          });
        },
        timeoutMs: 8000,
      });
      const notRun = r.checks.filter((c) => c.status === "not_run").map((c) => c.id);
      for (const id of ["A7.restart", "A7.backup_roundtrip", "A1.key_persisted"]) assert.ok(notRun.includes(id), `${id} not_run; got ${notRun.join(",")}`);
      assert.deepEqual(failing(r).filter((id) => !notRun.includes(id)), [], "everything else passes");
      assert.equal(r.ok, false);
    } finally {
      await booting;
      await (app as { stop(): Promise<void> } | null)?.stop();
    }
  });

  it("A9 without a deploy template asserts at manifest level; a public-binding env entry fails it", async () => {
    const plain = await run({}, { deployTemplate: undefined });
    const a9 = plain.checks.find((c) => c.id === "A9");
    assert.equal(a9?.status, "pass");
    assert.match(a9?.asserted ?? "", /manifest-level; the live project check is QA \(CONFORMANCE open Q1\)/);
    const exposed = { ...manifest, runtime: { ...manifest.runtime, env: [...(manifest.runtime.env ?? []), { name: "PUBLIC_URL", value: "https://app.example.org" }] } } as Manifest;
    const r = await runApp({ manifest: exposed, start: (env) => startMiniApp(exposed, env), timeoutMs: 8000 });
    assert.equal(r.checks.find((c) => c.id === "A9")?.status, "fail");
  });

  it("a URL that reaches another process (not the app under test) fails boot with that reason", async () => {
    const { createServer } = await import("node:http");
    const other = createServer((_req, res) => res.writeHead(302, { location: "/" }).end());
    await new Promise<void>((r) => other.listen(0, "127.0.0.1", () => r()));
    const port = (other.address() as { port: number }).port;
    let app: Awaited<ReturnType<typeof startMiniApp>> | null = null;
    try {
      const r = await runApp({
        manifest,
        start: async (env) => {
          app = await startMiniApp(manifest, env);
          return { url: `http://127.0.0.1:${port}`, stop: async () => {} };
        },
      });
      const a1 = r.checks.find((c) => c.id === "A1");
      assert.equal(a1?.status, "fail");
      assert.match(a1?.asserted ?? "", /does not answer as the app under test.*302/);
    } finally {
      await (app as { stop(): Promise<void> } | null)?.stop();
      other.close();
    }
  });

  it("an app that never claims fails every app check with the boot reason", async () => {
    const r = await runApp({ manifest, start: async () => ({ url: "http://127.0.0.1:9", stop: async () => {} }), bootTimeoutMs: 300 });
    const app = r.checks.filter((c) => (APP_CHECK_IDS as readonly string[]).includes(c.id));
    assert.equal(app.length, APP_CHECK_IDS.length);
    assert.ok(app.every((c) => c.status === "fail" && c.asserted.startsWith("boot failed")));
    assert.equal(r.ok, false);
  });

  it("an invalid manifest fails M1 and every app check without booting", async () => {
    let started = false;
    const r = await runApp({
      manifest: { ...manifest, schema: "tealbrick.miniapp/1" },
      start: async () => {
        started = true;
        return { url: "http://127.0.0.1:9", stop: async () => {} };
      },
    });
    assert.equal(started, false);
    assert.equal(r.checks.find((c) => c.id === "M1")?.status, "fail");
    assert.equal(r.ok, false);
  });
});
