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
    ["loses its instance key on restart", { newKeyOnRestart: true }, ["A1.key_persisted", "A7.restart"], 2000],
  ];
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
