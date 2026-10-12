// Bridge target sensitivity: the checks pass against a minimal correct bridge and FAIL against variants that break
// one rule each (skips the pause gate, forwards without a call proof, lists person ops, sends payloads to Portal,
// accepts a person token at MCP). Also: every reported id is catalogued, unselected groups report not_run, a bridge
// that never boots fails every check.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { BRIDGE_CHECKS, CHECK_IDS, type Report, runBridgeTarget } from "../../src/index.ts";
import { type MiniFlags, startMiniBridge } from "./mini-bridge.ts";

const status = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.status;
const run = (flags: MiniFlags, groups: string[]) =>
  runBridgeTarget({ start: (env) => startMiniBridge(env, flags), groups, timeoutMs: 3000, bootTimeoutMs: 15_000, pauseLatencyMs: 4000 });

const GOOD_IDS = ["B1.health", "B1.mcp_requires_auth", "B1.internal_not_public", "C1.K5", "cred.p1.bridge_rejects_clerk_jwt", "cred.p1.bridge_rejects_tbo", "B7.list_exact", "B7.no_person_ops", "B8.forward", "B8.grant_and_proof", "B5.bound_outside_wf", "P1.workspace.mcp", "B9.portal_paths", "B9.no_payload"];

describe("bridge target", () => {
  it("reports every catalogued id; unselected groups are not_run; a correct bridge passes the selected rules", async () => {
    const r = await run({}, ["surface", "auth", "mcp", "call", "pause.workspace", "scan"]);
    assert.equal(r.target, "bridge");
    assert.deepEqual(new Set(r.checks.map((c) => c.id)), new Set(BRIDGE_CHECKS.map((c) => c.id)));
    for (const c of r.checks) assert.ok(CHECK_IDS.has(c.id), c.id);
    for (const id of GOOD_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.equal(status(r, "B14.admin_pause"), "not_run");
    assert.equal(r.ok, false, "a partial run never passes");
  });

  const broken: [string, MiniFlags, string[], string[]][] = [
    ["skips the pause gate", { skipPause: true }, ["pause.workspace"], ["P1.workspace.mcp"]],
    ["forwards without a call proof", { noProof: true }, ["call"], ["B8.grant_and_proof", "B8.forward"]],
    ["lists person ops in tools/list", { listPerson: true }, ["mcp"], ["B7.no_person_ops", "B7.list_exact"]],
    ["sends tool payloads to Portal", { leakToPortal: true }, ["call", "scan"], ["B9.no_payload"]],
    ["accepts a person token at MCP", { acceptPerson: true }, ["auth"], ["cred.p1.bridge_rejects_clerk_jwt", "cred.p1.bridge_rejects_tbo"]],
  ];
  for (const [name, flags, groups, ids] of broken) {
    it(`fails a bridge that ${name}`, async () => {
      const r = await run(flags, groups);
      for (const id of ids) assert.equal(status(r, id), "fail", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
      assert.equal(r.ok, false);
    });
  }

  it("a bridge that never enrols fails every check (boot failure)", async () => {
    const r = await runBridgeTarget({
      start: async (env) => ({ publicUrl: `http://127.0.0.1:${env.PORT}`, internalUrl: `http://127.0.0.1:${env.TB_INTERNAL_PORT}`, stop: async () => undefined }),
      bootTimeoutMs: 500,
    });
    assert.equal(r.counts.fail, BRIDGE_CHECKS.length);
    assert.match(r.notes.join(" "), /boot failed/);
  });
});
