// Bridge target sensitivity: the checks pass against a minimal correct bridge and FAIL against variants that break
// one rule each (skips the pause gate, forwards without a call proof, lists person ops, sends payloads to Portal,
// accepts a person token at MCP, serves /keys on the main origin, opens the keys origin to other routes, serves the key
// page without CSP). Also: every reported id is catalogued, unselected groups report not_run, a bridge
// that never boots fails every check.
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { cspFormActionSelf } from "../../src/checks/bridge-flows.ts";
import { BRIDGE_CHECKS, CHECK_IDS, type Report, runBridgeTarget } from "../../src/index.ts";
import { type MiniFlags, type MiniState, startMiniBridge } from "./mini-bridge.ts";

const status = (r: Report, id: string) => r.checks.find((c) => c.id === id)?.status;
const run = (flags: MiniFlags, groups: string[], state: MiniState = {}) =>
  runBridgeTarget({ start: (env) => startMiniBridge(env, flags, state), groups, timeoutMs: 3000, bootTimeoutMs: 15_000, pauseLatencyMs: 4000 });

const KEYS_ORIGIN_IDS = ["B11.main_origin_keys_404", "B11.keys_origin_only", "B11.keys_origin_csp", "B11.keys_origin_unset_503"];
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

  it("key page on its own origin (C59): a correct bridge passes every keys_origin check and is restored after the unset probe", async () => {
    const r = await run({}, ["keys_origin"]);
    for (const id of KEYS_ORIGIN_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.equal(status(r, "B11.cookie_flags"), "not_run");
  });

  it("cspFormActionSelf accepts exactly form-action 'self'", () => {
    assert.equal(cspFormActionSelf("default-src 'none'; form-action 'self'; frame-ancestors 'none'"), true);
    assert.equal(cspFormActionSelf("default-src 'self'"), false);
    assert.equal(cspFormActionSelf("form-action 'self' https://evil.example"), false);
    assert.equal(cspFormActionSelf("form-action *"), false);
    assert.equal(cspFormActionSelf(null), false);
  });

  const broken: [string, MiniFlags, string[], string[]][] = [
    ["skips the pause gate", { skipPause: true }, ["pause.workspace"], ["P1.workspace.mcp"]],
    ["forwards without a call proof", { noProof: true }, ["call"], ["B8.grant_and_proof", "B8.forward"]],
    ["lists person ops in tools/list", { listPerson: true }, ["mcp"], ["B7.no_person_ops", "B7.list_exact"]],
    ["sends tool payloads to Portal", { leakToPortal: true }, ["call", "scan"], ["B9.no_payload"]],
    ["accepts a person token at MCP", { acceptPerson: true }, ["auth"], ["cred.p1.bridge_rejects_clerk_jwt", "cred.p1.bridge_rejects_tbo"]],
    ["serves /keys on the main origin (C59)", { keysOnMain: true }, ["keys_origin"], ["B11.main_origin_keys_404"]],
    ["serves other routes on the keys origin (C59)", { keysOriginOpen: true }, ["keys_origin"], ["B11.keys_origin_only"]],
    ["serves the key page without CSP form-action (C59)", { noKeysCsp: true }, ["keys_origin"], ["B11.keys_origin_csp"]],
    ["answers 404 instead of 503 when the keys origin is unset (C59)", { noUnset503: true }, ["keys_origin"], ["B11.keys_origin_unset_503"]],
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
