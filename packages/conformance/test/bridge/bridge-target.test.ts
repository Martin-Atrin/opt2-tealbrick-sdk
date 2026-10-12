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
/** `keyset`: runBridgeTarget's key-set options (default: test roots + strict, as the CLI) */
/** C91 group real_app: the workspace SDK source (no build needed: node strips the types outside node_modules) */
const SDK_MODULE = new URL("../../../miniapp-sdk/src/server/index.ts", import.meta.url).href;
const run = (flags: MiniFlags, groups: string[], state: MiniState = {}, keyset: { testRoots?: boolean; keysetRequired?: boolean; bootTimeoutMs?: number } = {}) =>
  runBridgeTarget({ start: (env) => startMiniBridge(env, flags, state), groups, timeoutMs: 3000, bootTimeoutMs: 15_000, pauseLatencyMs: 4000, sdkModule: SDK_MODULE, ...keyset });
const ADDRESS_IDS = ["B21.own_infra_allowed", "B21.internal_url_external", "B21.own_infra_flag_required", "B21.neighbour_url_refused"];
const KEYSET_IDS = ["B20.kss_enrolled", "B20.portal_keys_ignored", "B20.kss_unknown_root", "B20.kss_rollback", "B20.kss_missing", "B20.kss_compromise", "B20.kss_reenrol_missing"];

const SPINE013_IDS = ["B22.hold_verdict", "B22.hold_retry_refused", "B22.hv_tamper", "B23.on_behalf_of", "B23.reserved_tb_namespace", "B24.app_initiated", "B24.no_grant"];
const REAL_APP_IDS = ["B25.real_catalog_search", "B25.real_dynamic_call", "B25.real_op_call", "B25.real_mark"];
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

  it("app addresses (BSD-07): a correct bridge passes every addresses check", async () => {
    const r = await run({}, ["addresses"]);
    for (const id of ADDRESS_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
  });

  it("key-set statements (spec 0.1.12): by default (test roots, strict) a correct bridge passes every keyset check", async () => {
    const r = await run({}, ["keyset"]);
    for (const id of [...KEYSET_IDS, "B20.kss_enrol_missing"]) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`); // gitleaks:allow (check id, not a secret)
  });

  it("one pass with test roots (conformance 0.1.8, Lead · Bridge): Portal key rotation re-signs the statement", async () => {
    // the mini bridge has no standalone mode; the B14 fixture fix is proven by the real bridge's one-pass run
    const r = await run({}, ["config"]);
    const failed = r.checks.filter((c) => c.id.startsWith("C5.") && c.status === "fail").map((c) => `${c.id}: ${c.asserted}`);
    assert.deepEqual(failed, []);
    assert.equal(status(r, "C5.portal_key_rotation"), "pass", r.checks.find((c) => c.id === "C5.portal_key_rotation")?.asserted);
  });

  it("--no-test-roots: a strict bridge refuses the fake Portal's enrolment (boot fails with the pinned-roots hint); a 0.1.11 bridge runs with keyset not_run", async () => {
    const strict = await run({}, ["keyset"], {}, { testRoots: false, bootTimeoutMs: 3000 });
    assert.equal(strict.ok, false);
    assert.equal(status(strict, "B20.kss_enrolled"), "fail");
    assert.match(strict.notes.join(" "), /bridge build pins Portal Root Keys: run with test roots .*TBCONF_PORTAL_ROOT_KEYS.*--no-test-roots given/);
    const old = await run({ keysetTransitional: true }, ["keyset"], {}, { testRoots: false, keysetRequired: false });
    for (const id of KEYSET_IDS) assert.equal(status(old, id), "not_run", id);
    assert.match(old.checks.find((c) => c.id === "B20.kss_enrolled")?.asserted ?? "", /--no-test-roots: the bridge pins its build's Portal Root Keys/);
  });

  it("strict by default: a 0.1.11 bridge (first enrolment without a statement accepted) fails B20.kss_enrol_missing; --keyset-transitional makes it not_applicable", async () => {
    const lax = await run({ keysetTransitional: true }, ["keyset"]);
    assert.equal(status(lax, "B20.kss_enrol_missing"), "fail", lax.checks.find((c) => c.id === "B20.kss_enrol_missing")?.asserted);
    const tr = await run({ keysetTransitional: true }, ["keyset"], {}, { keysetRequired: false });
    for (const id of KEYSET_IDS) assert.equal(status(tr, id), "pass", `${id}: ${tr.checks.find((c) => c.id === id)?.asserted}`);
    const na = tr.checks.find((c) => c.id === "B20.kss_enrol_missing");
    assert.equal(na?.status, "not_applicable");
    assert.match(na?.asserted ?? "", /--keyset-transitional: 0\.1\.11 transition rules/);
  });

  it("fails a bridge that accepts a re-enrolment without a valid statement (C63a)", async () => {
    const r = await run({ acceptStrippedReenrol: true }, ["keyset"]);
    assert.equal(status(r, "B20.kss_reenrol_missing"), "fail", r.checks.find((c) => c.id === "B20.kss_reenrol_missing")?.asserted);
  });

  it("fails a bridge that ignores portalKeySet (pre-v0.1.11 rule)", async () => {
    const r = await run({ ignoreKeySet: true }, ["keyset"]);
    for (const id of ["B20.portal_keys_ignored", "B20.kss_unknown_root", "B20.kss_rollback", "B20.kss_missing", "B20.kss_compromise"]) assert.equal(status(r, id), "fail", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
  });

  it("spec 0.1.13 spine (spine013): a correct bridge passes every B22–B24 check", async () => {
    const r = await run({}, ["spine013"]);
    for (const id of SPINE013_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.equal(status(r, "B6.order"), "not_run", "an older bridge deselects spine013 the same way");
  });

  it("real SDK app behind the bridge (C91, group real_app): a correct bridge passes every B25 check against @opt2-tealbrick/miniapp-sdk", async () => {
    const r = await run({}, ["real_app"]);
    for (const id of REAL_APP_IDS) assert.equal(status(r, id), "pass", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
  });

  it("QA S1 regression (C91): a bridge that signs catalog proofs with `in` fails B25.real_catalog_search (real SDK) and B16.search_uses_catalog (fake app)", async () => {
    const r = await run({ catalogWithIn: true }, ["real_app", "dynamic"]);
    for (const id of ["B25.real_catalog_search", "B16.search_uses_catalog"]) assert.equal(status(r, id), "fail", `${id}: ${r.checks.find((c) => c.id === id)?.asserted}`);
    assert.match(r.checks.find((c) => c.id === "B25.real_catalog_search")?.asserted ?? "", /call_proof_invalid/);
    assert.equal(status(r, "B25.real_op_call"), "pass", "only the catalog binding is broken");
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
    ["routes to any internalUrl (BSD-07)", { noAddressCheck: true }, ["addresses"], ["B21.internal_url_external", "B21.own_infra_flag_required", "B21.neighbour_url_refused"]],
    // spec 0.1.13 (spine013)
    ["stops the before chain at a hold (a later refuse cannot win)", { holdStopsChain: true }, ["spine013"], ["B22.hold_verdict"]],
    ["sends the hold verdict outside the signed proof", { hvOutsideProof: true }, ["spine013"], ["B22.hold_verdict", "B22.hv_tamper"]],
    ["caches a hold verdict instead of re-running the chain on the retry", { cacheHoldVerdict: true }, ["spine013"], ["B22.hold_retry_refused"]],
    ["ignores _meta tealbrick/onBehalfOf", { noOnBehalfOf: true }, ["spine013"], ["B23.on_behalf_of"]],
    ["lets a context hook write tb.* keys", { allowTbContext: true }, ["spine013"], ["B23.reserved_tb_namespace"]],
    ["skips the hooks for app-initiated calls", { appCallsSkipHooks: true }, ["spine013"], ["B24.app_initiated"]],
    ["does not gate companion calls by the grant's workflow", { companionNoWfCheck: true }, ["spine013"], ["B24.no_grant"]],
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
