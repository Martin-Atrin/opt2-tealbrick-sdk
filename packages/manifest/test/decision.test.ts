// decision.ts: gate() step order (CORE §7, I4) and authorize() order (CORE §7, I1, C8, SDK-API §2).
import assert from "node:assert/strict";
import { test } from "node:test";
import type { GrantClaims } from "@opt2-tealbrick/spec/credentials";
import type { AuthorizeInput, GateInput, OperationView } from "@opt2-tealbrick/spec/sdk";
import { authorize, gate } from "../src/decision.ts";
import type { Issue } from "../src/jws.ts";
import { signGrant } from "../src/tokens.ts";
import { world } from "./fixtures.ts";

const op = (over: Partial<Extract<OperationView, { standard: false }>> = {}): OperationView => ({
  standard: false,
  id: "notes_search",
  title: "Search",
  description: "Search notes",
  crud: ["read"],
  effect: "read",
  scopeType: "area",
  idempotency: "none",
  receipt: true,
  audience: "agent",
  ...over,
});
const holdStatus: OperationView = { standard: true, id: "tb.hold_status", title: "Hold status", crud: ["read"], effect: "read", audience: "agent", idempotency: "none", receipt: false };

async function setup(grant: Partial<Issue<GrantClaims>> = {}) {
  const w = await world();
  const token = await signGrant(w.grantClaims(grant), w.portal);
  const bad = await signGrant(w.grantClaims(grant), w.stranger);
  const gateIn = (over: Partial<GateInput> = {}): GateInput => ({
    paused: { workspace: false, agent: false, connection: false, instance: false },
    grant: token,
    trust: w.trust,
    op: op(),
    declaredScopeTypes: ["area"],
    ...over,
  });
  const authIn = (over: Partial<AuthorizeInput> = {}): AuthorizeInput => ({
    paused: { workspace: false, instance: false, agent: false },
    grant: token,
    trust: w.trust,
    op: { id: "notes_search", crud: ["read"], effect: "read", scopeType: "area" },
    access: { level: "read", crud: ["read"] },
    usage: {},
    approval: "none",
    holdVerdict: null,
    ...over,
  });
  return { w, token, bad, gateIn, authIn };
}

test("gate: pass, and each step refuses in order", async () => {
  const { gateIn, bad } = await setup();
  assert.deepEqual(gate(gateIn()), { decision: "pass", reason: "pass" });
  // (1) paused wins over everything, including an invalid grant
  for (const k of ["workspace", "agent", "connection", "instance"] as const) {
    const paused = { workspace: false, agent: false, connection: false, instance: false, [k]: true };
    assert.deepEqual(gate(gateIn({ paused, grant: bad })), { decision: "refuse", reason: "paused" }, k);
  }
  // (2) grant invalid wins over CRUD
  assert.deepEqual(gate(gateIn({ grant: bad, op: op({ crud: ["delete"] }) })), { decision: "refuse", reason: "grant_invalid" });
  // (3) CRUD ceiling, audience, scope type
  assert.equal(gate(gateIn({ op: op({ crud: ["read", "delete"] }) })).reason, "crud_exceeds_grant");
  assert.equal(gate(gateIn({ op: op({ audience: "person" }) })).reason, "audience_not_agent");
  assert.equal(gate(gateIn({ op: op({ scopeType: "folder" }) })).reason, "scope_type_unknown");
  assert.equal(gate(gateIn({ op: op({ scopeType: undefined }), declaredScopeTypes: [] })).decision, "pass");
  // (3) before (4): CRUD failure reported even when not in wf
  assert.equal(gate(gateIn({ op: op({ crud: ["delete"] }) })).reason, "crud_exceeds_grant");
});

test("gate: Bound workflow (4)", async () => {
  const { gateIn } = await setup({ mode: "bound", wf: ["notes_search"] });
  assert.equal(gate(gateIn()).decision, "pass");
  assert.equal(gate(gateIn({ op: op({ id: "notes_list" }) })).reason, "not_in_workflow");
});

test("gate: tb.hold_status passes with any valid grant (I4), never with an invalid one", async () => {
  const { gateIn, bad } = await setup({ crud: ["create"], mode: "bound", wf: [] });
  assert.equal(gate(gateIn({ op: holdStatus })).decision, "pass");
  assert.equal(gate(gateIn({ op: holdStatus, grant: bad })).reason, "grant_invalid");
  assert.equal(gate(gateIn({ op: holdStatus, paused: { workspace: true, agent: false, connection: false, instance: false } })).reason, "paused");
});

test("gate: expired / revoked grants carry their codes", async () => {
  const { w, gateIn, token } = await setup();
  assert.equal(gate(gateIn({ trust: { ...w.trust, now: w.trust.now + 43200 + 30 } })).reason, "grant_expired");
  const jti = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString()).jti;
  assert.equal(gate(gateIn({ trust: { ...w.trust, revokedJtis: new Set([jti]) } })).reason, "grant_revoked");
});

test("authorize: run, pause (0), grant (1), scope (2)", async () => {
  const { authIn, bad } = await setup();
  assert.deepEqual(authorize(authIn()), { decision: "run", reason: "run" });
  for (const k of ["workspace", "instance", "agent"] as const) {
    const paused = { workspace: false, instance: false, agent: false, [k]: true };
    assert.deepEqual(authorize(authIn({ paused, grant: bad })), { decision: "refuse", reason: "paused" }, k);
  }
  // paused also blocks an approved held action (pause matrix: release refused while paused)
  assert.equal(authorize(authIn({ paused: { workspace: true, instance: false, agent: false }, approval: "approved" })).reason, "paused");
  assert.deepEqual(authorize(authIn({ grant: bad })), { decision: "refuse", reason: "grant_invalid" });
  // op.crud ⊄ grant.crud
  assert.equal(authorize(authIn({ op: { id: "notes_delete", crud: ["delete"], effect: "destructive", scopeType: "area" }, access: { level: "all", crud: ["read", "delete"] } })).reason, "scope_denied");
  // op.crud ⊄ access.crud
  assert.equal(authorize(authIn({ op: { id: "notes_add", crud: ["create"], effect: "write", scopeType: "area" } })).reason, "scope_denied");
  // scopeType but no access row
  assert.equal(authorize(authIn({ access: null })).reason, "scope_denied");
  // no scopeType: access is not consulted
  assert.equal(authorize(authIn({ op: { id: "ping", crud: ["read"], effect: "read" }, access: null })).decision, "run");
  // grant failure before scope check
  assert.equal(authorize(authIn({ grant: bad, access: null })).reason, "grant_invalid");
});

test("authorize: holds (3) — money always, held family, approval once per call", async () => {
  const { authIn } = await setup({ crud: ["read", "create", "update"], held: ["first_contact"] });
  const write = { level: "rw", crud: ["read", "create", "update"] as ("read" | "create" | "update")[] };
  const money = { id: "pay", crud: ["create"] as "create"[], effect: "money" as const, scopeType: "area" };
  assert.deepEqual(authorize(authIn({ op: money, access: write })), { decision: "hold", reason: "held_money", holdFamily: "money" });
  assert.deepEqual(authorize(authIn({ op: money, access: write, approval: "approved" })), { decision: "run", reason: "approved" });
  const contact = { id: "send", crud: ["create"] as "create"[], effect: "outward" as const, holdFamily: "first_contact" as const, scopeType: "area" };
  assert.deepEqual(authorize(authIn({ op: contact, access: write })), { decision: "hold", reason: "held_family", holdFamily: "first_contact" });
  assert.equal(authorize(authIn({ op: { ...contact, holdFamily: "live_call" }, access: write })).decision, "run");
  assert.equal(authorize(authIn({ op: contact, access: write, approval: "approved" })).decision, "run");
  // scope refusal precedes holds
  assert.equal(authorize(authIn({ op: money, access: { level: "r", crud: ["read"] } })).reason, "scope_denied");
});

test("authorize: Free caps (4) after holds; money has no cap", async () => {
  const { authIn } = await setup({ crud: ["read", "create"], held: ["first_contact"], caps: { write: { max: 5, per: "hour" }, outward: { max: 0, per: "day" } } });
  const access = { level: "rw", crud: ["read", "create"] as ("read" | "create")[] };
  const add = { id: "notes_add", crud: ["create"] as "create"[], effect: "write" as const, scopeType: "area" };
  assert.equal(authorize(authIn({ op: add, access, usage: { write: 4 } })).decision, "run");
  assert.deepEqual(authorize(authIn({ op: add, access, usage: { write: 5 } })), { decision: "hold", reason: "caps_exceeded", holdFamily: "caps" });
  assert.equal(authorize(authIn({ op: add, access, usage: { write: 5 }, approval: "approved" })).decision, "run");
  // max 0 holds the first call; usage of another effect does not count
  const send = { id: "send", crud: ["create"] as "create"[], effect: "outward" as const, scopeType: "area" };
  assert.equal(authorize(authIn({ op: send, access, usage: { write: 100 } })).reason, "caps_exceeded");
  // destructive has no cap in this grant → run
  assert.equal(authorize(authIn({ op: { ...add, effect: "destructive" }, access, usage: { destructive: 999 } })).decision, "run");
  // held family wins over caps
  assert.equal(authorize(authIn({ op: { ...send, holdFamily: "first_contact" }, access, usage: { outward: 9 } })).holdFamily, "first_contact");
});

test("authorize: tb.hold_status skips the scope step (I4)", async () => {
  const { authIn, bad } = await setup({ crud: ["create"] });
  const hs = { id: "tb.hold_status", crud: ["read"] as "read"[], effect: "read" as const };
  assert.equal(authorize(authIn({ op: hs, access: null })).decision, "run");
  assert.equal(authorize(authIn({ op: hs, access: null, grant: bad })).reason, "grant_invalid");
});

test("authorize v0.1.13 (G1): a hook hold verdict holds after scope; approval runs once; scope refusal wins", async () => {
  const { authIn } = await setup({ crud: ["read", "create"] });
  const access = { level: "rw", crud: ["read", "create"] as ("read" | "create")[] };
  const add = { id: "notes_add", crud: ["create"] as "create"[], effect: "write" as const, scopeType: "area" };
  const hv = { family: "policy" as const, reason: "needs owner review", by: "rules/rules_gate" };
  assert.deepEqual(authorize(authIn({ op: add, access, holdVerdict: hv })), { decision: "hold", reason: "held_by_hook", holdFamily: "policy", heldBy: "rules/rules_gate" });
  assert.equal(authorize(authIn({ op: add, access, holdVerdict: hv, approval: "approved" })).decision, "run");
  assert.equal(authorize(authIn({ op: add, access: { level: "r", crud: ["read"] }, holdVerdict: hv })).reason, "scope_denied");
  // a read op is held too when a hook says so
  assert.equal(authorize(authIn({ holdVerdict: { ...hv, family: "first_contact" } })).holdFamily, "first_contact");
});

test("gate + authorize v0.1.13 (G4): tb.holds_pending needs only a valid grant (I4)", async () => {
  const { authIn, gateIn, bad } = await setup({ crud: ["create"], mode: "bound", wf: ["notes_add"] });
  const hp = { id: "tb.holds_pending", crud: ["read"] as "read"[], effect: "read" as const };
  assert.equal(authorize(authIn({ op: hp, access: null })).decision, "run");
  const view = { standard: true as const, id: "tb.holds_pending" as const, title: "Pending approvals", crud: ["read"] as "read"[], effect: "read" as const, audience: "agent" as const, idempotency: "none" as const, receipt: false as const };
  assert.equal(gate(gateIn({ op: view })).decision, "pass");
  assert.equal(gate(gateIn({ op: view, grant: bad })).reason, "grant_invalid");
});
