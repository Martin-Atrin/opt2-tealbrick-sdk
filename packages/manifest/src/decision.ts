// Decision functions (CORE §7, C8, C10, I1, I4; SDK-API §2): bridge `gate()` and app `authorize()`. Pure, synchronous.
import type { CrudAction } from "@opt2-tealbrick/spec/manifest";
import type { AuthorizeInput, Decision, GateDecision, GateInput } from "@opt2-tealbrick/spec/sdk";
import { verifyGrant } from "./tokens.ts";

export type { AuthorizeInput, Decision, GateDecision, GateInput };

/** The one standard agent op that needs only a valid grant (CORE §7, I4). */
export const HOLD_STATUS_OP = "tb.hold_status";
/** v0.1.13 (G4): like `tb.hold_status`, a valid grant suffices (an agent sees only its own holds; the SDK filters). */
export const HOLDS_PENDING_OP = "tb.holds_pending";
const ANY_GRANT_OPS: ReadonlySet<string> = new Set([HOLD_STATUS_OP, HOLDS_PENDING_OP]);
/** `reason` values; refusal reasons are the wire error codes (BRIDGE / SDK-API). Grant failures use the verifyGrant code. */
export const DECISION_REASON = {
  paused: "paused",
  crudExceedsGrant: "crud_exceeds_grant",
  audienceNotAgent: "audience_not_agent",
  scopeTypeUnknown: "scope_type_unknown",
  notInWorkflow: "not_in_workflow",
  scopeDenied: "scope_denied",
  heldMoney: "held_money",
  /** v0.1.13 (G1): a before hook's attested hold verdict */
  heldByHook: "held_by_hook",
  heldFamily: "held_family",
  capsExceeded: "caps_exceeded",
  pass: "pass",
  approved: "approved",
  run: "run",
} as const;

const subset = (a: readonly CrudAction[], b: readonly CrudAction[]) => a.every((x) => b.includes(x));

/**
 * v0.1.21 (C111a, Bridge request, L1): THE workflow rule — `op` is allowed by the grant's `wf` iff the grant is Bound or
 * its `wf` is non-empty, and `wf` lists the op; otherwise (Free with an empty `wf`) every op passes this step. gate()
 * step (4) and tools/list use this one function.
 */
export function opInGrantWorkflow(claims: { mode: string; wf: readonly string[] }, opId: string, listing?: string): boolean {
  // v0.1.21 (spec 0.1.43, LR-1 C234): a `listing: "workflow"` op passes ONLY when the grant's wf names it, in any mode
  if (listing === "workflow") return claims.wf.includes(opId);
  return !(claims.mode === "bound" || claims.wf.length > 0) || claims.wf.includes(opId);
}
const listingOf = (op: GateInput["op"]): string | undefined => (op.standard ? undefined : op.listing);

/**
 * v0.1.21 (L1): THE tools/list rule — the static part of gate() steps (3)–(4) for one op and one verified grant: the
 * standard ops that need only a valid grant are listed; otherwise the op is agent-audience, `op.crud ⊆ grant.crud`, its
 * `scopeType` is declared by the target manifest, and opInGrantWorkflow holds. Pause and validity are the caller's
 * (a paused or invalid grant lists nothing). A tool listed here passes gate() steps (3)–(4) when called.
 */
export function opVisibleToGrant(op: GateInput["op"], claims: { mode: string; wf: readonly string[]; crud: readonly CrudAction[] }, declaredScopeTypes: readonly string[]): boolean {
  if (op.standard && ANY_GRANT_OPS.has(op.id)) return true;
  if (!subset(op.crud, claims.crud) || op.audience !== "agent") return false;
  const scopeType = op.standard ? undefined : op.scopeType;
  if (scopeType !== undefined && !declaredScopeTypes.includes(scopeType)) return false;
  return opInGrantWorkflow(claims, op.id, listingOf(op));
}

/**
 * Bridge, every routed call: (1) paused (workspace, agent, connection, instance) → refuse; (2) `verifyGrant` → refuse
 * with its code; (3) `op.crud ⊆ grant.crud`, agent audience, `scopeType` declared by the target manifest; (4) Bound or non-empty `wf`:
 * `op.id ∈ grant.wf` — v0.1.19 (C111a): also for a Free grant whose `wf` is non-empty. `tb.hold_status` and
 * `tb.holds_pending` need only a valid grant (I4): they skip (3) and (4).
 */
export function gate(input: GateInput): GateDecision {
  const p = input.paused;
  if (p.workspace || p.agent || p.connection || p.instance) return { decision: "refuse", reason: DECISION_REASON.paused };
  const g = verifyGrant(input.grant, input.trust);
  if (!g.ok) return { decision: "refuse", reason: g.code };
  const op = input.op;
  if (op.standard && ANY_GRANT_OPS.has(op.id)) return { decision: "pass", reason: DECISION_REASON.pass };
  if (!subset(op.crud, g.claims.crud)) return { decision: "refuse", reason: DECISION_REASON.crudExceedsGrant };
  if (op.audience !== "agent") return { decision: "refuse", reason: DECISION_REASON.audienceNotAgent };
  const scopeType = op.standard ? undefined : op.scopeType;
  if (scopeType !== undefined && !input.declaredScopeTypes.includes(scopeType)) return { decision: "refuse", reason: DECISION_REASON.scopeTypeUnknown };
  // v0.1.19 (C111a): `wf`, when non-empty, limits ops in ANY mode (bound grants always carry a non-empty wf)
  if (!opInGrantWorkflow(g.claims, op.id, listingOf(op))) return { decision: "refuse", reason: DECISION_REASON.notInWorkflow };
  return { decision: "pass", reason: DECISION_REASON.pass };
}

/**
 * App SDK, before executing: (0) slice pause (workspace, instance, calling agent) → refuse `paused`; (1) `verifyGrant`
 * → refuse with its code; (2) `op.crud ⊆ grant.crud`, and `⊆ access.crud` when the op has a `scopeType` (no access →
 * refuse) → else `scope_denied`; (2b, v0.1.13 G1) a hook hold verdict (proof `hv`) → hold with its family, `heldBy`;
 * (3) effect `money` (always) or `holdFamily ∈ grant.held` → hold; (4) Free caps:
 * `usage[effect] ≥ caps[effect].max` → hold `caps` (v0.1.19 C111a: in ANY mode, whenever `caps` has the effect); (5) run. An approved hold for this exact call (C8: once per call)
 * skips (2b), (3) and (4). `tb.hold_status` and `tb.holds_pending` skip (2) (I4).
 */
export function authorize(input: AuthorizeInput): Decision {
  const p = input.paused;
  if (p.workspace || p.instance || p.agent) return { decision: "refuse", reason: DECISION_REASON.paused };
  const g = verifyGrant(input.grant, input.trust);
  if (!g.ok) return { decision: "refuse", reason: g.code };
  const { op } = input;
  const grant = g.claims;
  if (!ANY_GRANT_OPS.has(op.id)) {
    if (!subset(op.crud, grant.crud)) return { decision: "refuse", reason: DECISION_REASON.scopeDenied };
    if (op.scopeType !== undefined && (input.access === null || !subset(op.crud, input.access.crud))) {
      return { decision: "refuse", reason: DECISION_REASON.scopeDenied };
    }
  }
  if (input.approval === "approved") return { decision: "run", reason: DECISION_REASON.approved };
  // v0.1.13 (G1): the bridge-attested before-hook verdict (proof `hv`) holds after the scope checks
  const hv = input.holdVerdict ?? null;
  if (hv) return { decision: "hold", reason: DECISION_REASON.heldByHook, holdFamily: hv.family, heldBy: hv.by };
  if (op.effect === "money") return { decision: "hold", reason: DECISION_REASON.heldMoney, holdFamily: "money" };
  if (op.holdFamily !== undefined && grant.held.includes(op.holdFamily)) return { decision: "hold", reason: DECISION_REASON.heldFamily, holdFamily: op.holdFamily };
  if (op.effect === "write" || op.effect === "outward" || op.effect === "destructive") {
    const cap = grant.caps[op.effect];
    if (cap && (input.usage[op.effect] ?? 0) >= cap.max) return { decision: "hold", reason: DECISION_REASON.capsExceeded, holdFamily: "caps" };
  }
  return { decision: "run", reason: DECISION_REASON.run };
}
