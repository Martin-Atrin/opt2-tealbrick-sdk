// Operation pipeline (SDK-API §3.2, §4, §6): bridge-forwarded agent/app calls on /tb/v1/ops/:op and person calls on
// /a/<product>/tb/v1/ops/:op. Order on /tb/v1/ops: call proof → verifyGrant → op/audience → input schema → idempotency
// → authorize() (step 0 = slice pause) → handler. Holds and receipts are rows of the one receipts table.
import type { IncomingMessage, ServerResponse } from "node:http";
import { authorize, DECISION_REASON, digest, EFFECTS, HOLDS_PENDING_OP, opInGrantWorkflow, validateAgainstSchema, validateInput, verifyCallProof, verifyGrant } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS, type OpCallBody, type OpResult } from "@opt2-tealbrick/spec/bridge";
import type { AgentId, CallId, InstanceId, PersonId, Sha256Digest } from "@opt2-tealbrick/spec/credentials";
import type { CrudAction, DynamicResolution, Effect, HoldFamily, Operation } from "@opt2-tealbrick/spec/manifest";
import type {
  Caller,
  Decision,
  HandlerSpec,
  HoldDecideInput,
  HoldsPendingItem,
  HoldsPendingOutput,
  Json,
  OpContext,
  OperationView,
  PersonPrincipal,
  Receipt,
  ReceiptStatus,
  ScopeAccessView,
  StandardOpId,
  VerifiedGrant,
} from "@opt2-tealbrick/spec/sdk";
import type { ContextExtras, SdkHookContext, SdkOpContext } from "./context.ts";
import { TbError } from "./errors.ts";
import { header, readJson, requestId, sendError, sendJson } from "./http.ts";
import { type ClaimedJob, jobsView, type OpFireOutcome, unsealGrant } from "./jobs.ts";
import { HOLD_TTL_MS, type NewReceipt } from "./receipts.ts";
import type { Runtime } from "./runtime.ts";

export const OP_TIMEOUT_MS = 30_000;
const SUMMARY_MAX = 280;
const META_MAX_BYTES = 4096;
const HOLD_VIEW_MAX = 16_000;
const IDEM_KEY_RE = /^[\x21-\x7e]{8,128}$/;
const IDEM_PURPOSE = "idempotency";

type ManifestOp = Operation & { standard: false };
interface EffectiveOp {
  id: string;
  crud: CrudAction[];
  effect: Effect;
  holdFamily?: HoldFamily;
  scopeType?: string;
}

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
const iso = (ms: number) => new Date(ms).toISOString();

/**
 * Unverified read of a compact JWS payload. Used ONLY to pick binding values (the grant `jti`/`sub` that the call proof
 * must name, the companion grant for a product); every token is verified by `@opt2-tealbrick/manifest` before trust.
 */
export function peekClaims(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part || part.length > 16384) return null;
  try {
    const v = JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
    return isObj(v) ? v : null;
  } catch {
    return null;
  }
}

export function handlerSpec(rt: Runtime, opId: string): HandlerSpec | null {
  const h = rt.def.handlers[opId];
  if (!h) return null;
  return typeof h === "function" ? { run: h } : h;
}

export function clampSummary(s: string): string {
  return s.length <= SUMMARY_MAX ? s : `${s.slice(0, SUMMARY_MAX - 1)}…`;
}

/** Body of the bridge→app op call (CORE §8). */
function parseOpBody(body: unknown): { input: Json; context: Record<string, Json>; idempotencyKey: string | null } {
  if (!isObj(body) || !("input" in body)) throw new TbError("input_invalid", "body must be { input, context, idempotencyKey? }", 400);
  const ctx = body.context ?? {};
  if (!isObj(ctx)) throw new TbError("input_invalid", "context must be an object", 400);
  const key = body.idempotencyKey;
  if (key !== undefined && key !== null && typeof key !== "string") throw new TbError("idempotency_key_invalid", "idempotencyKey must be a string", 400);
  return { input: body.input as Json, context: ctx as Record<string, Json>, idempotencyKey: typeof key === "string" ? key : null };
}

function idempotencyKeyFor(op: { idempotency: string }, key: string | null): string | null {
  if (op.idempotency === "none") return null;
  if (key === null) {
    if (op.idempotency === "required") throw new TbError("idempotency_key_required", "this operation requires an idempotency key", 400);
    return null;
  }
  if (!IDEM_KEY_RE.test(key)) throw new TbError("idempotency_key_invalid", "idempotency key must be 8..128 printable characters", 400);
  return key;
}

/** Collects `ctx.receipt` values set by the handler. */
export function receiptHelpers(): { helpers: OpContext["receipt"]; summary: string | null; meta: Json | undefined } {
  const state: { summary: string | null; meta: Json | undefined } = { summary: null, meta: undefined };
  return {
    get summary() {
      return state.summary;
    },
    get meta() {
      return state.meta;
    },
    helpers: {
      summary(text) {
        state.summary = clampSummary(String(text));
      },
      meta(value) {
        if (Buffer.byteLength(JSON.stringify(value ?? null)) > META_MAX_BYTES) throw new TbError("receipt_meta_too_large", "receipt meta must be ≤ 4 KB", 500);
        state.meta = value;
      },
    },
  };
}

export function buildContext(
  rt: Runtime,
  op: OperationView,
  caller: Caller,
  grant: VerifiedGrant | null,
  scope: ScopeAccessView,
  callId: CallId | null,
  idempotencyKey: string | null,
  context: Record<string, Json>,
  receipt: OpContext["receipt"],
  signal: AbortSignal,
  extras: ContextExtras = rt.extras(),
): SdkOpContext {
  return {
    ...extras,
    caller,
    grant,
    op,
    scope,
    callId,
    idempotencyKey,
    context,
    receipt,
    getKey: (name) => rt.keys.getKey(name),
    callApp: (product, opId, input, opts) => rt.callApp(product, opId, input, { idempotencyKey: opts?.idempotencyKey, parentCall: callId }),
    callServiceHelper: (serviceId, path, body) => rt.callServiceHelper(serviceId, path, body),
    db: rt.appDb,
    log: rt.log,
    signal,
    // v0.1.13 (C86)
    statusChanged: () => rt.statusChanged(),
    ownerLink: (path) => rt.ownerLink(path),
    ownerLinkFor: (product: string, path: string) => rt.ownerLinkFor(product, path),
    // v0.1.14 addition (SPEC-GAP: InstanceSlice.companionTargets)
    companionTargets: () => rt.companionTargets(),
    appsPolicy: () => rt.appsPolicy(),
    agentScopeRequest: (agt: string) => rt.agentScopeRequest(agt),
    // v0.1.21 (R1, SDK-1/SDK-2): ctx.jobs, ctx.schedule (fire-time authorize with THIS caller), ctx.paused
    ...jobsView(rt, rt.jobs, { caller, grant: grant ? { token: grant.token, iat: grant.claims.iat } : null }),
  };
}

/** AbortSignal for one handler run: client disconnect or 30 s op timeout (SDK-API §3.1). */
function opSignal(req: IncomingMessage, res: ServerResponse): { signal: AbortSignal; done(): void } {
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(new TbError("app_timeout", "operation timed out", 504)), OP_TIMEOUT_MS);
  timer.unref();
  const onClose = () => {
    if (!res.writableEnded) ac.abort(new TbError("client_closed", "client disconnected", 499));
  };
  req.socket.once("close", onClose);
  return {
    signal: ac.signal,
    done() {
      clearTimeout(timer);
      req.socket.off("close", onClose);
    },
  };
}

export async function runHandler(rt: Runtime, op: OperationView, input: Json, ctx: OpContext, dynamicTool: { tool: string; args: Record<string, unknown> } | null): Promise<Json> {
  const run = async (): Promise<Json> => {
    if (dynamicTool) {
      const d = rt.def.dynamic?.[op.id];
      if (!d) throw new TbError("dynamic_resolve_failed", "no dynamic handler", 500);
      return d.call(dynamicTool.tool, dynamicTool.args, ctx);
    }
    const spec = handlerSpec(rt, op.id);
    if (!spec) throw new TbError("unknown_tool", "no handler for this operation", 404);
    return spec.run(input, ctx);
  };
  const aborted = new Promise<never>((_, reject) => {
    if (ctx.signal.aborted) reject(ctx.signal.reason);
    ctx.signal.addEventListener("abort", () => reject(ctx.signal.reason), { once: true });
  });
  aborted.catch(() => {});
  const output = await Promise.race([run(), aborted]);
  if (output === undefined) throw new TbError("output_invalid", "handler returned no output", 500);
  if (!op.standard && !op.dynamic && op.output) {
    const v = validateAgainstSchema(op.output, output);
    if (!v.ok) throw new TbError("output_invalid", "handler output does not match the manifest output schema", 500, { errors: v.errors });
  }
  return output;
}

function toTbError(e: unknown, rt: Runtime): TbError {
  if (e instanceof TbError) return e;
  rt.log.error("handler failed", { error: e instanceof Error ? e.message : "unknown" });
  return new TbError("app_error", "the operation failed", 500);
}

/** Dynamic ops (MANIFEST §5.3): crud/effect/holdFamily come from the app's own `resolve`, never from the agent. */
async function resolveDynamic(rt: Runtime, op: ManifestOp, input: Json): Promise<{ eff: EffectiveOp; tool: string; args: Record<string, unknown> }> {
  if (!isObj(input) || typeof input.tool !== "string" || !isObj(input.arguments)) throw new TbError("input_invalid", "dynamic call input must be { tool, arguments }", 400);
  const d = rt.def.dynamic?.[op.id];
  const hctx: SdkHookContext = { log: rt.log, db: rt.appDb, getKey: (n) => rt.keys.getKey(n), signal: AbortSignal.timeout(2000), secrets: rt.secretsStore };
  const res: DynamicResolution | null = d ? await d.resolve(input.tool, hctx) : null;
  if (!res) throw new TbError("dynamic_resolve_failed", "unknown dynamic tool", 404);
  if (!withinCeiling(op, res)) throw new TbError("dynamic_ceiling_exceeded", "resolved tool exceeds the operation's ceiling", 403);
  return {
    eff: { id: op.id, crud: res.crud, effect: res.effect, ...(res.holdFamily ? { holdFamily: res.holdFamily } : {}), ...(op.scopeType ? { scopeType: op.scopeType } : {}) },
    tool: input.tool,
    args: input.arguments,
  };
}

export function withinCeiling(op: Operation, r: { crud: CrudAction[]; effect: Effect }): boolean {
  const c = op.dynamic;
  if (!c) return false;
  return r.crud.length > 0 && r.crud.every((x) => c.crudCeiling.includes(x)) && EFFECTS.indexOf(r.effect) <= EFFECTS.indexOf(c.effectCeiling);
}

function grantFailStatus(code: string): number {
  return code.startsWith("grant_") ? 401 : 403;
}

// ── POST /tb/v1/ops/:op ──────────────────────────────────────────────────────
export async function handleAgentOp(rt: Runtime, req: IncomingMessage, res: ServerResponse, opId: string): Promise<void> {
  const rid = requestId();
  try {
    if (rt.cfg.standalone) throw new TbError("no_bridge", "app-alone mode serves persons only", 503);
    const now = Date.now();
    const body = parseOpBody(await readJson(req));
    if (rt.trust.stale(now)) throw new TbError("slice_stale", "instance slice missing or older than 12 h", 503);
    const trust = rt.trust.context(now);
    if (!trust) throw new TbError("slice_stale", "no instance slice", 503);
    const auth = header(req, "authorization") ?? "";
    const grantToken = auth.startsWith("Bearer ") ? auth.slice(7).trim() : "";
    const proofToken = header(req, BRIDGE_HEADERS.callProof) ?? "";
    const inputDigest = digest(body.input);
    const contextDigest = digest(body.context);
    const peek = peekClaims(grantToken);
    const proof = verifyCallProof(
      proofToken,
      trust,
      { op: opId, inputDigest, contextDigest, grantJti: typeof peek?.jti === "string" ? peek.jti : "", grantSub: typeof peek?.sub === "string" ? peek.sub : "" },
      rt.replay,
    );
    if (!proof.ok) throw new TbError("call_proof_invalid", "call proof missing or not valid", 401);
    const g = verifyGrant(grantToken, trust);
    if (!g.ok) throw new TbError(g.code, "grant not valid", grantFailStatus(g.code));
    // v0.1.21: the caller's newest verified grant replaces the stored one of its pending scheduled ops (owner narrowing,
    // revocation by jti and a re-minted grant all reach the fire-time authorize)
    rt.noteGrant(g.caller.id, grantToken, g.claims.iat);
    const op = rt.ops.get(opId);
    if (!op) throw new TbError("unknown_tool", `unknown operation ${opId}`, 404);
    if (op.audience !== "agent") throw new TbError("audience_not_agent", "operation is not agent-audience", 403);
    const callerId = g.caller.id as AgentId | InstanceId;
    const sliceAgent = g.caller.type === "agent" ? rt.trust.agent(callerId) : undefined;
    const caller: Caller = {
      type: g.caller.type,
      id: callerId,
      // v0.1.14 (C102): app callers are named from slice companionCallers (verified grant sub), fallback the instance id
      name: sliceAgent?.name ?? (g.caller.type === "app" ? (rt.trust.companionCallers().find((x) => x.ins === callerId)?.name ?? callerId) : callerId),
      mode: g.caller.type === "agent" ? (sliceAgent?.mode ?? g.claims.mode) : null,
    };
    const callId = proof.claims.call;

    // tb.hold_status: valid grant suffices (I4); only the caller's own holds; no receipt.
    if (op.standard && op.id === "tb.hold_status") {
      const v = validateInput(op, body.input);
      if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
      const hs = rt.receipts.holdStatusSync(callerId, String((body.input as { holdId: string }).holdId));
      if (!hs) throw new TbError("hold_not_found", "no such hold for this caller", 404);
      const output: Json = {
        status: hs.status,
        expiresAt: hs.expiresAt === null ? null : iso(hs.expiresAt),
        ...(hs.decidedAt !== null ? { decidedAt: iso(hs.decidedAt) } : {}),
        // v0.1.13 clarification (additive): why it was held — hook verdict reason or SDK hold reason code only (C90)
        family: hs.family,
        reason: hs.reason,
      };
      return sendJson(res, 200, { status: "ok", output } satisfies OpResult);
    }
    // v0.1.13 (G4) tb.holds_pending: valid grant suffices (I4); no receipt.
    if (op.standard && op.id === HOLDS_PENDING_OP) {
      const v = validateInput(op, body.input);
      if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
      const output = holdsPending(rt, g.caller.type, callerId, g.claims.wf, body.input as { limit?: number; cursor?: string }, now);
      return sendJson(res, 200, { status: "ok", output: output as unknown as Json } satisfies OpResult);
    }
    if (op.standard) throw new TbError("audience_not_agent", "operation is not agent-audience", 403);

    // effective op (dynamic → resolved values) and input schema
    let eff: EffectiveOp = { id: op.id, crud: op.crud, effect: op.effect, ...(op.holdFamily ? { holdFamily: op.holdFamily } : {}), ...(op.scopeType ? { scopeType: op.scopeType } : {}) };
    let dyn: { tool: string; args: Record<string, unknown> } | null = null;
    const v = validateInput(op, body.input);
    if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
    if (op.dynamic) {
      const r = await resolveDynamic(rt, op, body.input);
      eff = r.eff;
      dyn = { tool: r.tool, args: r.args };
    }

    // first sight (§7.2): agent from the slice, or a companion app caller on its first call
    if (sliceAgent) await rt.ensureAgent(sliceAgent);
    else if (g.caller.type === "agent") await rt.ensureAgent({ id: callerId as AgentId, name: callerId, mode: g.claims.mode, status: "active" });
    else rt.scopes.applyDefaultsFor(callerId, caller.name);

    // idempotency (§4.4)
    const idemKey = idempotencyKeyFor(op, body.idempotencyKey);
    if (idemKey) {
      const prior = rt.receipts.idemGet(callerId, op.id, idemKey, now);
      if (prior && prior.inputDigest !== inputDigest) throw new TbError("idempotency_conflict", "idempotency key was used with a different input", 409);
      if (prior?.kind === "result") {
        const output = JSON.parse(rt.sealer.unsealText(IDEM_PURPOSE, `${callerId}:${op.id}:${idemKey}`, prior.output)) as Json;
        return sendJson(res, 200, { status: "ok", output } satisfies OpResult);
      }
      if (prior?.kind === "held") {
        const h = rt.receipts.getSync(prior.holdId);
        if (h?.status === "held") return sendJson(res, 202, { status: "held", holdId: h.id, expiresAt: iso(h.expiresAt ?? now) } satisfies OpResult);
        if (h?.status === "denied") throw new TbError("hold_denied", "the owner denied this call (or it expired)", 403);
        // approved → falls through to the approval path below
      }
    }

    // scope access (from the app's own store, never from the caller)
    const spec = handlerSpec(rt, op.id);
    let access: { level: string; crud: CrudAction[] } | null = null;
    let viewAccess: ScopeAccessView["access"] = null;
    if (eff.scopeType) {
      const target = spec?.scope ? spec.scope(body.input, caller) : null;
      const r = rt.scopes.resolve(callerId, eff.scopeType, target);
      access = r ? { level: r.level, crud: r.crud } : { level: "none", crud: [] };
      viewAccess = { type: eff.scopeType, id: target, level: access.level, crud: access.crud };
    }

    const approved = rt.receipts.findApproved(callerId, op.id, inputDigest, now);
    const usage = await rt.receipts.usage(callerId, g.claims.caps ?? {}, now);
    const decision = authorize({
      paused: rt.trust.paused(g.caller.type === "agent" ? callerId : null),
      grant: grantToken,
      trust,
      op: eff,
      access,
      usage,
      approval: approved ? "approved" : "none",
      // v0.1.13 (G1): the bridge-attested before-hook hold verdict; an approval for this exact call satisfies it
      holdVerdict: proof.claims.hv ? { family: proof.claims.hv.f, reason: proof.claims.hv.r, by: proof.claims.hv.by } : null,
    });
    const receiptCaller = { type: caller.type as "agent" | "app", id: callerId, name: caller.name };
    const base = { callId, caller: receiptCaller, op: op.id, effect: eff.effect, inputDigest: inputDigest as Sha256Digest, idempotencyKey: idemKey };
    const meta0: Json = dyn ? { tool: dyn.tool } : null;

    if (decision.decision === "refuse") {
      rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "refused", summary: clampSummary(op.title), meta: { reason: decision.reason } });
      throw new TbError(decision.reason, `refused: ${decision.reason}`, grantFailStatus(decision.reason));
    }
    if (decision.decision === "hold") {
      const hold = createHold(rt, base, spec, op, body.input, decision, decision.reason === DECISION_REASON.heldByHook ? (proof.claims.hv?.r ?? null) : null, meta0, now);
      if (idemKey) rt.receipts.idemPut(callerId, op.id, idemKey, inputDigest, { holdId: hold.id }, now);
      rt.statusChanged();
      return sendJson(res, 202, { status: "held", holdId: hold.id, expiresAt: iso(hold.expiresAt ?? now + HOLD_TTL_MS) } satisfies OpResult);
    }

    // run
    if (approved && !rt.receipts.consume(approved.id)) throw new TbError("hold_consumed", "this approval was already used", 409);
    const rh = receiptHelpers();
    const sig = opSignal(req, res);
    const ctx = buildContext(rt, op, caller, g, rt.scopes.view(callerId, viewAccess), callId, idemKey, body.context, rh.helpers, sig.signal);
    const writeReceipt = approved !== null || op.receipt || (dyn !== null && eff.effect !== "read");
    let output: Json;
    try {
      output = await runHandler(rt, op, body.input, ctx, dyn);
    } catch (e) {
      const err = toTbError(e, rt);
      const meta = rh.meta ?? meta0;
      if (approved) rt.receipts.finish(approved.id, "failed", { meta });
      else if (writeReceipt) rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "failed", summary: rh.summary ?? clampSummary(op.title), meta: { ...(isObj(meta) ? meta : {}), error: err.code } });
      throw err;
    } finally {
      sig.done();
    }
    const summary = rh.summary ?? clampSummary(spec?.redact ? spec.redact(body.input, output) : op.title);
    let receiptId: string | undefined;
    if (approved) {
      rt.receipts.finish(approved.id, "run", { summary, meta: rh.meta ?? meta0 });
      receiptId = approved.id;
    } else if (writeReceipt) {
      receiptId = rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "run", summary, meta: rh.meta ?? meta0 }).id;
    }
    if (idemKey) rt.receipts.idemPut(callerId, op.id, idemKey, inputDigest, { output: rt.sealer.sealText(IDEM_PURPOSE, `${callerId}:${op.id}:${idemKey}`, JSON.stringify(output)) }, Date.now());
    sendJson(res, 200, receiptId ? ({ status: "ok", output, receiptId } satisfies OpResult) : ({ status: "ok", output } satisfies OpResult));
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : toTbError(e, rt));
  }
}

type ReceiptBase = Pick<NewReceipt, "callId" | "caller" | "op" | "effect" | "inputDigest" | "idempotencyKey">;

/** A hold receipt for a `hold` decision (called op or scheduled op); refuses `hold_view_too_large`. */
function createHold(rt: Runtime, base: ReceiptBase, spec: HandlerSpec | null, op: OperationView, input: Json, decision: Decision, hookReason: string | null, meta: Json, now: number) {
  const view = spec?.holdView ? spec.holdView(input) : `${op.title}\n${JSON.stringify(input, null, 2)}`;
  if (view.length > HOLD_VIEW_MAX) {
    rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "refused", summary: clampSummary(op.title), meta: { reason: "hold_view_too_large" } });
    throw new TbError("hold_view_too_large", "hold view exceeds 16 000 characters", 500);
  }
  const summary = clampSummary(spec?.redact ? spec.redact(input) : op.title);
  // v0.1.13 (G1): heldBy + the reason (hook verdict reason, else the SDK decision reason code; C90: never input/view/meta)
  return rt.receipts.insert(
    {
      ...base,
      kind: "hld",
      holdFamily: decision.holdFamily ?? null,
      heldBy: decision.heldBy ?? null,
      holdReason: hookReason ?? decision.reason,
      status: "held",
      summary,
      meta,
      view,
      expiresAt: now + HOLD_TTL_MS,
    },
    now,
  );
}

// ── Scheduled ops (v0.1.21, SDK-2 / CON-01) ─────────────────────────────────
/**
 * Fire time of `ctx.schedule({ op, input }, …)`: THE app decision function `authorize()` runs again with the stored
 * caller against the CURRENT slice (pause: workspace kill switch, instance, agent; revoked jtis; issuer keys), the
 * current scope access, current usage (caps) and a current approval, and the receipt of the actual run is written.
 * Before that: an agent caller must still be in the slice (`agent_removed`), an app caller still a companion caller
 * (`grant_revoked`), and the op must still be in the grant's workflow (`not_in_workflow`, gate() step 4).
 * The grant is the caller's newest verified grant (refreshed on each of its calls). Its 12 h expiry is the one check
 * replaced: authorize() reads it at a time inside its validity, and caller presence in the Portal-signed slice
 * (≤ 12 h fresh, else nothing fires) stands in for it. SPEC-GAP (SDK-API §19): bridge before-hooks (Rules) are not
 * re-run at fire time; they ran for the scheduling call.
 */
export async function fireScheduledOp(rt: Runtime, job: ClaimedJob, signal: AbortSignal): Promise<OpFireOutcome> {
  const now = Date.now();
  const op = job.op ? rt.ops.get(job.op) : undefined;
  if (!op || op.standard || op.dynamic) return { kind: "refused", reason: "unknown_tool" };
  const who = job.caller;
  if (!who) return { kind: "refused", reason: "schedule_caller_required" };
  if (!rt.cfg.standalone && rt.trust.stale(now)) return { kind: "defer", reason: "slice_stale" };
  const input = job.input;
  const inputDigest = digest(input) as Sha256Digest;
  const spec = handlerSpec(rt, op.id);
  const caller: Caller = { type: who.type, id: who.id as Caller["id"], name: who.name, mode: (job.callerMode as Caller["mode"]) ?? null };
  const effect = op.effect;

  if (who.type === "person") {
    const p = rt.trust.paused(null);
    if (p.workspace || p.instance) return { kind: "refused", reason: DECISION_REASON.paused };
    const rh = receiptHelpers();
    const ctx = buildContext(rt, op, caller, null, rt.scopes.view(null, null), null, job.key, {}, rh.helpers, signal);
    const output = await runHandler(rt, op, input, ctx, null);
    return { kind: "done", result: output };
  }

  const callerId = who.id as AgentId | InstanceId;
  const receiptCaller = { type: who.type as "agent" | "app", id: callerId, name: who.name };
  const base: ReceiptBase = { callId: null, caller: receiptCaller, op: op.id, effect, inputDigest, idempotencyKey: job.key };
  const refuse = (reason: string): OpFireOutcome => {
    rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "refused", summary: clampSummary(op.title), meta: { reason, scheduled: job.id } });
    rt.statusChanged();
    return { kind: "refused", reason };
  };
  // the caller must still exist (an agent removed from the slice, an app whose companion grant was revoked)
  if (who.type === "agent" && !rt.trust.agent(callerId)) return refuse("agent_removed");
  if (who.type === "app" && !rt.trust.companionCallers().some((c) => c.ins === callerId)) return refuse("grant_revoked");
  if (!job.grantSealed) return refuse("grant_invalid");
  const token = unsealGrant(rt, callerId, job.grantSealed);
  const trust = rt.trust.context(now);
  if (!trust) return { kind: "defer", reason: "slice_stale" };
  const exp = Number(peekClaims(token)?.exp ?? 0);
  const at = { ...trust, now: Math.min(trust.now, exp - 1) };
  const g = verifyGrant(token, at);
  if (!g.ok) return refuse(g.code);
  if (g.caller.id !== callerId) return refuse("grant_invalid");
  if (!opInGrantWorkflow(g.claims, op.id)) return refuse(DECISION_REASON.notInWorkflow);

  let access: { level: string; crud: CrudAction[] } | null = null;
  let viewAccess: ScopeAccessView["access"] = null;
  if (op.scopeType) {
    const target = spec?.scope ? spec.scope(input, caller) : null;
    const r = rt.scopes.resolve(callerId, op.scopeType, target);
    access = r ? { level: r.level, crud: r.crud } : { level: "none", crud: [] };
    viewAccess = { type: op.scopeType, id: target, level: access.level, crud: access.crud };
  }
  // a hold created at an earlier fire: denied/expired ends the job; still held waits; approved runs once (C8)
  if (job.holdId) {
    const h = rt.receipts.getSync(job.holdId);
    if (h?.status === "held") return { kind: "wait", holdId: h.id };
    if (h?.status !== "approved") return { kind: "refused", reason: "hold_denied" };
  }
  const approved = rt.receipts.findApproved(callerId, op.id, inputDigest, now);
  const usage = await rt.receipts.usage(callerId, g.claims.caps ?? {}, now);
  const decision = authorize({
    paused: rt.trust.paused(who.type === "agent" ? callerId : null),
    grant: token,
    trust: at,
    op: { id: op.id, crud: op.crud, effect, ...(op.holdFamily ? { holdFamily: op.holdFamily } : {}), ...(op.scopeType ? { scopeType: op.scopeType } : {}) },
    access,
    usage,
    approval: approved ? "approved" : "none",
    holdVerdict: null,
  });
  if (decision.decision === "refuse") return refuse(decision.reason);
  if (decision.decision === "hold") {
    if (job.holdId) return { kind: "refused", reason: "hold_consumed" };
    const hold = createHold(rt, base, spec, op, input, decision, null, { scheduled: job.id }, now);
    rt.statusChanged();
    return { kind: "wait", holdId: hold.id };
  }
  if (approved && !rt.receipts.consume(approved.id)) return { kind: "refused", reason: "hold_consumed" };
  const rh = receiptHelpers();
  const ctx = buildContext(rt, op, caller, g, rt.scopes.view(callerId, viewAccess), null, job.key, {}, rh.helpers, signal);
  const writeReceipt = approved !== null || op.receipt;
  let output: Json;
  try {
    output = await runHandler(rt, op, input, ctx, null);
  } catch (e) {
    const err = toTbError(e, rt);
    const meta = rh.meta ?? null;
    if (approved) rt.receipts.finish(approved.id, "failed", { meta });
    else if (writeReceipt) rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "failed", summary: rh.summary ?? clampSummary(op.title), meta: { ...(isObj(meta) ? meta : {}), error: err.code } });
    return { kind: "failed", error: err.code };
  }
  const summary = rh.summary ?? clampSummary(spec?.redact ? spec.redact(input, output) : op.title);
  if (approved) rt.receipts.finish(approved.id, "run", { summary, meta: rh.meta ?? null });
  else if (writeReceipt) rt.receipts.insert({ ...base, kind: "rcp", holdFamily: null, status: "run", summary, meta: rh.meta ?? null });
  return { kind: "done", result: output };
}

// ── tb.holds_pending (v0.1.13, G4) ───────────────────────────────────────────
/**
 * An AGENT caller sees only its own pending holds; an APP caller whose companion grant names tb.holds_pending (`wf`)
 * sees every pending hold of the instance. SPEC-GAP: an app caller WITHOUT it in `wf` (I4 lets any valid grant through)
 * sees only its own holds, like an agent. Summaries only: never input, view or meta.
 */
export function holdsPending(
  rt: Runtime,
  callerType: "agent" | "app",
  callerId: string,
  wf: readonly string[],
  input: { limit?: number; cursor?: string },
  now: number,
): HoldsPendingOutput {
  const all = callerType === "app" && wf.includes(HOLDS_PENDING_OP);
  const page = rt.receipts.pending({ caller: all ? null : callerId, limit: input.limit ?? 50, ...(input.cursor ? { cursor: input.cursor } : {}) }, now);
  const items = page.items.map(
    (h): HoldsPendingItem => ({
      id: h.id as HoldsPendingItem["id"],
      product: rt.product,
      op: h.op,
      family: h.family ?? "policy",
      reason: h.reason.slice(0, SUMMARY_MAX),
      heldBy: h.heldBy,
      summary: h.summary,
      caller: h.caller,
      createdAt: iso(h.createdAt) as HoldsPendingItem["createdAt"],
      ageS: Math.max(0, Math.floor((now - h.createdAt) / 1000)),
      decidePath: `/holds/${h.id}`,
    }),
  );
  return { items, nextCursor: page.nextCursor };
}

// ── Hold decide (person only, §4.5) ──────────────────────────────────────────
export async function decide(rt: Runtime, principal: PersonPrincipal, input: HoldDecideInput): Promise<Receipt> {
  if (principal?.type !== "person" || principal.instance !== rt.instanceId) throw new TbError("session_required", "only the owner can decide holds", 403);
  if (input.decision !== "approve" && input.decision !== "deny") throw new TbError("input_invalid", "decision must be approve or deny", 400);
  const now = Date.now();
  const row = typeof input.holdId === "string" && input.holdId.startsWith("hld_") ? rt.receipts.getSync(input.holdId) : null;
  if (!row) throw new TbError("hold_not_found", "no such hold", 404);
  if (row.status === "held" && row.expiresAt !== null && row.expiresAt <= now) {
    rt.receipts.sweep(now);
    rt.statusChanged();
    throw new TbError("hold_expired", "the hold expired before a decision", 409);
  }
  if (row.status !== "held") throw new TbError("hold_decided", `hold is already ${row.status}`, 409);
  rt.receipts.decide(row.id, input.decision === "approve" ? "approved" : "denied", principal.id, now);
  await rt.audit.record({
    actor: principal.id,
    action: "hold.decide",
    target: row.id,
    detail: { decision: input.decision, op: row.op, caller: row.caller.id, ...(input.note ? { note: input.note.slice(0, 1000) } : {}) },
  });
  rt.statusChanged();
  // v0.1.21: a scheduled op waiting for this hold re-checks now
  if (rt.jobs.store.holdDecided(row.id, now) > 0) rt.jobs.kick();
  return rt.receipts.getSync(row.id) as Receipt;
}

// ── POST /a/<product>/tb/v1/ops/:op (person session + TB-CSRF) ─────────────
const HOLD_STATUSES: readonly ReceiptStatus[] = ["held", "approved", "denied"];

async function runStandardPersonOp(rt: Runtime, principal: PersonPrincipal, id: StandardOpId, input: Record<string, unknown>, res: ServerResponse): Promise<Json | null> {
  switch (id) {
    case "tb.holds_list": {
      const status = input.status as ReceiptStatus | undefined;
      if (status !== undefined && !HOLD_STATUSES.includes(status)) throw new TbError("input_invalid", "status must be held, approved or denied", 400);
      const r = await rt.receipts.list({ status: status ?? [...HOLD_STATUSES], cursor: input.cursor as string | undefined });
      return { items: r.items as unknown as Json, nextCursor: r.nextCursor };
    }
    case "tb.holds_decide":
      return (await decide(rt, principal, input as unknown as HoldDecideInput)) as unknown as Json;
    case "tb.receipts_list": {
      const r = await rt.receipts.list({
        caller: input.caller as AgentId | undefined,
        op: input.op as string | undefined,
        status: input.status as ReceiptStatus | undefined,
        cursor: input.cursor as string | undefined,
      });
      return { items: r.items as unknown as Json, nextCursor: r.nextCursor };
    }
    case "tb.agents_list": {
      const agents = rt.trust.slice?.agents ?? [];
      const out: Json[] = [];
      for (const a of agents) out.push({ id: a.id, name: a.name, mode: a.mode, status: a.status, access: (await rt.scopes.list(a.id)) as unknown as Json });
      return { agents: out };
    }
    case "tb.scopes_set": {
      const { agent, type, id: inst, access } = input as { agent: AgentId; type: string; id: string; access: string | null };
      await rt.scopes.set(principal, agent, type, inst, access);
      return { access: (await rt.scopes.access(agent, type, inst)) as unknown as Json };
    }
    case "tb.keys_status":
      return { keys: (await rt.keys.status()) as unknown as Json };
    case "tb.key_set":
      await rt.keys.set(principal, String(input.name), String(input.value));
      return { ok: true };
    case "tb.key_delete":
      await rt.keys.remove(principal, String(input.name));
      return { ok: true };
    case "tb.export": {
      const ex = await rt.backups.exportNow();
      res.writeHead(200, { "content-type": "application/gzip", "content-disposition": `attachment; filename="${ex.file.split("/").pop()}"`, "cache-control": "no-store" });
      const reader = ex.stream.getReader();
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
      res.end();
      return null;
    }
    default:
      throw new TbError("audience_not_person", "operation is not person-audience", 403);
  }
}

export async function handlePersonOp(rt: Runtime, req: IncomingMessage, res: ServerResponse, opId: string): Promise<void> {
  const rid = requestId();
  try {
    const session = rt.person.requireSession(req);
    rt.person.requireCsrf(req, session);
    const raw = await readJson(req);
    if (!isObj(raw)) throw new TbError("input_invalid", "body must be { input, idempotencyKey? }", 400);
    const input = (raw.input ?? {}) as Json;
    const op = rt.ops.get(opId);
    if (!op) throw new TbError("unknown_tool", `unknown operation ${opId}`, 404);
    if (op.audience !== "person") throw new TbError("audience_not_person", "operation is not person-audience", 403);
    const v = validateInput(op, input);
    if (!v.ok) throw new TbError("input_invalid", "input does not match the schema", 400, { errors: v.errors });
    const principal = session.principal;
    if (op.standard) {
      const out = await runStandardPersonOp(rt, principal, op.id, input as Record<string, unknown>, res);
      if (out !== null) sendJson(res, 200, { status: "ok", output: out } satisfies OpResult);
      return;
    }
    const now = Date.now();
    const inputDigest = digest(input);
    const idemKey = idempotencyKeyFor(op, typeof raw.idempotencyKey === "string" ? raw.idempotencyKey : null);
    const sealId = (k: string) => `${principal.id}:${op.id}:${k}`;
    if (idemKey) {
      const prior = rt.receipts.idemGet(principal.id, op.id, idemKey, now);
      if (prior && prior.inputDigest !== inputDigest) throw new TbError("idempotency_conflict", "idempotency key was used with a different input", 409);
      if (prior?.kind === "result") return sendJson(res, 200, { status: "ok", output: JSON.parse(rt.sealer.unsealText(IDEM_PURPOSE, sealId(idemKey), prior.output)) as Json });
    }
    const caller: Caller = { type: "person", id: principal.id as PersonId, name: "owner", mode: null };
    const rh = receiptHelpers();
    const sig = opSignal(req, res);
    const ctx = buildContext(rt, op, caller, null, rt.scopes.view(null, null), null, idemKey, {}, rh.helpers, sig.signal, { ...rt.extras(), workspace: principal.ws });
    let output: Json;
    try {
      output = await runHandler(rt, op, input, ctx, null);
    } finally {
      sig.done();
    }
    if (idemKey) rt.receipts.idemPut(principal.id, op.id, idemKey, inputDigest, { output: rt.sealer.sealText(IDEM_PURPOSE, sealId(idemKey), JSON.stringify(output)) }, Date.now());
    sendJson(res, 200, { status: "ok", output } satisfies OpResult);
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : toTbError(e, rt));
  }
}

export type { OpCallBody };
