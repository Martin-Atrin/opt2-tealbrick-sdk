// Grantless bridge→app routes (SDK-API §3.2): hook calls (`verifyHookProof`) and the bridge ops catalog, resolve,
// mark, scope-summary (`verifyBridgeOpProof`, C16 B5). No receipts, no hooks, no agent action.
import type { IncomingMessage, ServerResponse } from "node:http";
import { digest, mcpToolName, toolNameFits, verifyBridgeOpProof, verifyHookProof } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS, type HookRequest, type ScopeSummaryResult } from "@opt2-tealbrick/spec/bridge";
import type { BridgeOp } from "@opt2-tealbrick/spec/credentials";
import { type DynamicCatalogEntry, EFFECTS, HOOK_PHASES, type Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json, TrustContext } from "@opt2-tealbrick/spec/sdk";
import type { SdkHookContext } from "./context.ts";
import { TbError } from "./errors.ts";
import { header, readJson, requestId, sendError, sendJson } from "./http.ts";
import { withinCeiling } from "./ops.ts";
import type { Runtime } from "./runtime.ts";

const HOOK_DEFAULT_TIMEOUT_MS = 2000;
const CATALOG_LIST_MAX = 256;
const ENTRY_NAME_RE = /^[a-z][a-z0-9_]{1,47}$/;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

function ready(rt: Runtime): TrustContext {
  if (rt.cfg.standalone) throw new TbError("no_bridge", "app-alone mode serves persons only", 503);
  const now = Date.now();
  if (rt.trust.stale(now)) throw new TbError("slice_stale", "instance slice missing or older than 12 h", 503);
  const ctx = rt.trust.context(now);
  if (!ctx) throw new TbError("slice_stale", "no instance slice", 503);
  return ctx;
}

function hookContext(rt: Runtime, timeoutMs: number): SdkHookContext {
  return { log: rt.log, db: rt.appDb, getKey: (n) => rt.keys.getKey(n), signal: AbortSignal.timeout(timeoutMs), secrets: rt.secretsStore };
}

async function withTimeout<T>(p: Promise<T>, signal: AbortSignal): Promise<T> {
  return Promise.race([
    p,
    new Promise<never>((_, reject) => signal.addEventListener("abort", () => reject(new TbError("hook_failed", "handler timed out", 504)), { once: true })),
  ]);
}

const HOOK_RESPONSE_KEYS: Record<HookRequest["phase"], readonly string[]> = { before: ["allow", "reason"], context: ["add"], after: ["output", "redactions"] };

/** The phase's response shape (spec bridge.ts `HookResponseByPhase`), or why the answer violates it. */
function hookResponseProblem(phase: HookRequest["phase"], out: unknown, product: string): string | null {
  if (!isObj(out)) return "hook returned no object";
  const extra = Object.keys(out).filter((k) => !HOOK_RESPONSE_KEYS[phase].includes(k));
  if (extra.length) return `${phase} hook returned unknown keys ${extra.join(", ")}`;
  if (phase === "before") {
    if (typeof out.allow !== "boolean") return "before hook must return { allow }";
    if (out.reason !== undefined && typeof out.reason !== "string") return "before hook reason must be a string";
    return null;
  }
  if (phase === "context") {
    const add = out.add;
    return !isObj(add) || Object.keys(add).some((k) => !k.startsWith(`${product}.`)) ? `context keys must start with "${product}."` : null;
  }
  const red = out.redactions;
  if (red !== undefined && !(Array.isArray(red) && red.every((p) => typeof p === "string" && (p === "" || p.startsWith("/"))))) return "after hook redactions must be JSON pointers";
  return null;
}

// ── POST /tb/v1/hooks/:hookId ────────────────────────────────────────────────
export async function handleHook(rt: Runtime, req: IncomingMessage, res: ServerResponse, hookId: string): Promise<void> {
  const rid = requestId();
  try {
    const trust = ready(rt);
    const body = await readJson(req);
    const hook = rt.manifest.hooks?.find((h) => h.id === hookId);
    const handler = rt.def.hooks?.[hookId];
    if (!hook || !handler) throw new TbError("unknown_hook", `hook not declared: ${hookId}`, 404);
    if (!isObj(body) || !HOOK_PHASES.includes(body.phase as never) || !isObj(body.call) || !isObj(body.context)) throw new TbError("input_invalid", "body must be a HookRequest", 400);
    const r = body as unknown as HookRequest;
    const proof = verifyHookProof(
      header(req, BRIDGE_HEADERS.callProof) ?? "",
      trust,
      { hook: hookId, phase: hook.phase, contextDigest: digest(r.context as Json), ...(r.call.input !== undefined ? { inputDigest: digest(r.call.input as Json) } : {}) },
      rt.replay,
    );
    if (!proof.ok) throw new TbError("call_proof_invalid", "hook call proof missing or not valid", 401);
    if (r.phase !== hook.phase) throw new TbError("input_invalid", "phase does not match the declared hook", 400);
    const ctx = hookContext(rt, hook.timeoutMs ?? HOOK_DEFAULT_TIMEOUT_MS);
    const out = (await withTimeout(handler(r, ctx), ctx.signal)) as unknown;
    const problem = hookResponseProblem(r.phase, out, rt.product);
    if (problem) throw new TbError("hook_failed", problem, 500);
    sendJson(res, 200, out);
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : new TbError("hook_failed", "hook failed", 500));
  }
}

// ── POST /tb/v1/bridge/<bop> ─────────────────────────────────────────────────
function dynamicOp(rt: Runtime, opId: unknown): Operation {
  const op = rt.manifest.operations.find((o) => o.id === opId);
  if (!op?.dynamic) throw new TbError("unknown_tool", "not a dynamic operation", 404);
  return op;
}

function entryValid(rt: Runtime, op: Operation, e: DynamicCatalogEntry): boolean {
  return (
    ENTRY_NAME_RE.test(e.name) &&
    toolNameFits(mcpToolName(rt.product, e.name)) &&
    !rt.manifest.operations.some((o) => o.id === e.name) &&
    EFFECTS.includes(e.effect) &&
    withinCeiling(op, e) &&
    isObj(e.inputSchema) &&
    e.inputSchema.type === "object"
  );
}

export async function handleBridgeOp(rt: Runtime, req: IncomingMessage, res: ServerResponse, bop: BridgeOp): Promise<void> {
  const rid = requestId();
  try {
    const trust = ready(rt);
    const body = await readJson(req);
    if (!isObj(body)) throw new TbError("input_invalid", "body must be an object", 400);
    // Bound claims per SDK-API §3.2: catalog {op}, resolve {op, in}, mark {in}, scope_summary {}.
    // SPEC-GAP: CREDENTIALS §10 describes `in` generically; the catalog row of SDK-API §3.2 lists only `op`.
    const op = typeof body.op === "string" ? body.op : "";
    const bind =
      bop === "catalog" ? { bop, op } : bop === "resolve" ? { bop, op, inputDigest: digest(body as Json) } : bop === "mark" ? { bop, inputDigest: digest(body as Json) } : { bop };
    const proof = verifyBridgeOpProof(header(req, BRIDGE_HEADERS.callProof) ?? "", trust, bind, rt.replay);
    if (!proof.ok) throw new TbError("call_proof_invalid", "bridge-op proof missing or not valid", 401);
    switch (bop) {
      case "catalog": {
        const op = dynamicOp(rt, body.op);
        const d = rt.def.dynamic?.[op.id];
        if (!d) throw new TbError("unknown_tool", "no dynamic handler", 404);
        const limit = typeof body.limit === "number" ? Math.max(1, Math.min(CATALOG_LIST_MAX, Math.trunc(body.limit))) : undefined;
        const query = typeof body.query === "string" ? { query: body.query, ...(limit ? { limit } : {}) } : null;
        const entries = await d.catalog(query, hookContext(rt, 5000));
        const valid = entries.filter((e) => {
          const ok = entryValid(rt, op, e);
          if (!ok) rt.log.warn("dynamic catalog entry dropped", { op: op.id, name: String(e?.name) });
          return ok;
        });
        const max = op.dynamic?.mode === "list" ? CATALOG_LIST_MAX : (limit ?? CATALOG_LIST_MAX);
        return sendJson(res, 200, valid.slice(0, max));
      }
      case "resolve": {
        const op = dynamicOp(rt, body.op);
        const d = rt.def.dynamic?.[op.id];
        if (typeof body.tool !== "string" || !d) throw new TbError("input_invalid", "body must be { op, tool }", 400);
        const r = await d.resolve(body.tool, hookContext(rt, 2000));
        if (!r) throw new TbError("dynamic_resolve_failed", "unknown dynamic tool", 404);
        if (!withinCeiling(op, r)) throw new TbError("dynamic_ceiling_exceeded", "resolved tool exceeds the operation's ceiling", 403);
        return sendJson(res, 200, { tool: body.tool, crud: r.crud, effect: r.effect, ...(r.holdFamily ? { holdFamily: r.holdFamily } : {}) });
      }
      case "mark": {
        if (typeof body.call !== "string" || body.mark !== "after_failed") throw new TbError("input_invalid", "body must be { call, mark: after_failed }", 400);
        const rec = rt.receipts.byCall(body.call);
        if (rec) rt.receipts.finish(rec.id, "after_failed");
        return sendJson(res, 200, { ok: true, marked: rec !== null });
      }
      case "scope_summary": {
        const out: ScopeSummaryResult[] = [];
        for (const a of rt.trust.slice?.agents ?? []) out.push({ agent: a.id, label: await rt.scopes.summary(a.id) });
        return sendJson(res, 200, out);
      }
    }
  } catch (e) {
    sendError(res, rid, e instanceof TbError ? e : new TbError("app_error", "bridge op failed", 500));
  }
}
