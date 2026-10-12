// Bridge target group `real_app` (C91, QA S1): a REAL @opt2-tealbrick/miniapp-sdk app is deployed behind the bridge
// under test the way Core deploys one — listed in config apps[] with a one-time instance enrolment code, it claims
// through the bridge, the world binds the reported key (config instanceKeys) and the app installs its slice — then
// agent calls go through the bridge to it. The fake apps share their verification rules with this suite, so a bridge
// and a fake app could agree on a binding the SDK refuses (catalog proofs signed with `in` → 401 on every search).
import { randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { dynamicToolNames, manifestDigest, mcpToolName, opaqueDigest, opaqueValue, ulid } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Operation } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import type { FakeApp, Received } from "../fake-app.ts";
import { errorCode, type HttpAnswer } from "../http.ts";
import type { ToolCallResult } from "../mcp-agent.ts";
import { loadSdk, REAL_ENTRIES, REAL_HOOK, REAL_OPS, type RealApp, type RealStartContext, realAppManifest, startRealApp } from "../real-app.ts";
import { sampleInput } from "../sample.ts";
import { bad, notRun, type Outcome, verdict } from "../suite.ts";
import { newId, nowS } from "../tokens.ts";
import { type BridgeCtx, describeCall, isObj, sleep, toolRefused } from "./bridge-ctx.ts";
import { BRIDGE_GROUPS } from "./bridge-ids.ts";
import { chainFor } from "./bridge-spine013.ts";

/** Product id of the generated real app (generated, not an example product). */
export const REAL_PRODUCT = "tbconf-real";

export async function realAppChecks(c: BridgeCtx): Promise<void> {
  if (!c.on("real_app")) return;
  const all = BRIDGE_GROUPS.real_app ?? [];
  const every = (o: Outcome) => {
    for (const x of all) if (!c.s.has(x.id)) c.s.record(x.id, x.title, "the real SDK app is deployed behind the bridge", o);
  };
  if (!c.w.testRoots) return every(notRun("needs test roots (the real SDK app pins the run's TEST root through startApp's portalRootKeys)"));
  const port = c.w.realAppPort;
  if (!port) return every(bad("no port reserved for the real app (runBridgeTarget sets world.realAppPort)"));
  const loaded = await loadSdk(c.h.sdkModule);
  if ("error" in loaded) return every(notRun(loaded.error));

  // B26: the real app's companion edge = a plain read op of the primary fake app (its grant is minted like any app's)
  const target = c.primary;
  const targetOp = c.readOp(target);
  // L2 (B25.real_hook_hold): the real app's before hook matches ANOTHER agent op of the primary fake app (not the B26
  // companion op, whose hook counts B26 asserts), within the free agent's grant crud
  const freeCrud = c.w.grantSpecs.find((g) => g.role === "free" && g.app === target)?.crud ?? [];
  const hookOp = c.pick(target, (o) => o.id !== targetOp?.id && !o.dynamic && o.effect !== "money" && o.crud.every((x) => freeCrud.includes(x)));
  const manifest = realAppManifest(c.primary.manifest, REAL_PRODUCT, port, targetOp ? { product: target.product, operations: [targetOp.id], crud: [...targetOp.crud] } : undefined, hookOp ? { product: target.product, operation: hookOp.id } : undefined);
  const ins = newId("ins") as InstanceId;
  const dataDir = mkdtempSync(join(tmpdir(), "tb-conformance-real-"));
  mkdirSync(join(dataDir, "backup"), { recursive: true });
  let running: RealApp | null = null;
  try {
    // Core's deploy: the app is listed (apps[] + slice + a free-agent grant) with a one-time instance enrolment code
    const code = opaqueValue("tbe_");
    c.w.enrolCodes.push({ digest: opaqueDigest(code), kind: "instance", ins, product: manifest.id, exp: nowS() + 3600 });
    c.w.realApp = { ins, manifest, digest: manifestDigest(manifest), url: `http://127.0.0.1:${port}`, jwk: null, listed: true };
    await c.apply();
    const env: Record<string, string> = {
      TB_INSTANCE_ID: ins,
      TB_ENROL_CODE: code,
      TB_BRIDGE_URL: c.int,
      TB_PORTAL_KEYS: JSON.stringify({ keys: c.w.portal.keys.filter((k) => k.status !== "pending").map((k) => k.key.publicJwk) }),
      TB_KEK: randomBytes(32).toString("base64url"),
      TB_DATA_DIR: dataDir,
      TB_BACKUP_DIR: join(dataDir, "backup"),
      TB_LOG_LEVEL: "error",
      TB_DATA_EPHEMERAL: "1",
    };
    running = await startRealApp(loaded.sdk, manifest, env, dataDir, [c.w.root.publicJwk]);
    const app = running;
    // the bridge reports the claim (digest only); Core binds the reported key → config instanceKeys
    const d = opaqueDigest(code);
    const claim = (await c.until(async () => c.w.portal.acks.flatMap((a) => a.claims ?? []).find((x) => x.ins === ins && x.codeDigest === d), c.h.timeoutMs)).value;
    if (!claim) return every(bad(`the real app's claim was not reported by the bridge within ${c.h.timeoutMs} ms (app status ${app.status()})`));
    c.w.realApp.jwk = claim.publicKey;
    await c.apply();
    const ready = (await c.until(async () => app.status() === "ok", c.h.timeoutMs)).value;
    if (!ready) return every(bad(`the real app did not install its slice through the bridge (status ${app.status()})`));
    // list-mode catalogs are read with the app up
    await c.apply();
    const okStructured = (r: ToolCallResult) => c.isOk(r) && !r.isError;
    const raw = (r: ToolCallResult) => JSON.stringify(r.raw ?? null);

    await c.run("B25.real_catalog_search", "search through the bridge reaches the real SDK app's catalog", `${REAL_PRODUCT}__${REAL_OPS.search}_search → ok with the app's entry ${REAL_ENTRIES.search} (the SDK verifies the catalog proof bound to {bop, op} only)`, async () => {
      const a = await c.callTool("free", dynamicToolNames(manifest.id, REAL_OPS.search).search, { query: "conformance", limit: 5 });
      return verdict(okStructured(a) && raw(a).includes(REAL_ENTRIES.search), describeCall(a));
    });
    await c.run("B25.real_dynamic_call", "dynamic _call and a list entry reach the real SDK app", `_call {tool: ${REAL_ENTRIES.search}} (resolve, then the op call) → ok; list entry ${REAL_PRODUCT}__${REAL_ENTRIES.list} → ok`, async () => {
      const a = await c.callTool("free", dynamicToolNames(manifest.id, REAL_OPS.search).call, { tool: REAL_ENTRIES.search, arguments: { q: "conformance" } });
      const b = await c.callTool("free", mcpToolName(manifest.id, REAL_ENTRIES.list), { q: "conformance" });
      const pass = okStructured(a) && raw(a).includes(REAL_ENTRIES.search) && okStructured(b) && raw(b).includes(REAL_ENTRIES.list);
      return verdict(pass, `_call: ${describeCall(a)}; list entry: ${describeCall(b)}`);
    });
    await c.run("B25.real_op_call", "a plain op through the real SDK's verification and authorize()", `${REAL_PRODUCT}__${REAL_OPS.plain} → ok; the app holds a receipt with status run for it`, async () => {
      const t0 = Date.now() - 1000;
      const a = await c.callTool("free", mcpToolName(manifest.id, REAL_OPS.plain), { id: `conf-${ulid()}` }, c.idemKey());
      const rc = (await app.receipts.list({ op: REAL_OPS.plain })).items.filter((x) => x.createdAt >= t0);
      return verdict(okStructured(a) && a.structured?.written === true && rc.some((x) => x.status === "run"), `${describeCall(a)}; receipts since the call: ${rc.map((x) => x.status).join(",") || "none"}`);
    });
    await c.run("B25.real_mark", "a failing after hook marks the real app's receipt after_failed", "after hook answers 500 → isError after_failed; the real app's receipt of that call → after_failed (verified bridge-op mark)", async () => {
      const op: Operation | undefined = manifest.operations.find((o) => o.id === REAL_OPS.plain);
      const after = c.w.hookEntries().filter((h) => h.phase === "after" && (h.match.products.includes("*") || h.match.products.includes(manifest.id)) && (!h.match.operations || h.match.operations.includes(REAL_OPS.plain)) && (!h.match.effects || (op && h.match.effects.includes(op.effect))));
      const hookApp = after[0] ? c.w.apps.find((x) => x.product === after[0]?.product) : undefined;
      if (!after[0] || !hookApp) return bad("no after hook matches the real app's op");
      const id = after[0].hookId;
      hookApp.onHook = (hookId, phase) => (hookId === id ? { status: 500, body: {} } : { status: 200, body: phase === "before" ? { allow: true } : phase === "context" ? { add: {} } : {} });
      try {
        const t0 = Date.now() - 1000;
        const a = await c.callTool("free", mcpToolName(manifest.id, REAL_OPS.plain), { id: `conf-${ulid()}` }, c.idemKey());
        const o = toolRefused(a, ["after_failed"]);
        const marked = await c.until(async () => (await app.receipts.list({ op: REAL_OPS.plain })).items.find((x) => x.createdAt >= t0 && x.status === "after_failed"), c.h.timeoutMs);
        const rc = (await app.receipts.list({ op: REAL_OPS.plain })).items.filter((x) => x.createdAt >= t0);
        return verdict(o.pass === true && !!marked.value, `${o.asserted}; receipts since the call: ${rc.map((x) => x.status).join(",") || "none"}`);
      } finally {
        hookApp.onHook = null;
      }
    });
    await c.run("B25.real_hook_hold", "a REAL SDK before hook's hold verdict reaches the target app (L2)", `the real app's before hook ${REAL_HOOK.id} matches <primary>.<agent op>: input with the marker → it answers {allow: false, hold: {family ${REAL_HOOK.family}, reason "${REAL_HOOK.reason}"}} → the bridge forwards with hv {f, r, by ${REAL_PRODUCT}/${REAL_HOOK.id}} and the fake app's hold comes back held (never hook_failed); without the marker → allow → ok, no hv`, async () => {
      if (!hookOp) return bad("the primary fake app has no second agent op within the free grant for the real app's before hook");
      const by = `${REAL_PRODUCT}/${REAL_HOOK.id}`;
      const holdId = `hld_${ulid()}`;
      // the fake app holds on a verdict as the SDK's authorize() step 2b does
      target.onOp = (info) => {
        const hv = info.proof.hv as { r?: unknown } | undefined;
        if (info.op === hookOp.id && hv) return { status: 202, body: { status: "held", holdId, expiresAt: new Date(Date.now() + 3600_000).toISOString(), reason: hv.r } };
        return { status: 200, body: { status: "ok", output: { op: info.op } } };
      };
      try {
        const schema = hookOp.input ?? { type: "object" };
        const idem = () => (hookOp.idempotency === "none" ? null : c.idemKey());
        let s0 = c.w.seqNow();
        const held = await c.call("free", target, hookOp.id, sampleInput(schema, `${REAL_HOOK.marker}-${ulid()}`), idem());
        const recH = c.since(target, s0, "op").find((x) => x.name === hookOp.id);
        s0 = c.w.seqNow();
        const plain = await c.call("free", target, hookOp.id, c.input(target, hookOp.id), idem());
        const recP = c.since(target, s0, "op").find((x) => x.name === hookOp.id);
        const hv = (recH?.proof?.hv ?? null) as { f?: unknown; r?: unknown; by?: unknown } | null;
        const sc = held.structured ?? {};
        const heldOk = !held.isError && sc.status === "held" && sc.holdId === holdId;
        const hvOk = !!hv && hv.f === REAL_HOOK.family && hv.r === REAL_HOOK.reason && hv.by === by;
        const plainOk = c.isOk(plain) && !plain.isError && !!recP && recP.proof?.hv === undefined;
        return verdict(
          heldOk && hvOk && plainOk,
          `with marker: ${describeCall(held)}; forwarded hv ${hv ? JSON.stringify(hv) : "NONE"}${recH ? "" : " (app not called)"}; without marker: ${describeCall(plain)}${recP ? (recP.proof?.hv === undefined ? ", no hv" : ", hv FORWARDED") : " (app not called)"}`,
        );
      } finally {
        target.onOp = null;
      }
    });
    await appInitiatedChecks(c, ins, app, target, targetOp);
  } finally {
    await running?.stop().catch(() => undefined);
    // the app is removed again (Core undeploy): later groups see the original world
    c.w.realApp = null;
    await c.apply().catch(() => undefined);
    rmSync(dataDir, { recursive: true, force: true });
  }
}

// ── B26: app-initiated companion calls (C85) and ignored parentCalls (BRIDGE v0.1.14, A2A-10) ──
const APP_INITIATED = "call.app_initiated";
const RATE_BURST = 30;
const RATE_PROBES = 40;

/** Body of a recorded hook / op request (null when unreadable). */
function bodyOf(r: Received): Record<string, unknown> | null {
  try {
    const b = JSON.parse(r.body) as unknown;
    return isObj(b) ? b : null;
  } catch {
    return null;
  }
}

async function appInitiatedChecks(c: BridgeCtx, ins: InstanceId, app: RealApp, target: FakeApp, targetOp: Operation | undefined): Promise<void> {
  const p = c.primary;
  const peer = c.peer;
  const status = (a: HttpAnswer) => (isObj(a.body) && typeof a.body.status === "string" ? `${a.status} ${a.body.status}` : `${a.status} ${errorCode(a.body) ?? ""}`);
  const answeredOk = (a: HttpAnswer) => a.status === 200 && isObj(a.body) && a.body.status === "ok";
  /** `call.app_initiated` lines of the captured bridge log naming `who` (null: logs not captured) */
  const audited = (who: string): string[] | null => {
    const logs = c.h.logs();
    return logs === null ? null : logs.split("\n").filter((l) => l.includes(APP_INITIATED) && l.includes(who));
  };
  /** waits (bounded) until the log has more than `before` app-initiated lines for `who`; null when logs are not captured */
  const auditedAfter = async (who: string, before: number | null): Promise<boolean | null> => {
    if (before === null) return null;
    return !!(await c.until(async () => (audited(who)?.length ?? 0) > before, c.h.timeoutMs, 100)).value;
  };
  const auditNote = (x: boolean | null) => (x === null ? "audit not checked (bridge logs not captured)" : x ? `${APP_INITIATED} logged` : `NO ${APP_INITIATED} line for the caller`);
  for (const a of c.w.apps) {
    a.onHook = null;
    a.onOp = null;
  }

  // the real app's StartContext (onStart runs once after the claim)
  const sc = (await c.until(async () => app.startContext(), c.h.timeoutMs, 100)).value as RealStartContext | null;
  const opts = () => (targetOp?.idempotency === "required" ? { idempotencyKey: c.idemKey() } : undefined);
  let realOk = 0;
  const realCall = async (): Promise<{ ok: boolean; code: string }> => {
    if (!sc || !targetOp) return { ok: false, code: "no StartContext" };
    try {
      const r = await sc.callApp(target.product, targetOp.id, c.input(target, targetOp.id), opts());
      const fine = isObj(r) && r.status === "ok";
      if (fine) realOk++;
      return { ok: fine, code: fine ? "ok" : `answer ${JSON.stringify(r).slice(0, 60)}` };
    } catch (e) {
      return { ok: false, code: isObj(e) && typeof e.code === "string" ? e.code : e instanceof Error ? e.message.slice(0, 80) : String(e) };
    }
  };
  const missing = !targetOp ? "the primary fake app has no plain read op for the real app's companion edge" : !sc ? `the real app's onStart did not run within ${c.h.timeoutMs} ms (no StartContext)` : null;

  await c.run(
    "B26.app_initiated_real",
    "StartContext.callApp of the real SDK app passes the whole pipeline",
    "callApp(<primary>, <read op>) without parentCall → ok; the fake target receives a verified grant + op proof with sub tb:ins:<real app>; every matching hook (before, context, after) is called with call.caller {type: app, id: <real app>}; no parentCall in the hook envelopes or the op body",
    async () => {
      if (missing || !targetOp) return bad(missing ?? "no target op");
      const s0 = c.w.seqNow();
      const r = await realCall();
      const want = `tb:ins:${ins}`;
      const rec = c.since(target, s0, "op").find((x) => x.name === targetOp.id);
      const opBody = rec ? bodyOf(rec) : null;
      const opOk = !!rec?.verified && rec.proof?.sub === want && rec.grant?.sub === want && !!opBody && !("parentCall" in opBody);
      const expected = (["before", "context", "after"] as const).reduce((n, ph) => n + chainFor(c, target, targetOp, ph).length, 0);
      const hooks = c.everyApp(s0, "hook");
      const asApp = hooks.filter((h) => {
        const call = bodyOf(h)?.call;
        const caller = isObj(call) && isObj(call.caller) ? call.caller : null;
        return isObj(call) && caller?.type === "app" && caller.id === ins && (call.parentCall === undefined || call.parentCall === null);
      });
      const hooksOk = hooks.length === expected && asApp.length === expected;
      return verdict(
        r.ok && opOk && hooksOk,
        `callApp ${r.code}; target op ${rec ? `verified ${rec.verified}, proof sub ${String(rec.proof?.sub)}, grant sub ${String(rec.grant?.sub)}${opBody && "parentCall" in opBody ? ", parentCall FORWARDED" : ""}` : "not called"}; hooks ${asApp.length}/${hooks.length} as app without parentCall (${expected} matching)`,
      );
    },
  );

  await c.run(
    "B26.app_initiated_rate",
    "app-initiated calls are rate-limited per caller instance (120/min, burst 30)",
    `${RATE_PROBES} back-to-back callApp calls: none of the first ${RATE_BURST} refused rate_limited, at least one later one refused rate_limited, no other refusal; after ≤ 3 s (one token at 2/s) a call passes again`,
    async () => {
      if (missing) return bad(missing);
      await sleep(1000); // the bucket refills the token B26.app_initiated_real used
      const t0 = Date.now();
      const out: string[] = [];
      for (let i = 0; i < RATE_PROBES; i++) out.push((await realCall()).code);
      const ms = Date.now() - t0;
      const first = out.indexOf("rate_limited");
      const other = [...new Set(out.filter((x) => x !== "ok" && x !== "rate_limited"))];
      let after = { ok: false, code: "not tried" };
      for (const wait of [1500, 1500]) {
        await sleep(wait);
        after = await realCall();
        if (after.code !== "rate_limited") break;
      }
      const okN = out.filter((x) => x === "ok").length;
      return verdict(
        first >= RATE_BURST && other.length === 0 && after.ok,
        `${okN} ok of ${RATE_PROBES} in ${ms} ms; first rate_limited at call ${first < 0 ? "none" : first + 1}${other.length ? `; other answers [${other.join(", ")}]` : ""}; after the refill wait: ${after.code}; Retry-After is not observable through the SDK (callApp throws a TbError without the response headers)`,
      );
    },
  );

  await c.run("B26.app_initiated_audit", "app-initiated calls are audited in the bridge log", `the captured bridge log has ≥ one ${APP_INITIATED} line naming the real app's instance per app-initiated call answered ok, none of them with a parentCall id`, async () => {
    if (c.h.logs() === null) return notRun("the bridge's logs are not captured (run the bridge with --cmd or --start)");
    if (missing) return bad(missing);
    if (realOk === 0) return bad("no app-initiated call of the real app was answered ok (B26.app_initiated_real / _rate)");
    const lines = (await c.until(async () => {
      const l = audited(ins) ?? [];
      return l.length >= realOk ? l : null;
    }, c.h.timeoutMs, 100)).value ?? (audited(ins) ?? []);
    const withParent = lines.filter((l) => /"parentCall"\s*:\s*"/.test(l)).length;
    const anyApp = (c.h.logs() ?? "").split("\n").filter((l) => l.includes(APP_INITIATED)).length;
    return verdict(lines.length >= realOk && withParent === 0, `${realOk} app-initiated calls answered ok; ${lines.length} ${APP_INITIATED} lines name the real app's instance (${anyApp} in all)${withParent ? `; ${withParent} carry a parentCall id` : ""}`);
  });

  // parentCall rules (BRIDGE v0.1.14, A2A-10): fake app identities; the primary calls the peer over its companion edge
  const edge = p.manifest.companions?.[0];
  const pg = c.w.companionGrants.get(p.ins) ?? null;
  const edgeOp = edge?.operations[0];
  const prereq = !peer || !edge || !pg || !edgeOp ? "no companion edge between the primary and the peer app" : null;
  const nested = (parentCall: string) => {
    const peerApp = peer as FakeApp;
    const op = c.op(peerApp, edgeOp as string);
    return p.companion({ target: peerApp.product, op: edgeOp as string, input: c.input(peerApp, edgeOp as string) as Json, parentCall: parentCall as never, ...(op?.idempotency === "required" ? { idempotencyKey: c.idemKey() } : {}) }, pg);
  };
  const judge = async (a: HttpAnswer | null, before: number | null, extra: string): Promise<Outcome> => {
    if (!a) return bad(`nested call not made; ${extra}`);
    const logged = await auditedAfter(p.ins, before);
    return verdict(answeredOk(a) && logged !== false, `${status(a)} (want 200 ok, not hook_reentry / call_depth_exceeded); ${auditNote(logged)}; ${extra}`);
  };

  await c.run("B26.parent_call_forged", "a forged parentCall is ignored: the call is app-initiated", "companion call with parentCall = a call id the bridge never issued → 200 ok; audited call.app_initiated when the log is captured", async () => {
    if (prereq) return bad(prereq);
    const forged = `call_${ulid()}`;
    const before = audited(p.ins)?.length ?? null;
    return judge(await nested(forged), before, `parentCall ${forged} (random)`);
  });

  await c.run(
    "B26.parent_call_foreign",
    "another instance's in-flight call as parentCall is ignored",
    "while an agent call to the peer waits in the peer's own before hook, the primary calls with parentCall = that call id → 200 ok (not hook_reentry: the call is not in flight for the primary); audited call.app_initiated when the log is captured",
    async () => {
      if (prereq) return bad(prereq);
      const peerApp = peer as FakeApp;
      const outerOp = c.readOp(peerApp) ?? c.agentOps(peerApp)[0];
      const hook = outerOp ? chainFor(c, peerApp, outerOp, "before").find((h) => h.product === peerApp.product) : undefined;
      if (!outerOp || !hook) return bad("no peer agent op with a before hook of the peer itself");
      let started = false;
      let inner: HttpAnswer | null = null;
      let parent = "";
      peerApp.onHook = async (hookId, phase, body) => {
        const call = isObj(body.call) ? body.call : {};
        const target = isObj(call.target) ? call.target : {};
        if (!started && hookId === hook.hookId && phase === "before" && target.op === outerOp.id) {
          started = true;
          parent = String(call.id);
          inner = await nested(parent);
        }
        return { status: 200, body: phase === "before" ? { allow: true } : phase === "context" ? { add: {} } : {} };
      };
      try {
        const before = audited(p.ins)?.length ?? null;
        const outer = await c.call("free", peerApp, outerOp.id);
        return judge(inner, before, `parentCall = ${parent || "?"} (agent call to ${peerApp.product}.${outerOp.id}, inside ${hook.by}); outer ${describeCall(outer)}`);
      } finally {
        peerApp.onHook = null;
      }
    },
  );

  await c.run("B26.parent_call_expired", "a finished call of the caller as parentCall is ignored", "parentCall = the id of an agent call to the primary that has already answered → 200 ok; audited call.app_initiated when the log is captured", async () => {
    if (prereq) return bad(prereq);
    const read = c.readOp(p);
    if (!read) return bad("no read op on the primary app");
    let done = "";
    p.onOp = (info) => {
      done ||= info.call;
      return { status: 200, body: { status: "ok", output: { op: info.op } } };
    };
    let outer: ToolCallResult;
    try {
      outer = await c.call("free", p, read.id);
    } finally {
      p.onOp = null;
    }
    if (!c.isOk(outer) || !done) return bad(`the agent call that supplies the finished call id failed: ${describeCall(outer)}`);
    const before = audited(p.ins)?.length ?? null;
    return judge(await nested(done), before, `parentCall = ${done} (finished agent call ${p.product}.${read.id})`);
  });
}
