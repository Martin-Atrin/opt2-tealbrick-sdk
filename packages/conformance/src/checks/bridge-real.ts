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
import type { ToolCallResult } from "../mcp-agent.ts";
import { loadSdk, REAL_ENTRIES, REAL_OPS, type RealRunningApp, realAppManifest, startRealApp } from "../real-app.ts";
import { bad, notRun, type Outcome, verdict } from "../suite.ts";
import { newId, nowS } from "../tokens.ts";
import { type BridgeCtx, describeCall, toolRefused } from "./bridge-ctx.ts";
import { BRIDGE_GROUPS } from "./bridge-ids.ts";

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

  const manifest = realAppManifest(c.primary.manifest, REAL_PRODUCT, port);
  const ins = newId("ins") as InstanceId;
  const dataDir = mkdtempSync(join(tmpdir(), "tb-conformance-real-"));
  mkdirSync(join(dataDir, "backup"), { recursive: true });
  let running: RealRunningApp | null = null;
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
  } finally {
    await running?.stop().catch(() => undefined);
    // the app is removed again (Core undeploy): later groups see the original world
    c.w.realApp = null;
    await c.apply().catch(() => undefined);
    rmSync(dataDir, { recursive: true, force: true });
  }
}
