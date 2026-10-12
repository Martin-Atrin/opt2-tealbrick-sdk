// Bridge target, spec 0.1.24 (BRIDGE "v0.1.24 (C117, S1 fail-open: Rules hooks dropped after an update)"), group `c117`:
// the chain of a routed call comes from the hooks DECLARED in the manifests of the deployed apps; config `hooks[]` only
// carries the owner switch (`enabled`). A declared, matching hook that is absent from the config or whose app is down
// refuses the call (hook_failed, fail closed); `enabled: false` skips it. The hook under test is a before hook of the
// peer app (another deployed app) matching a read op of the primary app — picked by shape, no product id here.
import { bad, type Outcome, verdict } from "../suite.ts";
import { type BridgeCtx, describeCall, toolRefused } from "./bridge-ctx.ts";
import { BRIDGE_GROUPS } from "./bridge-ids.ts";
import { chainFor } from "./bridge-spine013.ts";

export async function c117Checks(c: BridgeCtx): Promise<void> {
  if (!c.on("c117")) return;
  const p = c.primary;
  const peer = c.peer;
  const read = c.readOp(p);
  const hook = peer && read ? chainFor(c, p, read, "before").find((h) => h.product === peer.product) : undefined;
  if (!peer || !read || !hook) {
    for (const x of BRIDGE_GROUPS.c117 ?? []) c.s.record(x.id, x.title, "a before hook of another deployed app matching a read op of the primary app", bad("no peer app / primary read op / matching peer before hook"));
    return;
  }
  for (const a of c.w.apps) {
    a.onHook = null;
    a.onOp = null;
  }
  const opCalls = (s0: number) => c.since(p, s0, "op").filter((r) => r.name === read.id).length;
  const hookCalls = (s0: number) => c.since(peer, s0, "hook").filter((r) => r.name === hook.hookId).length;
  /** runs `fn` with the hook's config entry in `state` (absent / disabled); the default config is restored after */
  const withEntry = async (state: "absent" | "disabled", fn: () => Promise<Outcome>): Promise<Outcome> => {
    c.w.hookState.set(hook.id, state);
    try {
      const { acked } = await c.apply();
      if (!acked) return bad(`config without ${state === "absent" ? "the entry" : "enabled"} not acknowledged`);
      return await fn();
    } finally {
      c.w.hookState.delete(hook.id);
      await c.apply();
    }
  };

  await c.run(
    "B27.hook_declared_absent",
    "a declared hook absent from config hooks[] refuses the call (C117)",
    `${hook.by} (before, declared in its manifest, matches ${p.product}.${read.id}) left out of config hooks[] → isError hook_failed; ${p.product} receives no op call; the next status report lists rejected {kind: config, code: hook_not_listed, ins: ${peer.product}'s instance} (BRIDGE v0.1.25)`,
    () =>
      withEntry("absent", async () => {
        const s0 = c.w.seqNow();
        const acks0 = c.w.portal.acks.length;
        const a = await c.call("free", p, read.id);
        const o = toolRefused(a, ["hook_failed"]);
        const n = opCalls(s0);
        // a new revision (same state) forces the next status report
        await c.apply();
        const listed = (x: { kind: string; code: string; ins?: string }) => x.kind === "config" && x.code === "hook_not_listed" && x.ins === peer.ins;
        const reported = (await c.until(async () => c.w.portal.acks.slice(acks0).some((x) => (x.rejected ?? []).some(listed)), c.h.timeoutMs)).value === true;
        return verdict(o.pass === true && n === 0 && reported, `${o.asserted}; op calls ${n}${n ? " (FORWARDED without the declared hook)" : ""}; rejected hook_not_listed with the hook app's ins ${reported ? "reported" : "NOT reported"}`);
      }),
  );

  await c.run(
    "B27.hook_disabled_skipped",
    "a declared hook listed with enabled: false is skipped (C117)",
    `${hook.by} listed with enabled: false → ${p.product}.${read.id} ok, forwarded once; ${peer.product} receives no ${hook.hookId} hook call`,
    () =>
      withEntry("disabled", async () => {
        const s0 = c.w.seqNow();
        const a = await c.call("free", p, read.id);
        const n = opCalls(s0);
        const h = hookCalls(s0);
        return verdict(c.isOk(a) && n === 1 && h === 0, `${describeCall(a)}; op calls ${n}; ${hook.hookId} calls ${h}`);
      }),
  );

  await c.run(
    "B27.hook_app_down",
    "a declared, enabled hook whose app is down refuses the call (C117)",
    `${peer.product} stopped (connection refused), ${hook.by} listed enabled → isError hook_failed; ${p.product} receives no op call`,
    async () => {
      await peer.stop();
      try {
        const s0 = c.w.seqNow();
        const a = await c.call("free", p, read.id);
        const o = toolRefused(a, ["hook_failed"]);
        const n = opCalls(s0);
        return verdict(o.pass === true && n === 0, `${o.asserted}; op calls ${n}${n ? " (FORWARDED without the hook)" : ""}`);
      } finally {
        await peer.start();
      }
    },
  );
}
