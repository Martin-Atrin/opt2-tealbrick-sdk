// Coordinator C31 / C33 additions: ctx.secrets, publicUrl/workspace/scopes on contexts, onStart, real callServiceHelper.
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { test } from "node:test";
import { keySetFrom, verifyAssertion } from "@opt2-tealbrick/manifest";
import { TYP } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { defineApp, type SdkOpContext, type StartContext, startApp, TbError } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { callProof, FakeBridge, freePort, grant, migrationsDir, slice, tempDir, until, world } from "./helpers.ts";

test("onStart runs after claim; ctx.secrets seals values; helper calls carry an instance assertion", async () => {
  const w = await world();
  const t = tempDir();
  const port = await freePort();
  const helperPort = await freePort();
  const seen: { assert?: string; body?: string; path?: string } = {};
  const helperServer = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    seen.assert = String(req.headers["tb-assert"] ?? "");
    seen.body = Buffer.concat(chunks).toString("utf8");
    seen.path = req.url ?? "";
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ provisioned: true }));
  });
  await new Promise<void>((r) => helperServer.listen(helperPort, "127.0.0.1", r));

  const manifest: Manifest = fixtureManifest(port);
  manifest.runtime.env = [{ name: "JOTTER_IDX_URL", value: "{{services.idx.url}}" }];
  manifest.runtime.services = [
    {
      id: "idx",
      build: { context: ".", dockerfile: "services/idx/Dockerfile" },
      port: 7700,
      resources: { cpu: 0.25, memoryMb: 256 },
      health: { kind: "tcp" },
      startOrder: 0,
      helper: { port: helperPort, paths: ["/v1/provision"] },
    },
  ];
  const bridge = new FakeBridge(w);
  const bridgeUrl = await bridge.start(await slice(w, "jotter"));
  let started: StartContext | null = null;
  let opCtx: SdkOpContext | null = null;
  const app = defineApp({
    manifest,
    migrations: migrationsDir(t.dir),
    onStart: async (ctx) => {
      started = ctx;
    },
    handlers: {
      note_create: { scope: () => null, run: async () => ({ id: "x" }) },
      note_get: async (_input, ctx) => {
        opCtx = ctx as SdkOpContext;
        await opCtx.secrets.put("oauth/token", "s3cret-value");
        return { secret: await opCtx.secrets.get("oauth/token"), workspace: opCtx.workspace } as Json;
      },
      note_delete: async () => ({}),
      notebook_rename: async () => ({}),
    },
  });
  const running = await startApp(app, {
    TB_INSTANCE_ID: w.ins,
    TB_ENROL_CODE: "tbe_test",
    TB_BRIDGE_URL: bridgeUrl,
    TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }),
    TB_DATA_DIR: t.dir,
    TB_LOG_LEVEL: "error",
    JOTTER_IDX_URL: `http://127.0.0.1:7700`,
  });
  try {
    const ctx = await until(async () => started);
    assert.equal(typeof ctx.scopes.instances.create, "function");

    // real helper call: POST to <service host>:<helper.port><path> with TB-Assert bound to method/path/body
    const out = await ctx.callServiceHelper("idx", "/v1/provision", { source: "s1" });
    assert.deepEqual(out, { provisioned: true });
    assert.equal(seen.path, "/v1/provision");
    assert.equal(seen.body, JSON.stringify({ source: "s1" }));
    assert.ok(bridge.instanceKey, "claim carried the instance public key");
    const v = verifyAssertion(seen.assert ?? "", keySetFrom({ keys: [bridge.instanceKey] }, `tb:ins:${w.ins}`), {
      typ: TYP.instanceAssertion,
      aud: `tb:brg:${w.brg}`,
      now: Math.floor(Date.now() / 1000),
      method: "POST",
      pathAndQuery: "/v1/provision",
      body: new TextEncoder().encode(seen.body ?? ""),
    });
    assert.equal(v.ok, true, JSON.stringify(v));
    await assert.rejects(ctx.callServiceHelper("idx", "/undeclared", {}), (e: unknown) => e instanceof TbError && e.code === "helper_path_undeclared");

    // ctx.secrets round trip + workspace on the op context
    const g = await grant(w, w.agents.a);
    const res = await fetch(`http://127.0.0.1:${port}/tb/v1/ops/note_get`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${g}`, "tb-call": await callProof(w, g, "note_get", { id: "1" }) },
      body: JSON.stringify({ input: { id: "1" }, context: {} }),
    });
    const body = (await res.json()) as { output: { secret: string; workspace: string } };
    assert.equal(res.status, 200);
    assert.equal(body.output.secret, "s3cret-value");
    assert.equal(body.output.workspace, w.ws);
    const oc = opCtx as SdkOpContext | null;
    assert.ok(oc);
    assert.equal(oc.publicUrl, null);
    await oc.secrets.delete("oauth/token");
    assert.equal(await oc.secrets.get("oauth/token"), null);
    await assert.rejects(oc.secrets.put("bad name!", "x"), (e: unknown) => e instanceof TbError && e.code === "secret_name_invalid");
  } finally {
    await running.stop();
    await bridge.stop();
    helperServer.closeAllConnections();
    helperServer.close();
    t.cleanup();
  }
});
