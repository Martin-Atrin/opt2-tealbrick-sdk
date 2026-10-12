// Fake Portal: bridge-auth + device-auth rows only (default deny), enrolment, config long-poll, ack, device flow.
import assert from "node:assert/strict";
import { after, before, describe, it } from "node:test";
import { type Ed25519KeyPair, generateKeyPair, keySetFrom, signAssertion, verifyConfig } from "@opt2-tealbrick/manifest";
import { createFakePortal, FAKE_PORTAL_ROUTES, type FakePortal } from "../src/index.ts";

const now = () => Math.floor(Date.now() / 1000);

describe("fake portal", () => {
  let p: FakePortal;
  let key: Ed25519KeyPair;
  const call = async (method: string, path: string, body?: unknown, assert_ = true) => {
    const bytes = body === undefined ? undefined : new TextEncoder().encode(JSON.stringify(body));
    const headers: Record<string, string> = { "content-type": "application/json" };
    if (assert_) {
      const brg = `tb:brg:${p.bridgeId}` as const;
      headers["TB-Assert"] = await signAssertion("tb-bridge-assert+jwt", { iss: brg, sub: brg, aud: "tb:portal", iat: now() }, key, { method, pathAndQuery: path, body: bytes });
    }
    const res = await fetch(p.url + path, { method, headers, body: bytes });
    const text = await res.text();
    return { status: res.status, type: res.headers.get("content-type") ?? "", text, body: text.startsWith("{") ? JSON.parse(text) : null };
  };
  before(async () => {
    p = await createFakePortal({ pollIntervalS: 0, maxWaitS: 1 });
    key = await generateKeyPair();
  });
  after(() => p.close());

  it("serves only bridge/device rows (+ their public starts); everything else 404", async () => {
    assert.deepEqual(FAKE_PORTAL_ROUTES.map((r) => r.opId).sort(), ["bridge_api.ack", "bridge_api.config", "bridge_api.enrol", "device.start", "device.token"]);
    for (const [m, path] of [["GET", "/api/v1/workspaces"], ["GET", "/internal/routes"], ["POST", "/api/v1/device/approve"], ["GET", "/api/v1/me"]]) {
      assert.equal((await call(m, path, undefined, false)).status, 404, path);
    }
  });

  it("enrolment: one-time code, own key; config requires the bridge assertion", async () => {
    const code = p.control.issueEnrolCode();
    const body = { code, publicKey: key.publicJwk, version: "1.0.0", sdkMajors: [1, 0], form: "deployed", publicOrigin: "https://bridge.conformance.test" };
    assert.equal((await call("GET", "/api/v1/bridge/config?after=0&wait=0")).status, 401, "not enrolled yet");
    const r = await call("POST", "/api/v1/bridge/enrol", body, false);
    assert.equal(r.status, 200);
    assert.equal(r.body.bridgeId, p.bridgeId);
    assert.equal((await call("POST", "/api/v1/bridge/enrol", body, false)).body.error.code, "enrolment_code_invalid");
    const unsigned = await call("GET", "/api/v1/bridge/config?after=0&wait=0", undefined, false);
    assert.equal(unsigned.status, 401);
  });

  it("config long-poll: 200 application/jose when newer, 304 after the wait, woken by a new revision", async () => {
    const first = await call("GET", "/api/v1/bridge/config?after=0&wait=1");
    assert.equal(first.status, 200);
    assert.match(first.type, /application\/jose/);
    const v = verifyConfig(first.text, { now: now(), self: `tb:brg:${p.bridgeId}`, issuers: keySetFrom({ keys: [p.activeKey().publicJwk] }, "tb:portal") });
    assert.ok(v.ok);
    const idle = await call("GET", `/api/v1/bridge/config?after=${p.rev}&wait=1`);
    assert.equal(idle.status, 304);
    const pending = call("GET", `/api/v1/bridge/config?after=${p.rev}&wait=1`);
    const agt = await p.control.addAgent("Agent X");
    const woken = await pending;
    assert.equal(woken.status, 200);
    const cfg = verifyConfig(woken.text, { now: now(), self: `tb:brg:${p.bridgeId}`, issuers: keySetFrom({ keys: [p.activeKey().publicJwk] }, "tb:portal") });
    assert.ok(cfg.ok && (cfg.body as { agents: { agt: string }[] }).agents.some((a) => a.agt === agt));
  });

  it("ack: recorded with the bridge assertion", async () => {
    const report = { rev: p.rev, appliedAt: new Date().toISOString(), bridge: { id: p.bridgeId, version: "1.0.0", form: "deployed", boot: "b1", sdkMajors: [1], mcpVersions: [] }, portalReachable: true, apps: [], keys: [], scopeSummaries: [], connectionsCreated: [], connectionsRevoked: [], claims: [], rejected: [], toolsOmitted: [] };
    const r = await call("POST", "/api/v1/bridge/ack", report);
    assert.deepEqual(r.body, { accepted: true, configRevision: p.rev });
    assert.equal(p.acks.length, 1);
  });

  it("device flow: kit cannot get owner; pending → approved → one-time; agent scope creates connections", async () => {
    const kitOwner = await call("POST", "/api/v1/device/authorize", { scope: "owner", client_id: "kit", machine_label: "m" }, false);
    assert.equal(kitOwner.body.error.code, "bad_request");
    const ownerKey = await call("POST", "/api/v1/device/authorize", { scope: "owner", client_id: "tbd", machine_label: "m", agents: [] }, false);
    assert.equal(ownerKey.status, 400);
    const agentKey = await generateKeyPair();
    const start = await call("POST", "/api/v1/device/authorize", { scope: "agent", client_id: "kit", machine_label: "mac", harness: "generic", agents: [{ public_key: agentKey.publicJwk }] }, false);
    assert.equal(start.status, 200);
    assert.match(start.body.user_code, /^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$/);
    const tok = { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.body.device_code, client_id: "kit" };
    assert.equal((await call("POST", "/api/v1/device/token", tok, false)).body.error.code, "authorization_pending");
    await p.control.approveDevice(start.body.user_code);
    const done = await call("POST", "/api/v1/device/token", tok, false);
    assert.equal(done.body.scope, "agent");
    assert.equal(done.body.bridge_id, p.bridgeId);
    assert.equal(done.body.connections.length, 1);
    assert.equal("access_token" in done.body, false, "agent scope carries no bearer");
    assert.equal((await call("POST", "/api/v1/device/token", tok, false)).body.error.code, "expired_token");
    const owner = await call("POST", "/api/v1/device/authorize", { scope: "owner", client_id: "tealbrick-cli", machine_label: "m" }, false);
    p.control.denyDevice(owner.body.user_code);
    assert.equal((await call("POST", "/api/v1/device/token", { ...tok, device_code: owner.body.device_code, client_id: "tealbrick-cli" }, false)).body.error.code, "access_denied");
  });

  it("slow_down when polled faster than the interval; offline drops connections", async () => {
    const q = await createFakePortal({ pollIntervalS: 5 });
    try {
      const start = await (await fetch(`${q.url}/api/v1/device/authorize`, { method: "POST", body: JSON.stringify({ scope: "owner", client_id: "tbd", machine_label: "m" }) })).json();
      const tok = JSON.stringify({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.device_code, client_id: "tbd" });
      const a = await (await fetch(`${q.url}/api/v1/device/token`, { method: "POST", body: tok })).json();
      const b = await (await fetch(`${q.url}/api/v1/device/token`, { method: "POST", body: tok })).json();
      assert.equal(a.error.code, "authorization_pending");
      assert.equal(b.error.code, "slow_down");
      q.control.goOffline(true);
      await assert.rejects(fetch(`${q.url}/api/v1/device/token`, { method: "POST", body: tok }));
    } finally {
      await q.close();
    }
  });

  it("key rotation reaches the config even when a world froze portalKeys into configExtra (Lead · Bridge finding, C5)", async () => {
    const q = await createFakePortal({ pollIntervalS: 0, maxWaitS: 1 });
    try {
      // what BridgeWorld.publish() does: freeze the current key list into configExtra (merged last)
      q.configExtra = { ...q.configExtra, portalKeys: q.keys.map((k) => ({ jwk: k.key.publicJwk, status: k.status })) };
      const statuses = () => (q.configBody(q.rev).portalKeys ?? []).map((k) => k.status);
      assert.deepEqual(statuses(), ["active"]);
      await q.control.rotateKey("announce");
      assert.deepEqual(statuses(), ["active", "pending"], "announce carries the pending key");
      await q.control.rotateKey("activate");
      assert.deepEqual(statuses(), ["retired", "active"], "activate applied");
      await q.control.rotateKey("retire");
      assert.deepEqual(statuses(), ["active"], "retired key dropped");
      // standalone worlds keep their empty list
      q.configExtra = { ...q.configExtra, portalKeys: [] };
      await q.control.rotateKey("announce");
      assert.deepEqual(statuses(), []);
    } finally {
      await q.close();
    }
  });
});
