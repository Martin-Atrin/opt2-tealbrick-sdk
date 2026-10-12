// v0.1.12 claim guard (spine S1): mountinfo parser + mount rule, the first-claim gate (an unmounted TB_DATA_DIR never
// redeems the one-time code), the boot mount line, and the reclaim rule (refused identity + NEW code → fresh claim).
import assert from "node:assert/strict";
import { realpathSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, test } from "node:test";
import type { Json, Logger } from "@opt2-tealbrick/spec/sdk";
import {
  enrolCodeDigest,
  identityRefused,
  judgeMount,
  logMountAtBoot,
  mountFields,
  parseMountinfo,
  probeDataDir,
  reclaimCode,
  waitForMountedDataDir,
} from "../src/server/claim-guard.ts";
import { TbError } from "../src/server/errors.ts";
import { defineApp, startApp } from "../src/server/index.ts";
import { fixtureManifest } from "./fixtures/manifest.ts";
import { FakeBridge, freePort, migrationsDir, slice, tempDir, testRoots, until, world } from "./helpers.ts";

// container with a volume at /data (ext4) and the usual Docker extras
const VOLUME = `
611 540 0:63 / / rw,relatime master:301 - overlay overlay rw,lowerdir=/var/lib/docker/overlay2/l/A:/var/lib/docker/overlay2/l/B,upperdir=/u,workdir=/w
612 611 0:66 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
613 611 0:67 / /dev rw,nosuid - tmpfs tmpfs rw,size=65536k,mode=755
620 611 259:1 /var/lib/docker/volumes/vol_1/_data /data rw,relatime - ext4 /dev/nvme0n1p1 rw
621 611 259:1 /var/lib/docker/containers/abc/hosts /etc/hosts rw,relatime - ext4 /dev/nvme0n1p1 rw
622 613 0:70 / /dev/shm rw,nosuid,nodev,noexec,relatime - tmpfs shm rw,size=65536k
`;
// the same container started before the volume existed: /data lives on the overlay root
const NO_VOLUME = `
611 540 0:63 / / rw,relatime master:301 - overlay overlay rw,lowerdir=/l,upperdir=/u,workdir=/w
612 611 0:66 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw
621 611 259:1 /var/lib/docker/containers/abc/hosts /etc/hosts rw,relatime - ext4 /dev/nvme0n1p1 rw
`;

const silent: Logger = { debug: () => undefined, info: () => undefined, warn: () => undefined, error: () => undefined };
function recorder(): { log: Logger; lines: { level: string; msg: string; fields?: Record<string, Json> }[] } {
  const lines: { level: string; msg: string; fields?: Record<string, Json> }[] = [];
  const at = (level: string) => (msg: string, fields?: Record<string, Json>) => void lines.push({ level, msg, ...(fields ? { fields } : {}) });
  return { log: { debug: at("debug"), info: at("info"), warn: at("warn"), error: at("error") }, lines };
}

describe("parseMountinfo", () => {
  test("mount points and fs types, optional fields and octal escapes; malformed lines skipped", () => {
    const e = parseMountinfo(`${VOLUME}\n36 35 98:0 /mnt1 /my\\040vol rw,noatime master:1 shared:2 - xfs /dev/sdb rw\ngarbage line\n1 2 3\n`);
    assert.deepEqual(
      e.map((x) => `${x.mountPoint}|${x.fsType}`),
      ["/|overlay", "/proc|proc", "/dev|tmpfs", "/data|ext4", "/etc/hosts|ext4", "/dev/shm|tmpfs", "/my vol|xfs"],
    );
    assert.deepEqual(parseMountinfo(""), []);
  });
});

describe("judgeMount (the rule: nearest mount ≠ / and not overlay/tmpfs)", () => {
  test("volume mounted at /data: the data dir itself and a path under it are mounted", () => {
    const e = parseMountinfo(VOLUME);
    assert.deepEqual(judgeMount("/data", e), { dataDir: "/data", mounted: true, mountPoint: "/data", fsType: "ext4" });
    assert.equal(judgeMount("/data/app/db", e).mounted, true);
    assert.equal(judgeMount("/data/app/db", e).mountPoint, "/data");
  });
  test("no volume: /data on the overlay root is NOT mounted; a sibling prefix (/database) does not match /data", () => {
    assert.deepEqual(judgeMount("/data", parseMountinfo(NO_VOLUME)), { dataDir: "/data", mounted: false, mountPoint: "/", fsType: "overlay" });
    assert.deepEqual(judgeMount("/database", parseMountinfo(VOLUME)), { dataDir: "/database", mounted: false, mountPoint: "/", fsType: "overlay" });
  });
  test("nested: a tmpfs under the volume wins for paths below it; a memory fs is never a volume", () => {
    const e = parseMountinfo(`${VOLUME}\n630 620 0:80 / /data/tmp rw - tmpfs tmpfs rw\n`);
    assert.equal(judgeMount("/data/tmp/x", e).mounted, false);
    assert.equal(judgeMount("/data/tmp/x", e).fsType, "tmpfs");
    assert.equal(judgeMount("/data/keep", e).mounted, true);
    assert.equal(judgeMount("/dev/shm/tb", e).mounted, false);
  });
  test("stacked mounts on one mount point: the later (top) entry counts; a bare-metal root (/ ext4) is not a volume", () => {
    const stacked = parseMountinfo(`${VOLUME}\n640 620 0:81 / /data rw - tmpfs tmpfs rw\n`);
    assert.equal(judgeMount("/data", stacked).mounted, false);
    assert.equal(judgeMount("/srv/data", parseMountinfo("1 0 8:1 / / rw - ext4 /dev/sda1 rw\n")).mounted, false);
    assert.deepEqual(judgeMount("/data", []), { dataDir: "/data", mounted: false, mountPoint: null, fsType: null });
  });
});

describe("probeDataDir / logMountAtBoot", () => {
  test("no mountinfo (macOS, non-Linux) → unknown; a fixture file is read and the real path judged", () => {
    const t = tempDir();
    try {
      assert.equal(probeDataDir(t.dir, join(t.dir, "missing")).mounted, null);
      const real = realpathSync(t.dir);
      const file = join(t.dir, "mountinfo");
      writeFileSync(file, `${NO_VOLUME}\n700 611 8:2 / ${real} rw - ext4 /dev/sdc rw\n`);
      const s = probeDataDir(join(t.dir, "not-yet-created", "data"), file);
      assert.deepEqual(s, { dataDir: join(real, "not-yet-created", "data"), mounted: true, mountPoint: real, fsType: "ext4" });
    } finally {
      t.cleanup();
    }
  });
  test("one info line with dataDir, mounted, mount point and fs type (unknown / skipped states named)", () => {
    const t = tempDir();
    try {
      const r = recorder();
      logMountAtBoot(t.dir, { ephemeral: false, mountinfoPath: join(t.dir, "missing"), log: r.log });
      logMountAtBoot(t.dir, { ephemeral: true, mountinfoPath: join(t.dir, "missing"), log: r.log });
      assert.equal(r.lines.length, 2);
      assert.deepEqual(r.lines.map((l) => [l.level, l.msg, l.fields?.mounted, l.fields?.firstClaimCheck]), [
        ["info", "data_dir_mount", "unknown", "skipped (no mountinfo)"],
        ["info", "data_dir_mount", "unknown", "skipped (TB_DATA_EPHEMERAL=1)"],
      ]);
      assert.deepEqual(mountFields({ dataDir: "/data", mounted: false, mountPoint: "/", fsType: "overlay" }, false), { dataDir: "/data", mounted: false, mountPoint: "/", fsType: "overlay", ephemeralAllowed: false });
    } finally {
      t.cleanup();
    }
  });
});

describe("waitForMountedDataDir (first-claim gate)", () => {
  test("blocks while not mounted (retries with backoff), proceeds once the volume appears", async () => {
    const t = tempDir();
    try {
      const real = realpathSync(t.dir);
      const file = join(t.dir, "mountinfo");
      writeFileSync(file, NO_VOLUME);
      const r = recorder();
      const blocked: boolean[] = [];
      const p = waitForMountedDataDir(t.dir, { ephemeral: false, mountinfoPath: file, log: r.log, signal: new AbortController().signal, onBlocked: (b) => blocked.push(b), minMs: 20, maxMs: 40 });
      await until(async () => r.lines.length >= 2);
      writeFileSync(file, `${NO_VOLUME}\n700 611 8:2 / ${real} rw - ext4 /dev/sdc rw\n`);
      assert.equal(await p, true);
      assert.equal(blocked.at(-1), false);
      assert.ok(blocked.includes(true));
      assert.equal(r.lines[0]?.msg, "data_dir_not_mounted");
      assert.equal(r.lines[0]?.fields?.retryInMs, 20);
      assert.equal(r.lines[1]?.fields?.retryInMs, 40);
    } finally {
      t.cleanup();
    }
  });
  test("TB_DATA_EPHEMERAL=1 and an unknown mount state pass at once; abort → false", async () => {
    const t = tempDir();
    try {
      const file = join(t.dir, "mountinfo");
      writeFileSync(file, NO_VOLUME);
      const sig = new AbortController().signal;
      assert.equal(await waitForMountedDataDir(t.dir, { ephemeral: true, mountinfoPath: file, log: silent, signal: sig }), true);
      assert.equal(await waitForMountedDataDir(t.dir, { ephemeral: false, mountinfoPath: join(t.dir, "missing"), log: silent, signal: sig }), true);
      const ac = new AbortController();
      const p = waitForMountedDataDir(t.dir, { ephemeral: false, mountinfoPath: file, log: silent, signal: ac.signal, minMs: 10_000 });
      ac.abort();
      assert.equal(await p, false);
    } finally {
      t.cleanup();
    }
  });
});

describe("reclaim rule", () => {
  test("only a refused identity (401 unauthenticated) counts", () => {
    assert.equal(identityRefused(new TbError("unauthenticated", "x", 401)), true);
    assert.equal(identityRefused(new TbError("paused", "x", 403)), false);
    assert.equal(identityRefused(new TbError("unauthenticated", "x", 503)), false);
    assert.equal(identityRefused(new Error("unauthenticated")), false);
  });
  test("new code (digest differs, or a pre-0.1.12 record without digest) → once; same code, no code, tried code → never", () => {
    const tried = new Set<string>();
    assert.match(enrolCodeDigest("tbe_a"), /^sha256:[0-9a-f]{64}$/);
    assert.equal(reclaimCode("tbe_a", enrolCodeDigest("tbe_a"), tried), null);
    assert.equal(reclaimCode(null, enrolCodeDigest("tbe_a"), tried), null);
    assert.equal(reclaimCode("tbe_b", enrolCodeDigest("tbe_a"), tried), "tbe_b");
    assert.equal(reclaimCode("tbe_b", enrolCodeDigest("tbe_a"), tried), null, "each code is tried once per process");
    assert.equal(reclaimCode("tbe_c", undefined, tried), "tbe_c");
    assert.deepEqual([...tried], [enrolCodeDigest("tbe_b"), enrolCodeDigest("tbe_c")]);
  });
});

// ── startApp end to end ──
const PRODUCT = "jotter";
function app(port: number, migrations: string) {
  const ok = async () => ({});
  return defineApp({ manifest: fixtureManifest(port), migrations, handlers: { note_create: { scope: () => "n", run: ok }, note_get: ok, note_delete: ok, notebook_rename: ok } });
}

describe("startApp claim guard", () => {
  test("an unmounted TB_DATA_DIR does not redeem the code: needs_claim + attention data_dir_not_mounted, wire not touched", async () => {
    const w = await world();
    const t = tempDir();
    const bridge = new FakeBridge(w);
    const url = await bridge.start(await slice(w, PRODUCT));
    const port = await freePort();
    const file = join(t.dir, "mountinfo");
    writeFileSync(file, NO_VOLUME);
    const env = { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_first", TB_BRIDGE_URL: url, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_LOG_LEVEL: "error" };
    const running = await startApp(app(port, migrationsDir(t.dir)), env, { ...testRoots(w), mountinfoPath: file });
    try {
      const h = await until(async () => {
        const r = (await (await fetch(`http://127.0.0.1:${port}/tb/v1/health`)).json()) as { status: string; attention?: string };
        return r.attention ? r : null;
      });
      assert.deepEqual([h.status, h.attention], ["needs_claim", "data_dir_not_mounted"]);
      await new Promise((r) => setTimeout(r, 300));
      assert.equal(bridge.claims, 0, "the one-time code was not sent");
      assert.equal(running.status(), "needs_claim");
    } finally {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    }
  });

  test("a mounted TB_DATA_DIR (no escape hatch) claims normally and stores only the code digest", async () => {
    const w = await world();
    const t = tempDir();
    const bridge = new FakeBridge(w);
    const url = await bridge.start(await slice(w, PRODUCT));
    const port = await freePort();
    const file = join(t.dir, "mountinfo");
    writeFileSync(file, `${NO_VOLUME}\n700 611 8:2 / ${realpathSync(t.dir)} rw - ext4 /dev/sdc rw\n`);
    const env = { TB_INSTANCE_ID: w.ins, TB_ENROL_CODE: "tbe_first", TB_BRIDGE_URL: url, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_LOG_LEVEL: "error" };
    const running = await startApp(app(port, migrationsDir(t.dir)), env, { ...testRoots(w), mountinfoPath: file });
    try {
      await until(async () => running.status() === "ok");
      assert.equal(bridge.claims, 1);
      const h = (await (await fetch(`http://127.0.0.1:${port}/tb/v1/health`)).json()) as Record<string, unknown>;
      assert.equal(h.status, "ok");
      assert.ok(!("attention" in h));
    } finally {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    }
  });

  test("refused identity: a NEW code → one fresh claim (app data kept); the same code → no claim, identity_refused", async () => {
    const w = await world();
    const t = tempDir();
    const bridge = new FakeBridge(w);
    bridge.oneTimeCodes = true;
    const url = await bridge.start(await slice(w, PRODUCT));
    const port = await freePort();
    const migrations = migrationsDir(t.dir);
    const base = { TB_INSTANCE_ID: w.ins, TB_BRIDGE_URL: url, TB_PORTAL_KEYS: JSON.stringify({ keys: [w.portal.publicJwk] }), TB_DATA_DIR: t.dir, TB_DATA_EPHEMERAL: "1", TB_LOG_LEVEL: "error" };
    const boot = (code: string) => startApp(app(port, migrations), { ...base, TB_ENROL_CODE: code }, testRoots(w));
    let running = await boot("tbe_first");
    try {
      await until(async () => running.status() === "ok");
      const key = bridge.instanceKey;
      await running.stop();

      // Core dropped the identity; the owner's Retry re-issued the code → a fresh claim with the new code
      bridge.refuseIdentity = true;
      running = await boot("tbe_second");
      await until(async () => bridge.claims === 2 && running.status() === "ok", 8000);
      assert.deepEqual(bridge.claimCodes, ["tbe_first", "tbe_second"]);
      assert.deepEqual(bridge.instanceKey, key, "same sealed instance key");
      const claims = (await running.audit.list({ action: "claim.complete" })).items.map((e) => e.detail);
      assert.deepEqual(claims, [{ bridge: w.brg, reclaim: true }, { bridge: w.brg }], "the store (audit) survived; the reclaim is audited");
      await running.stop();

      // refused again, but the code is the one the stored record was claimed with → keep refusing, no claim
      bridge.refuseIdentity = true;
      running = await boot("tbe_second");
      const h = await until(async () => {
        const r = (await (await fetch(`http://127.0.0.1:${port}/tb/v1/health`)).json()) as { status: string; attention?: string };
        return r.attention ? r : null;
      });
      assert.deepEqual([h.status, h.attention], ["needs_claim", "identity_refused"]);
      await new Promise((r) => setTimeout(r, 1500));
      assert.equal(bridge.claims, 2);
    } finally {
      await running.stop();
      await bridge.stop();
      t.cleanup();
    }
  });
});

test("v0.1.12: any FUSE fs is ephemeral; a Railway-style ext4 /data mount is a volume (Core reading qa1)", () => {
  const railway = "1 0 0:1 / / rw - overlay overlay rw\n2 1 230:9984 / /data rw,relatime - ext4 /dev/zd9984 rw\n";
  assert.equal(judgeMount("/data", parseMountinfo(railway)).mounted, true);
  assert.equal(judgeMount("/data/app", parseMountinfo(railway)).mounted, true);
  assert.equal(judgeMount("/srv", parseMountinfo(railway)).mounted, false);
  const fuse = "1 0 0:1 / / rw - ext4 /dev/sda1 rw\n2 1 0:50 / /data rw - fuse.sshfs host:/x rw\n3 1 0:51 / /mnt rw - fuse /dev/fuse rw\n";
  assert.equal(judgeMount("/data", parseMountinfo(fuse)).mounted, false);
  assert.equal(judgeMount("/mnt/x", parseMountinfo(fuse)).mounted, false);
});
