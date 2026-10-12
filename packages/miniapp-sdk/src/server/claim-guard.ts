// Claim guard (SDK-API §13 v0.1.12 addition, REQUESTS "spine S1"): the ONE module startApp and tb-exec use to
// (1) refuse a FIRST claim while TB_DATA_DIR is not on a mounted volume (a claim on the container's ephemeral disk
// redeems the one-time code and loses the identity with the container), (2) log the data-dir mount state at boot and
// (3) decide when a refused stored identity may be replaced by a claim with a new enrolment code.
import { readFileSync, realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { digestEqual, opaqueDigest } from "@opt2-tealbrick/manifest";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";

export const MOUNTINFO_PATH = "/proc/self/mountinfo";

/**
 * Filesystems that never hold a persistent volume: the container's own root (overlay / aufs / fuse-overlayfs) and
 * memory filesystems. A data dir whose nearest mount has one of these types is "not mounted".
 */
export const EPHEMERAL_FS_TYPES: ReadonlySet<string> = new Set(["overlay", "aufs", "tmpfs", "ramfs", "devtmpfs"]);

/**
 * True when `fsType` cannot hold a persistent volume: {@link EPHEMERAL_FS_TYPES} or any FUSE type (`fuse`, `fuse.*`,
 * e.g. fuse-overlayfs). Railway (Core reading, qa1 2026-10-12): `/data` is its own ext4 mount, `/` is overlay. No
 * allow-list of fs types or devices is kept on purpose.
 */
export function isEphemeralFs(fsType: string): boolean {
  return EPHEMERAL_FS_TYPES.has(fsType) || fsType === "fuse" || fsType.startsWith("fuse.");
}

/** Retry of the mount check before the first claim: 5 s, doubling, at most 60 s. */
export const MOUNT_RETRY_MIN_MS = 5000;
export const MOUNT_RETRY_MAX_MS = 60_000;

/** needs_attention codes (health detail `attention`, logs); on the wire (AppStatus.readiness) both are `degraded`. */
export type AttentionCode = "data_dir_not_mounted" | "identity_refused";

export interface MountEntry {
  mountPoint: string;
  fsType: string;
}

export interface MountState {
  /** TB_DATA_DIR, resolved (symlinks followed where the path exists) */
  dataDir: string;
  /** true: on a mounted volume; false: on the container root or a memory fs; null: unknown (no mountinfo) */
  mounted: boolean | null;
  /** mount point of the nearest (longest matching) mount, or null when unknown */
  mountPoint: string | null;
  fsType: string | null;
}

/** mountinfo escapes space, tab, newline and backslash as `\ooo` octal. */
function unescapeOctal(s: string): string {
  return s.replace(/\\([0-7]{3})/g, (_, o: string) => String.fromCharCode(Number.parseInt(o, 8)));
}

/**
 * Parses /proc/self/mountinfo (proc(5)): `id parent major:minor root MOUNT_POINT options [optional...] - FSTYPE source
 * super-options`. Malformed lines are skipped. Order is kept (a later entry on the same mount point is stacked on top).
 */
export function parseMountinfo(text: string): MountEntry[] {
  const out: MountEntry[] = [];
  for (const line of text.split("\n")) {
    const f = line.trim().split(" ");
    const sep = f.indexOf("-", 6);
    const mountPoint = f[4];
    const fsType = sep > 0 ? f[sep + 1] : undefined;
    if (!mountPoint?.startsWith("/") || !fsType) continue;
    out.push({ mountPoint: unescapeOctal(mountPoint), fsType });
  }
  return out;
}

function under(dir: string, mountPoint: string): boolean {
  if (mountPoint === "/") return dir.startsWith("/");
  const mp = mountPoint.endsWith("/") ? mountPoint.slice(0, -1) : mountPoint;
  return dir === mp || dir.startsWith(`${mp}/`);
}

/**
 * THE rule: the nearest mount of `dataDir` is the entry with the longest mount point that equals `dataDir` or is a
 * parent of it (on a tie the later entry, i.e. the one stacked on top). The data dir is on a mounted volume iff that
 * mount point is not `/` (the container root) and its fs type is not ephemeral ({@link isEphemeralFs}). A volume at
 * `/data` with TB_DATA_DIR `/data` or `/data/app` → mounted; TB_DATA_DIR `/data` with no volume (only `/` overlay) →
 * not mounted; a tmpfs at `/data/tmp` with TB_DATA_DIR `/data/tmp/x` → not mounted.
 */
export function judgeMount(dataDir: string, entries: readonly MountEntry[]): MountState {
  let best: MountEntry | null = null;
  for (const e of entries) if (under(dataDir, e.mountPoint) && (best === null || e.mountPoint.length >= best.mountPoint.length)) best = e;
  if (!best) return { dataDir, mounted: false, mountPoint: null, fsType: null };
  return { dataDir, mounted: best.mountPoint !== "/" && !isEphemeralFs(best.fsType), mountPoint: best.mountPoint, fsType: best.fsType };
}

/** Absolute path with symlinks resolved on the longest existing prefix (the data dir may not exist yet). */
function realDir(dir: string): string {
  const abs = resolve(dir);
  const rest: string[] = [];
  let head = abs;
  for (;;) {
    try {
      return join(realpathSync(head), ...rest);
    } catch {
      const up = dirname(head);
      if (up === head) return abs;
      rest.unshift(basename(head));
      head = up;
    }
  }
}

/** Reads `mountinfoPath` (default /proc/self/mountinfo) and judges `dataDir`; unreadable (macOS, non-Linux) → unknown. */
export function probeDataDir(dataDir: string, mountinfoPath: string = MOUNTINFO_PATH): MountState {
  const dir = realDir(dataDir);
  let text: string;
  try {
    text = readFileSync(mountinfoPath, "utf8");
  } catch {
    return { dataDir: dir, mounted: null, mountPoint: null, fsType: null };
  }
  return judgeMount(dir, parseMountinfo(text));
}

/** Log fields of a mount state (paths and fs type only; no secrets). */
export function mountFields(s: MountState, ephemeral: boolean): Record<string, string | boolean> {
  return { dataDir: s.dataDir, mounted: s.mounted === null ? "unknown" : s.mounted, mountPoint: s.mountPoint ?? "-", fsType: s.fsType ?? "-", ephemeralAllowed: ephemeral };
}

/** The one boot line (item 3): `data_dir_mount` at info. Unknown (no mountinfo) means the first-claim check is skipped. */
export function logMountAtBoot(dataDir: string, o: { ephemeral: boolean; mountinfoPath?: string; log: Logger }): MountState {
  const s = probeDataDir(dataDir, o.mountinfoPath);
  o.log.info("data_dir_mount", { ...mountFields(s, o.ephemeral), firstClaimCheck: o.ephemeral ? "skipped (TB_DATA_EPHEMERAL=1)" : s.mounted === null ? "skipped (no mountinfo)" : "on" });
  return s;
}

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((done) => {
    if (signal.aborted) return done();
    const t = setTimeout(finish, ms);
    t.unref();
    function finish() {
      clearTimeout(t);
      signal.removeEventListener("abort", finish);
      done();
    }
    signal.addEventListener("abort", finish, { once: true });
  });

export interface MountGateOptions {
  /** TB_DATA_EPHEMERAL=1 (tests / conformance only): no check */
  ephemeral: boolean;
  /** test harness only: another mountinfo file */
  mountinfoPath?: string;
  log: Logger;
  signal: AbortSignal;
  /** called with true while the data dir is not mounted, false once the claim may proceed */
  onBlocked?: (blocked: boolean) => void;
  /** tests only: retry delays */
  minMs?: number;
  maxMs?: number;
}

/**
 * Gate before redeeming the one-time enrolment code: resolves true once TB_DATA_DIR is on a mounted volume (or the check
 * does not apply: TB_DATA_EPHEMERAL=1, or no mountinfo), retrying 5 s → 60 s; false when `signal` aborts first.
 */
export async function waitForMountedDataDir(dataDir: string, o: MountGateOptions): Promise<boolean> {
  if (o.ephemeral) return true;
  let delay = o.minMs ?? MOUNT_RETRY_MIN_MS;
  for (;;) {
    if (o.signal.aborted) return false;
    const s = probeDataDir(dataDir, o.mountinfoPath);
    if (s.mounted !== false) {
      o.onBlocked?.(false);
      return true;
    }
    o.onBlocked?.(true);
    o.log.warn("data_dir_not_mounted", { ...mountFields(s, false), retryInMs: delay, hint: "TB_DATA_DIR is not on a mounted volume; the enrolment code is not redeemed until it is" });
    await sleep(delay, o.signal);
    delay = Math.min(delay * 2, o.maxMs ?? MOUNT_RETRY_MAX_MS);
  }
}

/** sha256 digest of the enrolment code stored in the claim record (never the code itself). */
export function enrolCodeDigest(code: string): `sha256:${string}` {
  return opaqueDigest(code);
}

/** The bridge refused the stored identity: 401 `unauthenticated` on an instance-assertion request (BRIDGE §8, §10). */
export function identityRefused(e: unknown): boolean {
  return e instanceof TbError && e.httpStatus === 401 && e.code === "unauthenticated";
}

/**
 * Reclaim rule: the stored identity was refused AND the current TB_ENROL_CODE differs from the code the record was
 * claimed with (`storedDigest`; a record from before 0.1.12 has none and counts as different). Each code is tried at
 * most once per process (`tried` holds digests), so an unchanged or used code never turns into a claim loop.
 */
export function reclaimCode(code: string | null, storedDigest: string | undefined, tried: Set<string>): string | null {
  if (!code) return null;
  const d = enrolCodeDigest(code);
  if (storedDigest !== undefined && digestEqual(storedDigest, d)) return null;
  if (tried.has(d)) return null;
  tried.add(d);
  return code;
}
