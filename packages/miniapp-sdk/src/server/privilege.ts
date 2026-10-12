// The ONE privilege drop (C53 / BSA-05), used by `startApp` and `tb-exec`: started as root (Railway mounts volumes
// root-owned, C38), the process hands TB_DATA_DIR (and TB_BACKUP_DIR when it lies outside it) to uid/gid 1000 and drops
// to 1000 before it opens the store, keys or any listener. Not root (or no POSIX ids) → no-op.
import { lchownSync, mkdirSync, readdirSync } from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { TbError } from "./errors.ts";

/** The uid and gid every SDK process runs as (the `node` user of the official Node images). */
export const RUN_UID = 1000;
export const RUN_GID = 1000;

/** The process calls the drop needs; tests pass a fake, production passes `process` + `lchownSync`. */
export interface PrivilegeProc {
  getuid?: () => number;
  getgid?: () => number;
  setuid?: (id: number) => void;
  setgid?: (id: number) => void;
  setgroups?: (groups: number[]) => void;
  /** chown of one path without following symlinks */
  chown?: (path: string, uid: number, gid: number) => void;
}

const defaultProc: PrivilegeProc = {
  getuid: process.getuid?.bind(process),
  getgid: process.getgid?.bind(process),
  setuid: process.setuid?.bind(process),
  setgid: process.setgid?.bind(process),
  setgroups: process.setgroups?.bind(process),
  chown: lchownSync,
};

function chownTree(path: string, chown: NonNullable<PrivilegeProc["chown"]>): void {
  chown(path, RUN_UID, RUN_GID);
  for (const d of readdirSync(path, { withFileTypes: true })) {
    const child = join(path, d.name);
    if (d.isDirectory()) chownTree(child, chown);
    else chown(child, RUN_UID, RUN_GID);
  }
}

function inside(dir: string, parent: string): boolean {
  const r = relative(parent, dir);
  return r === "" || (r !== ".." && !r.startsWith(`..${sep}`) && !isAbsolute(r));
}

/**
 * Root → mkdir -p + chown -R the data dir (and the backup dir when outside it) to 1000:1000, setgroups([]), setgid,
 * setuid, then verifies uid/gid 1000. Returns true when it dropped, false when there was nothing to do. Throws
 * TbError `privilege_drop_failed` when a step fails or the ids do not read back as 1000.
 */
export function dropPrivileges(dirs: { dataDir: string; backupDir: string }, proc: PrivilegeProc = defaultProc): boolean {
  if (proc.getuid?.() !== 0) return false;
  try {
    const chown = proc.chown ?? lchownSync;
    const data = resolve(dirs.dataDir);
    const backup = resolve(dirs.backupDir);
    for (const dir of inside(backup, data) ? [data] : [data, backup]) {
      mkdirSync(dir, { recursive: true });
      chownTree(dir, chown);
    }
    if (!proc.setgid || !proc.setuid) throw new Error("setgid/setuid unavailable");
    proc.setgroups?.([]);
    proc.setgid(RUN_GID);
    proc.setuid(RUN_UID);
  } catch (e) {
    throw new TbError("privilege_drop_failed", `cannot drop root to uid ${RUN_UID}: ${e instanceof Error ? e.message : "unknown"}`, 500);
  }
  if (proc.getuid?.() !== RUN_UID || (proc.getgid && proc.getgid() !== RUN_GID))
    throw new TbError("privilege_drop_failed", `process does not run as uid/gid ${RUN_UID} after the drop`, 500);
  return true;
}
