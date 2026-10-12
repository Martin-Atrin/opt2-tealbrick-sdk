// C64: the ONE privilege drop lives in @opt2-tealbrick/manifest (shared with the bridge); the SDK maps its failure to
// TbError `privilege_drop_failed` (HTTP 500) for boot errors.
import { dropPrivileges as drop, PrivilegeDropError, type PrivilegeProc, RUN_GID, RUN_UID } from "@opt2-tealbrick/manifest";
import { TbError } from "./errors.ts";

export { type PrivilegeProc, RUN_GID, RUN_UID };

export function dropPrivileges(dirs: { dataDir: string; backupDir: string }, proc?: PrivilegeProc): boolean {
  try {
    return drop(dirs, proc);
  } catch (e) {
    if (e instanceof PrivilegeDropError) throw new TbError("privilege_drop_failed", e.message, 500);
    throw e;
  }
}
