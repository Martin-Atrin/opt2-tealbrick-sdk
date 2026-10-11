// Extension point for SDK-API §7.3 (backups, restore, export) — implemented separately. The server core calls exactly
// these two functions: `restoreAtBoot` before migrations, `createBackupApi` once the store is open. Until the backup
// runner lands, a requested restore fails boot (`restore_failed`, nothing applied) and the backup API answers 501.
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, BackupApi, Logger } from "@opt2-tealbrick/spec/sdk";
import { TbError } from "./errors.ts";
import type { RawDb } from "./store.ts";

export interface BackupContext {
  manifest: Manifest;
  dataDir: string;
  backupDir: string;
  instanceId: string;
  sdkVersion: string;
  log: Logger;
  hooks: { beforeBackup?(): Promise<void>; afterRestore?(): Promise<void> } | undefined;
}

/** Runs before the store opens. `TB_RESTORE_FROM` set → restore that archive or fail boot `restore_failed`. */
export async function restoreAtBoot(ctx: BackupContext, restoreFrom: string | null): Promise<void> {
  if (restoreFrom === null) return;
  ctx.log.error("restore requested but this SDK build has no backup runner", { archive: restoreFrom });
  throw new TbError("restore_failed", "restore is not available in this SDK build", 500);
}

/** Backup runner + export (tb.export). Returns the RunningApp `backups` member and a stop function. */
export function createBackupApi(_ctx: BackupContext & { db: RawDb; audit: AuditLog }): { api: BackupApi; stop(): void } {
  const unavailable = () => Promise.reject(new TbError("backup_unavailable", "backups are not available in this SDK build", 501));
  return { api: { runNow: unavailable, list: async () => [], exportNow: unavailable }, stop() {} };
}
