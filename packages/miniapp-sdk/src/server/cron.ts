// The backup schedule (manifest `backups.schedule`, MANIFEST §11): 5-field cron in UTC. Since miniapp-sdk 0.1.12 a
// thin wrapper over THE one cron mechanism in @opt2-tealbrick/manifest (`parseCron`, `nextCronTime`), mapping its
// `cron_invalid` to the backup error code.
import { CronError, type CronSchedule, nextCronTime, parseCron as parseManifestCron } from "@opt2-tealbrick/manifest";
import { TbError } from "./errors.ts";

export type Cron = CronSchedule;

/** Parses `backups.schedule`; throws `backup_invalid` on anything outside the allowed subset. */
export function parseCron(expr: string): Cron {
  try {
    return parseManifestCron(expr);
  } catch (e) {
    if (e instanceof CronError) throw new TbError("backup_invalid", `backups.schedule is not a valid 5-field cron: ${expr}`, 500);
    throw e;
  }
}

/** First run strictly after `after` (minute resolution, UTC), or null when none falls within the horizon. */
export function nextRun(c: Cron, after: Date): Date | null {
  return nextCronTime(c, after);
}
