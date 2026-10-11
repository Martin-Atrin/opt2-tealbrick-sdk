// The backup schedule (manifest `backups.schedule`, MANIFEST §11): 5-field cron in UTC, exactly the subset the schema
// and M-BK-1 allow — numbers, `*`, ranges `a-b`, steps `/n`, lists `,`. Fields: minute 0–59, hour 0–23, day of month
// 1–31, month 1–12, day of week 0–7 (0 and 7 = Sunday). When both day fields are restricted a day matching either runs.
import { TbError } from "./errors.ts";

export interface Cron {
  minute: ReadonlySet<number>;
  hour: ReadonlySet<number>;
  dom: ReadonlySet<number>;
  month: ReadonlySet<number>;
  dow: ReadonlySet<number>;
  domAny: boolean;
  dowAny: boolean;
}

const RANGES: readonly [number, number][] = [
  [0, 59],
  [0, 23],
  [1, 31],
  [1, 12],
  [0, 7],
];
/** look-ahead bound: a schedule with no match in 5 years (e.g. `0 0 31 2 *`) never fires */
const HORIZON_MS = 5 * 366 * 86_400_000;

function bad(expr: string): TbError {
  return new TbError("backup_invalid", `backups.schedule is not a valid 5-field cron: ${expr}`, 500);
}

function parseField(src: string, [lo, hi]: [number, number], expr: string): Set<number> {
  const out = new Set<number>();
  for (const part of src.split(",")) {
    const m = /^(\*|(\d+)(?:-(\d+))?)(?:\/(\d+))?$/.exec(part);
    if (!m) throw bad(expr);
    const step = m[4] === undefined ? 1 : Number(m[4]);
    if (step < 1) throw bad(expr);
    let a = lo;
    let b = hi;
    if (m[1] !== "*") {
      a = Number(m[2]);
      b = m[3] !== undefined ? Number(m[3]) : m[4] !== undefined ? hi : a;
    }
    if (a < lo || b > hi || a > b) throw bad(expr);
    for (let v = a; v <= b; v += step) out.add(v);
  }
  return out;
}

/** Parses `backups.schedule`; throws `backup_invalid` on anything outside the allowed subset. */
export function parseCron(expr: string): Cron {
  const f = expr.split(" ");
  if (f.length !== 5) throw bad(expr);
  const sets = f.map((s, i) => parseField(s, RANGES[i] as [number, number], expr));
  const dow = new Set([...(sets[4] as Set<number>)].map((d) => d % 7));
  return {
    minute: sets[0] as Set<number>,
    hour: sets[1] as Set<number>,
    dom: sets[2] as Set<number>,
    month: sets[3] as Set<number>,
    dow,
    domAny: (f[2] as string).startsWith("*"),
    dowAny: (f[4] as string).startsWith("*"),
  };
}

function dayMatches(c: Cron, t: Date): boolean {
  const dom = c.dom.has(t.getUTCDate());
  const dow = c.dow.has(t.getUTCDay());
  if (c.domAny && c.dowAny) return true;
  if (c.domAny) return dow;
  if (c.dowAny) return dom;
  return dom || dow;
}

/** First run strictly after `after` (minute resolution, UTC), or null when none falls within the horizon. */
export function nextRun(c: Cron, after: Date): Date | null {
  const t = new Date(after.getTime());
  t.setUTCSeconds(0, 0);
  t.setUTCMinutes(t.getUTCMinutes() + 1);
  const limit = after.getTime() + HORIZON_MS;
  while (t.getTime() <= limit) {
    if (!c.month.has(t.getUTCMonth() + 1)) {
      t.setUTCMonth(t.getUTCMonth() + 1, 1);
      t.setUTCHours(0, 0, 0, 0);
    } else if (!dayMatches(c, t)) {
      t.setUTCDate(t.getUTCDate() + 1);
      t.setUTCHours(0, 0, 0, 0);
    } else if (!c.hour.has(t.getUTCHours())) {
      t.setUTCHours(t.getUTCHours() + 1, 0, 0, 0);
    } else if (!c.minute.has(t.getUTCMinutes())) {
      t.setUTCMinutes(t.getUTCMinutes() + 1, 0, 0);
    } else return t;
  }
  return null;
}
