// THE one cron mechanism (manifest 0.1.7): 5-field cron, next-due computation in UTC or an IANA time zone, and the
// due / misfire rule. Used by the SDK backup schedule (MANIFEST §11), Evolution routines and `tealbrick agent serve`
// poll mode. Deterministic, no dependencies (time zones via the runtime's Intl data).
//
// Syntax: numbers, `*`, ranges `a-b`, steps `/n` (on `*`, a range or a start `a/n`), lists `,`. Fields: minute 0–59,
// hour 0–23, day of month 1–31, month 1–12, day of week 0–7 (0 and 7 = Sunday). When both day fields are restricted,
// a day matching EITHER runs (Vixie cron).
//
// Time zones (opts.tz, IANA name; default UTC): the cron matches local wall-clock time. DST:
// - a wall time that does not exist (spring forward gap) runs at the first instant after the gap (the transition);
//   several skipped times collapse into that one run;
// - a wall time that exists twice (fall back) runs at its FIRST occurrence; the second occurrence is used only when
//   `after` already lies past the first one (a schedule never runs the same wall time twice when chained from its
//   own previous due time).

export interface CronSchedule {
  readonly expr: string;
  readonly minute: ReadonlySet<number>;
  readonly hour: ReadonlySet<number>;
  readonly dom: ReadonlySet<number>;
  readonly month: ReadonlySet<number>;
  readonly dow: ReadonlySet<number>;
  readonly domAny: boolean;
  readonly dowAny: boolean;
}

/** Thrown by {@link parseCron} / {@link nextCronTime} on an invalid expression or time zone. */
export class CronError extends Error {
  readonly code: "cron_invalid" | "tz_invalid";
  constructor(code: "cron_invalid" | "tz_invalid", message: string) {
    super(message);
    this.name = "CronError";
    this.code = code;
  }
}

export interface CronOptions {
  /** IANA time zone the cron is read in (e.g. "Europe/Prague"); default "UTC" */
  tz?: string;
}

const RANGES: readonly (readonly [number, number])[] = [
  [0, 59],
  [0, 23],
  [1, 31],
  [1, 12],
  [0, 7],
];
const MIN = 60_000;
const DAY = 86_400_000;
/** look-ahead bound: a schedule with no match in 5 years (e.g. `0 0 31 2 *`) never fires */
export const CRON_HORIZON_MS = 5 * 366 * DAY;

function bad(expr: string, why: string): CronError {
  return new CronError("cron_invalid", `not a valid 5-field cron (${why}): ${expr}`);
}

function parseField(src: string, [lo, hi]: readonly [number, number], expr: string): Set<number> {
  const out = new Set<number>();
  for (const part of src.split(",")) {
    const m = /^(\*|(\d{1,2})(?:-(\d{1,2}))?)(?:\/(\d{1,2}))?$/.exec(part);
    if (!m) throw bad(expr, `field "${src}"`);
    const step = m[4] === undefined ? 1 : Number(m[4]);
    if (step < 1) throw bad(expr, "step 0");
    let a = lo;
    let b = hi;
    if (m[1] !== "*") {
      a = Number(m[2]);
      b = m[3] !== undefined ? Number(m[3]) : m[4] !== undefined ? hi : a;
    }
    if (a < lo || b > hi || a > b) throw bad(expr, `field "${src}" out of range ${lo}-${hi}`);
    for (let v = a; v <= b; v += step) out.add(v);
  }
  return out;
}

/** Parses a 5-field cron (single spaces or any whitespace between fields); throws {@link CronError} `cron_invalid`. */
export function parseCron(expr: string): CronSchedule {
  const f = expr.trim().split(/\s+/);
  if (f.length !== 5) throw bad(expr, `${f.length} fields`);
  const sets = f.map((s, i) => parseField(s, RANGES[i] as readonly [number, number], expr));
  return {
    expr,
    minute: sets[0] as Set<number>,
    hour: sets[1] as Set<number>,
    dom: sets[2] as Set<number>,
    month: sets[3] as Set<number>,
    dow: new Set([...(sets[4] as Set<number>)].map((d) => d % 7)),
    domAny: (f[2] as string).startsWith("*"),
    dowAny: (f[4] as string).startsWith("*"),
  };
}

/** True when `expr` parses. */
export function isValidCron(expr: string): boolean {
  try {
    parseCron(expr);
    return true;
  } catch {
    return false;
  }
}

function dayMatches(c: CronSchedule, t: Date): boolean {
  if (c.domAny && c.dowAny) return true;
  const dom = c.dom.has(t.getUTCDate());
  const dow = c.dow.has(t.getUTCDay());
  if (c.domAny) return dow;
  if (c.dowAny) return dom;
  return dom || dow;
}

/** First matching minute strictly after `after`, reading the fields of `after` as UTC; null past the horizon. */
function nextUtc(c: CronSchedule, after: number, limit: number): number | null {
  const t = new Date(after);
  t.setUTCSeconds(0, 0);
  t.setUTCMinutes(t.getUTCMinutes() + 1);
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
    } else return t.getTime();
  }
  return null;
}

const FORMATTERS = new Map<string, Intl.DateTimeFormat>();

function formatter(tz: string): Intl.DateTimeFormat {
  let f = FORMATTERS.get(tz);
  if (!f) {
    try {
      f = new Intl.DateTimeFormat("en-US", { timeZone: tz, hourCycle: "h23", year: "numeric", month: "numeric", day: "numeric", hour: "numeric", minute: "numeric", second: "numeric" });
    } catch {
      throw new CronError("tz_invalid", `unknown IANA time zone: ${tz}`);
    }
    FORMATTERS.set(tz, f);
  }
  return f;
}

/** UTC offset (ms, local − UTC) of `tz` at instant `t` (minute resolution). */
function offsetAt(tz: string, t: number): number {
  const p: Record<string, number> = {};
  for (const x of formatter(tz).formatToParts(new Date(t))) if (x.type !== "literal") p[x.type] = Number(x.value);
  const wall = Date.UTC(p.year as number, (p.month as number) - 1, p.day as number, p.hour as number, p.minute as number, p.second as number);
  return Math.round((wall - Math.floor(t / 1000) * 1000) / MIN) * MIN;
}

/** Instants whose local wall time in `tz` is `wall` (fake-UTC ms), earliest first: 0 (gap), 1, or 2 (overlap). */
function instantsOf(tz: string, wall: number): number[] {
  const offs = new Set([offsetAt(tz, wall - DAY), offsetAt(tz, wall + DAY), offsetAt(tz, wall)]);
  const out: number[] = [];
  for (const o of offs) if (offsetAt(tz, wall - o) === o) out.push(wall - o);
  return [...new Set(out)].sort((a, b) => a - b);
}

/** First instant after a gap that swallowed `wall`: binary search on minutes between the two offset readings. */
function gapEnd(tz: string, wall: number): number {
  const before = offsetAt(tz, wall - DAY);
  const after = offsetAt(tz, wall + DAY);
  let lo = Math.min(wall - before, wall - after);
  let hi = Math.max(wall - before, wall - after);
  // invariant: lo is before the transition (offset `before`), hi is at/after it
  while (hi - lo > MIN) {
    const mid = lo + Math.floor((hi - lo) / 2 / MIN) * MIN;
    if (offsetAt(tz, mid) === before) lo = mid;
    else hi = mid;
  }
  return hi;
}

/**
 * The first due time strictly after `after` (minute resolution), or null when none falls within
 * {@link CRON_HORIZON_MS}. `cron` is an expression or a parsed schedule; `after` a Date or epoch ms; `opts.tz` an IANA
 * zone (default UTC).
 */
export function nextCronTime(cron: string | CronSchedule, after: Date | number, opts: CronOptions = {}): Date | null {
  const c = typeof cron === "string" ? parseCron(cron) : cron;
  const a = typeof after === "number" ? after : after.getTime();
  if (!Number.isFinite(a)) throw new CronError("cron_invalid", "after is not a valid date");
  const tz = opts.tz ?? "UTC";
  const limit = a + CRON_HORIZON_MS;
  if (tz === "UTC" || tz === "Etc/UTC") {
    const n = nextUtc(c, a, limit);
    return n === null ? null : new Date(n);
  }
  formatter(tz);
  // walk wall-clock candidates; start 3 h of wall time early (larger than any DST shift) so a candidate whose
  // instant is after `after` (fall-back second pass) is not skipped
  let wall = a + offsetAt(tz, a) - 3 * 3_600_000 - MIN;
  const wallLimit = limit + 2 * DAY;
  for (;;) {
    const w = nextUtc(c, wall, wallLimit);
    if (w === null) return null;
    wall = w;
    const instants = instantsOf(tz, w);
    if (instants.length === 0) {
      const g = gapEnd(tz, w);
      if (g > a) return g > limit ? null : new Date(g);
      continue;
    }
    // first occurrence after `after`; the second occurrence of a doubled wall time only when the first is past
    const hit = instants.find((i) => i > a);
    if (hit !== undefined) {
      // a doubled wall time whose first occurrence is at/before `after` was already due once: skip it when the
      // caller chained from that first occurrence (after === first) — never run the same wall time twice
      if (instants.length === 2 && hit === instants[1] && (instants[0] as number) >= a - MIN && (instants[0] as number) <= a) continue;
      return hit > limit ? null : new Date(hit);
    }
  }
}

export interface CronDueInput {
  /** the stored next due time (null = never computed: nothing is due, `nextDueAt` is computed from `now`) */
  nextDueAt: Date | null;
  now: Date;
  /** misfire grace in seconds (default 120) */
  graceSec?: number;
  tz?: string;
}

export interface CronDueResult {
  /** the ONE occurrence due now (missed periods collapse into it), or null when nothing is due */
  due: Date | null;
  /** true when `due` is older than the grace: record it `missed`, never run it */
  missed: boolean;
  /** the next due time to store (strictly after `now`), or null when the schedule never fires again */
  nextDueAt: Date | null;
}

/**
 * The due / misfire rule (Evolution routines, agent serve poll): when `nextDueAt ≤ now`, `due = nextDueAt`, the new
 * `nextDueAt` is the next cron time after `now` (missed periods collapse to ONE occurrence) and `missed` is
 * `now − due > grace`. Otherwise nothing is due and `nextDueAt` is kept.
 */
export function cronDue(cron: string | CronSchedule, i: CronDueInput): CronDueResult {
  const c = typeof cron === "string" ? parseCron(cron) : cron;
  const graceMs = (i.graceSec ?? 120) * 1000;
  const opts: CronOptions = i.tz ? { tz: i.tz } : {};
  if (i.nextDueAt === null) return { due: null, missed: false, nextDueAt: nextCronTime(c, i.now, opts) };
  if (i.nextDueAt.getTime() > i.now.getTime()) return { due: null, missed: false, nextDueAt: i.nextDueAt };
  return { due: i.nextDueAt, missed: i.now.getTime() - i.nextDueAt.getTime() > graceMs, nextDueAt: nextCronTime(c, i.now, opts) };
}
