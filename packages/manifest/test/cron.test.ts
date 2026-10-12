import assert from "node:assert/strict";
import { test } from "node:test";
import { CronError, cronDue, isValidCron, nextCronTime, parseCron } from "../src/index.ts";

const iso = (d: Date | null): string | null => (d ? d.toISOString() : null);
const at = (s: string): Date => new Date(s);

test("parseCron: the allowed subset; anything else is cron_invalid", () => {
  for (const ok of ["* * * * *", "0 3 * * *", "*/15 0-6 1,15 1-12/2 0-7", "5/10 * * * 1-5", " 0  3 * * * "]) assert.ok(isValidCron(ok), ok);
  for (const no of ["", "* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "* * 0 * *", "* * * 13 *", "* * * * 8", "*/0 * * * *", "5-1 * * * *", "a * * * *", "@daily", "L * * * *"]) {
    assert.throws(() => parseCron(no), (e: unknown) => e instanceof CronError && e.code === "cron_invalid", no);
  }
  assert.deepEqual([...parseCron("0 0 * * 7").dow], [0]);
});

test("nextCronTime UTC: strictly after, minute resolution, dom/dow OR rule, horizon", () => {
  assert.equal(iso(nextCronTime("0 3 * * *", at("2026-10-12T03:00:00Z"))), "2026-10-13T03:00:00.000Z");
  assert.equal(iso(nextCronTime("0 3 * * *", at("2026-10-12T02:59:59.999Z"))), "2026-10-12T03:00:00.000Z");
  assert.equal(iso(nextCronTime("*/15 * * * *", at("2026-10-12T10:07:30Z"))), "2026-10-12T10:15:00.000Z");
  // 13th of the month OR a Friday
  assert.equal(iso(nextCronTime("0 0 13 * 5", at("2026-10-12T00:00:00Z"))), "2026-10-13T00:00:00.000Z");
  assert.equal(iso(nextCronTime("0 0 13 * 5", at("2026-10-13T00:00:00Z"))), "2026-10-16T00:00:00.000Z");
  assert.equal(iso(nextCronTime("0 0 29 2 *", at("2026-03-01T00:00:00Z"))), "2028-02-29T00:00:00.000Z");
  assert.equal(nextCronTime("0 0 31 2 *", at("2026-01-01T00:00:00Z")), null);
  assert.equal(iso(nextCronTime("0 0 1 1 *", at("2026-12-31T23:59:00Z"))), "2027-01-01T00:00:00.000Z");
});

test("nextCronTime tz: plain local time; unknown zone is tz_invalid", () => {
  // Prague is UTC+2 in summer, UTC+1 in winter
  assert.equal(iso(nextCronTime("0 9 * * *", at("2026-07-01T00:00:00Z"), { tz: "Europe/Prague" })), "2026-07-01T07:00:00.000Z");
  assert.equal(iso(nextCronTime("0 9 * * *", at("2026-12-01T00:00:00Z"), { tz: "Europe/Prague" })), "2026-12-01T08:00:00.000Z");
  assert.equal(iso(nextCronTime("0 9 * * *", at("2026-07-01T00:00:00Z"), { tz: "UTC" })), "2026-07-01T09:00:00.000Z");
  assert.throws(() => nextCronTime("0 9 * * *", at("2026-07-01T00:00:00Z"), { tz: "Mars/Olympus" }), (e: unknown) => e instanceof CronError && e.code === "tz_invalid");
});

test("DST spring forward (gap): a skipped wall time runs once, at the transition", () => {
  // Europe/Prague 2026-03-29: 02:00 CET → 03:00 CEST at 01:00Z; 02:30 local does not exist
  const tz = "Europe/Prague";
  assert.equal(iso(nextCronTime("30 2 * * *", at("2026-03-28T12:00:00Z"), { tz })), "2026-03-29T01:00:00.000Z");
  // the next day it is a normal 02:30 CEST
  assert.equal(iso(nextCronTime("30 2 * * *", at("2026-03-29T01:00:00Z"), { tz })), "2026-03-30T00:30:00.000Z");
  // 02:00, 02:30 and 03:00 collapse into one run at the transition; then 03:30
  const c = "0,30 2-3 * * *";
  const t1 = nextCronTime(c, at("2026-03-29T00:45:00Z"), { tz });
  assert.equal(iso(t1), "2026-03-29T01:00:00.000Z");
  assert.equal(iso(nextCronTime(c, t1 as Date, { tz })), "2026-03-29T01:30:00.000Z");
  // every minute: 01:59 CET is followed by 03:00 CEST (one minute later in real time)
  assert.equal(iso(nextCronTime("* * * * *", at("2026-03-29T00:59:00Z"), { tz })), "2026-03-29T01:00:00.000Z");
  // US: New York 2026-03-08 02:00 EST → 03:00 EDT at 07:00Z
  assert.equal(iso(nextCronTime("15 2 * * *", at("2026-03-08T00:00:00Z"), { tz: "America/New_York" })), "2026-03-08T07:00:00.000Z");
});

test("DST fall back (overlap): a doubled wall time runs once, at its first occurrence", () => {
  // Europe/Prague 2026-10-25: 03:00 CEST → 02:00 CET at 01:00Z; 02:30 local happens at 00:30Z and 01:30Z
  const tz = "Europe/Prague";
  const first = nextCronTime("30 2 * * *", at("2026-10-24T12:00:00Z"), { tz });
  assert.equal(iso(first), "2026-10-25T00:30:00.000Z");
  // chained from its own due time it does NOT run again at the second 02:30
  assert.equal(iso(nextCronTime("30 2 * * *", first as Date, { tz })), "2026-10-26T01:30:00.000Z");
  // computed from inside the second pass with nothing earlier (e.g. a new schedule): the second occurrence
  assert.equal(iso(nextCronTime("30 2 * * *", at("2026-10-25T01:10:00Z"), { tz })), "2026-10-25T01:30:00.000Z");
  // hourly schedule across the overlap: 02:00 CEST, then 02:00 CET is skipped (same wall time), then 03:00 CET
  const h = "0 * * * *";
  const h1 = nextCronTime(h, at("2026-10-24T23:30:00Z"), { tz });
  assert.equal(iso(h1), "2026-10-25T00:00:00.000Z");
  assert.equal(iso(nextCronTime(h, h1 as Date, { tz })), "2026-10-25T02:00:00.000Z");
});

test("southern hemisphere and half-hour zones", () => {
  // Sydney 2026-10-04: 02:00 AEST → 03:00 AEDT (gap) at 16:00Z on 10-03
  assert.equal(iso(nextCronTime("30 2 * * *", at("2026-10-03T12:00:00Z"), { tz: "Australia/Sydney" })), "2026-10-03T16:00:00.000Z");
  // India +05:30, no DST
  assert.equal(iso(nextCronTime("0 9 * * *", at("2026-10-12T00:00:00Z"), { tz: "Asia/Kolkata" })), "2026-10-12T03:30:00.000Z");
});

test("cronDue: not due, due within grace, misfire beyond grace, missed periods collapse", () => {
  const c = "*/5 * * * *";
  // never computed: nothing due, next from now
  assert.deepEqual(cronDue(c, { nextDueAt: null, now: at("2026-10-12T10:02:00Z") }), { due: null, missed: false, nextDueAt: at("2026-10-12T10:05:00Z") });
  // not yet
  assert.deepEqual(cronDue(c, { nextDueAt: at("2026-10-12T10:05:00Z"), now: at("2026-10-12T10:04:59Z") }), { due: null, missed: false, nextDueAt: at("2026-10-12T10:05:00Z") });
  // exactly due
  assert.deepEqual(cronDue(c, { nextDueAt: at("2026-10-12T10:05:00Z"), now: at("2026-10-12T10:05:00Z") }), { due: at("2026-10-12T10:05:00Z"), missed: false, nextDueAt: at("2026-10-12T10:10:00Z") });
  // 120 s grace is inclusive; 121 s is a misfire
  assert.equal(cronDue(c, { nextDueAt: at("2026-10-12T10:05:00Z"), now: at("2026-10-12T10:07:00Z") }).missed, false);
  assert.equal(cronDue(c, { nextDueAt: at("2026-10-12T10:05:00Z"), now: at("2026-10-12T10:07:01Z") }).missed, true);
  // an hour down: ONE occurrence (missed), next after now
  assert.deepEqual(cronDue(c, { nextDueAt: at("2026-10-12T10:05:00Z"), now: at("2026-10-12T11:03:00Z"), graceSec: 600 }), { due: at("2026-10-12T10:05:00Z"), missed: true, nextDueAt: at("2026-10-12T11:05:00Z") });
  // tz is honoured for the next due time
  assert.deepEqual(cronDue("0 9 * * *", { nextDueAt: at("2026-07-01T07:00:00Z"), now: at("2026-07-01T07:00:30Z"), tz: "Europe/Prague" }).nextDueAt, at("2026-07-02T07:00:00Z"));
});
