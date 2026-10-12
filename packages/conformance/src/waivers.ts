// Waivers (CONFORMANCE v0.1.13, Fleet C89): `--waive <checkId>@<untilVersion>` (repeatable) and an optional
// `tealbrick-conformance.json` next to the manifest `{ "waivers": [{ "id", "until", "reason" }] }`. A waived check that
// would fail / not_run reports `waived` while this package's version < `until` (report.ts applyWaivers). Unknown ids
// and malformed entries are usage errors (exit 2): a waiver must never silently cover nothing.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { CHECK_IDS } from "./checks/catalog.ts";
import type { Waiver } from "./report.ts";

/** This package's version (`package.json` one level above src/ and dist/). */
export const CONFORMANCE_VERSION: string = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

/** File name of the per-app waiver list, read from the manifest's directory. */
export const WAIVER_FILE = "tealbrick-conformance.json";

const VERSION_RE = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/** Thrown for a malformed or unknown waiver; the CLI answers it with exit 2 (usage error). */
export class WaiverError extends Error {}

function checked(w: Waiver, where: string): Waiver {
  if (!CHECK_IDS.has(w.id)) throw new WaiverError(`${where}: unknown check id ${JSON.stringify(w.id)}`);
  if (!VERSION_RE.test(w.until)) throw new WaiverError(`${where}: until ${JSON.stringify(w.until)} is not a version (x.y.z)`);
  if (w.reason.trim().length === 0) throw new WaiverError(`${where}: reason required`);
  return w;
}

/** `<checkId>@<untilVersion>`; the reason is "--waive (command line)". */
export function parseWaiveFlag(value: string): Waiver {
  const at = value.lastIndexOf("@");
  if (at <= 0 || at === value.length - 1) throw new WaiverError(`--waive ${JSON.stringify(value)}: expected <checkId>@<untilVersion>`);
  return checked({ id: value.slice(0, at), until: value.slice(at + 1), reason: "--waive (command line)" }, "--waive");
}

/** Waivers from `tealbrick-conformance.json` beside `manifestPath` ([] when the file is absent). */
export function loadWaiverFile(manifestPath: string): Waiver[] {
  const path = join(dirname(manifestPath), WAIVER_FILE);
  if (!existsSync(path)) return [];
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new WaiverError(`${path}: not JSON (${e instanceof Error ? e.message : String(e)})`);
  }
  const list = doc && typeof doc === "object" && !Array.isArray(doc) ? (doc as { waivers?: unknown }).waivers : undefined;
  if (list === undefined) return [];
  if (!Array.isArray(list)) throw new WaiverError(`${path}: waivers must be an array`);
  return list.map((x, i) => {
    const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
    if (typeof o.id !== "string" || typeof o.until !== "string" || typeof o.reason !== "string") throw new WaiverError(`${path}: waivers[${i}] needs string id, until and reason`);
    return checked({ id: o.id, until: o.until, reason: o.reason }, `${path} waivers[${i}]`);
  });
}
