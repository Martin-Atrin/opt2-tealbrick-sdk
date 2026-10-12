// Per-app conformance config (v0.1.18: one loader for `waivers`, `setup`, `inputs`, `inputsAs`, `dynamic`; v0.1.23
// (package 0.1.14): `narrowing`).
// Waivers (CONFORMANCE v0.1.13, Fleet C89): `--waive <checkId>@<untilVersion>` (repeatable) and an optional
// `tealbrick-conformance.json` next to the manifest `{ "waivers": [{ "id", "until", "reason" }] }`. A waived check that
// would fail / not_run reports `waived` while this package's version < `until` (report.ts applyWaivers). Unknown ids
// and malformed entries are usage errors (exit 2): a waiver must never silently cover nothing.
import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import { CHECK_IDS } from "./checks/catalog.ts";
import type { Waiver } from "./report.ts";

/** This package's version (`package.json` one level above src/ and dist/). */
export const CONFORMANCE_VERSION: string = (JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8")) as { version: string }).version;

/** File name of the per-app conformance config (waivers + setup fixtures), read from the manifest's directory. */
export const WAIVER_FILE = "tealbrick-conformance.json";

const VERSION_RE = /^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

/** Thrown for a malformed or unknown waiver or a malformed config file; the CLI answers it with exit 2 (usage error). */
export class WaiverError extends Error {}
/** The same usage error under its v0.1.18 name (the file holds more than waivers). */
export const ConfigError = WaiverError;

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
  return loadConformanceConfig(manifestPath).waivers;
}

// ── the one per-app config file (CONFORMANCE v0.1.18, package 0.1.12): waivers + setup fixtures ──
// `{ waivers?, setup?, inputs?, inputsAs?, dynamic? }` (see CONFORMANCE "v0.1.18 — package 0.1.12"). Every malformed
// part is a usage error (exit 2), like a malformed waiver: a fixture must never silently cover nothing.

/** Who a setup step calls as: the person session, fake agent A / B, or the suite's companion app caller (A12.*). */
export const SETUP_CALLERS = ["owner", "agentA", "agentB", "app"] as const;
export type SetupCaller = (typeof SETUP_CALLERS)[number];
/** Callers `inputsAs` may name (the owner calls person ops; their inputs are never generated). */
export const INPUT_CALLERS = ["agentA", "agentB", "app"] as const;
export type InputCaller = (typeof INPUT_CALLERS)[number];
/**
 * Built-in placeholder values the suite fills in (SPEC-GAP: CONFORMANCE v0.1.18 names only captures; a fixture that
 * grants the app caller or an agent a scope needs their run-random ids): `${tb.agentA}`, `${tb.agentB}`, `${tb.app}`
 * (the companion app caller's instance id), `${tb.instance}` (the app under test).
 */
export const BUILTIN_PLACEHOLDERS = ["tb.agentA", "tb.agentB", "tb.app", "tb.instance"] as const;

export interface SetupStep {
  id: string;
  as: SetupCaller;
  op: string;
  input: Json;
  /** capture name → JSON pointer (RFC 6901) into the step's `output` */
  capture: Record<string, string>;
}

export interface ConformanceConfig {
  waivers: Waiver[];
  setup: SetupStep[];
  /** known-good inputs per op id (merged over `--inputs`; the file wins per key) */
  inputs: Record<string, Json>;
  /** per-caller inputs; `inputsAs.<caller>.<op>` overrides `inputs.<op>` for that caller */
  inputsAs: Partial<Record<InputCaller, Record<string, Json>>>;
  /** dynamic op id → tool names A11.resolve_family resolves instead of the catalog's */
  dynamic: Record<string, { resolveTools: string[] }>;
  /** v0.1.23 (C115, package 0.1.14): the tag-filtered read A11.narrowing_empty_anyof sends (absent → not_applicable) */
  narrowing?: NarrowingFixture;
}

/**
 * `narrowing` (CONFORMANCE v0.1.23, C115): `op` = an agent read op that filters its items by `rules.narrowing`
 * memoryTags; `input` = its input (placeholders allowed; default: generated from the schema); `tag` = a tag the
 * setup gave at least one item (optional: without it the `anyOf: [tag]` part is not checked).
 */
export interface NarrowingFixture {
  op: string;
  input?: Json;
  tag?: string;
}

export const EMPTY_CONFIG: ConformanceConfig = Object.freeze({ waivers: [], setup: [], inputs: {}, inputsAs: {}, dynamic: {} });

/** A whole-string placeholder `${name}`; any other string (also one that merely contains `${`) is a literal. */
export const PLACEHOLDER_RE = /^\$\{([A-Za-z_][A-Za-z0-9_.]*)\}$/;
const CAPTURE_NAME_RE = /^[A-Za-z_][A-Za-z0-9_]*$/;
const STEP_ID_RE = /^[A-Za-z0-9_.-]{1,64}$/;
const TOP_KEYS = new Set(["waivers", "setup", "inputs", "inputsAs", "dynamic", "narrowing", "$schema", "$comment"]);
const NARROWING_KEYS = new Set(["op", "input", "tag"]);
const STEP_KEYS = new Set(["id", "as", "op", "input", "capture"]);

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

/** Every placeholder name in `v` (whole-string values only). */
export function placeholderNames(v: unknown, out: string[] = []): string[] {
  if (typeof v === "string") {
    const m = PLACEHOLDER_RE.exec(v);
    if (m) out.push(m[1] as string);
  } else if (Array.isArray(v)) for (const x of v) placeholderNames(x, out);
  else if (isRecord(v)) for (const x of Object.values(v)) placeholderNames(x, out);
  return out;
}

/** Validates a parsed `tealbrick-conformance.json` (`where` names the file in errors). */
export function parseConformanceConfig(doc: unknown, where: string): ConformanceConfig {
  if (!isRecord(doc)) throw new WaiverError(`${where}: must be a JSON object`);
  for (const k of Object.keys(doc)) if (!TOP_KEYS.has(k)) throw new WaiverError(`${where}: unknown key ${JSON.stringify(k)} (allowed: waivers, setup, inputs, inputsAs, dynamic, narrowing)`);
  const waivers = parseWaivers(doc.waivers, where);
  const builtins = new Set<string>(BUILTIN_PLACEHOLDERS);
  const captured = new Set<string>();
  const known = (names: string[], at: string, by: "an earlier setup step" | "any setup step") => {
    for (const n of names) if (!builtins.has(n) && !captured.has(n)) throw new WaiverError(`${where}: ${at}: placeholder \${${n}} is not captured by ${by} (built-ins: ${BUILTIN_PLACEHOLDERS.join(", ")})`);
  };
  const setup: SetupStep[] = [];
  if (doc.setup !== undefined) {
    if (!Array.isArray(doc.setup)) throw new WaiverError(`${where}: setup must be an array`);
    const ids = new Set<string>();
    for (const [i, x] of doc.setup.entries()) {
      const at = `setup[${i}]`;
      if (!isRecord(x)) throw new WaiverError(`${where}: ${at} must be an object`);
      for (const k of Object.keys(x)) if (!STEP_KEYS.has(k)) throw new WaiverError(`${where}: ${at}: unknown key ${JSON.stringify(k)} (allowed: id, as, op, input, capture)`);
      if (typeof x.id !== "string" || !STEP_ID_RE.test(x.id)) throw new WaiverError(`${where}: ${at}.id must be a string of letters, digits, _ . - (≤ 64)`);
      if (ids.has(x.id)) throw new WaiverError(`${where}: ${at}.id ${JSON.stringify(x.id)} is not unique`);
      ids.add(x.id);
      if (!(SETUP_CALLERS as readonly unknown[]).includes(x.as)) throw new WaiverError(`${where}: ${at}.as must be one of ${SETUP_CALLERS.join(", ")}`);
      if (typeof x.op !== "string" || x.op.length === 0) throw new WaiverError(`${where}: ${at}.op must be an operation id`);
      const input = (x.input ?? {}) as Json;
      known(placeholderNames(input), `${at}.input`, "an earlier setup step");
      const capture: Record<string, string> = {};
      if (x.capture !== undefined) {
        if (!isRecord(x.capture)) throw new WaiverError(`${where}: ${at}.capture must be an object {name: JSON pointer}`);
        for (const [name, ptr] of Object.entries(x.capture)) {
          if (!CAPTURE_NAME_RE.test(name)) throw new WaiverError(`${where}: ${at}.capture: name ${JSON.stringify(name)} must match ${CAPTURE_NAME_RE.source}`);
          if (captured.has(name)) throw new WaiverError(`${where}: ${at}.capture: ${name} is already captured by an earlier step`);
          if (typeof ptr !== "string" || (ptr !== "" && !ptr.startsWith("/"))) throw new WaiverError(`${where}: ${at}.capture.${name} must be a JSON pointer ("" or "/…")`);
          capture[name] = ptr;
        }
        for (const name of Object.keys(capture)) captured.add(name);
      }
      setup.push({ id: x.id, as: x.as as SetupCaller, op: x.op, input, capture });
    }
  }
  const opMap = (v: unknown, at: string): Record<string, Json> => {
    if (v === undefined) return {};
    if (!isRecord(v)) throw new WaiverError(`${where}: ${at} must be an object {<opId>: input}`);
    known(placeholderNames(v), at, "any setup step");
    return v as Record<string, Json>;
  };
  const inputs = opMap(doc.inputs, "inputs");
  const inputsAs: ConformanceConfig["inputsAs"] = {};
  if (doc.inputsAs !== undefined) {
    if (!isRecord(doc.inputsAs)) throw new WaiverError(`${where}: inputsAs must be an object {<caller>: {<opId>: input}}`);
    for (const [who, v] of Object.entries(doc.inputsAs)) {
      if (!(INPUT_CALLERS as readonly string[]).includes(who)) throw new WaiverError(`${where}: inputsAs.${who}: caller must be one of ${INPUT_CALLERS.join(", ")}`);
      inputsAs[who as InputCaller] = opMap(v, `inputsAs.${who}`);
    }
  }
  const dynamic: ConformanceConfig["dynamic"] = {};
  if (doc.dynamic !== undefined) {
    if (!isRecord(doc.dynamic)) throw new WaiverError(`${where}: dynamic must be an object {<dynamicOpId>: {resolveTools: [names]}}`);
    for (const [op, v] of Object.entries(doc.dynamic)) {
      const tools = isRecord(v) ? v.resolveTools : undefined;
      if (!isRecord(v) || Object.keys(v).some((k) => k !== "resolveTools") || !Array.isArray(tools) || tools.length === 0 || !tools.every((t) => typeof t === "string" && t.length > 0)) {
        throw new WaiverError(`${where}: dynamic.${op} must be {resolveTools: [non-empty tool names]}`);
      }
      dynamic[op] = { resolveTools: [...(tools as string[])] };
    }
  }
  let narrowing: NarrowingFixture | undefined;
  if (doc.narrowing !== undefined) {
    const n = doc.narrowing;
    const shape = `${where}: narrowing must be {op: "<agent read op id>", input?: <input>, tag?: "<tag>"}`;
    if (!isRecord(n)) throw new WaiverError(shape);
    for (const k of Object.keys(n)) if (!NARROWING_KEYS.has(k)) throw new WaiverError(`${where}: narrowing: unknown key ${JSON.stringify(k)} (allowed: op, input, tag)`);
    if (typeof n.op !== "string" || n.op.length === 0) throw new WaiverError(`${shape}; op missing`);
    // SDK-API §18: tags ≤ 64 chars (compared after normalizeTag = trim + lower case)
    if (n.tag !== undefined && (typeof n.tag !== "string" || n.tag.trim().length === 0 || n.tag.length > 64)) throw new WaiverError(`${where}: narrowing.tag must be a non-empty string of ≤ 64 characters`);
    if (n.input !== undefined) known(placeholderNames(n.input), "narrowing.input", "any setup step");
    narrowing = { op: n.op, ...(n.input !== undefined ? { input: n.input as Json } : {}), ...(typeof n.tag === "string" ? { tag: n.tag } : {}) };
  }
  return { waivers, setup, inputs, inputsAs, dynamic, ...(narrowing ? { narrowing } : {}) };
}

function parseWaivers(list: unknown, where: string): Waiver[] {
  if (list === undefined) return [];
  if (!Array.isArray(list)) throw new WaiverError(`${where}: waivers must be an array`);
  return list.map((x, i) => {
    const o = (x && typeof x === "object" ? x : {}) as Record<string, unknown>;
    if (typeof o.id !== "string" || typeof o.until !== "string" || typeof o.reason !== "string") throw new WaiverError(`${where}: waivers[${i}] needs string id, until and reason`);
    return checked({ id: o.id, until: o.until, reason: o.reason }, `${where} waivers[${i}]`);
  });
}

/** `tealbrick-conformance.json` beside `manifestPath` (EMPTY_CONFIG when the file is absent); throws WaiverError (usage error) when malformed. */
export function loadConformanceConfig(manifestPath: string): ConformanceConfig {
  const path = join(dirname(manifestPath), WAIVER_FILE);
  if (!existsSync(path)) return EMPTY_CONFIG;
  let doc: unknown;
  try {
    doc = JSON.parse(readFileSync(path, "utf8"));
  } catch (e) {
    throw new WaiverError(`${path}: not JSON (${e instanceof Error ? e.message : String(e)})`);
  }
  return parseConformanceConfig(doc, path);
}
