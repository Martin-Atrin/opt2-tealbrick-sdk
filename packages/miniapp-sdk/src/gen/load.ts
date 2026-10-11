// Shared plumbing of `tb-gen`: manifest loading (validator-gated), the in-memory file set, deterministic JSON.
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { validateManifest } from "@opt2-tealbrick/manifest";
import type { Manifest, ManifestIssue } from "@opt2-tealbrick/spec/manifest";

export const DEFAULT_MANIFEST = "tealbrick.manifest.json";

/** SDK version stamped into the OpenAPI document (same source as the server's `SDK_VERSION`). */
export const GEN_SDK_VERSION: string = (JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }).version;

export class GenError extends Error {
  readonly code: string;
  readonly issues: readonly ManifestIssue[];
  constructor(code: string, message: string, issues: readonly ManifestIssue[] = []) {
    super(message);
    this.name = "GenError";
    this.code = code;
    this.issues = issues;
  }
}

export interface LoadedManifest {
  manifest: Manifest;
  digest: `sha256:${string}`;
  /** Directory of the manifest file: skill files resolve against it (repo root). */
  dir: string;
}

/** Validated manifest input of every generator. `dir` is only needed by generators that read skill files. */
export function fromManifest(json: unknown, dir = "."): LoadedManifest {
  const v = validateManifest(json);
  if (!v.ok) throw new GenError("manifest_invalid", `manifest invalid (${v.errors.length} issue(s))`, v.errors);
  return { manifest: v.manifest, digest: v.digest, dir: resolve(dir) };
}

/** Reads and validates `tealbrick.manifest.json`; refuses an unreadable or invalid manifest. */
export function loadManifest(path: string): LoadedManifest {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new GenError("manifest_unreadable", `cannot read ${path}`);
  }
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    throw new GenError("manifest_invalid", `${path} is not JSON`);
  }
  return fromManifest(json, dirname(resolve(path)));
}

/** Generated files: path relative to the kind's output dir → content. */
export type GenFiles = Map<string, string>;

/** JSON with object keys sorted recursively, 2-space indent, trailing newline (byte-stable output). */
export function stableJson(value: unknown): string {
  return `${JSON.stringify(sortKeys(value), null, 2)}\n`;
}

function sortKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(sortKeys);
  if (typeof v === "object" && v !== null) {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(v).sort()) out[k] = sortKeys((v as Record<string, unknown>)[k]);
    return out;
  }
  return v;
}

export function writeFiles(outDir: string, files: GenFiles): string[] {
  const written: string[] = [];
  for (const [rel, content] of [...files].sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))) {
    const path = join(outDir, rel);
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, content);
    written.push(path);
  }
  return written;
}

/** Markdown table cell: one line, pipes escaped. */
export function cell(v: unknown): string {
  if (v === undefined || v === null || v === "") return "—";
  const s = Array.isArray(v) ? v.join(", ") : typeof v === "object" ? JSON.stringify(v) : String(v);
  return s.replace(/\s+/g, " ").replaceAll("|", "\\|");
}

/** `{a: x, b: [y, z]}` condition → `a = x and b ∈ {y, z}`. */
export function conditionText(when: Record<string, unknown> | undefined): string {
  if (!when) return "";
  return Object.entries(when)
    .map(([k, v]) => (Array.isArray(v) ? `${k} ∈ {${v.map(String).join(", ")}}` : `${k} = ${String(v)}`))
    .join(" and ");
}
