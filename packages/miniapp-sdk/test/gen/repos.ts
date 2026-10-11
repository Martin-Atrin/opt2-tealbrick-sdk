// tb-gen test repos: the spec example manifest and the create-tealbrick-miniapp template manifest, each in a temp dir
// with its skill files (the spec example ships none, so stubs are written).
import { mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { dirname, join } from "node:path";
import type { TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { tempDir } from "../helpers.ts";

export const NOTES_MANIFEST = createRequire(import.meta.url).resolve("@opt2-tealbrick/spec/examples/notes.manifest.json");
export const TEMPLATE_DIR = fileURLToPath(new URL("../../../create-tealbrick-miniapp/template/", import.meta.url));
export const TB_GEN_CLI = fileURLToPath(new URL("../../src/gen/cli.ts", import.meta.url));

export const TEMPLATE_ID = "demo-items";
export const TEMPLATE_NAME = "Demo Items";

export function notesJson(): Manifest {
  return JSON.parse(readFileSync(NOTES_MANIFEST, "utf8")) as Manifest;
}

export function templateJson(): Manifest {
  const text = readFileSync(join(TEMPLATE_DIR, "tealbrick.manifest.json"), "utf8").replaceAll("__APP_ID__", TEMPLATE_ID).replaceAll("__APP_NAME__", TEMPLATE_NAME);
  return JSON.parse(text) as Manifest;
}

export function temp(t: TestContext, prefix = "tb-gen-test-"): string {
  const d = tempDir(prefix);
  t.after(() => d.cleanup());
  return d.dir;
}

/** Writes `manifest` (and a SKILL.md per skill) into `dir`; returns the manifest path. */
export function writeRepo(dir: string, manifest: unknown, skillText: (id: string) => string = (id) => `---\nname: ${id}\ndescription: Stub skill ${id}.\n---\n# ${id}\n\nHello {{agent.name}}.\n`): string {
  for (const s of (manifest as Manifest).skills ?? []) {
    mkdirSync(dirname(join(dir, s.file)), { recursive: true });
    writeFileSync(join(dir, s.file), skillText(s.id));
  }
  const path = join(dir, "tealbrick.manifest.json");
  writeFileSync(path, `${JSON.stringify(manifest, null, 2)}\n`);
  return path;
}

/** The template repo: its real skill file (placeholders substituted). */
export function writeTemplateRepo(dir: string): string {
  const skillDir = join(TEMPLATE_DIR, "skills");
  const [only] = readdirSync(skillDir);
  const text = readFileSync(join(skillDir, only as string, "SKILL.md"), "utf8").replaceAll("__APP_ID__", TEMPLATE_ID).replaceAll("__APP_NAME__", TEMPLATE_NAME);
  return writeRepo(dir, templateJson(), () => text);
}

/** Every file under `dir` → content (sorted relative paths). */
export function tree(dir: string, base = dir): Map<string, Buffer> {
  const out = new Map<string, Buffer>();
  for (const e of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const p = join(dir, e.name);
    if (e.isDirectory()) for (const [k, v] of tree(p, base)) out.set(k, v);
    else out.set(p.slice(base.length + 1), readFileSync(p));
  }
  return out;
}
