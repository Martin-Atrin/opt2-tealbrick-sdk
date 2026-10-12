// Scaffold writer (SDK-API §15): copies template/ into an empty directory, substituting the product id and name.
// Everything is rendered and checked in memory first (the manifest must pass validateManifest), so a refusal
// never leaves a half-written directory.
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { validateManifest } from "@opt2-tealbrick/manifest";

export const TEMPLATE_DIR: string = fileURLToPath(new URL("../template", import.meta.url));
/** Manifest `id` (product id, CORE §1). */
export const ID_PATTERN: RegExp = /^[a-z][a-z0-9-]{1,31}$/;
/** Display name: manifest `name` (≤ 40) restricted to characters that need no escaping in JSON, TS, HTML or YAML. */
export const NAME_PATTERN: RegExp = /^[A-Za-z0-9](?:[A-Za-z0-9 ._-]{0,38}[A-Za-z0-9.])?$/;
/** Every placeholder form the template uses; none may survive rendering. */
export const PLACEHOLDER: RegExp = /__APP_[A-Z]+__/;

/** Template files stored under another name (npm pack drops or rewrites dotfiles; a nested biome.json breaks the repo lint). */
const RENAMES: Record<string, string> = {
  gitignore: ".gitignore",
  dockerignore: ".dockerignore",
  "woodpecker/ci.yaml": ".woodpecker/ci.yaml",
  "github/workflows/opt2-release.yml": ".github/workflows/opt2-release.yml",
  "biome.template.json": "biome.json",
};

export class CreateError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = "CreateError";
    this.code = code;
  }
}

export interface CreateOptions {
  dir: string;
  id: string;
  name?: string;
}

export interface CreateResult {
  dir: string;
  id: string;
  name: string;
  /** written files, relative to `dir`, sorted */
  files: string[];
}

/** "my-app" → "My App" */
export function defaultName(id: string): string {
  return id
    .split("-")
    .filter((w) => w !== "")
    .map((w) => w[0]?.toUpperCase() + w.slice(1))
    .join(" ");
}

function templateFiles(dir: string): string[] {
  const out: string[] = [];
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.isFile()) out.push(relative(dir, p).split(sep).join("/"));
    }
  };
  walk(dir);
  return out.sort();
}

/** Renders the template for (id, name): output path → content. Throws CreateError on an invalid result. */
export function renderTemplate(id: string, name: string, templateDir: string = TEMPLATE_DIR): Map<string, string> {
  const values: Record<string, string> = { __APP_ID__: id, __APP_NAME__: name };
  const fill = (text: string) => text.replace(/__APP_(?:ID|NAME)__/g, (m) => values[m] as string);
  const files = new Map<string, string>();
  for (const rel of templateFiles(templateDir)) {
    const path = fill(RENAMES[rel] ?? rel);
    const content = fill(readFileSync(join(templateDir, rel), "utf8"));
    if (PLACEHOLDER.test(path) || PLACEHOLDER.test(content)) throw new CreateError("template_invalid", `unreplaced placeholder in ${path}`);
    files.set(path, content);
  }
  const manifestText = files.get("tealbrick.manifest.json");
  if (manifestText === undefined) throw new CreateError("template_invalid", "template has no tealbrick.manifest.json");
  const v = validateManifest(JSON.parse(manifestText));
  if (!v.ok) throw new CreateError("manifest_invalid", `generated manifest is invalid: ${v.errors.map((e) => `${e.path} ${e.code}`).join("; ")}`);
  return files;
}

/** Writes the scaffold into `dir` (created if missing; refused if it exists and is not an empty directory). */
export function createMiniapp(opts: CreateOptions, templateDir: string = TEMPLATE_DIR): CreateResult {
  const id = opts.id;
  if (!ID_PATTERN.test(id)) throw new CreateError("id_invalid", `--id must match ${ID_PATTERN.source} (lowercase letters, digits, hyphens; 2-32 chars)`);
  const name = opts.name === undefined ? defaultName(id) : opts.name.trim();
  if (!NAME_PATTERN.test(name) || name.includes("  "))
    throw new CreateError("name_invalid", "--name must be 1-40 characters: letters, digits, single spaces, '.', '_' or '-'");
  const dir = resolve(opts.dir);
  if (existsSync(dir)) {
    if (!statSync(dir).isDirectory()) throw new CreateError("dir_not_empty", `${dir} exists and is not a directory`);
    if (readdirSync(dir).length > 0) throw new CreateError("dir_not_empty", `${dir} is not empty`);
  }
  const files = renderTemplate(id, name, templateDir);
  for (const [rel, content] of files) {
    const target = join(dir, rel);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, content, { flag: "wx" });
  }
  return { dir, id, name, files: [...files.keys()].sort() };
}
