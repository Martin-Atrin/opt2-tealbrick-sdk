import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it, type TestContext } from "node:test";
import { fileURLToPath } from "node:url";
import { validateAppFiles, validateManifest } from "@opt2-tealbrick/manifest";
import { CreateError, createMiniapp, defaultName, PLACEHOLDER, renderTemplate, TEMPLATE_DIR } from "../src/create.ts";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const PLATFORM_CI = fileURLToPath(new URL("../../../../opt2-tealbrick-platform/ci/woodpecker/ci.yaml", import.meta.url));
// same rule as the platform CI setup step (ci/tb-ci.ts RELEASE_URL_RE)
const RELEASE_URL_RE =
  /^https:\/\/github\.com\/Martin-Atrin\/opt2-tealbrick-[a-z0-9-]+\/releases\/download\/[a-z0-9-]+-v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\/[a-z0-9-]+-\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?\.tgz$/;

function temp(t: TestContext): string {
  const dir = mkdtempSync(join(tmpdir(), "create-tb-miniapp-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  return dir;
}

function walk(dir: string, base = dir): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name), base) : [join(dir, e.name).slice(base.length + 1)]));
}

const read = (dir: string, rel: string) => readFileSync(join(dir, rel), "utf8");
const readJson = <T = Record<string, any>>(dir: string, rel: string) => JSON.parse(read(dir, rel)) as T;

function rejectsWith(code: string) {
  return (e: unknown) => e instanceof CreateError && e.code === code;
}

describe("createMiniapp", () => {
  it("writes a scaffold whose manifest and app files validate", async (t) => {
    const dir = join(temp(t), "my-notes");
    const r = createMiniapp({ dir, id: "my-notes", name: "My Notes" });
    assert.equal(r.dir, dir);
    assert.equal(r.name, "My Notes");
    for (const f of [
      "tealbrick.manifest.json",
      "src/app.ts",
      "src/main.ts",
      "src/items.ts",
      "src/ui/main.tsx",
      "src/ui/App.tsx",
      "src/ui/index.html",
      "migrations/0001_init.sql",
      "skills/use-my-notes/SKILL.md",
      "Dockerfile",
      ".woodpecker/ci.yaml",
      "tealbrick-ci.json",
      "biome.json",
      "tsconfig.json",
      "package.json",
      "test/app.test.ts",
      ".gitignore",
      ".dockerignore",
      "README.md",
    ])
      assert.ok(r.files.includes(f), `scaffold has ${f}`);
    assert.deepEqual(walk(dir).sort(), r.files);

    const manifest = readJson(dir, "tealbrick.manifest.json");
    const v = validateManifest(manifest);
    assert.equal(v.ok, true, v.ok ? "" : JSON.stringify(v.errors));
    if (!v.ok) return;
    assert.equal(v.manifest.id, "my-notes");
    assert.equal(v.manifest.name, "My Notes");
    const files = await validateAppFiles(v.manifest, dir);
    assert.equal(files.ok, true, files.ok ? "" : JSON.stringify(files.errors));

    // starter content the template promises (SDK-API §15, C28)
    const ops = v.manifest.operations;
    assert.deepEqual(
      ops.map((o) => [o.id, o.crud.join(","), o.idempotency]),
      [
        ["items_list", "read", "none"],
        ["item_create", "create", "required"],
      ],
    );
    assert.deepEqual(
      v.manifest.runtime.volumes.map((x) => x.purpose),
      ["data", "backup"],
    );
    assert.equal(v.manifest.scopes?.length, 1);
    assert.ok((v.manifest.scopes?.[0]?.defaultGrants.length ?? 0) > 0);
    assert.ok(v.manifest.backups.schedule && v.manifest.backups.retain > 0);
    assert.equal(v.manifest.ui?.launchPath, "/");
  });

  it("leaves no placeholder in any path or file", (t) => {
    const dir = join(temp(t), "app");
    const r = createMiniapp({ dir, id: "zz-top", name: "ZZ Top" });
    for (const f of r.files) {
      assert.doesNotMatch(f, PLACEHOLDER, f);
      assert.doesNotMatch(read(dir, f), PLACEHOLDER, f);
    }
    assert.match(read(dir, "src/ui/main.tsx"), /product="zz-top"/);
    assert.match(read(dir, "src/ui/index.html"), /<base href="\/a\/zz-top\/" \/>/);
  });

  it("ships pnpm-lock.yaml with sha512 integrity for every release-URL tarball (ci-v8; no tealbrick-integrity.json)", (t) => {
    const dir = join(temp(t), "app");
    const r = createMiniapp({ dir, id: "pin-check" });
    assert.ok(r.files.includes("pnpm-lock.yaml"));
    assert.ok(!r.files.includes("tealbrick-integrity.json"), "retired in ci-v8");
    const lock = readFileSync(join(dir, "pnpm-lock.yaml"), "utf8");
    const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8")) as { dependencies: Record<string, string>; devDependencies: Record<string, string> };
    for (const url of Object.values({ ...pkg.dependencies, ...pkg.devDependencies }).filter((u) => u.startsWith("https://github.com/"))) {
      const at = lock.indexOf(`tarball: ${url}`);
      assert.ok(at >= 0, `lockfile resolves ${url}`);
      assert.match(lock.slice(Math.max(0, at - 200), at + url.length + 200), /integrity: sha512-/, `integrity for ${url}`);
    }
  });

  it("follows the platform CI standard and the release-URL dependency rule", (t) => {
    const dir = join(temp(t), "app");
    createMiniapp({ dir, id: "tasks", name: "Tasks" });
    const pkg = readJson(dir, "package.json");
    assert.equal(pkg.name, "opt2-tealbrick-tasks");
    assert.equal(pkg.private, true);
    assert.equal(pkg.publishConfig, undefined);
    assert.match(pkg.packageManager, /^pnpm@\d+\.\d+\.\d+\+sha512\.[0-9a-f]{128}$/, "ci-v8: packageManager pinned by hash");
    assert.match(readFileSync(join(dir, "Dockerfile"), "utf8"), /RUN pnpm install --frozen-lockfile --ignore-scripts/, "ci-v8: image installs never run scripts");
    for (const s of ["typecheck", "lint", "test", "conformance", "build", "gen"]) assert.equal(typeof pkg.scripts[s], "string", `script ${s}`);
    assert.equal(pkg.scripts.conformance, "node --run kit && tb-conformance app --start conformance.start.ts --manifest tealbrick.manifest.json");
    // BSA-12: op ids and I/O types come from the generated kit, generated before every step that compiles or runs src
    assert.equal(pkg.scripts.kit, "tb-gen kit && tsc -p gen/kit/tasks-kit --outDir dist/kit");
    assert.deepEqual(pkg.imports, { "#kit": "./dist/kit/index.js" });
    for (const s of ["start", "typecheck", "test", "conformance", "build"]) assert.match(pkg.scripts[s], /^node --run kit && /, `script ${s}`);
    const app = read(dir, "src/app.ts");
    assert.match(app, /^import \{[^}]*\bOP\b[^}]*\} from "#kit";$/m);
    assert.match(app, /\[OP\.itemsList\]/);
    assert.match(app, /satisfies Record<OpId, HandlerSpec>/);
    assert.doesNotMatch(app, /\binterface \w+(Input|Output)\b/, "no hand-written I/O types");
    // generated artifacts (SDK-API §15): produced by tb-gen, never committed
    assert.equal(pkg.scripts.gen, "tb-gen all");
    assert.ok(read(dir, ".gitignore").split("\n").includes("gen/"), "gen/ is gitignored");
    // the conformance harness the script names: default-exports start(env) with backupNow (A7 round-trip)
    const harness = read(dir, "conformance.start.ts");
    assert.match(harness, /export default async function start\(env/);
    assert.match(harness, /startApp\(app, env\)/);
    assert.match(harness, /backupNow/);
    const tb = Object.entries<string>({ ...pkg.dependencies, ...pkg.devDependencies }).filter(([n]) => n.startsWith("@opt2-tealbrick/"));
    assert.deepEqual(tb.map(([n]) => n).sort(), ["@opt2-tealbrick/conformance", "@opt2-tealbrick/manifest", "@opt2-tealbrick/miniapp-sdk", "@opt2-tealbrick/ui"]);
    for (const [n, url] of tb) assert.match(url, RELEASE_URL_RE, n);
    assert.match(pkg.devDependencies["@opt2-tealbrick/ui"], /\/ui-v0\.1\.1\//);
    assert.match(pkg.dependencies["@opt2-tealbrick/miniapp-sdk"], /\/miniapp-sdk-v0\.1\.10\//);
    assert.match(pkg.devDependencies["@opt2-tealbrick/conformance"], /\/conformance-v0\.1\.6\//);
    // BSA-07: the ONE app shell from ui, no local frame
    const ui = read(dir, "src/ui/App.tsx");
    assert.match(ui, /import \{[^}]*\bAppShell\b[^}]*\} from "@opt2-tealbrick\/ui";/);
    assert.match(ui, /<AppShell\b/);
    assert.doesNotMatch(ui, /SPEC-GAP|function Frame\b/);

    const ci = readJson(dir, "tealbrick-ci.json");
    assert.equal(ci.kind, "miniapp");
    assert.deepEqual(ci.images, [{ name: "opt2-tealbrick-tasks", product: "tasks", kind: "app", manifest: "tealbrick.manifest.json" }]);
    const pipeline = read(dir, ".woodpecker/ci.yaml");
    assert.match(pipeline, /GENERATED from Martin-Atrin\/opt2-tealbrick-platform: ci\/woodpecker\/ci\.yaml/);
    if (existsSync(PLATFORM_CI)) assert.equal(pipeline, readFileSync(PLATFORM_CI, "utf8"), "byte-identical copy of the platform template");

    const docker = read(dir, "Dockerfile");
    const froms = [...docker.matchAll(/^FROM (\S+)/gm)].map((m) => m[1]);
    assert.ok(froms.length > 0);
    for (const f of froms) assert.match(f as string, /^node:24-slim@sha256:[0-9a-f]{64}$/);
    assert.match(docker, /^USER node$/m);
    assert.match(docker, /^CMD \["node", "dist\/main\.js"\]$/m);
    assert.match(docker, /^COPY tealbrick\.manifest\.json \/opt\/tb\/tealbrick\.manifest\.json$/m);
    // BSA-06: the ONE Dockerfile pattern (pnpm frozen lockfile, kit + tsc + UI build to dist, data under /data)
    const [build = "", runtime = ""] = docker.split(/^FROM .*$/m).slice(1);
    assert.match(build, /^RUN corepack enable$/m);
    assert.match(build, /^RUN pnpm install --frozen-lockfile --ignore-scripts$/m);
    assert.match(build, /^COPY tealbrick\.manifest\.json .*\n(?:.*\n)*RUN pnpm run build && pnpm prune --prod$/m, "manifest is in the build stage before tb-gen runs");
    assert.match(build, /^COPY skills \.\/skills$/m, "the kit embeds the skill texts");
    assert.match(runtime, /^ENV .*\bTB_DATA_DIR=\/data TB_BACKUP_DIR=\/data\/backup$/m);
    assert.match(runtime, /^COPY --from=build \/app\/dist \.\/dist$/m);
    assert.match(read(dir, ".dockerignore"), /^gen$/m);

    const skill = read(dir, "skills/use-tasks/SKILL.md");
    const front = /^---\n([\s\S]*?)\n---\n/.exec(skill)?.[1] ?? "";
    assert.deepEqual(
      front.split("\n").map((l) => l.split(":")[0]),
      ["name", "description"],
    );
    assert.match(front, /^name: use-tasks$/m);
  });

  it("derives the name from the id when --name is omitted", (t) => {
    const r = createMiniapp({ dir: join(temp(t), "a"), id: "field-notes" });
    assert.equal(r.name, "Field Notes");
    assert.equal(defaultName("a1-b--c"), "A1 B C");
  });

  it("accepts an existing empty directory", (t) => {
    const dir = temp(t);
    assert.equal(createMiniapp({ dir, id: "empty-ok" }).dir, dir);
  });

  it("refuses a non-empty directory and writes nothing", (t) => {
    const dir = temp(t);
    writeFileSync(join(dir, "keep.txt"), "mine");
    assert.throws(() => createMiniapp({ dir, id: "taken" }), rejectsWith("dir_not_empty"));
    assert.deepEqual(readdirSync(dir), ["keep.txt"]);
    const file = join(dir, "keep.txt");
    assert.throws(() => createMiniapp({ dir: file, id: "taken" }), rejectsWith("dir_not_empty"));
  });

  it("refuses invalid slugs and names", (t) => {
    const dir = join(temp(t), "x");
    for (const id of ["", "a", "A-app", "1app", "my_app", "my.app", "x".repeat(33), "app/../evil"])
      assert.throws(() => createMiniapp({ dir, id }), rejectsWith("id_invalid"), JSON.stringify(id));
    for (const name of ["", "  ", 'Quote"s', "<b>Bold</b>", "x".repeat(41), "Two  spaces", "Colon: no", "-dash"])
      assert.throws(() => createMiniapp({ dir, id: "ok-app", name }), rejectsWith("name_invalid"), JSON.stringify(name));
    assert.equal(existsSync(dir), false);
  });
});

describe("renderTemplate", () => {
  it("refuses a template with an unknown placeholder or an invalid manifest", (t) => {
    const tpl = join(temp(t), "tpl");
    cpSync(TEMPLATE_DIR, tpl, { recursive: true });
    writeFileSync(join(tpl, "extra.txt"), "__APP_VERSION__");
    assert.throws(() => renderTemplate("abc", "Abc", tpl), rejectsWith("template_invalid"));
    rmSync(join(tpl, "extra.txt"));
    const m = JSON.parse(readFileSync(join(tpl, "tealbrick.manifest.json"), "utf8"));
    m.runtime.volumes = m.runtime.volumes.filter((v: { purpose: string }) => v.purpose !== "backup");
    writeFileSync(join(tpl, "tealbrick.manifest.json"), JSON.stringify(m));
    assert.throws(() => renderTemplate("abc", "Abc", tpl), rejectsWith("manifest_invalid"));
  });
});

describe("cli", () => {
  const run = (args: string[], cwd: string) => spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8" });

  it("scaffolds and prints next steps", (t) => {
    const cwd = temp(t);
    const r = run(["hello", "--id", "hello", "--name", "Hello World"], cwd);
    assert.equal(r.status, 0, r.stderr);
    assert.match(r.stdout, /Created Hello World \(hello\) in hello/);
    assert.match(r.stdout, /pnpm install/);
    assert.equal(readJson(join(cwd, "hello"), "tealbrick.manifest.json").name, "Hello World");
  });

  it("exits non-zero on a non-empty dir, a bad slug, or missing arguments", (t) => {
    const cwd = temp(t);
    mkdirSync(join(cwd, "full"));
    writeFileSync(join(cwd, "full", "x"), "");
    const full = run(["full", "--id", "full"], cwd);
    assert.equal(full.status, 1);
    assert.match(full.stderr, /dir_not_empty/);
    const bad = run(["bad", "--id", "Bad"], cwd);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /id_invalid/);
    assert.equal(run(["only-dir"], cwd).status, 2);
    assert.equal(run(["a", "--id", "aa", "--bogus"], cwd).status, 2);
  });
});
