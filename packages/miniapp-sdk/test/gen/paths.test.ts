// tb-gen path bases (MANIFEST §3, v0.1.11 (C70)): build paths are repo-relative, skill files manifest-relative.
// Layout of opt2-tealbrick-samples: <repo>/<app>/tealbrick.manifest.json, <repo>/<app>/skills/..., <repo>/<app>/Dockerfile.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { describe, test } from "node:test";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import { generate } from "../../src/gen/generate.ts";
import { fromManifest, GenError, loadManifest } from "../../src/gen/load.ts";
import { genRailway } from "../../src/gen/railway.ts";
import { notesJson, TB_GEN_CLI, temp } from "./repos.ts";

const isGen = (code: string) => (e: unknown) => e instanceof GenError && e.code === code;
const cli = (args: string[], cwd: string) => spawnSync(process.execPath, [TB_GEN_CLI, ...args], { cwd, encoding: "utf8" });
const skill = (id: string) => `---\nname: ${id}\ndescription: Skill ${id}.\n---\n# ${id}\n\nSKILL-BODY-${id}\n`;

/** The notes example as an app in subdirectory `app/` of a repo: build paths repo-relative, `search` built too. */
function appManifest(): Manifest {
  const m = notesJson() as unknown as Record<string, any>;
  m.runtime.build = { context: "app", dockerfile: "app/Dockerfile" };
  const svc = m.runtime.services[0];
  delete svc.image;
  svc.build = { context: "app", dockerfile: "app/Dockerfile.search" };
  return m as unknown as Manifest;
}

function put(root: string, files: Record<string, string>): void {
  for (const [rel, text] of Object.entries(files)) {
    mkdirSync(dirname(join(root, rel)), { recursive: true });
    writeFileSync(join(root, rel), text);
  }
}

/** Multi-app repo: build files and skills inside `app/`, the manifest next to them. */
function multiAppRepo(root: string, over: { skillsAt?: string } = {}): string {
  const at = over.skillsAt ?? "app";
  put(root, {
    "app/Dockerfile": "FROM scratch\n",
    "app/Dockerfile.search": "FROM scratch\n",
    [`${at}/skills/notes-basics/SKILL.md`]: skill("notes-basics"),
    [`${at}/skills/notes-summaries/SKILL.md`]: skill("notes-summaries"),
    "app/tealbrick.manifest.json": `${JSON.stringify(appManifest(), null, 2)}\n`,
  });
  return join(root, "app", "tealbrick.manifest.json");
}

describe("tb-gen path bases", () => {
  test("multi-app layout: skills read next to the manifest, build paths emitted and checked from the repo root", (t) => {
    const root = temp(t);
    multiAppRepo(root);
    const lm = loadManifest(join(root, "app", "tealbrick.manifest.json"), root);
    assert.equal(lm.repoDir, root);
    assert.equal(lm.manifestDir, join(root, "app"));
    const kit = [...generate("kit", lm).entries()].find(([k]) => k.endsWith("src/index.ts"))?.[1] as string;
    assert.match(kit, /SKILL-BODY-notes-basics/, "skill text read from the manifest directory");
    const tpl = JSON.parse(genRailway(lm, { settings: { search_index: "fulltext" } }).get("template.json") as string);
    const app = tpl.services.find((s: { role: string }) => s.role === "app");
    assert.equal(app.source.rootDirectory, "app");
    assert.equal(app.source.dockerfilePath, "Dockerfile", "dockerfilePath is relative to the repo-relative root directory");
    const search = tpl.services.find((s: { role: string }) => s.role === "service");
    assert.equal(search.source.dockerfilePath, "Dockerfile.search");
  });

  test("negative: a skill that exists only at the repo root is not found (it is manifest-relative)", (t) => {
    const root = temp(t);
    multiAppRepo(root, { skillsAt: "." });
    const lm = loadManifest(join(root, "app", "tealbrick.manifest.json"), root);
    assert.throws(() => generate("kit", lm), isGen("skill_file_missing"));
  });

  test("negative: build paths resolved from the manifest directory do not exist (railway, repo dir given)", (t) => {
    const root = temp(t);
    multiAppRepo(root);
    const wrong = loadManifest(join(root, "app", "tealbrick.manifest.json"), join(root, "app"));
    assert.throws(
      () => genRailway(wrong),
      (e: unknown) => isGen("build_path_missing")(e) && /runtime\.build\.context app/.test((e as GenError).message),
    );
  });

  test("negative: a missing Dockerfile of a service build under the repo root is refused", (t) => {
    const root = temp(t);
    multiAppRepo(root);
    writeFileSync(join(root, "app", "Dockerfile.search"), "");
    const json = JSON.parse(JSON.stringify(appManifest()));
    json.runtime.services[0].build.dockerfile = "app/Dockerfile.nope";
    assert.throws(() => genRailway(fromManifest(json, root, join(root, "app"))), (e: unknown) => isGen("build_path_missing")(e) && /Dockerfile\.nope/.test((e as GenError).message));
  });

  test("without a repo dir the railway generator does not touch the disk (repoDir defaults to the manifest dir)", (t) => {
    const root = temp(t);
    const path = multiAppRepo(root);
    const lm = loadManifest(path);
    assert.equal(lm.repoDir, lm.manifestDir);
    assert.equal(lm.repoDirGiven, false);
    assert.ok(genRailway(lm).has("template.json"));
    const same = fromManifest(JSON.parse(JSON.stringify(appManifest())), root);
    assert.equal(same.manifestDir, same.repoDir, "manifestDir defaults to repoDir");
  });

  test("CLI: --repo is the repo root, the manifest directory is dirname(--manifest)", (t) => {
    const root = temp(t);
    multiAppRepo(root);
    const ok = cli(["all", "--manifest", "app/tealbrick.manifest.json", "--repo", ".", "--out", "gen", "--set", "search_index=fulltext"], root);
    assert.equal(ok.status, 0, ok.stderr);
    assert.match(ok.stdout, /gen\/railway\/template\.json/);
    // the repo root given as the app dir: build paths do not exist there
    const bad = cli(["railway", "--manifest", "app/tealbrick.manifest.json", "--repo", "app", "--set", "search_index=fulltext"], root);
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /build_path_missing/);
    // no --repo: nothing to check, skills still come from dirname(--manifest)
    const none = cli(["all", "--manifest", "app/tealbrick.manifest.json", "--out", "gen2"], root);
    assert.equal(none.status, 0, none.stderr);
  });

  test("CLI negative: skills only at the repo root fail even with --repo .", (t) => {
    const root = temp(t);
    multiAppRepo(root, { skillsAt: "." });
    const r = cli(["kit", "--manifest", "app/tealbrick.manifest.json", "--repo", "."], root);
    assert.equal(r.status, 1);
    assert.match(r.stderr, /skill_file_missing/);
  });

  test("CLI: --repo needs a value", (t) => {
    const r = cli(["kit", "--repo"], temp(t));
    assert.equal(r.status, 2);
    assert.match(r.stderr, /--repo needs a value/);
  });
});
