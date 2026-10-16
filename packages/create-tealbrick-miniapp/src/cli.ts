#!/usr/bin/env node
// create-tealbrick-miniapp <dir> --id <slug> [--name "<Name>"]
import { relative } from "node:path";
import { parseArgs } from "node:util";
import { CreateError, createMiniapp } from "./create.ts";

const USAGE = 'usage: create-tealbrick-miniapp <dir> --id <slug> [--name "<Name>"]';

const OPTIONS = { id: { type: "string" }, name: { type: "string" }, help: { type: "boolean", short: "h" } } as const;

function parse(argv: string[]) {
  try {
    return parseArgs({ args: argv, options: OPTIONS, allowPositionals: true });
  } catch (e) {
    console.error(`${e instanceof Error ? e.message : String(e)}\n${USAGE}`);
    return null;
  }
}

function main(argv: string[]): number {
  const parsed = parse(argv);
  if (!parsed) return 2;
  const { values, positionals } = parsed;
  if (values.help) {
    console.log(USAGE);
    return 0;
  }
  if (positionals.length !== 1 || values.id === undefined) {
    console.error(USAGE);
    return 2;
  }
  try {
    const r = createMiniapp({ dir: positionals[0] as string, id: values.id, ...(values.name !== undefined ? { name: values.name } : {}) });
    const rel = relative(process.cwd(), r.dir);
    const shown = rel === "" ? "." : rel.startsWith("..") ? r.dir : rel;
    console.log(
      [
        `Created ${r.name} (${r.id}) in ${shown}: ${r.files.length} files.`,
        "",
        "Next steps:",
        `  cd ${shown}`,
        "  pnpm install                 # then commit pnpm-lock.yaml (CI installs with --frozen-lockfile)",
        "  pnpm typecheck && pnpm lint && pnpm test",
        "  pnpm build                   # server to dist/, UI to dist/ui",
        "  pnpm conformance",
        '  git init && git add -A && git commit -m "chore: scaffold"',
        "",
        `Push to github.com/Tealbrick/opt2-tealbrick-${r.id}; release with a v<semver> tag equal to the manifest version.`,
      ].join("\n"),
    );
    return 0;
  } catch (e) {
    if (e instanceof CreateError) {
      console.error(`error ${e.code}: ${e.message}`);
      return 1;
    }
    throw e;
  }
}

process.exitCode = main(process.argv.slice(2));
