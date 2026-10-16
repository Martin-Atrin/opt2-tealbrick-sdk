/* run-tests.ts: runs the package's node:test files in two groups so the CI `unit` and `conformance` stages do not run the same
   files twice. `conformance` = the suite's own gates (the app target against a correct app and each broken variant, the SDK
   coverage table, the manifest target); `unit` = every other test file. A new test file is a unit test unless it is listed here.
   usage: node scripts/run-tests.ts unit|conformance */
import { spawnSync } from "node:child_process";
import { globSync } from "node:fs";
import { join } from "node:path";

const CONFORMANCE = new Set(["test/app-suite.test.ts", "test/coverage.test.ts", "test/manifest.test.ts"]);
const group = process.argv[2];
if (group !== "unit" && group !== "conformance") {
  console.error("usage: node scripts/run-tests.ts unit|conformance");
  process.exit(2);
}
const root = join(import.meta.dirname, "..");
const all = globSync("test/**/*.test.ts", { cwd: root }).sort();
for (const f of CONFORMANCE) if (!all.includes(f)) throw new Error(`run-tests: conformance file ${f} not found`);
const files = all.filter((f) => CONFORMANCE.has(f) === (group === "conformance"));
console.log(`run-tests ${group}: ${files.length} file(s)`);
const r = spawnSync(process.execPath, ["--test", ...files], { cwd: root, stdio: "inherit" });
process.exit(r.status ?? 1);
