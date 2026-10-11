// Manifest target and the not-yet-built bridge / relay / core targets. A pending target reports every catalogued id
// as `not_implemented`, so its run FAILS (CONFORMANCE §4: no "coverage: none", never a silent pass).
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { BRIDGE_CHECKS, CORE_CHECKS, type PendingCheck, RELAY_CHECKS } from "./checks/catalog.ts";
import { runManifestChecks } from "./checks/manifest.ts";
import { buildReport, type Report, type Target } from "./report.ts";
import { notImplemented, Suite } from "./suite.ts";

export interface ManifestTargetOptions {
  manifestPath: string;
  /** source trees for M5; default: the installed @opt2-tealbrick/manifest package and this package */
  scanDirs?: string[];
  extraProductIds?: string[];
  expectDigest?: string;
}

/** Default M5 trees: the manifest package and the conformance package (both must hold no product id). */
export function defaultScanDirs(): string[] {
  const manifestPkg = dirname(dirname(fileURLToPath(import.meta.resolve("@opt2-tealbrick/manifest"))));
  const own = dirname(dirname(fileURLToPath(import.meta.url)));
  return [join(manifestPkg, "src"), join(manifestPkg, "dist"), join(own, "src"), join(own, "dist")];
}

/** Product ids of the spec examples (always part of the M5 grep list). */
export function exampleProductIds(): string[] {
  const p = fileURLToPath(import.meta.resolve("@opt2-tealbrick/spec/examples/notes.manifest.json"));
  return [String((JSON.parse(readFileSync(p, "utf8")) as { id: string }).id)];
}

export async function runManifestTarget(opts: ManifestTargetOptions): Promise<Report> {
  const startedAt = new Date();
  const json = JSON.parse(readFileSync(opts.manifestPath, "utf8")) as unknown;
  const r = await runManifestChecks(json, {
    manifestPath: opts.manifestPath,
    scanDirs: opts.scanDirs ?? defaultScanDirs(),
    extraProductIds: [...exampleProductIds(), ...(opts.extraProductIds ?? [])],
    ...(opts.expectDigest ? { expectDigest: opts.expectDigest } : {}),
  });
  return buildReport({ target: "manifest", subject: opts.manifestPath, startedAt, checks: r.results });
}

const PENDING: Record<Exclude<Target, "app" | "manifest">, readonly PendingCheck[]> = { bridge: BRIDGE_CHECKS, relay: RELAY_CHECKS, core: CORE_CHECKS };

/** Bridge / relay / core targets: not built yet → every catalogued check reports not_implemented (run fails). */
export function runPendingTarget(target: Exclude<Target, "app" | "manifest">, subject: string): Report {
  const s = new Suite();
  for (const c of PENDING[target]) s.record(c.id, c.title, "implemented check with a real assertion", notImplemented());
  return buildReport({ target, subject, startedAt: new Date(), checks: s.results, notes: [`${target} target: fakes and checks are scaffolded only; every id reports not_implemented and the run fails`] });
}
