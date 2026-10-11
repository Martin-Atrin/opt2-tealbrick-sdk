// Manifest checks M1–M5 (CONFORMANCE §4.1). M1/M2 run the ONE validator (`validateManifest`) and re-assert the key
// cross-field rules independently, then prove the validator enforces them with mutated copies (sensitivity). M3
// recomputes the digest several ways. M4 scans for hand-written generator outputs beside the manifest. M5 greps source
// trees for product ids taken from manifests.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { basename, dirname, extname, join } from "node:path";
import { digest, manifestDigest, mcpToolName, toolNameFits, validateManifest } from "@opt2-tealbrick/manifest";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { Json } from "@opt2-tealbrick/spec/sdk";
import type { CheckResult } from "../report.ts";
import { bad, na, notRun, ok, Suite, verdict } from "../suite.ts";

export interface ManifestCheckOptions {
  /** path of the manifest file (M4 scans its directory) */
  manifestPath?: string;
  /** source trees for M5 (default: none → M5 not_run) */
  scanDirs?: string[];
  /** extra product ids for M5 (e.g. ids from the spec examples) */
  extraProductIds?: string[];
  /** expected digest (e.g. the one in a release record) */
  expectDigest?: string;
  /** when set and no scanDirs are given, M5 reports not_applicable with this reason (app target) */
  m5NotApplicable?: string;
}

const clone = <T>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const codes = (r: ReturnType<typeof validateManifest>) => (r.ok ? [] : r.errors.map((e) => e.code));

function shuffleKeys(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(shuffleKeys);
  if (v && typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>).reverse();
    return Object.fromEntries(entries.map(([k, x]) => [k, shuffleKeys(x)]));
  }
  return v;
}

/** Synthetic agent op appended to a copy of the manifest for the sensitivity probes. */
function probeOp(over: Record<string, unknown>): Record<string, unknown> {
  return {
    id: "conformance_probe",
    title: "Probe",
    description: "Conformance probe operation.",
    input: { type: "object", properties: {} },
    output: { type: "object" },
    crud: ["read"],
    effect: "read",
    idempotency: "none",
    receipt: false,
    audience: "agent",
    ...over,
  };
}

const SOURCE_EXT = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".go", ".py", ".rs"]);
const SKIP_DIRS = new Set(["node_modules", ".git", "test", "tests", "fixtures", "examples", "__tests__", "coverage"]);

function* sourceFiles(dir: string): Generator<string> {
  let names: string[];
  try {
    names = readdirSync(dir);
  } catch {
    return;
  }
  for (const n of names) {
    const p = join(dir, n);
    let st: ReturnType<typeof statSync>;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) {
      if (!SKIP_DIRS.has(n)) yield* sourceFiles(p);
    } else if (SOURCE_EXT.has(extname(n)) && !n.includes(".test.") && st.size < 4 * 1024 * 1024) yield p;
  }
}

/** M5: product ids appearing as string literals (or path segments) in source trees. */
export function findProductLiterals(dirs: readonly string[], productIds: readonly string[]): string[] {
  const hits: string[] = [];
  const res = productIds.map((id) => ({ id, re: new RegExp(`["'\`/]${id.replace(/[-]/g, "\\-")}["'\`/]`) }));
  for (const d of dirs) {
    for (const f of sourceFiles(d)) {
      const text = readFileSync(f, "utf8");
      for (const { id, re } of res) if (re.test(text)) hits.push(`${f}: "${id}"`);
    }
  }
  return hits;
}

export async function runManifestChecks(json: unknown, opts: ManifestCheckOptions = {}): Promise<{ results: CheckResult[]; manifest: Manifest | null }> {
  const s = new Suite();
  const v = validateManifest(json);
  const m = v.ok ? v.manifest : null;

  // ── M1 schema ──
  await s.run("M1", "manifest schema valid (tealbrick.miniapp/2, strict)", "validateManifest ok, schema tealbrick.miniapp/2", () =>
    v.ok ? ok(`valid; schema ${v.manifest.schema}`) : bad(`${v.errors.length} errors: ${v.errors.slice(0, 5).map((e) => `${e.path} ${e.code}`).join("; ")}`),
  );
  await s.run("M1.strict_unknown_key", "unknown top-level key rejected", "validateManifest refuses an extra key", () => {
    if (!m) return bad("manifest invalid");
    const r = validateManifest({ ...clone(m), conformanceUnknownKey: true });
    return verdict(!r.ok, r.ok ? "accepted" : `refused: ${codes(r).join(",")}`);
  });
  await s.run("M1.reserved_prefix", "tb_ operation ids reserved", "an op id starting tb_ is refused", () => {
    if (!m) return bad("manifest invalid");
    const r = validateManifest({ ...clone(m), operations: [...clone(m.operations), probeOp({ id: "tb_conformance" })] });
    return verdict(!r.ok, r.ok ? "accepted" : `refused: ${codes(r).join(",")}`);
  });

  // ── M2 cross-field rules: independent re-assertion + validator sensitivity ──
  await s.run("M2.create_idempotency", "create ⇒ idempotency required (M-OP-5)", "every op with create in crud has idempotency required", () => {
    if (!m) return bad("manifest invalid");
    const off = m.operations.filter((o) => o.crud.includes("create") && o.idempotency !== "required").map((o) => o.id);
    return verdict(off.length === 0, off.length ? `violations: ${off.join(",")}` : `${m.operations.filter((o) => o.crud.includes("create")).length} create ops, all required`);
  });
  await s.run("M2.create_idempotency.enforced", "validator enforces M-OP-5", "validateManifest refuses create + idempotency supported (idempotency_invalid)", () => {
    if (!m) return bad("manifest invalid");
    const r = validateManifest({ ...clone(m), operations: [...clone(m.operations), probeOp({ crud: ["create"], effect: "write", idempotency: "supported", receipt: true })] });
    return verdict(codes(r).includes("idempotency_invalid"), r.ok ? "accepted" : codes(r).join(","));
  });
  await s.run("M2.scope_types", "scopeType declared (M-OP-7)", "every op scopeType names a declared scope whose access covers op.crud", () => {
    if (!m) return bad("manifest invalid");
    const off = m.operations
      .filter((o) => o.scopeType !== undefined)
      .filter((o) => {
        const sc = m.scopes?.find((x) => x.type === o.scopeType);
        const union = new Set(sc?.access.flatMap((a) => a.crud) ?? []);
        return !sc || !o.crud.every((c) => union.has(c));
      })
      .map((o) => o.id);
    return verdict(off.length === 0, off.length ? `violations: ${off.join(",")}` : "all scoped ops reference declared scopes");
  });
  await s.run("M2.scope_types.enforced", "validator enforces M-OP-7", "validateManifest refuses an undeclared scopeType (scope_ref_invalid)", () => {
    if (!m) return bad("manifest invalid");
    const r = validateManifest({ ...clone(m), operations: [...clone(m.operations), probeOp({ scopeType: "conformance_undeclared" })] });
    return verdict(codes(r).includes("scope_ref_invalid"), r.ok ? "accepted" : codes(r).join(","));
  });
  await s.run("M2.money_held", "money effect ⇒ holdFamily money + receipt (M-OP-4/6)", "money ops declare holdFamily money and receipt true", () => {
    if (!m) return bad("manifest invalid");
    const money = m.operations.filter((o) => o.effect === "money");
    if (money.length === 0) return na("no money op declared");
    const off = money.filter((o) => o.holdFamily !== "money" || !o.receipt).map((o) => o.id);
    return verdict(off.length === 0, off.length ? `violations: ${off.join(",")}` : `${money.length} money ops ok`);
  });
  await s.run("M2.tool_names", "MCP tool names ≤ 64 chars (M-OP-1, CORE I9)", "every <product>__<op> fits ^[a-z0-9_-]+$ and ≤ 64", () => {
    if (!m) return bad("manifest invalid");
    const names = m.operations.filter((o) => o.audience === "agent").map((o) => mcpToolName(m.id, o.id));
    const off = names.filter((n) => !toolNameFits(n));
    return verdict(off.length === 0, off.length ? `too long/invalid: ${off.join(",")}` : `${names.length} names fit (longest ${Math.max(0, ...names.map((n) => n.length))})`);
  });
  await s.run("M2.key_names_unique", "settings/key names unique (M-ST-1)", "no duplicate step id, field key or key name", () => {
    if (!m) return bad("manifest invalid");
    const keys = [...(m.settings?.steps.flatMap((st) => st.fields.map((f) => `field:${f.key}`)) ?? []), ...(m.settings?.keys?.map((k) => `key:${k.name}`) ?? [])];
    const dup = keys.filter((k, i) => keys.indexOf(k) !== i);
    return verdict(dup.length === 0, dup.length ? `duplicates: ${dup.join(",")}` : `${keys.length} names unique`);
  });
  await s.run("M2.hook_ops", "hooks reference real ops (M-HK-3)", "own-product hook match.operations exist with audience agent", () => {
    if (!m) return bad("manifest invalid");
    if (!m.hooks?.length) return na("no hooks declared");
    const agentOps = new Set(m.operations.filter((o) => o.audience === "agent").map((o) => o.id));
    const off = m.hooks.filter((h) => h.match.products.length === 1 && h.match.products[0] === m.id && (h.match.operations ?? []).some((o) => !agentOps.has(o))).map((h) => h.id);
    return verdict(off.length === 0, off.length ? `violations: ${off.join(",")}` : `${m.hooks.length} hooks ok`);
  });
  await s.run("M2.when_settings", "`when` references declared settings (M-ST-3)", "every when key names an enum/boolean field", () => {
    if (!m) return bad("manifest invalid");
    const fields = new Map((m.settings?.steps ?? []).flatMap((st) => st.fields.map((f) => [f.key, f.type] as const)));
    const whens = [
      ...(m.settings?.steps ?? []).flatMap((st) => [st.when, ...st.fields.map((f) => f.when)]),
      ...(m.settings?.keys ?? []).map((k) => k.when),
      ...(m.runtime.services ?? []).map((x) => x.when),
      ...(m.skills ?? []).map((x) => x.when),
    ].filter((w) => w !== undefined);
    if (whens.length === 0) return na("no when conditions declared");
    const off = whens.flatMap((w) => Object.keys(w)).filter((k) => fields.get(k) !== "enum" && fields.get(k) !== "boolean");
    return verdict(off.length === 0, off.length ? `unknown/invalid: ${off.join(",")}` : `${whens.length} conditions ok`);
  });

  // ── M3 digest ──
  await s.run("M3", "digest = sha256(JCS) reproducible", "manifestDigest stable across runs, key order and JSON round-trip", () => {
    if (!m) return bad("manifest invalid");
    const d1 = manifestDigest(m);
    const d2 = manifestDigest(clone(m));
    const d3 = digest(shuffleKeys(json) as Json);
    const d4 = v.ok ? v.digest : "";
    const same = d1 === d2 && d2 === d3 && d3 === d4 && /^sha256:[0-9a-f]{64}$/.test(d1);
    if (opts.expectDigest && opts.expectDigest !== d1) return bad(`${d1} ≠ expected ${opts.expectDigest}`);
    return verdict(same, same ? d1 : `mismatch: ${[d1, d2, d3, d4].join(" / ")}`);
  });

  // ── M4 no hand-written generator outputs ──
  await s.run("M4.no_copies", "no hand-written generator outputs beside the manifest", "no openapi.*, manifest.json or recipe.json next to the manifest", () => {
    if (!opts.manifestPath) return notRun("manifest path unknown (pass --manifest <file>)");
    const dir = dirname(opts.manifestPath);
    const own = basename(opts.manifestPath);
    const found = readdirSync(dir).filter((n) => n !== own && (/^openapi\./i.test(n) || n === "manifest.json" || n === "recipe.json"));
    return verdict(found.length === 0, found.length ? `found: ${found.join(",")}` : `clean: ${dir}`);
  });

  // ── M5 no product literal ──
  await s.run("M5", "no product literal in platform source trees", "no product id from any manifest appears as a literal in the scanned trees", () => {
    if (!m) return bad("manifest invalid");
    if (!opts.scanDirs?.length) return opts.m5NotApplicable ? na(opts.m5NotApplicable) : notRun("no source trees given (pass --scan <dir>)");
    const ids = [...new Set([m.id, ...(opts.extraProductIds ?? [])])];
    const hits = findProductLiterals(opts.scanDirs, ids);
    return verdict(hits.length === 0, hits.length ? `${hits.length} hits: ${hits.slice(0, 5).join("; ")}` : `${opts.scanDirs.length} trees clean of ${ids.join(",")}`);
  });

  return { results: s.results, manifest: m };
}
