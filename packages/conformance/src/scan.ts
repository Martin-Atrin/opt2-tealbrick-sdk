// Captured-payload scan (CONFORMANCE §4.2 C4 `cred.p1.payload_scan_no_person_cred`, C8, B11): looks for person
// credentials and secret values in everything an implementation sent to a fake or answered on an agent path.
// Findings name the place and the pattern label, never the matched value.
import type { CapturedPayload } from "./fake-bridge.ts";
import type { PayloadScan } from "./report.ts";

export interface ScanNeedle {
  label: string;
  /** exact secret strings (tickets minted, cookie values, key values) */
  values?: string[];
  /** structural patterns */
  pattern?: RegExp;
}

const JWS_RE = /eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{16,}/g;

/** Compact JWS strings in `text` whose header names one of `typs` (e.g. a person ticket echoed somewhere). */
export function jwsWithTyp(text: string, typs: readonly string[]): number {
  let n = 0;
  for (const m of text.matchAll(JWS_RE)) {
    try {
      const h = JSON.parse(Buffer.from(m[0].split(".")[0], "base64url").toString("utf8")) as { typ?: unknown };
      if (typeof h.typ === "string" && typs.includes(h.typ)) n++;
    } catch {
      // not a JWS header
    }
  }
  return n;
}

export interface ScanScope {
  /** which captured payloads to scan, and a label for the place */
  select: (p: CapturedPayload) => string | null;
}

export function scanPayloads(payloads: readonly CapturedPayload[], needles: readonly ScanNeedle[], scope: ScanScope, personTyps: readonly string[] = ["tb-ticket+jwt"]): PayloadScan {
  const findings = new Set<string>();
  let n = 0;
  for (const p of payloads) {
    const where = scope.select(p);
    if (where === null) continue;
    n++;
    const text = `${Object.entries(p.headers)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n")}\n${p.body}`;
    for (const nd of needles) {
      if (nd.values?.some((v) => v.length >= 8 && text.includes(v))) findings.add(`${where}: ${nd.label}`);
      if (nd.pattern?.test(text)) findings.add(`${where}: ${nd.label}`);
    }
    if (jwsWithTyp(text, personTyps) > 0) findings.add(`${where}: person ticket (${personTyps.join("|")})`);
  }
  return { payloads: n, patterns: [...needles.map((x) => x.label), `jws typ ${personTyps.join("|")}`], findings: [...findings].sort() };
}
