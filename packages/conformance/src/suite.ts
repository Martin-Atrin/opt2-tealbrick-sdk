// Check runner primitives: every check returns an Outcome from a real assertion; an exception is a failure with the
// error message as the asserted value (never a silent pass).
import type { CheckResult, CheckStatus } from "./report.ts";

export interface Outcome {
  status?: CheckStatus;
  pass?: boolean;
  asserted: string;
}

export const ok = (asserted: string): Outcome => ({ pass: true, asserted });
export const bad = (asserted: string): Outcome => ({ pass: false, asserted });
export const verdict = (pass: boolean, asserted: string): Outcome => ({ pass, asserted });
export const na = (reason: string): Outcome => ({ status: "not_applicable", asserted: reason });
export const notRun = (reason: string): Outcome => ({ status: "not_run", asserted: reason });
export const notImplemented = (reason = "check listed in CONFORMANCE §4 but not implemented yet"): Outcome => ({ status: "not_implemented", asserted: reason });

/** Refusal assertion: a 4xx answer whose CORE §8 envelope code is one of `codes`. */
export function refusedWith(a: { status: number; code: string | null; body?: unknown }, codes: readonly string[]): Outcome {
  const pass = a.status >= 400 && a.status < 500 && a.code !== null && codes.includes(a.code);
  const b = a.body as { status?: unknown } | null | undefined;
  const what = a.code ?? (b && typeof b === "object" && typeof b.status === "string" ? `${b.status} (not refused)` : "(no error envelope)");
  return { pass, asserted: `${a.status} ${what}` };
}

export class Suite {
  readonly results: CheckResult[] = [];

  async run(id: string, title: string, expected: string, fn: () => Promise<Outcome> | Outcome): Promise<Outcome> {
    const t0 = Date.now();
    let o: Outcome;
    try {
      o = await fn();
    } catch (e) {
      o = bad(`error: ${e instanceof Error ? e.message : String(e)}`);
    }
    const status: CheckStatus = o.status ?? (o.pass ? "pass" : "fail");
    this.results.push({ id, title, status, asserted: o.asserted, expected, ms: Date.now() - t0 });
    return { ...o, status };
  }

  has(id: string): boolean {
    return this.results.some((r) => r.id === id);
  }

  /** Records a fixed result (e.g. every remaining check after a fatal boot failure). */
  record(id: string, title: string, expected: string, o: Outcome): void {
    this.results.push({ id, title, status: o.status ?? (o.pass ? "pass" : "fail"), asserted: o.asserted, expected });
  }
}
