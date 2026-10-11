// Small shared helpers for tb-exec.
import { constants } from "node:os";

/** Resolves after `ms`, or at once when `signal` aborts (callers check `signal.aborted`). */
export function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal?.aborted) return resolve();
    const t = setTimeout(done, ms);
    function done() {
      clearTimeout(t);
      signal?.removeEventListener("abort", done);
      resolve();
    }
    signal?.addEventListener("abort", done, { once: true });
  });
}

/** Shell convention for a process ended by a signal: 128 + signal number. */
export function signalExitCode(sig: NodeJS.Signals | null): number {
  const n = sig ? constants.signals[sig] : undefined;
  return typeof n === "number" ? 128 + n : 1;
}
