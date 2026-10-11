// Structured logger with redaction (SDK-API §3.1 `log`): secret-looking field names and any value equal to a
// fetched key value become "[redacted]". Key values are kept only as digests here (never compared in clear).
import { createHash } from "node:crypto";
import type { Json, Logger } from "@opt2-tealbrick/spec/sdk";

export const LOG_LEVELS = ["error", "warn", "info", "debug"] as const;
export type LogLevel = (typeof LOG_LEVELS)[number];

const SECRET_FIELD = /key|token|secret|password|authorization|cookie/i;
const REDACTED = "[redacted]";

function sha(v: string): string {
  return createHash("sha256").update(v, "utf8").digest("hex");
}

/** Digests of key values seen by this process; the logger redacts any field value whose digest matches. */
export class SecretRegistry {
  #digests = new Set<string>();
  #lengths = new Set<number>();
  add(value: string): void {
    this.#digests.add(sha(value));
    this.#lengths.add(value.length);
  }
  clear(): void {
    this.#digests.clear();
    this.#lengths.clear();
  }
  matches(value: string): boolean {
    return this.#lengths.has(value.length) && this.#digests.has(sha(value));
  }
}

function scrub(value: Json, secrets: SecretRegistry, depth = 0): Json {
  if (typeof value === "string") return secrets.matches(value) ? REDACTED : value;
  if (value === null || typeof value !== "object" || depth > 8) return value;
  if (Array.isArray(value)) return value.map((v) => scrub(v, secrets, depth + 1));
  const out: Record<string, Json> = {};
  for (const [k, v] of Object.entries(value)) out[k] = SECRET_FIELD.test(k) ? REDACTED : scrub(v, secrets, depth + 1);
  return out;
}

export interface LogSink {
  write(level: LogLevel, line: string): void;
}

const stdSink: LogSink = {
  write(level, line) {
    (level === "error" || level === "warn" ? process.stderr : process.stdout).write(`${line}\n`);
  },
};

export function createLogger(level: LogLevel, secrets: SecretRegistry, base: Record<string, Json> = {}, sink: LogSink = stdSink): Logger {
  const max = LOG_LEVELS.indexOf(level);
  const emit = (lvl: LogLevel, msg: string, fields?: Record<string, Json>) => {
    if (LOG_LEVELS.indexOf(lvl) > max) return;
    const record = scrub({ ...base, ...(fields ?? {}) }, secrets) as Record<string, Json>;
    sink.write(lvl, JSON.stringify({ at: new Date().toISOString(), level: lvl, msg: secrets.matches(msg) ? REDACTED : msg, ...record }));
  };
  return {
    debug: (m, f) => emit("debug", m, f),
    info: (m, f) => emit("info", m, f),
    warn: (m, f) => emit("warn", m, f),
    error: (m, f) => emit("error", m, f),
  };
}
