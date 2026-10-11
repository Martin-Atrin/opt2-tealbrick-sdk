// SDK environment (SDK-API §13): one name per setting, no aliases; only TB_* names are read.
import { join } from "node:path";
import type { Ed25519PublicJwk, InstanceId } from "@opt2-tealbrick/spec/credentials";
import { TbError } from "./errors.ts";
import { LOG_LEVELS, type LogLevel } from "./log.ts";

/** Every TB_* name the SDK knows (SdkEnv). Any other TB_* name at boot → warning `env_unknown`. */
export const SDK_ENV_NAMES = [
  "TB_INSTANCE_ID",
  "TB_SERVICE",
  "TB_ENROL_CODE",
  "TB_BRIDGE_URL",
  "TB_PORTAL_KEYS",
  "TB_KEK",
  "TB_KEK_PREVIOUS",
  "TB_DATA_DIR",
  "TB_BACKUP_DIR",
  "TB_STANDALONE",
  "TB_STANDALONE_RESET",
  "TB_RESTORE_FROM",
  "TB_LOG_LEVEL",
] as const;

export interface SdkConfig {
  instanceId: InstanceId | null;
  enrolCode: string | null;
  bridgeUrl: string | null;
  portalKeys: { keys: Ed25519PublicJwk[] } | null;
  kek: string | null;
  kekPrevious: string | null;
  dataDir: string;
  /** C28: defaults to <TB_DATA_DIR>/backup */
  backupDir: string;
  standalone: boolean;
  standaloneReset: boolean;
  restoreFrom: string | null;
  logLevel: LogLevel;
  unknown: string[];
}

const INSTANCE_ID_RE = /^ins_[0-7][0-9A-HJKMNP-TV-Z]{25}$/;

function nonEmpty(v: string | undefined): string | null {
  return v === undefined || v === "" ? null : v;
}

function parsePortalKeys(raw: string | null): { keys: Ed25519PublicJwk[] } | null {
  if (raw === null) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new TbError("env_invalid", "TB_PORTAL_KEYS is not JSON", 500);
  }
  const keys = (parsed as { keys?: unknown })?.keys;
  if (!Array.isArray(keys) || keys.length === 0) throw new TbError("env_invalid", "TB_PORTAL_KEYS must be a JWKS with keys[]", 500);
  for (const k of keys) {
    if (k?.kty !== "OKP" || k?.crv !== "Ed25519" || typeof k?.x !== "string" || "d" in k)
      throw new TbError("env_invalid", "TB_PORTAL_KEYS must hold public Ed25519 JWKs only", 500);
  }
  return { keys: keys as Ed25519PublicJwk[] };
}

/** Reads the TB_* names of `env`; throws `env_invalid` on a malformed value. */
export function readEnv(env: Record<string, string | undefined>): SdkConfig {
  const dataDir = nonEmpty(env.TB_DATA_DIR);
  if (dataDir === null) throw new TbError("env_invalid", "TB_DATA_DIR is required", 500);
  const instanceId = nonEmpty(env.TB_INSTANCE_ID);
  if (instanceId !== null && !INSTANCE_ID_RE.test(instanceId)) throw new TbError("env_invalid", "TB_INSTANCE_ID is not an ins_ id", 500);
  const level = nonEmpty(env.TB_LOG_LEVEL) ?? "info";
  if (!(LOG_LEVELS as readonly string[]).includes(level)) throw new TbError("env_invalid", "TB_LOG_LEVEL must be error|warn|info|debug", 500);
  const bridgeUrl = nonEmpty(env.TB_BRIDGE_URL);
  if (bridgeUrl !== null && !/^https?:\/\/[^/?#]+$/.test(bridgeUrl.replace(/\/$/, "")))
    throw new TbError("env_invalid", "TB_BRIDGE_URL must be an origin (scheme://host[:port])", 500);
  const known = new Set<string>(SDK_ENV_NAMES);
  return {
    instanceId: instanceId as InstanceId | null,
    enrolCode: nonEmpty(env.TB_ENROL_CODE),
    bridgeUrl: bridgeUrl === null ? null : bridgeUrl.replace(/\/$/, ""),
    portalKeys: parsePortalKeys(nonEmpty(env.TB_PORTAL_KEYS)),
    kek: nonEmpty(env.TB_KEK),
    kekPrevious: nonEmpty(env.TB_KEK_PREVIOUS),
    dataDir,
    backupDir: nonEmpty(env.TB_BACKUP_DIR) ?? join(dataDir, "backup"),
    standalone: env.TB_STANDALONE === "1",
    standaloneReset: env.TB_STANDALONE_RESET === "1",
    restoreFrom: nonEmpty(env.TB_RESTORE_FROM),
    logLevel: level as LogLevel,
    unknown: Object.keys(env).filter((k) => k.startsWith("TB_") && !known.has(k)),
  };
}
