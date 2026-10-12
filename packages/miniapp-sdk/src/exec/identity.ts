// Service identity (SDK-API §11, BRIDGE §10.1): own K8 sealed under TB_KEK in TB_DATA_DIR, one claim with the K6 code,
// and the claim record (public values only) so a restart never re-uses the one-time code.
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { assertPublicJwk, type Ed25519KeyPair } from "@opt2-tealbrick/manifest";
import type { ClaimResponse } from "@opt2-tealbrick/spec/bridge";
import type { BridgeId, Ed25519PublicJwk, InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Logger } from "@opt2-tealbrick/spec/sdk";
import { enrolCodeDigest, waitForMountedDataDir } from "../server/claim-guard.ts";
import { TbError } from "../server/errors.ts";
import { createSealer, loadInstanceKey, resolveKeks } from "../server/secrets.ts";
import type { ServiceBridge } from "./bridge.ts";
import { type ExecConfig, SDK_VERSION } from "./config.ts";
import { sleep } from "./util.ts";

export interface ClaimRecord {
  ins: InstanceId;
  svc: string;
  bridge: { id: BridgeId; publicKey: Ed25519PublicJwk };
  /** the app instance key this service accepts on its control port and helper port */
  app: { publicKey: Ed25519PublicJwk };
  serviceKeys: { name: string; env: string }[];
  /** v0.1.12: sha256 digest of the enrolment code this record was claimed with (never the code); absent before 0.1.12 */
  codeDigest?: `sha256:${string}`;
}

export interface ClaimGate {
  /** test harness only: mountinfo file for the first-claim mount check (default /proc/self/mountinfo) */
  mountinfoPath?: string;
}

const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]*$/;

/** The service's own key pair (same sealed format and path as the app instance key, on the service's volume). */
export async function loadServiceKey(cfg: ExecConfig): Promise<Ed25519KeyPair> {
  return loadInstanceKey(cfg.env.dataDir, createSealer(resolveKeks(cfg.env.dataDir, cfg.env.kek, cfg.env.kekPrevious)));
}

function recordFile(dataDir: string): string {
  return join(dataDir, "tb", "claim.json");
}

/** Validates a claim answer for this service; throws `instance_mismatch` / `claim_invalid`. */
export function recordFromClaim(cfg: ExecConfig, r: ClaimResponse): ClaimRecord {
  if (r?.ins !== cfg.instanceId) throw new TbError("instance_mismatch", "claim answer names another instance than TB_INSTANCE_ID", 500);
  try {
    assertPublicJwk(r.bridge?.publicKey);
    assertPublicJwk(r.app?.publicKey);
  } catch {
    throw new TbError("claim_invalid", "claim answer lacks the bridge or app public key", 502);
  }
  const serviceKeys = r.serviceKeys ?? [];
  if (!Array.isArray(serviceKeys) || serviceKeys.some((k) => typeof k?.name !== "string" || typeof k.env !== "string" || !ENV_NAME.test(k.env) || k.env.startsWith("TB_")))
    throw new TbError("claim_invalid", "claim answer has a malformed serviceKeys list", 502);
  return {
    ins: r.ins,
    svc: cfg.service.id,
    bridge: { id: r.bridge.id, publicKey: r.bridge.publicKey },
    app: { publicKey: (r.app as { publicKey: Ed25519PublicJwk }).publicKey },
    serviceKeys: serviceKeys.map((k) => ({ name: k.name, env: k.env })),
  };
}

export function readClaimRecord(cfg: ExecConfig): ClaimRecord | null {
  const file = recordFile(cfg.env.dataDir);
  if (!existsSync(file)) return null;
  const rec = JSON.parse(readFileSync(file, "utf8")) as ClaimRecord;
  if (rec.ins !== cfg.instanceId || rec.svc !== cfg.service.id) throw new TbError("instance_mismatch", "stored claim names another instance or service", 500);
  return rec;
}

function writeClaimRecord(dataDir: string, rec: ClaimRecord): void {
  const file = recordFile(dataDir);
  mkdirSync(join(dataDir, "tb"), { recursive: true, mode: 0o700 });
  writeFileSync(`${file}.tmp`, JSON.stringify(rec), { mode: 0o600 });
  renameSync(`${file}.tmp`, file);
}

/** Retryable failures (bridge down, 5xx) back off up to 30 s; refusals (`code_invalid`, `manifest_mismatch`, …) throw. */
export function retryable(e: unknown): boolean {
  return e instanceof TbError && (e.code === "bridge_unreachable" || e.httpStatus >= 500 || e.httpStatus === 429);
}

/** Stored claim, or claim now (`POST /tb/v1/claim` with `service`), retrying while the bridge is unreachable. */
export async function claimOrLoad(cfg: ExecConfig, key: Ed25519KeyPair, bridge: ServiceBridge, log: Logger, signal: AbortSignal, gate: ClaimGate = {}): Promise<ClaimRecord> {
  const stored = readClaimRecord(cfg);
  if (stored) {
    bridge.setBridge(stored.bridge.id);
    return stored;
  }
  if (!cfg.env.enrolCode) throw new TbError("env_invalid", "TB_ENROL_CODE is required for the first claim", 500);
  return claimWith(cfg, cfg.env.enrolCode, key, bridge, log, signal, gate);
}

/**
 * ONE claim path (first claim, and the v0.1.12 reclaim after a refused identity with a new code): waits until
 * TB_DATA_DIR is on a mounted volume (never redeems the one-time code before), then claims and writes the record
 * (replacing a refused one). Throws `stopped` when `signal` aborts.
 */
export async function claimWith(cfg: ExecConfig, code: string, key: Ed25519KeyPair, bridge: ServiceBridge, log: Logger, signal: AbortSignal, gate: ClaimGate = {}): Promise<ClaimRecord> {
  const mounted = await waitForMountedDataDir(cfg.env.dataDir, { ephemeral: cfg.env.dataEphemeral, ...(gate.mountinfoPath ? { mountinfoPath: gate.mountinfoPath } : {}), log, signal });
  if (!mounted) throw new TbError("stopped", "stopped before the claim", 500);
  let delay = 1000;
  for (;;) {
    try {
      const r = await bridge.claim(
        { code, instancePublicKey: key.publicJwk, manifestDigest: cfg.manifestDigest, version: cfg.manifest.version, sdkVersion: SDK_VERSION, service: cfg.service.id },
        signal,
      );
      const rec = { ...recordFromClaim(cfg, r), codeDigest: enrolCodeDigest(code) };
      writeClaimRecord(cfg.env.dataDir, rec);
      bridge.setBridge(rec.bridge.id);
      log.info("claim completed", { svc: rec.svc, keys: rec.serviceKeys.length });
      return rec;
    } catch (e) {
      if (!retryable(e) || signal.aborted) throw e;
      log.warn("claim retry", { code: (e as TbError).code, inMs: delay });
      await sleep(delay, signal);
      delay = Math.min(delay * 2, 30_000);
    }
  }
}
