// Internal runtime shared by the route modules of one running app (not exported from the package).
import type { Ed25519KeyPair, ReplayGuard } from "@opt2-tealbrick/manifest";
import type { InstanceId } from "@opt2-tealbrick/spec/credentials";
import type { Manifest } from "@opt2-tealbrick/spec/manifest";
import type { AuditLog, BackupApi, CompanionResult, Db, HealthStatus, Json, Logger, OperationView, SliceAgent } from "@opt2-tealbrick/spec/sdk";
import type { AppSecrets } from "./app-secrets.ts";
import type { BridgeClient } from "./bridge-client.ts";
import type { AttentionCode } from "./claim-guard.ts";
import type { ContextExtras, SdkAppDefinition } from "./context.ts";
import type { SdkConfig } from "./env.ts";
import type { KeysInternals } from "./keys.ts";
import type { SecretRegistry } from "./log.ts";
import type { PersonAuth } from "./person.ts";
import type { Receipts } from "./receipts.ts";
import type { ScopeStoreInternals } from "./scopes.ts";
import type { Sealer } from "./secrets.ts";
import type { RawDb } from "./store.ts";
import type { TrustState } from "./trust.ts";

export interface Runtime {
  readonly def: SdkAppDefinition<string>;
  readonly manifest: Manifest;
  readonly product: string;
  readonly digest: `sha256:${string}`;
  readonly ops: ReadonlyMap<string, OperationView>;
  readonly sdkVersion: string;
  readonly cfg: SdkConfig;
  readonly env: Record<string, string | undefined>;
  readonly db: RawDb;
  readonly appDb: Db;
  readonly log: Logger;
  readonly secrets: SecretRegistry;
  readonly sealer: Sealer;
  readonly instanceId: InstanceId;
  readonly instanceKey: Ed25519KeyPair;
  readonly trust: TrustState;
  readonly receipts: Receipts;
  readonly scopes: ScopeStoreInternals;
  readonly keys: KeysInternals;
  readonly audit: AuditLog;
  readonly person: PersonAuth;
  readonly secretsStore: AppSecrets;
  readonly backups: BackupApi;
  readonly bridge: BridgeClient | null;
  /** jti replay set for call proofs (CREDENTIALS §10: memory is enough) */
  readonly replay: ReplayGuard;
  /** `attention` (v0.1.12): why the instance needs the owner (health detail; wire readiness `degraded`) */
  readonly state: { claimed: boolean; failed: boolean; restoring: boolean; stopping: boolean; attention: AttentionCode | null };
  /** test harness only (startApp `harness.mountinfoPath`): mountinfo file for the first-claim mount check */
  readonly mountinfoPath: string | undefined;
  health(): HealthStatus;
  /** C31 context members for agent/app calls (person calls override `workspace`) */
  extras(): ContextExtras;
  /** pending-hold count or scopes changed: push a status report at once (C16 S2) */
  kickStatus(): void;
  /** claim completed (or already recorded): runs `onStart` once */
  onClaimed(): void;
  /** re-reads the slice from the bridge once (companion `grant_stale`) */
  refreshSlice(): Promise<void>;
  /** first sight of an agent edge (§7.2): agentAdded event, then manifest defaultGrants */
  ensureAgent(agent: SliceAgent): Promise<void>;
  callApp<O = Json>(product: string, op: string, input: Json, opts: { idempotencyKey?: string; parentCall: string | null }): Promise<CompanionResult<O>>;
  callServiceHelper<O = Json>(serviceId: string, path: string, body: Json): Promise<O>;
}
