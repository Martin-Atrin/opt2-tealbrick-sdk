// Context members added by Coordinator C31 on top of types/sdk.ts §B (SPEC-GAP until the spec package declares them):
// `publicUrl` (slice `bridge.publicUrl`), `workspace`, `scopes.instances` and `secrets` (the ONE app-secret store).
import type { WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { AppDefinition, Db, HookContext, Json, Logger, OpContext, PublicHandler, ScopeStore } from "@opt2-tealbrick/spec/sdk";
import type { AppSecrets } from "./app-secrets.ts";

export interface ContextExtras {
  /** bridge public origin (`https://<bridge>`) for third-party callbacks `…/p/<product><path>`; null until the slice names it */
  publicUrl: string | null;
  /** workspace from the verified slice; before the first slice the SDK refuses with 503 workspace_unknown */
  workspace: WorkspaceId;
  scopes: Pick<ScopeStore, "instances">;
  secrets: AppSecrets;
}
export type SdkOpContext = OpContext & ContextExtras;
export type SdkHookContext = HookContext & { secrets: AppSecrets };
export type SdkPublicContext = Parameters<PublicHandler>[1] & ContextExtras;
export type { AppSecrets };

/** Coordinator C33: `onStart` runs once after boot and (bridge mode) after the claim succeeded; errors are logged. */
export interface StartContext {
  db: Db;
  log: Logger;
  scopes: ScopeStore;
  secrets: AppSecrets;
  getKey(name: string): Promise<string | null>;
  callServiceHelper<O = Json>(serviceId: string, path: string, body: Json): Promise<O>;
}
export type SdkAppDefinition<A extends string = never> = AppDefinition<A> & { onStart?(ctx: StartContext): Promise<void> };
