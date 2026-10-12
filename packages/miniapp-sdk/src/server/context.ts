// Context members added by Coordinator C31 on top of types/sdk.ts §B (SPEC-GAP until the spec package declares them):
// `publicUrl` (slice `bridge.publicUrl`), `workspace`, `scopes.instances` and `secrets` (the ONE app-secret store).
import type { ScopeRequest } from "@opt2-tealbrick/spec/bridge";
import type { WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { AppDefinition, EventContext, HookContext, OpContext, PublicHandler, ScopeStore, SliceAgent, StartContext as SpecStartContext } from "@opt2-tealbrick/spec/sdk";
import type { AppSecrets } from "./app-secrets.ts";

export interface ContextExtras {
  /** bridge public origin (`https://<bridge>`) for third-party callbacks `…/p/<product><path>`; null until the slice names it */
  publicUrl: string | null;
  /** workspace from the verified slice; before the first slice the SDK refuses with 503 workspace_unknown */
  workspace: WorkspaceId;
  scopes: Pick<ScopeStore, "instances">;
  secrets: AppSecrets;
}
export type SdkOpContext = OpContext & ContextExtras & CompanionTargetsView;
export type SdkHookContext = HookContext & { secrets: AppSecrets };
export type SdkPublicContext = Parameters<PublicHandler>[1] & ContextExtras;
export type { AppSecrets };

/**
 * v0.1.14 addition (Lead, item 10): the target products of this app's companion grants, from the verified slice's
 * `companionTargets` (de-duplicated, sorted; [] when the slice has none). A wildcard companion (`product: "*"`) uses it
 * to know which apps it can call `tb.holds_pending` on.
 * SPEC-GAP: spec 0.1.14 InstanceSlice.companionTargets — not in the 0.1.13 types; read defensively.
 */
export interface CompanionTargetsView {
  companionTargets(): string[];
  /** v0.1.15 (C105a): the workspace apps policy's held families from the slice (display only; enforcement is the
   *  companion grant `held` claim at the target app), or null when the slice has none */
  appsPolicy(): readonly string[] | null;
  /** v0.1.18 (C106a, Connect F21): the slice's `agents[].scopeRequest` for `agt` when it targets THIS product, else null */
  agentScopeRequest(agt: string): ScopeRequest | null;
}

/** v0.1.13 (C33, C85, C86): `onStart` runs once after boot and (bridge mode) after the claim succeeded; errors are logged. */
export type StartContext = SpecStartContext & CompanionTargetsView;
/** v0.1.13: the ctx every event handler gets (C85 callApp without parentCall, C86 statusChanged / ownerLink). */
export type SdkEventContext = EventContext & CompanionTargetsView;
/** AppEvents (types/sdk.ts) with the SDK event ctx; a handler typed against the spec EventContext still fits. */
export interface SdkAppEvents {
  agentAdded?(agent: SliceAgent, ctx: SdkEventContext): Promise<void>;
  agentRemoved?(agent: SliceAgent, ctx: SdkEventContext): Promise<void>;
  keysChanged?(names: string[], ctx: SdkEventContext): Promise<void>;
  /** v0.1.13 (Fleet): full agent list, once per installed slice whose agents differ, and once after boot */
  agentsChanged?(agents: SliceAgent[], ctx: SdkEventContext): Promise<void>;
}
export type SdkAppDefinition<A extends string = never> = Omit<AppDefinition<A>, "onStart" | "events"> & {
  onStart?(ctx: StartContext): Promise<void>;
  events?: SdkAppEvents;
};
