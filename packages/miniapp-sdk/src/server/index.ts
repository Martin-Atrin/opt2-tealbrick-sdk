// @opt2-tealbrick/miniapp-sdk — server entry (SDK-API §3–§13, types/sdk.ts §B).

export { SDK_AUDIT_ACTIONS } from "@opt2-tealbrick/manifest";
export { decideHold, defineApp, getKey, onKeysChanged, SDK_MAJOR, SDK_VERSION, startApp } from "./app.ts";
export type { AppSecrets, ContextExtras, SdkAppDefinition, SdkHookContext, SdkOpContext, SdkPublicContext, StartContext } from "./context.ts";
export { TbError } from "./errors.ts";
export { CSRF_HEADER, SESSION_COOKIE } from "./person.ts";

/** tb-exec control port (SDK-API §11), private network only. */
export const TB_EXEC_CONTROL_PORT = 7077 as const;

export type {
  App,
  AppDefinition,
  AppEvents,
  AppStatus,
  AuditEntry,
  AuditLog,
  BackupApi,
  BackupMeta,
  CallEnvelope,
  Caller,
  ClaimRequest,
  ClaimResponse,
  CompanionResult,
  Db,
  DynamicHandlers,
  ExportMeta,
  Handler,
  HandlerSpec,
  Health,
  HealthStatus,
  HoldDecideInput,
  HookContext,
  HookHandler,
  HookRequest,
  HookResponseByPhase,
  IdempotencyCheck,
  InstanceSlice,
  Json,
  KeyApi,
  KeyStatus,
  Logger,
  OpCallBody,
  OpContext,
  OperationView,
  OpResult,
  PersonPrincipal,
  PublicHandler,
  Receipt,
  ReceiptHelpers,
  ReceiptQuery,
  ReceiptStatus,
  ReceiptStore,
  RunningApp,
  ScopeAccessView,
  ScopeGrantRow,
  ScopeInstance,
  ScopeStore,
  ScopeSummaryResult,
  SdkEnv,
  SessionInfo,
  SliceAgent,
} from "@opt2-tealbrick/spec/sdk";
