// @opt2-tealbrick/conformance — CONFORMANCE.md: fakes generated from @opt2-tealbrick/spec + @opt2-tealbrick/manifest
// (S12: no other @opt2-tealbrick import), the app and manifest targets, the report shape, and the CLI entry.

export { AppClient, type CallOptions, type OpAnswer, type OpTamper, type PersonSession, tamperValue } from "./app-client.ts";
export { type AppTargetContext, coverageOutcome, runAppChecks } from "./checks/app.ts";
export { APP_CHECK_IDS, BRIDGE_CHECKS, CHECK_IDS, CORE_CHECKS, MANIFEST_CHECK_IDS, RELAY_CHECKS } from "./checks/catalog.ts";
export { findProductLiterals, type ManifestCheckOptions, runManifestChecks } from "./checks/manifest.ts";
export {
  type CapturedPayload,
  createFakeBridge,
  type FakeAgent,
  FakeBridge,
  FakeBridgeControl,
  type FakeBridgeIds,
  type FakeBridgeOptions,
} from "./fake-bridge.ts";
export { createFakePortal, FAKE_PORTAL_ROUTES, FakePortal, FakePortalControl, type FakePortalOptions } from "./fake-portal.ts";
export { SDK_EXPORTS, type SdkExport } from "./generated/sdk-exports.ts";
export { buildReport, type CheckResult, type CheckStatus, exitCode, FAILING_STATUSES, type PayloadScan, type Report, renderMarkdown, specDigest, type Target } from "./report.ts";
export { type AppStartResult, appEnv, loadManifest, type RunAppOptions, runApp } from "./run-app.ts";
export { sampleInput } from "./sample.ts";
export { scanPayloads } from "./scan.ts";
export { SDK_COVERAGE } from "./sdk-coverage.ts";
export { type Outcome, Suite } from "./suite.ts";
export { readTar, type TarEntry } from "./tar.ts";
export { defaultScanDirs, runManifestTarget, runPendingTarget } from "./targets.ts";
export { Mint, peek, rawSign } from "./tokens.ts";
