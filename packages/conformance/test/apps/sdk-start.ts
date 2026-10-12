// `--start` harness on the REAL miniapp-sdk `startApp` (workspace source, no build needed): as root it drops the
// process to uid 1000 (BSA-05 / C53). Manifest and migrations come from the inherited env (TBTEST_SDK_MANIFEST,
// TBTEST_SDK_MIGRATIONS); every manifest op gets a generic handler (the root test asserts the report is written, not
// that this stub app conforms).
import { readFileSync } from "node:fs";

interface SdkModule {
  defineApp(def: unknown): unknown;
  startApp(app: unknown, env: Record<string, string>, harness?: { portalRootKeys?: unknown[] }): Promise<{ stop(): Promise<void>; backups: { runNow(): Promise<unknown> } }>;
}

// computed specifier: the SDK source stays out of this package's typecheck graph
const sdkUrl = new URL("../../../miniapp-sdk/src/server/index.ts", import.meta.url).href;

export default async function start(env: Record<string, string>) {
  const sdk = (await import(sdkUrl)) as SdkModule;
  const manifest = JSON.parse(readFileSync(process.env.TBTEST_SDK_MANIFEST as string, "utf8")) as {
    runtime: { port: number };
    operations: { id: string }[];
    hooks?: { id: string }[];
  };
  const stub = { scope: () => null, run: async () => ({}) };
  const app = sdk.defineApp({
    manifest,
    migrations: process.env.TBTEST_SDK_MIGRATIONS,
    handlers: Object.fromEntries(manifest.operations.map((o) => [o.id, stub])),
    hooks: Object.fromEntries((manifest.hooks ?? []).map((h) => [h.id, async () => ({})])),
  });
  // v0.1.11 (C63): test roots reach the SDK only through the harness option, never through env (CONFORMANCE §7)
  const running = await sdk.startApp(app, env, env.TBCONF_PORTAL_ROOT_KEYS ? { portalRootKeys: JSON.parse(env.TBCONF_PORTAL_ROOT_KEYS) as unknown[] } : undefined);
  return {
    url: `http://127.0.0.1:${manifest.runtime.port}`,
    stop: () => running.stop(),
    backupNow: async () => {
      await running.backups.runNow();
    },
  };
}
