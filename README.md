# Tealbrick SDK

The owner of every crypto and decision primitive (`@opt2-tealbrick/manifest`), the mini app runtime (`@opt2-tealbrick/miniapp-sdk`), the conformance suite (`@opt2-tealbrick/conformance`) and the scaffold (`create-tealbrick-miniapp`).

- Repository: `Tealbrick/opt2-tealbrick-sdk` (GitHub organisation `Tealbrick`)
- Visibility target: PRIVATE. The repo is PUBLIC for now (the flip is held for the org Actions billing). Consumers install from the dist host (`Tealbrick/opt2-tealbrick-dist`).
- Licence: the SDK is not Apache-2.0. Decision C191 sets the Tealbrick SDK Licence (Part B of the Tealbrick Software Licence, published at https://tealbrick.com/software-licence, to ship as `LICENSE` inside each SDK package tarball). This repo does not apply it yet: every `package.json` still declares `"license": "MIT"` and there is no `LICENSE` file in the repo or in the packages. Versions published with an MIT declaration stay available under MIT (licence section 1.3). The Apache-2.0 apps (their own `LICENSE` and `NOTICE`) depend on and bundle these packages.
- Status: manifest 0.1.18, miniapp-sdk 0.1.25 (upgrade safety), conformance 0.1.18, create-tealbrick-miniapp 0.1.14. CI template ci-v9.9. Apps pinning miniapp-sdk 0.1.25 on 2026-10-17: connect, evolution, inbox, kanban, knowledge, portal-core, rules (fleet pins 0.1.22).

Do not put secrets, tokens, keys, customer data or personal data in this repository, its issues or its pull requests. This repository is public for now and must stay clean either way: no API keys, tokens, passwords, private keys, `.env` files (use `.env.example` with placeholders), connection strings, personal names, private agent configurations or customer data. Every CI run starts with a secret scan (gitleaks, a step in `.woodpecker/ci.yaml`). GitHub secret scanning and push protection are NOT enabled on this repo (free organisation plan), so the CI step is the guard. An optional local guard is `pre-commit install`. If a secret is committed, rotate it first, then remove it from history.

## What this repo is and is not

The SDK is the one definition of what a mini app is: a spec, a runtime library, a template and conformance checks. It makes an app work standalone (no Portal) and behind a bridge.

`manifest` has pure, synchronous functions with no I/O, so the bridge and every app run identical code. CORE section 3 in `Tealbrick/opt2-tealbrick-specs` forbids copying a primitive elsewhere.

## Quick start

pnpm workspace, TypeScript run directly by Node 24+ (type stripping).

```sh
corepack enable && pnpm install --frozen-lockfile --ignore-scripts
pnpm typecheck && pnpm lint && pnpm test      # builds manifest first
pnpm conformance     # runs each package's `conformance` script; no package defines one today, so it runs nothing
```

New app: `npx create-tealbrick-miniapp <dir> --id <slug> --name "<Name>"` (from the released tarball).

## Layout

| Path | Purpose |
|---|---|
| `packages/manifest/src` | JCS, digests, JWS, keys and key sets, token verifiers, sealing, `gate()` and `authorize()` (`decision.ts`), cron, hook helpers, privilege drop, version helpers, vocabulary re-exports |
| `packages/miniapp-sdk/src/server` | `defineApp` and `startApp`: store, receipts and holds, scopes, keys, secrets, backups, jobs, status, person sessions, bridge client and routes, trust |
| `packages/miniapp-sdk/src/client` | React client (`TbProvider`, `useHolds`, `callOp`) |
| `packages/miniapp-sdk/src/exec`, `src/gen` | `tb-exec` (companion service wrapper) and `tb-gen` (openapi, kit, docs, railway, check) |
| `packages/conformance/src` | Fake Portal, fake bridge, checks, runners for app, bridge, core, relay, manifest |
| `packages/create-tealbrick-miniapp/template` | The scaffold (manifest, src, UI, migrations, Dockerfile, CI files, licence files) |
| `tealbrick-ci.json` | Repo-specific CI settings (kind `library`, conformance on, `distBaseUrl`) |

## Configuration

App runtime variables (read by `miniapp-sdk`): `TB_INSTANCE_ID`, `TB_SERVICE`, `TB_ENROL_CODE`, `TB_BRIDGE_URL`, `TB_PORTAL_KEYS`, `TB_KEK`, `TB_KEK_PREVIOUS`, `TB_DATA_DIR` (required), `TB_BACKUP_DIR`, `TB_STANDALONE`, `TB_STANDALONE_RESET`, `TB_RESTORE_FROM`, `TB_LOG_LEVEL`, `TB_DATA_EPHEMERAL` (tests only). Unknown `TB_*` names raise a warning.

## CI and release

Woodpecker CI with the shared opt2 pipeline template ci-v9.9 (`.woodpecker/ci.yaml` and `.github/workflows/opt2-release.yml` are generated copies; do not edit them, change `tealbrick-ci.json` or the template in `Tealbrick/opt2-tealbrick-platform`). Library pins come from the dist host.

Tag `<package dir>-v<x>`: `manifest-v`, `miniapp-sdk-v`, `conformance-v`, `create-tealbrick-miniapp-v`. The Action installs, builds, rewrites in-repo `workspace:` dependencies to released tarball URLs (the dependency must be released first), packs, runs the pack guard, and attaches the tarball plus `.sha256` and `.integrity`. Never npm.

## Language

New code is TypeScript (Node 24+).

## Documentation

- `ARCHITECTURE.md` explains the design.
- `CONTRIBUTING.md` explains how to change it.
- `Tealbrick/opt2-tealbrick-specs`: `docs/SDK-API.md`, `MANIFEST.md`, `CONFORMANCE.md`.
- `Tealbrick/opt2-tealbrick-samples`: fixture apps.
- System documentation (overview, environments, runbooks) lives in the private repo Tealbrick/opt2-tealbrick-docs.
