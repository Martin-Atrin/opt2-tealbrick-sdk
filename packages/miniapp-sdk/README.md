# @opt2-tealbrick/miniapp-sdk

Server runtime for opt2 miniapps (SDK-API §3–§13): `defineApp({ manifest, handlers, hooks?, dynamic?, publicRoutes?, migrations, onStart?, events? })` + `startApp(app, process.env)`. The SDK mounts every route from the manifest (`/tb/v1/ops/:op`, hooks, bridge ops, person session under `/a/<product>/`, health), verifies grants and call proofs, runs `authorize()`, owns the one store (node:sqlite under `TB_DATA_DIR`), receipts/holds, idempotency, scopes (manifest default grants), audit, keys (`getKey`: app-own > workspace default via the bridge), app secrets (`ctx.secrets`, sealed under `TB_KEK`), claim via the bridge, slice refresh, and `callServiceHelper`.

0.1.0 = server. Next: client hooks (`/client`), `tb-exec`, backups/restore/export.
