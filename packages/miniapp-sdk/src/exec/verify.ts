// Accepts only instance assertions signed by this service's OWN app instance key (C6, SDK-API §11): the key from
// `ClaimResponse.app.publicKey`, `iss = sub = tb:ins:<ins>`, no `svc` (a sibling service cannot call), `aud` =
// `tb:brg:<bridge>` (the audience every instance assertion carries, CREDENTIALS §10), htm/htu/bd bound, one-time `jti`.
import type { IncomingMessage } from "node:http";
import { keySetFrom, memoryReplayGuard, type ReplayGuard, verifyAssertion } from "@opt2-tealbrick/manifest";
import { BRIDGE_HEADERS } from "@opt2-tealbrick/spec/bridge";
import { TYP } from "@opt2-tealbrick/spec/credentials";
import { TbError } from "../server/errors.ts";
import { header } from "../server/http.ts";
import type { ClaimRecord } from "./identity.ts";

export type AppAssertionVerifier = (req: IncomingMessage, body: Uint8Array) => void;

/** Throws TbError 401 `unauthenticated` unless the request carries a valid assertion from the own app instance. */
export function appAssertionVerifier(rec: ClaimRecord, replay: ReplayGuard = memoryReplayGuard(), now: () => number = () => Math.floor(Date.now() / 1000)): AppAssertionVerifier {
  const keys = keySetFrom({ keys: [rec.app.publicKey] }, `tb:ins:${rec.ins}`);
  const aud = `tb:brg:${rec.bridge.id}`;
  return (req, body) => {
    const token = header(req, BRIDGE_HEADERS.assertion);
    if (!token) throw new TbError("unauthenticated", "instance assertion required", 401);
    const r = verifyAssertion(token, keys, { typ: TYP.instanceAssertion, aud, now: now(), method: req.method ?? "", pathAndQuery: req.url ?? "", body, replay });
    if (!r.ok || r.claims.svc !== undefined) throw new TbError("unauthenticated", "instance assertion invalid", 401);
  };
}
