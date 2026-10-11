// Shared test fixtures: a workspace with Portal, bridge and instance keys, and a raw signer for malformed tokens.
import { webcrypto } from "node:crypto";
import type { AgentId, BridgeId, GrantClaims, InstanceId, PersonId, WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { Ed25519KeyPair, TrustContext } from "@opt2-tealbrick/spec/sdk";
import type { Issue } from "../src/jws.ts";
import { generateKeyPair, keySetFrom } from "../src/keys.ts";
import { ulid } from "../src/random.ts";

export const NOW = 1_800_000_000;

export async function world() {
  const portal = await generateKeyPair();
  const bridgeKey = await generateKeyPair();
  const insKey = await generateKeyPair();
  const stranger = await generateKeyPair();
  const ws = `ws_${ulid()}` as WorkspaceId;
  const brg = `brg_${ulid()}` as BridgeId;
  const ins = `ins_${ulid()}` as InstanceId;
  const other = `ins_${ulid()}` as InstanceId;
  const agt = `agt_${ulid()}` as AgentId;
  const per = `per_${ulid()}` as PersonId;
  const trust: TrustContext = {
    now: NOW,
    self: `tb:ins:${ins}`,
    ws,
    bridge: brg,
    issuers: keySetFrom({ keys: [portal.publicJwk] }, "tb:portal"),
    bridgeKeys: keySetFrom({ keys: [bridgeKey.publicJwk] }, `tb:brg:${brg}`),
    revokedJtis: new Set(),
  };
  const grantClaims = (over: Partial<Issue<GrantClaims>> = {}): Issue<GrantClaims> => ({
    iss: "tb:portal",
    sub: `tb:agt:${agt}`,
    aud: `tb:ins:${ins}`,
    ws,
    cnf: { brg },
    crud: ["read", "create"],
    mode: "free",
    held: ["first_contact"],
    caps: { write: { max: 5, per: "hour" } },
    wf: [],
    polrev: 1,
    iat: NOW - 10,
    ...over,
  });
  return { portal, bridgeKey, insKey, stranger, ws, brg, ins, other, agt, per, trust, grantClaims };
}

const b64 = (v: unknown) => Buffer.from(typeof v === "string" ? v : JSON.stringify(v)).toString("base64url");

/** Signs arbitrary header + payload (bypasses the claim checks of signJws) to build malformed tokens. */
export async function rawSign(header: unknown, payload: unknown, key: Ed25519KeyPair): Promise<string> {
  const input = `${b64(header)}.${b64(payload)}`;
  const sig = await webcrypto.subtle.sign({ name: "Ed25519" }, key.privateKey as webcrypto.CryptoKey, Buffer.from(input));
  return `${input}.${Buffer.from(sig).toString("base64url")}`;
}

/** Decodes the payload of a compact JWS (tests only). */
export function payloadOf(token: string): Record<string, unknown> {
  return JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8"));
}
