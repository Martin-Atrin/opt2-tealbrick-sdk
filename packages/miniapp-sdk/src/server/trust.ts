// Trust state of the instance (SDK-API §9 Slice, §12, CREDENTIALS §9.2): the last good instance slice, the trusted
// issuer set (bootstrap TB_PORTAL_KEYS → slice portalKeys → standalone issuer, or the own key in app-alone mode), call-proof
// keys, revoked jtis and pause state. Verification itself is `@opt2-tealbrick/manifest` (verifyJws + verifySlice).
import { keySetAnnounce, keySetFrom, keySetFromPortalKeys, thumbprint, verifyJws, verifySlice } from "@opt2-tealbrick/manifest";
import type { InstanceSlice } from "@opt2-tealbrick/spec/bridge";
import { type BridgeId, type Ed25519PublicJwk, type InstanceId, type InstanceRef, LIFETIME_S, TYP, type WorkspaceId } from "@opt2-tealbrick/spec/credentials";
import type { KeySet, Refusal, SliceAgent, TrustContext } from "@opt2-tealbrick/spec/sdk";
import { metaGet, metaSet, type RawDb } from "./store.ts";

interface StoredSlice {
  token: string;
  slice: InstanceSlice;
  /** the issuer set the slice established (portalKeys + standalone issuer) */
  issuers: KeySet;
}

export interface SliceChange {
  added: SliceAgent[];
  removed: SliceAgent[];
  pausedNow: boolean;
}

const nowS = (ms: number) => Math.floor(ms / 1000);

export class TrustState {
  readonly self: InstanceRef;
  readonly instanceId: InstanceId;
  #db: RawDb;
  #bootstrap: KeySet | null;
  #alone: { ws: WorkspaceId; ownKey: Ed25519PublicJwk } | null;
  #stored: StoredSlice | null;
  #bridge: BridgeId | null = null;

  constructor(db: RawDb, instanceId: InstanceId, opts: { bootstrap: KeySet | null; alone?: { ws: WorkspaceId; ownKey: Ed25519PublicJwk } }) {
    this.#db = db;
    this.instanceId = instanceId;
    this.self = `tb:ins:${instanceId}`;
    this.#bootstrap = opts.bootstrap;
    this.#alone = opts.alone ?? null;
    this.#stored = metaGet<StoredSlice>(db, "slice");
  }

  get slice(): InstanceSlice | null {
    return this.#stored?.slice ?? null;
  }
  get ws(): WorkspaceId | null {
    return this.#alone?.ws ?? this.#stored?.slice.ws ?? null;
  }
  /** Bridge id from the claim record (before the first slice) or the slice. */
  get bridgeId(): BridgeId | null {
    return this.#stored?.slice.bridge.id ?? this.#bridge;
  }
  setBridge(id: BridgeId): void {
    this.#bridge = id;
  }

  /** Issuers trusted for grants, tickets and slices. */
  issuers(): KeySet {
    if (this.#alone) return keySetFrom({ keys: [this.#alone.ownKey] }, this.self);
    return this.#stored?.issuers ?? this.#bootstrap ?? { keys: [] };
  }

  /** CORE C9: a slice older than 12 h → ops answer `slice_stale`. App-alone mode has no slice and never goes stale. */
  stale(nowMs: number): boolean {
    if (this.#alone) return false;
    const s = this.slice;
    return s === null || nowS(nowMs) > s.iat + LIFETIME_S.configOrSlice;
  }

  /** TrustContext for the manifest verifiers; null until a slice exists (or always available in app-alone mode). */
  context(nowMs: number): TrustContext | null {
    const ws = this.ws;
    if (this.#alone && ws) {
      return { now: nowS(nowMs), self: this.self, ws, bridge: "brg_00000000000000000000000000" as BridgeId, issuers: this.issuers(), bridgeKeys: { keys: [] }, revokedJtis: new Set() };
    }
    const s = this.slice;
    if (!s || !ws) return null;
    return {
      now: nowS(nowMs),
      self: this.self,
      ws,
      bridge: s.bridge.id,
      issuers: this.issuers(),
      bridgeKeys: keySetFrom({ keys: s.bridge.keys }, `tb:brg:${s.bridge.id}`),
      revokedJtis: new Set(s.revoked.jtis.map((j) => j.jti)),
    };
  }

  /** Slice pause (CORE I1): workspace kill switch, this instance, the calling agent (listed or status `paused`). */
  paused(callerId: string | null): { workspace: boolean; instance: boolean; agent: boolean } {
    const s = this.slice;
    if (!s) return { workspace: false, instance: false, agent: false };
    const agentEntry = callerId ? s.agents.find((a) => a.id === callerId) : undefined;
    return {
      workspace: s.pause.workspace,
      instance: s.pause.instances.includes(this.instanceId),
      agent: callerId !== null && ((s.pause.agents as string[]).includes(callerId) || agentEntry?.status === "paused"),
    };
  }

  agent(id: string): SliceAgent | undefined {
    return this.slice?.agents.find((a) => a.id === id);
  }

  /**
   * Verifies and installs a slice (`rev` must increase). The first slice teaches `ws` (ClaimResponse carries none):
   * verifyJws with the trusted issuers authenticates it, then verifySlice runs the kind checks with that `ws`.
   */
  install(token: string, nowMs: number): { ok: true; changed: SliceChange | null } | Refusal {
    const bridge = this.bridgeId;
    if (!bridge) return { ok: false, code: "slice_invalid", reason: "bridge unknown before claim" };
    const issuers = this.issuers();
    const issList = [...new Set(issuers.keys.map((k) => k.issuer as string))];
    const pre = verifyJws<InstanceSlice>(token, issuers, { typ: TYP.slice, aud: this.self, iss: issList, now: nowS(nowMs), maxLifetimeS: LIFETIME_S.configOrSlice });
    if (!pre.ok) return pre;
    const ws = this.ws ?? pre.claims.ws;
    const v = verifySlice(token, { now: nowS(nowMs), self: this.self, ws, bridge, issuers });
    if (!v.ok) return v;
    const slice = v.slice;
    const prev = this.#stored?.slice ?? null;
    if (prev && slice.rev <= prev.rev) return { ok: true, changed: null };
    // CORE §4: the slice's portalKeys replace the trusted set only because a trusted key signed it.
    let next = keySetAnnounce(issuers, keySetFromPortalKeys(slice.portalKeys), { kid: pre.header.kid });
    if (slice.standalone) {
      const key = slice.bridge.keys.find((k) => thumbprint(k) === slice.standalone?.kid);
      if (key) next = { keys: [...next.keys, ...keySetFrom({ keys: [key] }, slice.standalone.issuer).keys] };
    }
    this.#stored = { token, slice, issuers: next };
    metaSet(this.#db, "slice", this.#stored);
    const before = new Map((prev?.agents ?? []).map((a) => [a.id, a]));
    const after = new Map(slice.agents.map((a) => [a.id, a]));
    const wasPaused = prev ? prev.pause.workspace || prev.pause.instances.includes(this.instanceId) : false;
    const isPaused = slice.pause.workspace || slice.pause.instances.includes(this.instanceId);
    return {
      ok: true,
      changed: {
        added: slice.agents.filter((a) => !before.has(a.id)),
        removed: [...before.values()].filter((a) => !after.has(a.id)),
        pausedNow: isPaused && !wasPaused,
      },
    };
  }
}
