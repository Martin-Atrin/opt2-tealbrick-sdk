// App pages over the SDK client hooks (holds, agents, session) inside the ONE app shell, <AppShell> from
// @opt2-tealbrick/ui (SDK-API §14). Holds are decided here, one call at a time (C8).
import { useAgents, useHolds, useSession } from "@opt2-tealbrick/miniapp-sdk/client";
import { AppShell, Button, Notice, STANDARD_PAGES, Tag } from "@opt2-tealbrick/ui";
import { useEffect, useState } from "react";

const NAME = "__APP_NAME__";

/** Pages this app serves, by shell page id → path under the base `/a/__APP_ID__/` (manifest `ui.launchPath`, `ui.configurePath`). */
const PATHS: Record<string, string> = { holds: "./", agents: "./configure" };
const PAGES = STANDARD_PAGES.filter((p) => p.id in PATHS);
const pageOf = (pathname: string) => (pathname.replace(/\/+$/, "").endsWith("/configure") ? "agents" : "holds");
/** SDK 0.1.13 (G4): `tb.holds_pending` decidePath `/holds/<id>` opens here (Portal launch ticket with path); show that hold. */
const holdOf = (pathname: string) => /\/holds\/(hld_[0-9A-HJKMNP-TV-Z]{26})\/?$/.exec(pathname)?.[1] ?? null;

function Holds({ only }: { only: string | null }) {
  const { holds: all, loading, decide } = useHolds({ status: "held" });
  if (loading) return <p>Loading holds.</p>;
  const holds = only ? all.filter((h) => h.id === only) : all;
  if (holds.length === 0) return <p>{only ? "This approval is no longer waiting." : "No calls wait for your approval."}</p>;
  return (
    <ul>
      {holds.map((h) => (
        <li key={h.id}>
          <strong>{h.caller.name}</strong> {h.summary} <Tag tone="action">{h.op}</Tag>
          {h.holdFamily ? <Tag>{h.holdFamily}</Tag> : null}
          {h.heldBy ? <Tag>held by {h.heldBy}</Tag> : null}
          {h.view ? <pre>{h.view}</pre> : null}
          <Button variant="primary" onClick={() => void decide(h.id as Parameters<typeof decide>[0], "approve")}>
            Approve
          </Button>{" "}
          <Button onClick={() => void decide(h.id as Parameters<typeof decide>[0], "deny")}>Deny</Button>
        </li>
      ))}
    </ul>
  );
}

function Agents() {
  const { agents, loading } = useAgents();
  if (loading) return <p>Loading agents.</p>;
  if (agents.length === 0) return <p>No agents are connected to this app.</p>;
  return (
    <ul>
      {agents.map((a) => (
        <li key={a.id}>
          {a.name} <Tag>{a.mode}</Tag>
        </li>
      ))}
    </ul>
  );
}

export function App() {
  const { principal, status, signOut } = useSession();
  const [page, setPage] = useState(() => pageOf(globalThis.location.pathname));
  useEffect(() => {
    const onPop = () => setPage(pageOf(globalThis.location.pathname));
    globalThis.addEventListener("popstate", onPop);
    return () => globalThis.removeEventListener("popstate", onPop);
  }, []);
  const navigate = (id: string) => {
    globalThis.history.pushState(null, "", PATHS[id]);
    setPage(id);
  };
  return (
    <AppShell
      title={NAME}
      pages={PAGES}
      current={page}
      onNavigate={navigate}
      actions={
        status === "signed_in" && principal ? (
          <Button onClick={() => void signOut()}>Sign out</Button>
        ) : (
          <Tag tone={status === "loading" ? "progress" : "action"}>{status === "loading" ? "Loading" : "Signed out"}</Tag>
        )
      }
      banner={
        status === "signed_out" ? (
          <Notice tone="action" role="alert">
            Open this app from Portal to sign in.
          </Notice>
        ) : null
      }
    >
      {status === "signed_out" ? null : page === "agents" ? <Agents /> : <Holds only={holdOf(globalThis.location.pathname)} />}
    </AppShell>
  );
}
