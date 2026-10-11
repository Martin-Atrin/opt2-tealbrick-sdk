// App pages over the SDK client hooks (holds, agents, session). Holds are decided here, one call at a time (C8).
// SPEC-GAP: SDK-API §14 names <AppShell> from @opt2-tealbrick/ui; ui 0.1.0 does not export it yet. `Frame` is a
// minimal stand-in built from ui primitives; replace it with <AppShell> when ui ships it (no other change needed).
import { useAgents, useHolds, useSession } from "@opt2-tealbrick/miniapp-sdk/client";
import { Button, Eyebrow, Notice, Tag } from "@opt2-tealbrick/ui";
import type { ReactNode } from "react";

const NAME = "__APP_NAME__";

function Frame({ children }: { children: ReactNode }) {
  const { principal, status, signOut } = useSession();
  return (
    <main style={{ maxWidth: "48rem", margin: "0 auto", padding: "1.5rem" }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: "1rem" }}>
        <div>
          <Eyebrow>Teal Brick app</Eyebrow>
          <h1>{NAME}</h1>
        </div>
        {status === "signed_in" && principal ? (
          <Button onClick={() => void signOut()}>Sign out</Button>
        ) : (
          <Tag tone={status === "loading" ? "progress" : "action"}>{status === "loading" ? "Loading" : "Signed out"}</Tag>
        )}
      </header>
      <nav style={{ display: "flex", gap: "1rem", margin: "1rem 0" }}>
        <a href="./">Holds</a>
        <a href="./configure">Agents</a>
      </nav>
      {status === "signed_out" ? (
        <Notice tone="action" role="alert">
          Open this app from Portal to sign in.
        </Notice>
      ) : (
        children
      )}
    </main>
  );
}

function Holds() {
  const { holds, loading, decide } = useHolds({ status: "held" });
  if (loading) return <p>Loading holds.</p>;
  if (holds.length === 0) return <p>No calls wait for your approval.</p>;
  return (
    <ul>
      {holds.map((h) => (
        <li key={h.id}>
          <strong>{h.caller.name}</strong> {h.summary} <Tag tone="action">{h.op}</Tag>
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
  const configure = globalThis.location.pathname.replace(/\/+$/, "").endsWith("/configure");
  return <Frame>{configure ? <Agents /> : <Holds />}</Frame>;
}
