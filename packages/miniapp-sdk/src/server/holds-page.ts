// v0.1.13 (G4): the SDK's minimal hold decision page `GET|POST /a/<product>/holds/<id>` for apps WITHOUT a person UI
// (apps with `manifest.ui` route `/holds/<id>` in their own UI). Server-rendered, every value escaped, no script (the
// sendHtml CSP allows none): approve / deny is a same-origin form POST carrying the session CSRF token, checked like the
// TB-CSRF header, then the one decide path of tb.holds_decide. Post/redirect/get back to the page.
import type { IncomingMessage, ServerResponse } from "node:http";
import { TbError } from "./errors.ts";
import { escapeHtml, readRaw, sendHtml } from "./http.ts";
import { decide } from "./ops.ts";
import type { Runtime } from "./runtime.ts";

/** `/holds/<hld_ULID>` (decidePath of tb.holds_pending) */
export const HOLD_PAGE_RE = /^\/holds\/(hld_[0-9A-HJKMNP-TV-Z]{26})$/;
const FORM_MAX = 16 * 1024;

const iso = (ms: number | null) => (ms === null ? "—" : new Date(ms).toISOString());

function errorPage(res: ServerResponse, e: unknown): void {
  const err = e instanceof TbError ? e : new TbError("internal_error", "internal error", 500);
  sendHtml(res, err.httpStatus, "Hold", `<h1>Hold</h1><p>${escapeHtml(err.message)}</p><p><code>${escapeHtml(err.code)}</code></p>`);
}

export async function handleHoldPage(rt: Runtime, req: IncomingMessage, res: ServerResponse, holdId: string): Promise<void> {
  let session: ReturnType<Runtime["person"]["requireSession"]>;
  try {
    session = rt.person.requireSession(req);
  } catch (e) {
    const code = e instanceof TbError ? e.code : "session_required";
    return sendHtml(res, 401, "Sign in", `<h1>Sign in required</h1><p>Open this app from Portal.</p><p><code>${escapeHtml(code)}</code></p>`);
  }
  try {
    const self = `/a/${rt.product}/holds/${holdId}`;
    if (req.method === "POST") {
      const form = new URLSearchParams((await readRaw(req, FORM_MAX)).toString("utf8"));
      rt.person.requireCsrfToken(req, session, form.get("csrf") ?? undefined);
      const decision = form.get("decision");
      if (decision !== "approve" && decision !== "deny") throw new TbError("input_invalid", "decision must be approve or deny", 400);
      await decide(rt, session.principal, { holdId: holdId as `hld_${string}`, decision });
      res.writeHead(303, { location: self, "cache-control": "no-store" });
      return void res.end();
    }
    const h = rt.receipts.getSync(holdId);
    if (!h) throw new TbError("hold_not_found", "no such hold", 404);
    const reason = rt.receipts.holdReason(holdId) ?? "—";
    const title = rt.ops.get(h.op)?.title ?? h.op;
    const rows: [string, string][] = [
      ["Status", h.status],
      ["Operation", title],
      // v0.1.27: an app caller's name is display only; the verified product id is what identifies it
      ["Caller", `${h.caller.name} (${h.caller.type}${h.caller.product ? `, ${h.caller.product}` : ""})`],
      ["Family", h.holdFamily ?? "policy"],
      ["Reason", reason],
      ["Held by", h.heldBy ?? "—"],
      ["Summary", h.summary],
      ["Created", iso(h.createdAt)],
      [h.status === "held" ? "Expires" : "Decided", h.status === "held" ? iso(h.expiresAt) : iso(h.decidedAt)],
    ];
    const table = `<dl>${rows.map(([k, v]) => `<dt><b>${escapeHtml(k)}</b></dt><dd>${escapeHtml(v)}</dd>`).join("")}</dl>`;
    const view = typeof h.view === "string" ? `<pre style="white-space:pre-wrap;border:1px solid #ccc;padding:.5rem">${escapeHtml(h.view)}</pre>` : "";
    const form =
      h.status === "held"
        ? `<form method="post" action="${escapeHtml(self)}"><input type="hidden" name="csrf" value="${escapeHtml(session.csrf)}"><button type="submit" name="decision" value="approve">Approve</button> <button type="submit" name="decision" value="deny">Deny</button></form>`
        : "";
    sendHtml(res, 200, "Hold", `<h1>Hold</h1>${table}${view}${form}`, { "x-content-type-options": "nosniff", "x-frame-options": "DENY" });
  } catch (e) {
    errorPage(res, e);
  }
}
