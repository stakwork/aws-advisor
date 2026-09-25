import { useEffect, useRef, useState } from "react";
import { api, when } from "../api";
import { Badge, Button } from "./ui";
import { Prose } from "./playbook";
import { Markdown } from "./markdown";

/** GET /api/recommendations/:id/messages (src/chat.ts). */
interface Message { id: number; role: "user" | "agent"; author: string | null; content: string; extra: { suggest_replan?: boolean; step_fixes?: { step: number; step_text: string; command?: string; verify?: string }[] } | null; request_id: string | null; status: "pending" | "completed" | "failed"; error: string | null; created_at: string; finished_at: string | null }

/**
 * The thread on a recommendation: the engineer and the agent, back and forth, with the plan and the step outcomes
 * as the agent's context. A sent message gets a pending agent reply that the webhook fills in; while one is
 * pending the thread polls every 5 s (and nudges the run's poll, the fallback when the webhook is missed).
 * The agent's replies are Markdown (components/markdown.tsx); what the person wrote stays as typed, since a pasted
 * command output full of # and * must not turn into headings and bullets.
 */
export function Thread({ base, general, onReplan, replanBusy, title, hint, tall, onSent }: { base: string; general?: boolean; onReplan?: () => void; replanBusy?: boolean; title?: string; hint?: string; tall?: boolean; onSent?: () => void }) {
  // `base` is the messages endpoint: /recommendations/:id/messages, or /chat/threads/:id/messages for a general thread.
  const recId = general ? null : base;
  const [messages, setMessages] = useState<Message[] | null>(null);
  const [draft, setDraft] = useState("");
  const [sending, setSending] = useState(false);
  const [err, setErr] = useState("");
  const endRef = useRef<HTMLDivElement>(null);
  const load = () => api(base).then(setMessages).catch((e) => setErr(e.message));
  useEffect(() => { setMessages(null); setErr(""); setDraft(""); load(); }, [base]);
  const pending = messages?.find((m) => m.status === "pending") ?? null;
  useEffect(() => {
    if (!pending) return;
    const t = setInterval(() => { if (pending.request_id) api(`/agent-runs/${pending.request_id}/poll`, { method: "POST" }).catch(() => {}); load(); }, 5000);
    return () => clearInterval(t);
  }, [pending?.id, pending?.request_id, base]);
  useEffect(() => { endRef.current?.scrollIntoView({ block: "nearest" }); }, [messages?.length, pending?.status]);
  const send = async () => {
    const text = draft.trim();
    if (!text || sending || pending) return;
    setSending(true); setErr("");
    try { await api(base, { method: "POST", body: JSON.stringify({ message: text }) }); setDraft(""); await load(); onSent?.(); }
    catch (e: any) { setErr(e.message); }
    finally { setSending(false); }
  };
  const lastAgent = [...(messages || [])].reverse().find((m) => m.role === "agent" && m.status === "completed");
  return (
    <div className={`rounded border border-zinc-800 bg-zinc-950/60 p-3 ${recId == null ? "" : "mt-3"}`}>
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-sm font-medium text-zinc-200">{title ?? "Chat about this"} <span className="font-normal text-zinc-500">· {hint ?? "the agent gets the plan, the step outcomes and this thread"}</span></span>
        {pending && <Badge>answering…</Badge>}
      </div>
      {messages && messages.length === 0 && <div className="mt-1 text-xs text-zinc-500">{recId == null ? "Ask about spend, a resource, a pool, an alert or what to do next. The agent gets a few account numbers and the list of what it can look up, and fetches what your question needs." : "Ask why a step failed, paste an output and ask what it means, or ask for the next command. The agent gets the plan and the outcomes and can check facts with the advisor's tools."}</div>}
      {messages && messages.length > 0 && (
        <div className={`mt-2 space-y-3 overflow-y-auto pr-1 text-sm ${tall ? "max-h-[70vh]" : "max-h-[28rem]"}`}>
          {messages.map((m) => (
            <div key={m.id} className={`rounded p-2 ${m.role === "user" ? "ml-6 bg-sky-500/10 text-zinc-200" : "mr-6 bg-zinc-900 text-zinc-300"}`}>
              <div className="mb-1 flex items-center gap-2 text-[11px] text-zinc-500"><span className="font-medium text-zinc-400">{m.role === "agent" ? "advisor" : m.author || "you"}</span><span>{when(m.finished_at || m.created_at)}</span>{m.status === "failed" && <span className="text-red-300">failed</span>}</div>
              {m.status === "pending" && <div className="text-xs text-zinc-500">The agent is checking the facts and writing the answer{m.request_id ? ` (request ${m.request_id})` : ""}…</div>}
              {m.status === "failed" && <div className="text-xs text-red-300">{m.error}</div>}
              {m.status === "completed" && <div className="leading-relaxed">{m.role === "agent" ? <Markdown text={m.content} /> : <Prose text={m.content} />}</div>}
              {m.extra?.step_fixes && m.extra.step_fixes.length > 0 && (
                <div className="mt-2 space-y-2 text-xs">
                  {m.extra.step_fixes.map((f, i) => (
                    <div key={i} className="rounded border border-emerald-500/20 bg-emerald-500/5 p-2">
                      <div className="text-[11px] uppercase tracking-wide text-emerald-300">Corrected step {f.step}</div>
                      <div className="mt-0.5 text-zinc-200"><Prose text={f.step_text} /></div>
                      {f.command && <pre className="mt-1 overflow-x-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 font-mono text-[11px] leading-5 text-zinc-200">{f.command}</pre>}
                      {f.verify && <div className="mt-1 text-emerald-300/90">verify: <Prose text={f.verify} /></div>}
                    </div>
                  ))}
                </div>
              )}
              {m.extra?.suggest_replan && onReplan && m.id === lastAgent?.id && (
                <div className="mt-2 flex items-center gap-2 text-xs text-amber-300">The agent thinks the plan needs rewriting from here.
                  <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={onReplan} disabled={Boolean(replanBusy)}>Re-plan from here</Button>
                </div>
              )}
            </div>
          ))}
          <div ref={endRef} />
        </div>
      )}
      {err && <div className="mt-2 text-xs text-red-300">{err}</div>}
      <div className="mt-2 flex items-end gap-2">
        <textarea className="!text-xs flex-1" rows={2} placeholder={pending ? "Wait for the answer…" : recId == null ? "Ask the advisor. Enter sends, Shift+Enter for a new line." : "Write to the agent about this recommendation. Enter sends, Shift+Enter for a new line."} value={draft} disabled={Boolean(pending) || sending} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); send(); } }} />
        <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={send} disabled={!draft.trim() || Boolean(pending) || sending}>{sending ? "Sending…" : "Send"}</Button>
      </div>
    </div>
  );
}
