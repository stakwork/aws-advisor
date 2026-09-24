import { Fragment, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../api";
import { Badge, Card } from "./ui";
import { paragraphs } from "./incident";

/** GET /api/playbooks/:controlId (see src/playbooks.ts). */
export interface Playbook {
  control_id: string;
  title: string;
  meaning: string;
  act_when: string;
  ignore_when: string;
  steps: string[];
  saving: string;
  tier: "auto" | "approve" | "report";
  effort: "low" | "medium" | "high";
  references?: string[];
  findings?: number;
}

const cache = new Map<string, Promise<Playbook | null>>();

/** Loads a playbook by control id once per page life; null when the control has none. */
export function usePlaybook(controlId: string | null | undefined): Playbook | null | undefined {
  const [pb, setPb] = useState<Playbook | null | undefined>(undefined);
  useEffect(() => {
    if (!controlId) { setPb(null); return; }
    if (!cache.has(controlId)) cache.set(controlId, api(`/playbooks/${encodeURIComponent(controlId)}`).catch(() => null));
    let live = true;
    cache.get(controlId)!.then((p) => { if (live) setPb(p); });
    return () => { live = false; };
  }, [controlId]);
  return pb;
}

/** Inline code spans for the `backticked` commands in playbook text. */
function Inline({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`)/g);
  return <>{parts.map((p, i) => (p.startsWith("`") && p.endsWith("`") ? <code key={i} className="rounded bg-zinc-950 px-1 py-0.5 font-mono text-[11px] text-zinc-200">{p.slice(1, -1)}</code> : <span key={i}>{p}</span>))}</>;
}

/**
 * Agent and playbook text as readable paragraphs with inline code. Blank lines split paragraphs; a single long
 * block is cut every two sentences (see paragraphs in incident.tsx). Rendered as block spans so it is valid inside
 * a <p> or an <li>, with a gap between paragraphs and single newlines kept as line breaks.
 */
export function Prose({ text }: { text: string }) {
  const paras = paragraphs(text || "");
  if (paras.length <= 1 && !/\n/.test(text || "")) return <Inline text={text || ""} />;
  return <>{paras.map((para, i) => (
    <span key={i} className={`block ${i ? "mt-2" : ""}`}>
      {para.split(/\n/).map((line, j) => <Fragment key={j}>{j > 0 && <br />}<Inline text={line} /></Fragment>)}
    </span>
  ))}</>;
}

export const EffortBadge = ({ effort }: { effort: string }) => (
  <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-medium ${effort === "low" ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-300" : effort === "medium" ? "border-amber-500/30 bg-amber-500/15 text-amber-300" : "border-red-500/30 bg-red-500/15 text-red-300"}`}>effort {effort}</span>
);

/** What happened to a step (src/progress.ts StepOutcome): it worked, or it failed with the output pasted in. */
export interface StepOutcome { step: number; state: "worked" | "failed"; note: string; at: string }

/**
 * A step checklist: which steps are ticked and how to tick one, plus (when outcomes are tracked) what happened to
 * each and how to record it. A tick means the step worked; "failed" opens a box for the output, which the
 * re-plan and the thread hand back to the agent (see the progress panel on Recommendations).
 */
export interface StepChecks { done: Set<number>; toggle: (i: number) => void; busy?: boolean; outcomes?: Map<number, StepOutcome>; setOutcome?: (i: number, state: "worked" | "failed" | null, note: string) => void; runnable?: (i: number) => { runnable: boolean; reason: string; via?: "sql" | "cli" } | null; run?: (i: number) => void; running?: number | null }

/** One step of a plan, with a checkbox when it is being tracked. Ticked steps are struck through so the next one stands out. */
export function Step({ i, checks, children }: { i: number; checks?: StepChecks; children: ReactNode }) {
  const done = checks?.done.has(i) ?? false;
  const outcome = checks?.outcomes?.get(i) ?? null;
  const failed = outcome?.state === "failed";
  const [draft, setDraft] = useState<string | null>(null);
  const note = draft ?? outcome?.note ?? "";
  const save = () => { if (checks?.setOutcome && draft !== null && draft !== (outcome?.note ?? "")) checks.setOutcome(i, "failed", draft); setDraft(null); };
  return (
    <li className={done ? "text-zinc-500" : failed ? "text-zinc-200" : ""}>
      <div className="flex items-start gap-2">
        {checks && <input type="checkbox" className="!mt-1 !w-auto" checked={done} disabled={checks.busy} onChange={() => checks.toggle(i)} title={done ? "Untick this step" : "Tick this step as done"} />}
        <div className={`min-w-0 flex-1 ${done ? "line-through decoration-zinc-600" : ""}`}>{children}</div>
        {checks?.run && (() => { const v = checks.runnable?.(i); const isRunning = checks.running === i; return v?.runnable ? (
          <button className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] ${isRunning ? "border-sky-500/40 bg-sky-500/15 text-sky-300" : "border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/10"}`} disabled={checks.busy || checks.running != null}
            title={`Run from the app with the advisor's credentials (read-only, ${v.via === "sql" ? "through Steampipe" : "through the aws CLI"}: ${v.reason}); the output becomes this step's outcome`} onClick={() => checks.run!(i)}>{isRunning ? "Running…" : v.via === "sql" ? "Run · SQL" : "Run · CLI"}</button>
        ) : v ? <span className="shrink-0 text-[11px] text-zinc-600" title={v.reason}>copy to run</span> : null; })()}
        {checks?.setOutcome && !done && (
          <button className={`shrink-0 rounded border px-1.5 py-0.5 text-[11px] ${failed ? "border-red-500/40 bg-red-500/15 text-red-300" : "border-zinc-700 text-zinc-500 hover:text-zinc-300"}`} disabled={checks.busy}
            title={failed ? "Clear the failure" : "This step failed: record what happened, so the agent can re-plan from it"} onClick={() => checks.setOutcome!(i, failed ? null : "failed", failed ? "" : note)}>{failed ? "failed ✕" : "failed?"}</button>
        )}
      </div>
      {failed && checks?.setOutcome && (
        <div className="mt-1.5 ml-6">
          <textarea className="!text-[11px] !leading-4 font-mono w-full" rows={Math.min(8, Math.max(2, note.split("\n").length))} placeholder="Paste the output or say what went wrong. Saved when you click away." value={note} disabled={checks.busy} onChange={(e) => setDraft(e.target.value)} onBlur={save} />
          {outcome?.at && draft === null && <div className="text-[11px] text-zinc-600">recorded {outcome.at}</div>}
        </div>
      )}
      {!failed && outcome?.note && (
        <details className="mt-1 ml-6 text-[11px]"><summary className="cursor-pointer text-zinc-500">output · {outcome.at}</summary>
          <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 font-mono leading-4 text-zinc-400">{outcome.note}</pre>
        </details>
      )}
    </li>
  );
}

/** The playbook's body: meaning, act / ignore, numbered steps (with checkboxes when `checks` is given), saving formula, references. */
export function PlaybookBody({ pb, compact = false, checks }: { pb: Playbook; compact?: boolean; checks?: StepChecks }) {
  const cls = compact ? "text-xs" : "text-sm";
  return (
    <div className={`space-y-3 ${cls} text-zinc-300`}>
      <p><Prose text={pb.meaning} /></p>
      <div className="grid gap-2 sm:grid-cols-2">
        <div className="rounded border border-emerald-500/20 bg-emerald-500/5 p-2"><div className="mb-1 text-[11px] uppercase tracking-wide text-emerald-300">Act when</div><Prose text={pb.act_when} /></div>
        <div className="rounded border border-zinc-700 bg-zinc-950/60 p-2"><div className="mb-1 text-[11px] uppercase tracking-wide text-zinc-400">Ignore when</div><Prose text={pb.ignore_when} /></div>
      </div>
      <div>
        <div className="mb-1 text-[11px] uppercase tracking-wide text-zinc-500">Steps</div>
        <ol className="list-decimal space-y-1 pl-5">{pb.steps.map((s, i) => <Step key={i} i={i} checks={checks}><Prose text={s} /></Step>)}</ol>
      </div>
      <div><span className="text-[11px] uppercase tracking-wide text-zinc-500">Saving</span> <span className="text-zinc-400"><Prose text={pb.saving} /></span></div>
      {pb.references?.length ? <div className="text-xs text-zinc-500">{pb.references.map((r) => <a key={r} href={r} target="_blank" rel="noreferrer" className="mr-2 underline">{r.replace(/^https?:\/\//, "")}</a>)}</div> : null}
    </div>
  );
}

/** The "How to act" panel. Findings renders it inline, full width, under the row that opened it. */
export function PlaybookPanel({ controlId, onClose, findings }: { controlId: string; onClose: () => void; findings?: number }) {
  const pb = usePlaybook(controlId);
  const ref = useRef<HTMLDivElement>(null);
  // Bring the panel into view when it opens or switches control: "nearest" leaves the
  // page alone if it is already visible, and only scrolls the minimum otherwise.
  useEffect(() => {
    const el = ref.current; if (!el) return;
    const top = el.getBoundingClientRect().top;
    if (top < 0 || top > window.innerHeight * 0.66) el.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [controlId]);
  return (
    <div ref={ref}>
    <Card title={<span className="flex items-center justify-between">How to act <button className="text-zinc-500" onClick={onClose}>close</button></span>}>
      {pb === undefined ? <div className="text-sm text-zinc-500">Loading…</div> : !pb ? (
        <div className="text-sm text-zinc-500">No playbook for <span className="font-mono text-xs">{controlId}</span> yet.</div>
      ) : (
        <>
          <h2 className="text-base font-medium text-zinc-100">{pb.title}</h2>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-xs"><Badge>{pb.tier}</Badge><EffortBadge effort={pb.effort} />{findings != null && <span className="text-zinc-500">{findings} finding{findings === 1 ? "" : "s"} in this run</span>}<span className="font-mono text-[11px] text-zinc-600">{pb.control_id}</span></div>
          <div className="mt-3"><PlaybookBody pb={pb} /></div>
        </>
      )}
    </Card>
    </div>
  );
}
