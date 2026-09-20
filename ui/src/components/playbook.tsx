import { useEffect, useRef, useState } from "react";
import { api } from "../api";
import { Badge, Card } from "./ui";

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
export function Prose({ text }: { text: string }) {
  const parts = text.split(/(`[^`]+`)/g);
  return <>{parts.map((p, i) => (p.startsWith("`") && p.endsWith("`") ? <code key={i} className="rounded bg-zinc-950 px-1 py-0.5 font-mono text-[11px] text-zinc-200">{p.slice(1, -1)}</code> : <span key={i}>{p}</span>))}</>;
}

export const EffortBadge = ({ effort }: { effort: string }) => (
  <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-medium ${effort === "low" ? "border-emerald-500/30 bg-emerald-500/15 text-emerald-300" : effort === "medium" ? "border-amber-500/30 bg-amber-500/15 text-amber-300" : "border-red-500/30 bg-red-500/15 text-red-300"}`}>effort {effort}</span>
);

/** The playbook's body: meaning, act / ignore, numbered steps, saving formula, references. */
export function PlaybookBody({ pb, compact = false }: { pb: Playbook; compact?: boolean }) {
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
        <ol className="list-decimal space-y-1 pl-5">{pb.steps.map((s, i) => <li key={i}><Prose text={s} /></li>)}</ol>
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
