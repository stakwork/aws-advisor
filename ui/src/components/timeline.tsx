import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, when } from "../api";
import { Badge } from "./ui";

/** GET /api/inventory/:kind/:id/timeline (src/timeline.ts). */
interface Event { at: string; kind: string; title: string; detail: string | null; href: string | null; badge: string | null }

const KIND_LABEL: Record<string, string> = { seen: "first seen", gone: "gone", finding: "finding", recommendation: "recommendation", decision: "decision", resolution: "resolution", verification: "bill check", alert: "alert", incident: "incident", probe: "probe" };
const KIND_TONE: Record<string, string> = { decision: "text-sky-300", recommendation: "text-violet-300", alert: "text-amber-300", incident: "text-red-300", verification: "text-emerald-300", finding: "text-zinc-300", seen: "text-zinc-400", gone: "text-zinc-400", resolution: "text-zinc-300", probe: "text-zinc-400" };

/**
 * Everything the advisor recorded about one resource, newest first: findings, recommendations and decisions,
 * resolutions, bill checks, alerts, incidents, probes. Repeated alerts of one kind on one day are folded.
 */
export function Timeline({ kind, id }: { kind: string; id: string }) {
  const [data, setData] = useState<{ events: Event[]; counts: Record<string, number> } | null | undefined>(undefined);
  const [all, setAll] = useState(false);
  useEffect(() => { setData(undefined); setAll(false); api(`/inventory/${kind}/${encodeURIComponent(id)}/timeline`).then(setData).catch(() => setData(null)); }, [kind, id]);
  if (data === undefined) return <div className="mt-4 text-xs text-zinc-500">Loading history…</div>;
  if (!data || !data.events.length) return <div className="mt-4 text-xs text-zinc-500">No history recorded yet.</div>;
  const folded = fold(data.events);
  const shown = all ? folded : folded.slice(0, 12);
  const summary = Object.entries(data.counts).map(([k, n]) => `${n} ${KIND_LABEL[k] || k}${n === 1 ? "" : "s"}`).join(" · ");
  return (
    <div className="mt-4">
      <div className="mb-1 text-[11px] uppercase tracking-wide text-zinc-500">History <span className="normal-case tracking-normal text-zinc-600">· {summary}</span></div>
      <ul className="space-y-1 text-xs">
        {shown.map((e, i) => (
          <li key={i} className="grid grid-cols-[8.5rem_1fr] gap-2">
            <span className="text-zinc-500">{when(e.at)}</span>
            <span className="min-w-0">
              <span className={`mr-1 ${KIND_TONE[e.kind] || "text-zinc-300"}`}>{KIND_LABEL[e.kind] || e.kind}</span>
              {e.href ? <Link className="hover:underline" to={e.href}>{e.title}</Link> : <span>{e.title}</span>}
              {e.repeats > 1 && <span className="text-zinc-500"> · ×{e.repeats} that day</span>}
              {e.badge && <> <Badge>{e.badge}</Badge></>}
              {e.detail && <div className="text-zinc-500">{e.detail}</div>}
            </span>
          </li>
        ))}
      </ul>
      {folded.length > 12 && <button className="mt-1 text-xs text-zinc-400 hover:text-zinc-200" onClick={() => setAll((v) => !v)}>{all ? "show fewer" : `show all ${folded.length}`}</button>}
    </div>
  );
}

/** The watcher raises the same alert every half hour while a state lasts: one line per (day, title), with a count. */
function fold(events: Event[]): (Event & { repeats: number })[] {
  const out: (Event & { repeats: number })[] = [];
  for (const e of events) {
    const last = out[out.length - 1];
    if (last && e.kind === "alert" && last.kind === "alert" && last.title === e.title && last.at.slice(0, 10) === e.at.slice(0, 10)) { last.repeats++; continue; }
    out.push({ ...e, repeats: 1 });
  }
  return out;
}
