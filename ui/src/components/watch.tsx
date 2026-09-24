import { useEffect, useState } from "react";
import { api } from "../api";

/** GET / POST /api/inventory/:kind/:id/watch (src/notify.ts): is this resource paged about in Sphinx, and why. */
export function WatchToggle({ kind, id }: { kind: string; id: string }) {
  const [s, setS] = useState<{ watched: boolean; override: 0 | 1 | null; reason: string } | null | undefined>(undefined);
  const [busy, setBusy] = useState(false);
  useEffect(() => { setS(undefined); api(`/inventory/${kind}/${encodeURIComponent(id)}/watch`).then(setS).catch(() => setS(null)); }, [kind, id]);
  const set = async (watch: boolean | null) => { setBusy(true); try { setS(await api(`/inventory/${kind}/${encodeURIComponent(id)}/watch`, { method: "POST", body: JSON.stringify({ watch }) })); } catch { /* shown as unchanged */ } finally { setBusy(false); } };
  if (s === undefined) return null;
  if (!s) return null;
  const btn = (label: string, v: boolean | null, active: boolean) => <button key={label} disabled={busy || active} onClick={() => set(v)} className={`rounded border px-1.5 py-0.5 ${active ? "border-zinc-500 bg-zinc-800 text-zinc-100" : "border-zinc-700 text-zinc-400 hover:text-zinc-200"} disabled:cursor-default`}>{label}</button>;
  return (
    <div className="mt-1 flex flex-wrap items-center gap-2 text-xs">
      <span className={s.watched ? "text-emerald-300" : "text-zinc-500"} title="Alerts on watched resources are sent to the Sphinx chat (Settings > Notifications)">{s.watched ? "Watched" : "Not watched"} <span className="text-zinc-500">· {s.reason}</span></span>
      <span className="flex gap-1">{btn("watch", true, s.override === 1)}{btn("ignore", false, s.override === 0)}{btn("auto", null, s.override === null)}</span>
    </div>
  );
}
