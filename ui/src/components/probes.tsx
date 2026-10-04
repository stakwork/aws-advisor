import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Badge, Button, Card, Code, CopyButton } from "./ui";

type Deployed = { status: "current" | "stale" | "missing" | "error"; deployed_description: string | null; deployed_version: string | null; error: string | null } | null;
type Kind = {
  kind: string; title: string; what: string; version: string; sections: string[]; timeout_seconds: number; cron_key: string; scope_key: string; takes_signals: boolean;
  cron: string; cron_off: boolean; scope: string; interval_hours: number;
  document: { name: string; version: string; hash: string; edited: boolean; create_command: string; update_command: string };
  script: { default: string; override: string | null; effective: string; edited: boolean; lines: number };
  last_24h: { at: string | null; boxes: number }; ever: { boxes: number; rows: number }; candidates_now: number; deployed: Deployed;
};

const statusTone: Record<string, string> = { current: "text-emerald-300", stale: "text-amber-300", missing: "text-red-300", error: "text-zinc-500" };
const statusWord: Record<string, string> = { current: "deployed, current", stale: "deployed, stale: redeploy", missing: "not deployed", error: "status unknown" };

/**
 * Settings card: the probes, one per concern, each with its own SSM document and schedule. Shows what each collects,
 * whether its document in the account matches the script here, when it last ran and on how many boxes, the create and
 * update commands, and the script itself with an editor (saved edits take effect when the document is redeployed).
 */
export function ProbesCard() {
  const [d, setD] = useState<{ base_document: string; kinds: Kind[]; legacy_rows: number } | null>(null);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState<string | null>(null);
  const [text, setText] = useState("");
  const [msg, setMsg] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState("");
  const load = () => api("/probes").then((x) => { setD(x); setErr(""); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  const cur = d?.kinds.find((k) => k.kind === open);
  useEffect(() => { if (cur) setText(cur.script.effective); }, [open, cur?.document.hash]);
  const note = (kind: string, m: string) => setMsg((x) => ({ ...x, [kind]: m }));
  const save = async (kind: string) => { setBusy(kind); try { await api(`/probes/${kind}/script`, { method: "PUT", body: JSON.stringify({ text }) }); note(kind, "Saved. Redeploy the document (update command below) for the boxes to run it."); await load(); } catch (e: any) { note(kind, e.message); } finally { setBusy(""); } };
  const reset = async (kind: string) => { setBusy(kind); try { await api(`/probes/${kind}/script`, { method: "DELETE" }); note(kind, "Back to the default script. Redeploy the document if it was deployed with the edit."); await load(); } catch (e: any) { note(kind, e.message); } finally { setBusy(""); } };
  const pass = async (kind: string) => { setBusy(kind); note(kind, "Running the pass…"); try { const r = await api(`/probes/${kind}/pass`, { method: "POST", body: "{}" }); note(kind, `${r.probed.length} probed, ${r.failed.length} failed of ${r.candidates} candidates in ${Math.round(r.took_ms / 1000)} s${r.failed[0] ? `; first failure: ${r.failed[0].message}` : ""}`); await load(); } catch (e: any) { note(kind, e.message); } finally { setBusy(""); } };

  if (err) return <Card title="Probes"><div className="text-sm text-red-300">{err}</div></Card>;
  if (!d) return <Card title="Probes"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  return (
    <Card title={<span>Probes <span className="font-normal text-zinc-500">· read-only scripts run on the boxes through Systems Manager, one document per concern, each on its own schedule</span></span>}>
      <p className="mb-3 text-sm text-zinc-400">
        Each probe is a fixed shell script embedded in its own SSM document (<code className="text-zinc-200">{d.base_document}-&lt;kind&gt;</code>), so <code className="text-zinc-200">ssm:SendCommand</code> is granted on these documents only and nothing else can run on the fleet. Schedules, scopes and intervals are below; a script edited here takes effect when its document is redeployed, and the status column says whether the deployed document matches.
        {d.legacy_rows > 0 && <> {d.legacy_rows} stored rows still come from the pre-2.0 combined probe; a box without the per-kind documents keeps probing through the old <code className="text-zinc-200">{d.base_document}</code> document for host, containers and programs until they are created.</>}
      </p>
      <table className="w-full border-collapse text-sm">
        <thead className="text-xs text-zinc-500"><tr><th className="py-1 text-left font-normal">Probe</th><th className="text-left font-normal">Document</th><th className="text-left font-normal">Schedule</th><th className="text-left font-normal">Scope</th><th className="text-right font-normal">Last 24 h</th><th className="text-right font-normal">Due now</th><th className="font-normal"></th></tr></thead>
        <tbody>
          {d.kinds.map((k) => (
            <tr key={k.kind} className="border-t border-zinc-800 align-top">
              <td className="py-2 pr-3"><button type="button" className="text-left" onClick={() => setOpen(open === k.kind ? null : k.kind)}><div className="text-zinc-100">{k.title} <span className="font-mono text-xs text-zinc-500">{k.kind} {k.version}</span>{k.script.edited && <span className="ml-1"><Badge>edited</Badge></span>}</div><div className="max-w-md text-xs text-zinc-500">{k.what}</div></button></td>
              <td className="py-2 pr-3 text-xs"><div className="font-mono text-zinc-300">{k.document.name}</div><div className={statusTone[k.deployed?.status ?? "error"]}>{k.deployed ? statusWord[k.deployed.status] : "status unknown"}{k.deployed?.deployed_version ? <span className="text-zinc-600"> · v{k.deployed.deployed_version}</span> : null}</div>{k.deployed?.error && <div className="text-zinc-600">{k.deployed.error}</div>}</td>
              <td className="py-2 pr-3 text-xs"><span className={k.cron_off ? "text-zinc-600" : "font-mono text-zinc-300"}>{k.cron_off ? "off" : k.cron}</span><div className="text-zinc-600">every {k.interval_hours} h at most per box</div></td>
              <td className="py-2 pr-3 text-xs text-zinc-400">{k.scope === "all" ? "every box" : "idle candidates"}</td>
              <td className="py-2 pr-3 text-right text-xs text-zinc-400">{k.last_24h.boxes} box{k.last_24h.boxes === 1 ? "" : "es"}<div className="text-zinc-600">{k.last_24h.at ? when(k.last_24h.at) : "never"}</div></td>
              <td className="py-2 pr-3 text-right text-xs text-zinc-400">{k.candidates_now}</td>
              <td className="py-2 text-right"><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => pass(k.kind)} disabled={busy === k.kind}>{busy === k.kind ? "Running…" : "Run pass now"}</Button></td>
            </tr>
          ))}
        </tbody>
      </table>
      {d.kinds.some((k) => msg[k.kind]) && <div className="mt-2 space-y-1 text-xs text-zinc-400">{d.kinds.filter((k) => msg[k.kind]).map((k) => <div key={k.kind}><span className="text-zinc-500">{k.title}:</span> {msg[k.kind]}</div>)}</div>}
      {cur && (
        <div className="mt-4 rounded border border-zinc-800 p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <div className="text-sm text-zinc-200">{cur.title} <span className="text-xs text-zinc-500">· sections {cur.sections.join(", ")} · {cur.timeout_seconds} s timeout · script hash {cur.document.hash}{cur.deployed?.deployed_description ? <> · deployed: {cur.deployed.deployed_description}</> : null}</span></div>
            <div className="flex gap-2"><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => reset(cur.kind)} disabled={!cur.script.edited || busy === cur.kind}>Reset to default</Button><Button className="!px-2 !py-1 !text-xs" onClick={() => save(cur.kind)} disabled={busy === cur.kind || text === cur.script.effective}>Save script</Button></div>
          </div>
          <div className="mb-2 text-xs text-zinc-500">Create the document once, update it after a version change or an edit (the commands fetch the document from this advisor with your API token):</div>
          <div className="mb-1 flex items-start gap-2"><Code>{cur.document.create_command}</Code><CopyButton text={cur.document.create_command} /></div>
          <div className="mb-3 flex items-start gap-2"><Code>{cur.document.update_command}</Code><CopyButton text={cur.document.update_command} /></div>
          <textarea value={text} onChange={(e) => setText(e.target.value)} spellCheck={false} className="h-96 w-full rounded border border-zinc-700 bg-zinc-950 p-2 font-mono text-[11px] leading-snug text-zinc-200" />
          <div className="mt-1 text-xs text-zinc-600">{cur.script.lines} lines. Edits are refused when they stop looking like a read-only probe (rm, kill, systemctl, sudo, writes into system directories), lose the JSON line with <code>"probe":"aws-advisor/…"</code> and <code>"kind":"{cur.kind}"</code>{cur.takes_signals ? <>, or drop the <code>__SIGNALS__</code> placeholder</> : null}.</div>
        </div>
      )}
    </Card>
  );
}
