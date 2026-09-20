import { useEffect, useState } from "react";
import { api } from "../api";
import { Badge, Button, Card } from "./ui";

type Setting = { key: string; env: string; kind: string; group: string; label: string; help: string; options?: string[]; value: string; source: "setting" | "env" | "default"; default: string; env_set: boolean };

/** Everything that used to be an environment variable and is not a bootstrap secret: saved here, it wins over the env. */
export function RuntimeSettings() {
  const [rows, setRows] = useState<Setting[] | null>(null);
  const [edit, setEdit] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState<string>("");
  const [err, setErr] = useState<Record<string, string>>({});
  const load = () => api("/settings/runtime").then((d) => setRows(d.settings)).catch(() => setRows([]));
  useEffect(() => { load(); }, []);
  const save = async (key: string, value: string | null) => {
    setBusy(key); setErr((e) => ({ ...e, [key]: "" }));
    try { await api("/settings/runtime", { method: "PUT", body: JSON.stringify({ key, value }) }); setEdit((e) => { const n = { ...e }; delete n[key]; return n; }); await load(); }
    catch (e: any) { setErr((x) => ({ ...x, [key]: e.message })); } finally { setBusy(""); }
  };
  if (!rows) return <Card title="Settings"><div className="text-sm text-zinc-500">Loading…</div></Card>;
  const groups = [...new Set(rows.map((r) => r.group))];
  return (
    <Card title={<span>Settings <span className="font-normal text-zinc-500">· saved here they win over the environment; reset to fall back to it</span></span>}>
      <div className="space-y-4">
        {groups.map((g) => (
          <div key={g}>
            <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">{g}</div>
            <table className="w-full border-collapse text-sm">
              <tbody>{rows.filter((r) => r.group === g).map((r) => {
                const editing = r.key in edit;
                const val = editing ? edit[r.key] : r.value;
                const input = r.kind === "enum" ? (
                  <select value={val} onChange={(e) => setEdit((x) => ({ ...x, [r.key]: e.target.value }))}>{r.options!.map((o) => <option key={o} value={o}>{o}</option>)}</select>
                ) : r.kind === "bool" ? (
                  <select value={val === "true" ? "true" : "false"} onChange={(e) => setEdit((x) => ({ ...x, [r.key]: e.target.value }))}><option value="false">off</option><option value="true">on</option></select>
                ) : (
                  <input className="w-full font-mono text-xs" type={r.kind === "secret" && !editing ? "text" : r.kind === "secret" ? "password" : "text"} value={val} placeholder={r.kind === "secret" ? "paste to replace" : r.default || "empty"} autoComplete="off"
                    onFocus={() => { if (r.kind === "secret" && !editing) setEdit((x) => ({ ...x, [r.key]: "" })); }}
                    onChange={(e) => setEdit((x) => ({ ...x, [r.key]: e.target.value }))} />
                );
                return (
                  <tr key={r.key} className="border-t border-zinc-800/70 align-top">
                    <td className="w-56 py-1.5 pr-3"><div className="text-zinc-200">{r.label}</div><div className="font-mono text-[10px] text-zinc-600">{r.env}</div></td>
                    <td className="py-1.5 pr-3">{input}{r.help && <div className="mt-0.5 text-xs text-zinc-500">{r.help}</div>}{err[r.key] && <div className="mt-0.5 text-xs text-red-300">{err[r.key]}</div>}</td>
                    <td className="w-40 py-1.5 text-right whitespace-nowrap">
                      {editing ? <><Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => save(r.key, edit[r.key])} disabled={busy === r.key}>Save</Button> <button className="text-xs text-zinc-500" onClick={() => setEdit((x) => { const n = { ...x }; delete n[r.key]; return n; })}>cancel</button></>
                        : <><Badge>{r.source === "setting" ? "saved" : r.source === "env" ? "env" : "default"}</Badge>{r.source === "setting" && <button className="ml-2 text-xs text-zinc-500 hover:text-zinc-300" title={r.env_set ? `back to the environment value` : "back to the default"} onClick={() => save(r.key, null)}>reset</button>}</>}
                    </td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>
        ))}
        <div className="text-xs text-zinc-500">Bootstrap settings stay in the environment: port and bind address, data and config paths, the Steampipe connection, the three shared secrets (API, MCP, webhook), the public URL and the probe document. A cron change takes effect at once; a Neo4j or Jev change on the next call.</div>
      </div>
    </Card>
  );
}
