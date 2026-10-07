import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Button, Card, Empty, Td, Th } from "./ui";

/**
 * Settings › Accounts › Local machines: the laptops, desktops and on-prem servers that run part of the stack outside
 * any cloud account, each with what runs on it. Declared, not collected: the graph draws each as a box hosting its
 * operating system, with a deployment per entry running on it (src/adapters/local/index.ts).
 */

type Deployment = { name: string; kind: string; url: string | null; repo: string | null; environment: string | null };
type Machine = { id?: string; name: string; kind: string; platform: string | null; os: string | null; arch: string | null; kernel: string | null; hostname: string | null; owner: string | null; notes: string | null; deployments: Deployment[]; updated_at?: string };
type Data = { machines: Machine[]; this_machine: Machine; kinds: string[]; platforms: string[]; workload_kinds: string[] };

const blank = (): Machine => ({ name: "", kind: "laptop", platform: null, os: null, arch: null, kernel: null, hostname: null, owner: null, notes: null, deployments: [] });

export function LocalMachines({ onChange }: { configured?: boolean; onChange?: () => void }) {
  const [d, setD] = useState<Data | null>(null); const [form, setForm] = useState<Machine | null>(null);
  const [busy, setBusy] = useState(false); const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const load = () => api("/local/machines").then(setD).catch((e) => setMsg({ ok: false, text: e.message }));
  useEffect(() => { load(); }, []);
  const set = (p: Partial<Machine>) => setForm((f) => (f ? { ...f, ...p } : f));
  const setDep = (i: number, p: Partial<Deployment>) => setForm((f) => (f ? { ...f, deployments: f.deployments.map((x, j) => (j === i ? { ...x, ...p } : x)) } : f));
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); if (!form) return; setBusy(true); setMsg(null);
    try { const r = await api("/providers/local/accounts", { method: "POST", body: JSON.stringify(form) }); setMsg({ ok: true, text: `${r.machine.name}: ${r.note}` }); setForm(null); load(); onChange?.(); }
    catch (err: any) { setMsg({ ok: false, text: err.message }); } finally { setBusy(false); }
  };
  const remove = async (m: Machine) => {
    setBusy(true); setMsg(null);
    try { await api(`/providers/local/accounts/${encodeURIComponent(m.id!)}`, { method: "DELETE" }); setMsg({ ok: true, text: `${m.name} removed, with its nodes in the graph` }); load(); onChange?.(); }
    catch (err: any) { setMsg({ ok: false, text: err.message }); } finally { setBusy(false); }
  };
  if (!d) return msg ? <div className="text-sm text-red-300">{msg.text}</div> : null;
  return (
    <div className="space-y-4">
      <Card title="Local machines">
        <p className="mb-3 text-sm text-zinc-400">Machines outside any cloud account that run part of the stack: a laptop running the app in docker compose, an office server. The advisor cannot reach them, so each is declared here with what it runs; the graph draws the machine (a box), its operating system and a deployment per entry running on it, next to the cloud ones.</p>
        {d.machines.length === 0 ? <Empty>No machine yet.</Empty> : (
          <table className="mb-3 w-full text-sm">
            <thead><tr><Th>Machine</Th><Th>Kind</Th><Th>System</Th><Th>Runs</Th><Th>Owner</Th><Th>Updated</Th><Th></Th></tr></thead>
            <tbody>
              {d.machines.map((m) => (
                <tr key={m.id} className="border-t border-zinc-800/60">
                  <Td><div className="text-zinc-100">{m.name}</div>{m.hostname && <div className="font-mono text-[11px] text-zinc-500">{m.hostname}</div>}</Td>
                  <Td>{m.kind}</Td>
                  <Td className="text-xs text-zinc-400">{[m.os ?? m.platform, m.arch].filter(Boolean).join(" · ") || "—"}{m.kernel && <div className="text-[11px] text-zinc-500">kernel {m.kernel}</div>}</Td>
                  <Td className="text-xs text-zinc-400">{m.deployments.length ? m.deployments.map((x) => <div key={x.name}>{x.name} <span className="text-zinc-500">({x.kind.replace("_", " ")}{x.url ? `, ${x.url}` : ""})</span></div>) : "—"}</Td>
                  <Td className="text-xs text-zinc-400">{m.owner ?? "—"}</Td>
                  <Td className="text-xs text-zinc-500">{m.updated_at ? when(m.updated_at) : ""}</Td>
                  <Td className="whitespace-nowrap text-right">
                    <Button variant="ghost" onClick={() => setForm({ ...m, deployments: m.deployments.map((x) => ({ ...x })) })} disabled={busy}>Edit</Button>
                    <Button variant="danger" onClick={() => remove(m)} disabled={busy}>Remove</Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
        {!form && (
          <div className="flex items-center gap-2">
            <Button variant="ghost" onClick={() => setForm(blank())}>Add a machine</Button>
            <Button variant="ghost" onClick={() => setForm({ ...d.this_machine, deployments: [] })} title="the name, platform, architecture and kernel of the machine the advisor runs on">Add this machine ({d.this_machine.name})</Button>
          </div>
        )}
        {msg && <div className={`mt-2 text-sm ${msg.ok ? "text-emerald-300" : "text-red-300"}`}>{msg.text}</div>}
      </Card>
      {form && (
        <Card title={form.id ? `Edit ${form.name}` : "Add a machine"}>
          <form onSubmit={save} className="grid gap-3">
            <div className="grid gap-3 md:grid-cols-3">
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Name</span><input value={form.name} onChange={(e) => set({ name: e.target.value })} required disabled={Boolean(form.id)} /></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Kind</span><select value={form.kind} onChange={(e) => set({ kind: e.target.value })}>{d.kinds.map((k) => <option key={k} value={k}>{k}</option>)}</select></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Platform</span><select value={form.platform ?? ""} onChange={(e) => set({ platform: e.target.value || null })}><option value="">unknown</option>{d.platforms.map((k) => <option key={k} value={k}>{k}</option>)}</select></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Operating system</span><input value={form.os ?? ""} onChange={(e) => set({ os: e.target.value })} placeholder="macOS 26, Ubuntu 24.04" /></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Architecture</span><input value={form.arch ?? ""} onChange={(e) => set({ arch: e.target.value })} placeholder="arm64, x86_64" /></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Kernel (optional)</span><input value={form.kernel ?? ""} onChange={(e) => set({ kernel: e.target.value })} /></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Hostname (optional)</span><input value={form.hostname ?? ""} onChange={(e) => set({ hostname: e.target.value })} /></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Owner (optional)</span><input value={form.owner ?? ""} onChange={(e) => set({ owner: e.target.value })} placeholder="who looks after it" /></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Notes (optional)</span><input value={form.notes ?? ""} onChange={(e) => set({ notes: e.target.value })} /></label>
            </div>
            <div className="grid gap-2">
              <div className="text-sm text-zinc-400">What runs on it</div>
              {form.deployments.map((x, i) => (
                <div key={i} className="grid gap-2 md:grid-cols-[1fr_9rem_1fr_1fr_auto]">
                  <input value={x.name} onChange={(e) => setDep(i, { name: e.target.value })} placeholder="name (the compose project, the service)" required />
                  <select value={x.kind} onChange={(e) => setDep(i, { kind: e.target.value })}>{d.workload_kinds.map((k) => <option key={k} value={k}>{k.replace("_", " ")}</option>)}</select>
                  <input value={x.url ?? ""} onChange={(e) => setDep(i, { url: e.target.value })} placeholder="URL (optional)" />
                  <input value={x.repo ?? ""} onChange={(e) => setDep(i, { repo: e.target.value })} placeholder="repository (optional)" />
                  <Button type="button" variant="ghost" onClick={() => set({ deployments: form.deployments.filter((_, j) => j !== i) })}>Remove</Button>
                </div>
              ))}
              <div><Button type="button" variant="ghost" onClick={() => set({ deployments: [...form.deployments, { name: "", kind: "compose", url: null, repo: null, environment: null }] })}>Add what it runs</Button></div>
            </div>
            <div className="flex items-center gap-2">
              <Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save"}</Button>
              <Button type="button" variant="ghost" onClick={() => setForm(null)} disabled={busy}>Cancel</Button>
            </div>
          </form>
        </Card>
      )}
    </div>
  );
}
