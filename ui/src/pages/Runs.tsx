import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, when } from "../api";
import { Badge, Button, Empty, Td, Th } from "../components/ui";

export default function Runs() {
  const [runs, setRuns] = useState<any[]>([]);
  const [err, setErr] = useState("");
  const nav = useNavigate();
  const load = () => api("/runs").then(setRuns).catch((e) => setErr(e.message));
  useEffect(() => { load(); const t = setInterval(load, 5000); return () => clearInterval(t); }, []);
  const start = async () => { try { const r = await api("/runs", { method: "POST" }); nav(`/runs/${r.id}`); } catch (e: any) { setErr(e.message); } };
  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold text-zinc-100">Runs</h1>
        <Button onClick={start} disabled={runs.some((r) => r.status === "running")}>Start run</Button>
      </div>
      {err && <div className="text-sm text-red-300">{err}</div>}
      {runs.length === 0 ? <Empty>No runs yet.</Empty> : (
        <table className="w-full border-collapse overflow-hidden rounded-lg border border-zinc-800">
          <thead className="bg-zinc-900"><tr><Th>#</Th><Th>Started</Th><Th>Finished</Th><Th>Status</Th><Th>Account</Th><Th className="text-right">Findings</Th><Th className="text-right">Open recs</Th><Th /></tr></thead>
          <tbody>
            {runs.map((r) => (
              <tr key={r.id} className="border-t border-zinc-800 hover:bg-zinc-900/60">
                <Td>{r.id}</Td><Td>{when(r.started_at)}</Td><Td>{when(r.finished_at)}</Td>
                <Td><Badge>{r.status}</Badge>{r.error && <div className="mt-1 max-w-md truncate text-xs text-red-300">{r.error}</div>}</Td>
                <Td>{r.account_id || "—"}</Td><Td className="text-right">{r.findings_count}</Td><Td className="text-right">{r.recommendations_count}</Td>
                <Td><Link className="text-sky-300 hover:underline" to={`/runs/${r.id}`}>open</Link></Td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
