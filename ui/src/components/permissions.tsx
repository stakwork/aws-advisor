import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Badge, Button, Card, Code, CopyButton, Td, Th } from "./ui";

/**
 * Settings > Permissions: what the advisor's credentials should be, the capability check, the missing
 * actions seen anywhere in the app and the IAM policy JSON that fixes them (GET/POST /api/permissions).
 */

export function PermissionsCard() {
  const [p, setP] = useState<any>(null);
  const [check, setCheck] = useState<any>(null);
  const [checking, setChecking] = useState(false);
  const [instanceId, setInstanceId] = useState("");
  const [err, setErr] = useState("");
  const [showFull, setShowFull] = useState(false);

  const load = () => api("/permissions").then((d) => { setP(d); if (d.last_check) setCheck(d.last_check); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);

  const run = async () => {
    setChecking(true); setErr("");
    try { setCheck(await api("/permissions/check", { method: "POST", body: JSON.stringify({ instance_id: instanceId.trim() || undefined }) })); load(); }
    catch (e: any) { setErr(e.message); }
    finally { setChecking(false); }
  };

  if (!p) return <Card title="Permissions"><div className="text-sm text-zinc-500">{err || "Loading…"}</div></Card>;
  const issues: any[] = p.issues || [];
  const counts = (check?.results || []).reduce((acc: Record<string, number>, r: any) => ({ ...acc, [r.status]: (acc[r.status] || 0) + 1 }), {} as Record<string, number>);
  const fixPolicy = JSON.stringify(p.policy, null, 2);
  const fullPolicy = JSON.stringify(p.recommended_policy, null, 2);
  const doc = p.probe_document;

  return (
    <Card title="Permissions">
      <p className="mb-3 text-sm text-zinc-400">
        Use a dedicated IAM user or role for the advisor, never personal credentials, with the read-only policy below plus the SSM probe statements.
        The advisor only reads; the credentials must not be able to change anything, so a misuse cannot destroy anything either.
        The complete policy, the safety model and the four CLI commands that create the user are in the README, section <a className="text-sky-300 hover:underline" href="/readme" target="_blank" rel="noreferrer">IAM permissions</a>.
        Every log line and API error caused by a missing permission names the action and points here; the policy block at the bottom merges everything seen so far.
      </p>

      <div className="mb-4 rounded border border-zinc-800 p-3">
        <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">SSM probe document</div>
        <p className="text-sm text-zinc-400">
          The probe runs through <code className="text-zinc-200">{doc?.name}</code>{doc?.custom
            ? <>, a custom document that embeds the probe script (version <code className="text-zinc-200">{doc.version}</code>), so <code className="text-zinc-200">ssm:SendCommand</code> is granted on that document only and the credentials can never run any other shell on the fleet.</>
            : <>, the stock document that runs any shell script, so IAM alone cannot make the probe read-only. Recommended: create the custom document below and set <code className="text-zinc-200">PROBE_DOCUMENT=AwsAdvisorProbe</code>; then the SSM statement is scoped to it.</>}
          {" "}Create it (once) and update it when the probe version changes:
        </p>
        <div className="mt-2 flex items-start gap-2"><Code>{doc?.create_command || ""}</Code><CopyButton text={doc?.create_command || ""} /></div>
        <div className="mt-2 flex items-start gap-2"><Code>{doc?.update_command || ""}</Code><CopyButton text={doc?.update_command || ""} /></div>
      </div>

      <div className="mb-2 flex flex-wrap items-center gap-2">
        <Button type="button" onClick={run} disabled={checking}>{checking ? "Checking…" : "Check permissions"}</Button>
        <input className="w-64" placeholder="instance id for a real probe (optional)" value={instanceId} onChange={(e) => setInstanceId(e.target.value)} />
        {check && <span className="text-xs text-zinc-500">last check {when(check.checked_at)} · account {check.account_id || "?"} · region {check.region} · {counts.ok || 0} ok, {counts.missing || 0} missing, {counts.error || 0} errors, {counts.skipped || 0} skipped · {check.took_ms} ms</span>}
      </div>
      {err && <div className="mb-2 text-sm text-red-300">{err}</div>}
      {check?.credentials_error && <div className="mb-2 text-sm text-amber-300">{check.credentials_error}</div>}
      {check && (
        <div className="mb-4 max-h-96 overflow-auto rounded border border-zinc-800">
          <table className="w-full table-fixed">
            <thead><tr><Th className="w-48">Capability</Th><Th className="w-44">Actions</Th><Th className="w-20">Status</Th><Th>Detail</Th></tr></thead>
            <tbody>
              {check.results.map((r: any) => (
                <tr key={r.id} className="border-t border-zinc-800">
                  <Td>{r.label}<div className="text-xs text-zinc-500">{r.group}</div></Td>
                  <Td className="break-words font-mono text-xs">{r.actions.join(", ")}</Td>
                  <Td><Badge>{r.status}</Badge></Td>
                  <Td className="break-words text-xs text-zinc-400">{r.message || (r.status === "ok" ? `${r.took_ms} ms` : "")}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Missing permissions seen anywhere in the app</div>
      {issues.length === 0 ? <div className="mb-4 text-sm text-zinc-500">None recorded. Run a check, a collection, the watcher or a probe: any denial lands here with the action it needs.</div> : (
        <div className="mb-4 overflow-auto rounded border border-zinc-800">
          <table className="w-full table-fixed">
            <thead><tr><Th className="w-48">Action</Th><Th className="w-40">Seen</Th><Th className="w-48">Where</Th><Th>Last message</Th></tr></thead>
            <tbody>
              {issues.map((i: any) => (
                <tr key={i.action} className="border-t border-zinc-800">
                  <Td className="break-words font-mono text-xs">{i.action}</Td>
                  <Td className="text-xs text-zinc-400">{i.count}x · first {when(i.first_seen)} · last {when(i.last_seen)}</Td>
                  <Td className="break-words text-xs text-zinc-400">{(i.contexts || []).slice(-5).join("; ")}</Td>
                  <Td className="break-words text-xs text-zinc-500"><span title={i.last_message || ""}>{String(i.last_message || "").slice(0, 160)}</span></Td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="mb-1 flex items-center justify-between">
        <div className="text-xs uppercase tracking-wide text-zinc-500">{issues.length && !showFull ? "IAM policy that fixes the missing permissions" : "Complete read-only policy the advisor needs"}</div>
        <div className="flex gap-2">
          {issues.length > 0 && <Button type="button" variant="ghost" onClick={() => setShowFull((v) => !v)}>{showFull ? "Show the fix only" : "Show the full policy"}</Button>}
          <CopyButton text={issues.length && !showFull ? fixPolicy : fullPolicy} label="Copy JSON" />
        </div>
      </div>
      <Code>{issues.length && !showFull ? fixPolicy : fullPolicy}</Code>
      <p className="mt-2 text-xs text-zinc-500">Attach it with <code className="text-zinc-300">aws iam put-user-policy --user-name aws-advisor --policy-name aws-advisor --policy-document file://policy.json</code> (or the role equivalent). The AWS managed <code className="text-zinc-300">ReadOnlyAccess</code> plus the Cost Explorer, pricing and SSM statements is an acceptable shortcut.</p>
    </Card>
  );
}
