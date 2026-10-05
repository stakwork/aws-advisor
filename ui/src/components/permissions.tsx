import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Badge, Button, Card, Code, CopyButton, Td, Th } from "./ui";
import { RunAsMe } from "./consent";

/**
 * Settings > Permissions: what the advisor's credentials should be, the capability check, the missing
 * actions seen anywhere in the app and the IAM policy JSON that fixes them (GET/POST /api/permissions).
 */

export function PermissionsCard() {
  const [p, setP] = useState<any>(null);
  const [check, setCheck] = useState<any>(null);
  const [checking, setChecking] = useState(false);
  const [instanceId, setInstanceId] = useState("");
  // which account the check runs for: "" is the parent, else a member's id (src/accounts.ts); each keeps its own last result
  const [account, setAccount] = useState("");
  const [err, setErr] = useState("");
  const [showFull, setShowFull] = useState(false);
  const [proposing, setProposing] = useState(false);
  const [proposeMsg, setProposeMsg] = useState<{ text: string; err?: boolean } | null>(null);
  const propose = async (fixOnly: boolean) => {
    setProposing(true); setProposeMsg(null);
    try {
      const r = await api("/permissions/propose", { method: "POST", body: JSON.stringify({ fix_only: fixOnly, by: "the Permissions page" }) });
      const n = (st: string) => r.results.filter((x: any) => x.status === st).length;
      setProposeMsg({ text: `${n("proposed")} row${n("proposed") === 1 ? "" : "s"} proposed${n("up_to_date") ? `, ${n("up_to_date")} account${n("up_to_date") === 1 ? "" : "s"} already up to date` : ""}${n("refused") ? `, ${n("refused")} refused` : ""}${n("error") ? `, ${n("error")} could not be read` : ""}${r.results.filter((x: any) => x.status === "refused" || x.status === "error").map((x: any) => ` · ${x.name}: ${x.detail}`).join("")}`, err: n("refused") + n("error") > 0 && n("proposed") === 0 });
      load();
    } catch (e: any) { setProposeMsg({ text: e.message, err: true }); } finally { setProposing(false); }
  };

  const load = (acct = account) => api(`/permissions${acct ? `?account=${acct}` : ""}`).then((d) => { setP(d); setCheck(d.last_check || null); }).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, [account]);

  const dismiss = async (action: string) => { try { await api(`/permissions/issues/${encodeURIComponent(action)}`, { method: "DELETE" }); load(); } catch { /* shown on the next load */ } };
  const run = async () => {
    setChecking(true); setErr("");
    try { setCheck(await api("/permissions/check", { method: "POST", body: JSON.stringify({ instance_id: instanceId.trim() || undefined, account_id: account || undefined }) })); load(); }
    catch (e: any) { setErr(e.message); }
    finally { setChecking(false); }
  };

  if (!p) return <Card title="Permissions"><div className="text-sm text-zinc-500">{err || "Loading…"}</div></Card>;
  // a member selected above narrows the list to the denials seen there (and those no account was named for)
  const issues: any[] = (p.issues || []).filter((i: any) => !account || !(i.accounts || []).length || i.accounts.includes(account));
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
        <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">SSM probe documents</div>
        <p className="text-sm text-zinc-400">
          The probes run through custom documents named <code className="text-zinc-200">{doc?.name?.replace(/-host$/, "")}-&lt;kind&gt;</code>, one per probe (host, docker, apps, software), each embedding its read-only script, so <code className="text-zinc-200">ssm:SendCommand</code> is granted on those documents only and the credentials can never run anything else on the fleet.
          {" "}Create them once and update them when a probe changes; Settings › Probes shows each one's status, script and commands.
        </p>
        {(p.probe_documents || []).map((x: any) => (
          <div key={x.kind} className="mt-2 text-xs"><span className="font-mono text-zinc-300">{x.name}</span> <span className="text-zinc-500">{x.kind} {x.version} · {x.hash}{x.edited ? " · edited" : ""}</span>
            <div className="mt-1 flex items-start gap-2"><Code>{x.create_command}</Code><CopyButton text={x.create_command} /></div>
          </div>
        ))}
      </div>

      <div className="mb-2 flex flex-wrap items-center gap-2">
        {(p.accounts || []).length > 1 && (
          <select className="text-sm" value={account} onChange={(e) => setAccount(e.target.value)} title="which account to check: the parent through its own credentials, a member through its read role and its own Steampipe connection">
            {(p.accounts || []).map((a: any) => (
              <option key={a.account_id} value={a.is_parent ? "" : a.account_id}>{a.is_parent ? `parent ${a.account_id}` : `${a.name} ${a.account_id}`}{a.checked_at ? ` · ${a.missing} missing, ${a.errors} errors` : " · not checked yet"}</option>
            ))}
          </select>
        )}
        <Button type="button" onClick={run} disabled={checking}>{checking ? "Checking…" : `Check permissions${account ? " of this member" : ""}`}</Button>
        <input className="w-64" placeholder="instance id for a real probe (optional)" value={instanceId} onChange={(e) => setInstanceId(e.target.value)} />
        {check && <span className="text-xs text-zinc-500">last check {when(check.checked_at)} · {check.target && !check.target.is_parent ? `member ${check.target.name} · ` : ""}account {check.account_id || "?"}{check.target?.schema ? ` via ${check.target.schema}` : ""} · region {check.region} · {counts.ok || 0} ok, {counts.missing || 0} missing, {counts.error || 0} errors, {counts.skipped || 0} skipped · {check.took_ms} ms</span>}
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

      <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Missing permissions seen anywhere in the app{account ? " · this member and unattributed" : ""}</div>
      {check?.reverified?.length > 0 && <ul className="mb-2 space-y-0.5 text-xs">{check.reverified.map((r: any) => <li key={r.action}><span className={r.status === "ok" ? "text-emerald-300" : r.status === "missing" ? "text-red-300" : "text-amber-300"}>{r.status}</span> <span className="font-mono text-zinc-300">{r.action}</span> <span className="text-zinc-500">{r.message}</span></li>)}</ul>}
      {issues.length === 0 ? <div className="mb-4 text-sm text-zinc-500">None recorded. Run a check, a collection, the watcher or a probe: any denial lands here with the action it needs, and leaves once the same call works again or a check proves it.</div> : (
        <div className="mb-4 overflow-auto rounded border border-zinc-800">
          <table className="w-full table-fixed">
            <thead><tr><Th className="w-48">Action</Th><Th className="w-40">Seen</Th><Th className="w-48">Where</Th><Th>Last message</Th><Th className="w-20"></Th></tr></thead>
            <tbody>
              {issues.map((i: any) => (
                <tr key={i.action} className="border-t border-zinc-800">
                  <Td className="break-words font-mono text-xs">{i.action}</Td>
                  <Td className="text-xs text-zinc-400">{i.count}x · first {when(i.first_seen)} · last {when(i.last_seen)}</Td>
                  <Td className="break-words text-xs text-zinc-400">{(i.accounts || []).length ? <div className="text-zinc-300">account {i.accounts.map((a: string) => (p.accounts || []).find((x: any) => x.account_id === a)?.name || a).join(", ")}</div> : null}{(i.contexts || []).slice(-5).join("; ")}</Td>
                  <Td className="break-words text-xs text-zinc-500"><span title={i.last_message || ""}>{String(i.last_message || "").slice(0, 160)}</span></Td>
                  <Td className="text-right text-xs"><button type="button" className="text-zinc-500 hover:text-zinc-200" title="Remove this entry; it comes back if the call is denied again" onClick={() => dismiss(i.action)}>dismiss</button></Td>
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
      <p className="mt-2 text-xs text-zinc-500">This goes inline next to the AWS managed <code className="text-zinc-300">ViewOnlyAccess</code>, which covers every list and describe call (and new ones as AWS adds them) without reading any data; the document above holds only what that policy leaves out. Put it on the role with <code className="text-zinc-300">aws iam put-role-policy --role-name aws-advisor-read --policy-name aws-advisor-read --policy-document file://policy.json</code> and <code className="text-zinc-300">aws iam attach-role-policy --role-name aws-advisor-read --policy-arn {p.managed_policies?.[0] ?? "arn:aws:iam::aws:policy/ViewOnlyAccess"}</code>.</p>

      <div className="mt-4 rounded border border-zinc-800 p-3">
        <div className="mb-1 text-xs uppercase tracking-wide text-zinc-500">Apply it with your own credentials</div>
        <p className="text-sm text-zinc-400">
          The advisor's identities hold no IAM write right, so they can never widen their own permissions. Instead, one ledger row per account whose read policy lacks something is proposed here
          (the parent's read identity, each member's read role), and you apply each with temporary credentials of your own, previewed first: a single <code className="text-zinc-200">PutRolePolicy</code> of the whole document inline on the role,
          under the setup script's policy name, plus <code className="text-zinc-200">AttachRolePolicy</code> of ViewOnlyAccess when it is not attached yet. The row records who did it; Revert puts the previous document back and detaches ViewOnlyAccess if the row attached it.
        </p>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Button type="button" onClick={() => propose(false)} disabled={proposing}>{proposing ? "Reading the policies…" : "Propose the full policy"}</Button>
          {issues.length > 0 && <Button type="button" variant="ghost" onClick={() => propose(true)} disabled={proposing}>Propose the fix only</Button>}
          {proposeMsg && <span className={`text-xs ${proposeMsg.err ? "text-red-300" : "text-zinc-400"}`}>{proposeMsg.text}</span>}
        </div>
        {(p.policy_rows || []).length > 0 && (
          <table className="mt-3 w-full table-fixed">
            <thead><tr><Th className="w-56">Account · identity</Th><Th className="w-24">Status</Th><Th>What</Th><Th className="w-44">Run</Th></tr></thead>
            <tbody>
              {(p.policy_rows || []).map((r: any) => (
                <tr key={r.id} className="border-t border-zinc-800 align-top">
                  <Td className="text-xs"><div className="text-zinc-200">{r.resource_name || r.resource}</div><div className="text-zinc-500">{r.account_id || p.account_id || "parent"}{r.facts?.fix_only ? " · fix only" : " · full policy"}</div></Td>
                  <Td><Badge>{r.status}</Badge></Td>
                  <Td className="break-words text-xs text-zinc-400">{r.title}{(r.facts?.missing || []).length ? <div className="mt-0.5 font-mono text-[11px] text-zinc-500">{(r.facts.missing as string[]).slice(0, 10).join(", ")}{r.facts.missing.length > 10 ? ` +${r.facts.missing.length - 10}` : ""}</div> : null}{r.error ? <div className="text-red-300">{r.error}</div> : r.result ? <div className="text-zinc-500">{r.result}</div> : null}</Td>
                  <Td className="text-xs">{r.status === "proposed" || r.status === "failed" ? <RunAsMe actionId={r.id} onDone={() => load()} /> : r.status === "applied" || r.status === "verified" ? <RunAsMe actionId={r.id} verb="revert" onDone={() => load()} /> : <span className="text-zinc-600">—</span>}</Td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </Card>
  );
}
