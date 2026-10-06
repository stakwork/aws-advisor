import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, currentScope, setScope, usd } from "../api";
import { Badge, Card, Stat, Td, Th } from "./ui";

/**
 * Overview › Accounts: the general view across every account the advisor is pointed at, one row each, with the
 * numbers a person wants before choosing one to look at (the sidebar's "Looking at" sets the scope every page
 * then uses): resources, last month's bill, what the last run and scan flagged, open
 * recommendations and alerts, the vulnerability verdicts that matter, probe coverage.
 */
export function AccountsOverview() {
  const [loaded, setRows] = useState<any[] | null>(null);
  const [err, setErr] = useState("");
  const navigate = useNavigate();
  useEffect(() => { api("/accounts/overview").then((d) => setRows(d.accounts)).catch((e) => setErr(e.message)); }, []);
  const scope = currentScope();
  if (err) return null;
  if (!loaded || loaded.length === 0) return null;
  // one account selected: its own family (the provider's accounts, so an AWS parent sees itself and its members); "all": every provider
  const all = loaded;
  const rows = scope === "all" ? all : all.filter((r) => r.provider === (all.find((x) => x.id === scope)?.provider ?? r.provider));
  const look = (id: string) => { setScope(id, rows?.find((r) => r.id === id)?.provider ?? null); navigate(0); };
  const tone = (v: number, warn: number, bad: number) => (v >= bad ? "text-red-300" : v >= warn ? "text-orange-300" : "text-zinc-300");
  return (
    <Card title={<span>Accounts <span className="font-normal text-zinc-500">· {rows.length}{all.length > rows.length ? ` of ${all.length}` : ""} across {new Set(rows.map((r) => r.provider)).size} provider{new Set(rows.map((r) => r.provider)).size === 1 ? "" : "s"}; {scope === "all" ? "every page shows all of them" : `the pages are scoped to ${scope}${all.length > rows.length ? "; pick \"all accounts\" for every provider" : ""}`} · <Link className="underline" to="/settings?tab=accounts">manage</Link></span></span>}>
      <table className="w-full border-collapse text-sm">
        <thead><tr><Th>Account</Th><Th>Resources</Th><Th className="text-right">Last full month</Th><Th className="text-right">Findings</Th><Th className="text-right">Security</Th><Th className="text-right">Vulnerable</Th><Th className="text-right">Open recs</Th><Th className="text-right">Alerts</Th><Th>Probes</Th><Th></Th></tr></thead>
        <tbody>
          {rows.map((a) => (
            <tr key={a.id} className={`border-t border-zinc-800 ${scope === a.id ? "bg-zinc-900/50" : ""}`}>
              <Td>
                <div className="text-zinc-100">{a.provider.toUpperCase()} · {a.name}{a.parent_id && <span className="ml-1 text-xs text-zinc-500">member</span>}{!a.enabled && <span className="ml-1 text-xs text-zinc-500">disabled</span>}</div>
                <div className="font-mono text-[11px] text-zinc-500">{a.id}</div>
                <div className="text-[11px] text-zinc-600">{a.access}{a.last_test && !a.last_test.ok ? <span className="text-red-300"> · {a.last_test.detail}</span> : null}</div>
              </Td>
              <Td className="text-xs text-zinc-300">
                {a.resources.ec2_running}/{a.resources.ec2_total} EC2 · {a.resources.rds} RDS · {a.resources.lambda} λ{a.resources.dynamodb ? ` · ${a.resources.dynamodb} tables` : ""} · {a.resources.elb} LB · {a.resources.s3} S3 · {a.resources.ebs_gb} GB EBS{a.resources.clusters ? ` · ${a.resources.clusters} clusters` : ""}
              </Td>
              <Td className="text-right">{a.spend.usd != null ? <span title={a.spend.month}>{usd(a.spend.usd)}</span> : <span className="text-zinc-600">—</span>}</Td>
              <Td className="text-right">{a.findings_alarms}</Td>
              <Td className="text-right"><span className={tone(a.security.critical, 1, 1)}>{a.security.critical} crit</span> <span className="text-zinc-500">· {a.security.high} high</span></Td>
              <Td className="text-right"><span className={tone(a.vulnerabilities.critical, 1, 1)}>{a.vulnerabilities.critical} crit</span> <span className="text-zinc-500">· {a.vulnerabilities.exposed} exposed · {a.vulnerabilities.boxes} boxes</span></Td>
              <Td className="text-right">{a.recommendations.open}{a.recommendations.saving_usd_month ? <span className="text-zinc-500"> · {usd(a.recommendations.saving_usd_month)}/mo</span> : null}</Td>
              <Td className="text-right"><span className={tone(a.alerts_open, 1, 5)}>{a.alerts_open}</span></Td>
              <Td className="text-xs text-zinc-400">{a.probes.ssm_online} online · {a.probes.probed_24h} probed today</Td>
              <Td className="text-right whitespace-nowrap">{scope === a.id ? <button type="button" className="text-xs text-zinc-400 hover:underline" onClick={() => look("all")}>all accounts</button> : <button type="button" className="text-xs text-sky-300 hover:underline" onClick={() => look(a.id)}>look at →</button>}</Td>
            </tr>
          ))}
        </tbody>
      </table>
    </Card>
  );
}


/** The general view across accounts: the month summed where it means the same thing, what is open, and what needs attention with the account each item is about. */
export function GeneralOverview() {
  const [d, setD] = useState<any>(null);
  useEffect(() => { api("/accounts/general").then(setD).catch(() => setD(null)); }, []);
  if (!d) return null;
  const m = d.month; const r = d.recommendations;
  // each provider's parts of the month in its own words (a projection, a period estimate, stores at plan)
  const monthHint = (m.parts || []).filter((p: any) => p.usd != null).map((p: any) => `${p.label} ${usd(p.usd)}`).join(" · ");
  const tone = (l: string) => (l === "alarm" ? "text-red-300" : l === "warning" ? "text-orange-300" : "text-zinc-400");
  const open = (a: any) => { setScope(a.account, a.provider); window.location.assign(a.link); };
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <Stat label="This month, all providers" value={m.total_usd != null ? `~${usd(m.total_usd)}` : "—"} hint={monthHint || "no spend read yet"} />
        <Stat label="Open recommendations" value={r.open} hint={`${usd(r.saving_usd_month)}/mo claimed · ${Object.entries(r.by_provider).map(([p, b]: any) => `${p.toUpperCase()} ${b.open}`).join(" · ")}`} />
        <Stat label="Alarms" value={<span className={d.counts.alarms ? "text-orange-300" : "text-emerald-300"}>{d.counts.alarms}</span>} hint={`alarm findings of each provider's latest run · ${d.counts.alerts_open} open alerts`} />
        <Stat label="Security" value={<span className={d.counts.security_critical ? "text-red-300" : d.counts.security_high ? "text-orange-300" : "text-emerald-300"}>{d.counts.security_critical} / {d.counts.security_high}</span>} hint="critical / high across accounts" />
        <Stat label="Accounts" value={d.accounts} hint={d.providers.map((p: string) => p.toUpperCase()).join(" · ")} />
      </div>
      <Card title={<span>Needs attention <span className="font-normal text-zinc-500">· across every account; each line says whose</span></span>}>
        {!d.attention.length ? <div className="text-sm text-zinc-500">Nothing open: no alarm findings, no unacknowledged alerts, nothing in any provider's attention list.</div> : (
          <ul className="space-y-1 text-sm">
            {d.attention.map((a: any, i: number) => (
              <li key={i} className="flex items-start gap-2">
                <Badge>{a.level}</Badge>
                <span className="shrink-0 text-xs text-zinc-500">{a.provider.toUpperCase()} · {a.account_name || a.account}</span>
                <span className={tone(a.level)}>{a.what}</span>
                {a.link && <button type="button" className="text-xs text-sky-300 hover:underline" onClick={() => open(a)}>open</button>}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
