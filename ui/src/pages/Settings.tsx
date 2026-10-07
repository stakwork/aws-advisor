import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api, when } from "../api";
import { Button, Card, Empty } from "../components/ui";
import { PermissionsCard } from "../components/permissions";
import { SetupWizard } from "../components/setup";
import { AgentPrompts } from "../components/prompts";
import { RuntimeSettings } from "../components/runtimeSettings";
import { ProbesCard } from "../components/probes";
import { ProviderView } from "../views";

type Mode = "keys" | "profile" | "chain";

/**
 * Settings is organised around the accounts the advisor is pointed at (docs/cloud-ontology.md §8a): the Accounts
 * tab lists every configured account with its provider, and everything bound to a provider (credentials, what the
 * identity may read, the probes and their documents, the benchmarks, member accounts) lives under that account.
 * Only what is provider-neutral stays at the top level: the global schedules, the executor, the agent and Jev, the
 * notifications, quotas and tags. Tabs and the selected account are in the URL, so other pages can link to them.
 */
const TABS = ["accounts", "schedules", "auto-actions", "agent", "notifications", "other"] as const;
type Tab = (typeof TABS)[number];
const TAB_LABEL: Record<Tab, string> = { accounts: "Accounts", schedules: "Schedules", "auto-actions": "Auto-actions", agent: "Agent & Jev", notifications: "Notifications", other: "Other" };
const TAB_HINT: Record<Tab, string> = {
  accounts: "every account the advisor is pointed at, each with its provider's own setup: credentials, permissions, probes, benchmarks, members",
  schedules: "the provider-neutral jobs: collection, security scan, watcher, spend, review, executor; the probe passes are on the AWS account's Probes section",
  "auto-actions": "the executor: mode, roles, floors, caps and kill switch",
  agent: "repo2graph, Jev, the prompts and the graph mirror",
  notifications: "the Sphinx bot: where alerts and threads go",
  other: "quotas, required tags, export and import of the settings, and the dev token",
};
/** The sections of an AWS account: what the AWS adapter brings. Another provider will declare its own list. */
const AWS_SECTIONS = ["access", "permissions", "probes", "benchmarks", "members"] as const;
type AwsSection = (typeof AWS_SECTIONS)[number];
const AWS_SECTION_LABEL: Record<AwsSection, string> = { access: "Access", permissions: "Permissions", probes: "Probes", benchmarks: "Benchmarks", members: "Member accounts" };
const PROBE_CRONS = ["probeCron", "probeDockerCron", "probeAppsCron", "probeSoftwareCron"];
type ProviderInfo = { id: string; label: string; boundary: string; credentials: string; children: string; available: boolean; configured: boolean; sections: { id: string; label: string }[]; ui: { settings: { id: string; label: string; view: string }[] } | null };
/** A provider whose Settings sections are this page's own (the AWS adapter declares aws.* views: credentials, permissions, probes, benchmarks, members); every other provider's sections are its views in ui/src/views.tsx. */
const BUILTIN_VIEW = /^aws\./;


const MODES: { id: Mode; label: string; hint: string }[] = [
  { id: "keys", label: "Access keys", hint: "a dedicated IAM user's key, or temporary keys with a session token" },
  { id: "profile", label: "AWS profile", hint: "a profile from ~/.aws/config: SSO, keys, anything the CLI can use" },
  { id: "chain", label: "Instance / default chain", hint: "no secrets in the app: environment, instance profile or container credentials" },
];

const emptyForm = { mode: "keys" as Mode, accessKey: "", secretKey: "", sessionToken: "", profile: "", roleArn: "", credentialSource: "Ec2InstanceMetadata", regions: "*", defaultRegion: "us-east-1" };

/** Which side (Steampipe, the SDK) answered what, after save or test. */
function TestOutcome({ test, sdk }: { test: { ok: boolean; accountId?: string; error?: string }; sdk?: { ok: boolean; arn?: string; error?: string; describe?: string } }) {
  return (
    <ul className="space-y-1 text-sm">
      <li className={test.ok ? "text-emerald-300" : "text-red-300"}>Steampipe: {test.ok ? `connected to account ${test.accountId}` : test.error}</li>
      {sdk && <li className={sdk.ok ? "text-emerald-300" : "text-red-300"}>SDK (SSM probe, identity): {sdk.ok ? <>{sdk.arn}{sdk.describe ? <span className="text-zinc-500"> via {sdk.describe}</span> : null}</> : sdk.error}</li>}
    </ul>
  );
}

export default function Settings() {
  const [params, setParams] = useSearchParams();
  const tab = (TABS.includes(params.get("tab") as Tab) ? params.get("tab") : "accounts") as Tab;
  const account = params.get("account") || ""; // the selected account's id (the AWS parent's account id, or "aws" before it is known)
  const section = (AWS_SECTIONS.includes(params.get("section") as AwsSection) ? params.get("section") : "access") as AwsSection;
  const setQ = (patch: Record<string, string | null>) => { const next = new URLSearchParams(params); for (const [k, v] of Object.entries(patch)) { if (v == null || v === "") next.delete(k); else next.set(k, v); } setParams(next); };
  const setTab = (t: Tab) => setQ({ tab: t, account: null, section: null });
  const [members, setMembers] = useState<MemberAccount[]>([]);
  const [adding, setAdding] = useState(false);
  const [providerList, setProviderList] = useState<ProviderInfo[]>([]);
  const [records, setRecords] = useState<{ provider: string; id: string; native_type: string; name: string; parent_id: string | null; access: string; enabled: boolean; last_test: { ok: boolean; detail: string | null; at: string | null } | null }[]>([]);
  const loadRecords = () => api("/accounts").then((d) => { setMembers((d.accounts || []).filter((a: MemberAccount) => !a.is_parent)); setRecords(d.records || []); }).catch(() => { setMembers([]); setRecords([]); });
  const [s, setS] = useState<any>(null);
  const [form, setForm] = useState(emptyForm);
  const [saving, setSaving] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text?: string; node?: React.ReactNode } | null>(null);
  const [tokenInput, setTokenInput] = useState(localStorage.getItem("advisor_token") || "");

  const load = () => api("/settings").then((d) => {
    setS(d);
    const a = d.aws || {};
    setForm((f) => ({ ...f, mode: a.mode || f.mode, profile: a.profile || f.profile, roleArn: a.roleArn || "", credentialSource: a.credentialSource || f.credentialSource, regions: a.regions?.join(",") || "*", defaultRegion: a.defaultRegion || "us-east-1" }));
  }).catch((e) => setMsg({ ok: false, text: e.message }));
  useEffect(() => { load(); loadRecords(); api("/providers").then((d) => setProviderList(d.providers || [])).catch(() => setProviderList([])); }, []);

  const set = (patch: Partial<typeof emptyForm>) => setForm((f) => ({ ...f, ...patch }));

  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setSaving(true); setMsg(null);
    try {
      const body: any = { mode: form.mode, regions: form.regions, defaultRegion: form.defaultRegion, roleArn: form.roleArn || undefined };
      if (form.mode === "keys") Object.assign(body, { accessKey: form.accessKey, secretKey: form.secretKey, sessionToken: form.sessionToken || undefined });
      if (form.mode === "profile") body.profile = form.profile;
      if (form.mode === "chain") body.credentialSource = form.credentialSource;
      const r = await api("/settings/aws", { method: "PUT", body: JSON.stringify(body) });
      setMsg({ ok: r.test.ok && (r.sdk?.ok ?? true), node: <TestOutcome test={r.test} sdk={r.sdk} /> });
      setForm((f) => ({ ...f, accessKey: "", secretKey: "", sessionToken: "" }));
      load();
    } catch (e: any) { setMsg({ ok: false, text: e.message }); }
    finally { setSaving(false); }
  };
  const test = async () => {
    setMsg(null);
    try { const r = await api("/settings/aws/test", { method: "POST" }); setMsg({ ok: r.ok && (r.sdk?.ok ?? true), node: <TestOutcome test={r} sdk={r.sdk} /> }); load(); }
    catch (e: any) { setMsg({ ok: false, text: e.message }); }
  };
  const remove = async () => { await api("/settings/aws", { method: "DELETE" }); setMsg({ ok: true, text: "Credentials removed (the connection file and the managed profile sections)" }); load(); };
  const toggleBench = async (b: string) => {
    const enabled = s.benchmarks.enabled.includes(b) ? s.benchmarks.enabled.filter((x: string) => x !== b) : [...s.benchmarks.enabled, b];
    await api("/settings/benchmarks", { method: "PUT", body: JSON.stringify({ enabled }) }); load();
  };

  if (!s) return <Empty>Loading…</Empty>;
  const aws = s.aws || {};
  const managed = aws.managedProfile || "aws-advisor";
  const roleField = (
    <label className="grid gap-1 text-sm">
      <span className="text-zinc-400">Role to assume (optional): <code className="text-zinc-300">arn:aws:iam::&lt;account&gt;:role/&lt;name&gt;</code></span>
      <input autoComplete="off" value={form.roleArn} onChange={(e) => set({ roleArn: e.target.value })} placeholder="arn:aws:iam::123456789012:role/aws-advisor-read" pattern={aws.validation?.roleArn} title="arn:aws:iam::<12 digits>:role/<name>" />
      <span className="text-xs text-zinc-500">With a role, the app writes <code className="text-zinc-300">[profile {managed}]</code> (role_arn + source) into <code className="text-zinc-300">{aws.awsConfigFile}</code> between <code className="text-zinc-300"># &gt;&gt;&gt; aws-advisor managed</code> markers and points the Steampipe connection at it; the rest of that file is never touched.</span>
    </label>
  );

  const parentId = aws.accountId || "aws";
  // the parent's sections as its adapter declares them (the built-in views), in its order
  const declared = providerList.find((p) => p.ui?.settings.some((x) => BUILTIN_VIEW.test(x.view)))?.ui?.settings.map((x) => x.id).filter((x): x is AwsSection => (AWS_SECTIONS as readonly string[]).includes(x));
  const awsSections: AwsSection[] = declared?.length ? declared : [...AWS_SECTIONS];
  const providerOf = (id: string) => providerList.find((p) => p.id === id);
  const builtin = (provider: string) => Boolean(providerOf(provider)?.ui?.settings.some((x) => BUILTIN_VIEW.test(x.view)));
  // an account of a provider with its own views; a provider id stands for its first account before one exists (Add account)
  const other = records.find((r) => !builtin(r.provider) && r.id === account)
    ?? (account && providerOf(account) && !builtin(account) ? { provider: account, id: account, native_type: providerOf(account)!.boundary, name: providerOf(account)!.label, parent_id: null, access: "", enabled: true, last_test: null } : null);
  const selected = other ? "other" : account === parentId || account === "aws" ? "parent" : members.find((m) => m.account_id === account) ? "member" : null;
  const accountRows = [
    ...(aws.configured ? [{ provider: "aws", boundary: "account", id: parentId, name: "parent", access: aws.mode === "profile" ? `profile ${aws.profile}` : aws.mode === "chain" ? "instance / default chain" : `key ${aws.accessKeyMasked || ""}`, status: aws.accountId ? `connected · saved ${when(aws.savedAt)}` : "saved, not tested yet", parent: null as string | null }] : []),
    ...members.map((m) => ({ provider: "aws", boundary: "account", id: m.account_id, name: m.name, access: `role ${m.role_arn.split("/").pop()}`, status: m.last_test ? `${m.last_test.ok ? "ok" : "failed"} · ${when(m.last_test.at)}${m.enabled ? "" : " · disabled"}` : "not tested yet", parent: parentId })),
    ...records.filter((r) => !builtin(r.provider)).map((r) => ({ provider: r.provider, boundary: r.native_type.replace(/_/g, " "), id: r.id, name: r.name, access: r.access, status: r.last_test ? `${r.last_test.ok ? "ok" : "failed"} · ${r.last_test.detail || ""}` : "not read yet", parent: r.parent_id })),
  ];

  return (
    <div className="max-w-3xl space-y-6">
      <h1 className="text-xl font-semibold text-zinc-100">Settings</h1>

      <div className="flex flex-wrap gap-1 border-b border-zinc-800" role="tablist">
        {TABS.map((t) => (
          <button key={t} type="button" role="tab" aria-selected={tab === t} onClick={() => setTab(t)} title={TAB_HINT[t]} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${tab === t ? "border-zinc-100 text-zinc-100" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}>
            {TAB_LABEL[t]}{t === "accounts" && !aws.configured && <span className="ml-1 text-xs text-amber-300">· start here</span>}
          </button>
        ))}
      </div>
      <p className="-mt-3 text-xs text-zinc-500">{TAB_HINT[tab]}</p>

      {tab === "accounts" && !selected && (
        <Card title={<span>Accounts <span className="font-normal text-zinc-500">· one row per account the advisor is pointed at; open one for its provider's setup</span></span>}>
          {accountRows.length === 0 ? <div className="mb-3 text-sm text-zinc-500">No account yet. Add one below: the AWS setup takes about ten minutes and needs admin credentials in a terminal, never in the app.</div> : (
            <table className="mb-3 w-full text-sm">
              <thead><tr className="text-left text-xs text-zinc-500"><th className="py-1 pr-3">Provider</th><th className="py-1 pr-3">Account</th><th className="py-1 pr-3">Name</th><th className="py-1 pr-3">Access</th><th className="py-1 pr-3">Status</th><th></th></tr></thead>
              <tbody>
                {accountRows.map((r) => (
                  <tr key={r.id} className="cursor-pointer border-t border-zinc-800/60 hover:bg-zinc-900/60" onClick={() => setQ({ account: r.id, section: r.parent ? "members" : "access" })}>
                    <td className="py-1.5 pr-3">{providerList.find((p) => p.id === r.provider)?.label || r.provider.toUpperCase()} <span className="text-xs text-zinc-500">{r.boundary}</span></td>
                    <td className="py-1.5 pr-3 font-mono text-zinc-200">{r.id}{r.parent && <div className="font-sans text-[11px] text-zinc-500">member of {r.parent}</div>}</td>
                    <td className="py-1.5 pr-3">{r.name}</td>
                    <td className="py-1.5 pr-3 text-xs text-zinc-400">{r.access}</td>
                    <td className="py-1.5 pr-3 text-xs text-zinc-400">{r.status}</td>
                    <td className="py-1.5 text-right text-xs text-sky-300">open →</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
          <div className="flex items-center gap-2">
            <Button variant="ghost" onClick={() => setAdding(!adding)}>{adding ? "Close" : "Add account"}</Button>
            {aws.configured && <span className="text-xs text-zinc-500">Another AWS account joins as a member of the parent (open the parent › Member accounts); a second parent is not supported yet.</span>}
          </div>
          {adding && (
            <div className="mt-3 grid gap-2 md:grid-cols-2">
              {providerList.map((p) => (
                <button key={p.id} type="button" disabled={!p.available} onClick={() => { setAdding(false); if (builtin(p.id)) setQ({ account: aws.configured ? parentId : "aws", section: aws.configured ? "members" : "access" }); else setQ({ account: records.find((r) => r.provider === p.id)?.id || p.id, section: "access" }); }}
                  className={`rounded border p-3 text-left ${p.available ? "border-zinc-700 hover:bg-zinc-900" : "cursor-not-allowed border-zinc-800 opacity-50"}`} title={`${p.credentials}; children: ${p.children}`}>
                  <div className="text-sm text-zinc-100">{p.label} <span className="text-xs text-zinc-500">· {p.boundary}</span>{!p.available && <span className="ml-2 text-xs text-zinc-500">not available yet</span>}</div>
                  <div className="text-xs text-zinc-500">{p.credentials}</div>
                </button>
              ))}
            </div>
          )}
        </Card>
      )}
      {tab === "accounts" && !selected && <DataCard accounts={accountRows.map((r) => ({ id: r.id, provider: r.provider, name: r.name }))} />}

      {tab === "accounts" && selected === "other" && other && (
        <>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <button type="button" className="text-sky-300 hover:underline" onClick={() => setQ({ account: null, section: null })}>← Accounts</button>
            <span className="text-zinc-500">/</span>
            <span className="text-zinc-200">{providerList.find((p) => p.id === other.provider)?.label || other.provider} {other.native_type.replace(/_/g, " ")} <span className="font-mono">{other.id !== other.provider ? other.id : ""}</span></span>
          </div>
          <div className="flex flex-wrap gap-1 border-b border-zinc-800" role="tablist">
            {(providerOf(other.provider)?.ui?.settings ?? [{ id: "access", label: "Access", view: "" }]).map((sec) => (
              <button key={sec.id} type="button" role="tab" aria-selected={(params.get("section") || "access") === sec.id} onClick={() => setQ({ section: sec.id })} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${(params.get("section") || "access") === sec.id ? "border-zinc-100 text-zinc-100" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}>{sec.label}</button>
            ))}
          </div>
          {(() => { const sec = providerOf(other.provider)?.ui?.settings.find((x) => x.id === (params.get("section") || "access")); return sec ? <ProviderView id={sec.view} configured={providerOf(other.provider)?.configured ?? false} onChange={() => { loadRecords(); api("/providers").then((d) => setProviderList(d.providers || [])).catch(() => {}); }} /> : null; })()}
        </>
      )}

      {tab === "accounts" && (selected === "parent" || selected === "member") && (
        <>
          <div className="flex flex-wrap items-center gap-2 text-sm">
            <button type="button" className="text-sky-300 hover:underline" onClick={() => setQ({ account: null, section: null })}>← Accounts</button>
            <span className="text-zinc-500">/</span>
            <span className="text-zinc-200">AWS account <span className="font-mono">{selected === "parent" ? parentId : account}</span></span>
            {selected === "member" && <span className="text-xs text-zinc-500">· reached through a role from the parent; its credentials, permissions and probes are the parent's</span>}
          </div>
          <div className="flex flex-wrap gap-1 border-b border-zinc-800" role="tablist">
            {awsSections.map((sec) => (
              <button key={sec} type="button" role="tab" aria-selected={section === sec} onClick={() => setQ({ section: sec })} className={`-mb-px border-b-2 px-3 py-1.5 text-sm ${section === sec ? "border-zinc-100 text-zinc-100" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}>
                {AWS_SECTION_LABEL[sec]}{sec === "members" && members.length ? <span className="ml-1 text-xs text-zinc-500">{members.length}</span> : null}
              </button>
            ))}
          </div>

          {section === "access" && (
            <>
              {s?.account_change && <AccountChangeBanner change={s.account_change} parent={aws.accountId} onDone={load} />}
              <SetupWizard aws={aws} onSaved={load} />
      <Card title="AWS credentials (manual)">
        <p className="mb-3 text-sm text-zinc-400">
          For credentials that already exist (an SSO profile, keys from elsewhere); the wizard above fills this in for you otherwise. The same identity is used by Steampipe (connection <code className="text-zinc-200">{s.schema}</code>, file mode 0600) and by the advisor's own AWS SDK calls (the SSM probe, the identity check). Nothing else stores it.
          {aws.configured && <> Currently: <span className="text-zinc-200">{aws.label || aws.accessKeyMasked}</span>{aws.temporary ? " (expires)" : ""}, saved {when(aws.savedAt)}{aws.accountId ? `, account ${aws.accountId}` : ""}.</>}
        </p>
        <div className="mb-3 flex flex-wrap gap-1 rounded border border-zinc-800 p-1" role="tablist">
          {MODES.map((m) => (
            <button key={m.id} type="button" role="tab" aria-selected={form.mode === m.id} onClick={() => set({ mode: m.id })} className={`rounded px-3 py-1.5 text-sm ${form.mode === m.id ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:text-zinc-200"}`} title={m.hint}>
              {m.label}{aws.configured && aws.mode === m.id && <span className="ml-1 text-xs text-emerald-300">· active</span>}
            </button>
          ))}
        </div>
        <form onSubmit={save} className="grid gap-3">
          {form.mode === "keys" && (
            <>
              <p className="text-xs text-zinc-500">Long-lived keys of a dedicated read-only IAM user, or temporary keys with their session token. Better: give the user no permissions and chain a role below, then the keys alone can do nothing.</p>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Access key ID</span><input autoComplete="off" value={form.accessKey} onChange={(e) => set({ accessKey: e.target.value })} required /></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Secret access key</span><input type="password" autoComplete="off" value={form.secretKey} onChange={(e) => set({ secretKey: e.target.value })} required /></label>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Session token (optional, temporary credentials)</span><textarea rows={3} value={form.sessionToken} onChange={(e) => set({ sessionToken: e.target.value })} /></label>
              {roleField}
            </>
          )}
          {form.mode === "profile" && (
            <>
              <p className="text-xs text-zinc-500">A profile from the AWS config file the advisor and the Steampipe service read (<code className="text-zinc-300">{aws.awsConfigFile}</code>, or <code className="text-zinc-300">AWS_CONFIG_FILE</code>). No key is pasted here. For an SSO profile run <code className="text-zinc-300">aws sso login --profile &lt;name&gt;</code> on this machine first and again when the session expires; the test below tells you when.</p>
              <label className="grid gap-1 text-sm"><span className="text-zinc-400">Profile name</span><input autoComplete="off" value={form.profile} onChange={(e) => set({ profile: e.target.value })} required pattern={aws.validation?.profile} placeholder="aws-advisor" /></label>
              {roleField}
            </>
          )}
          {form.mode === "chain" && (
            <>
              <p className="text-xs text-zinc-500">No credentials in the connection: Steampipe and the SDK use the default chain (environment variables, the EC2 instance profile, the ECS task role). This is the mode for the swarm deployment: the host's instance role assumes the read-only advisor role below.</p>
              {roleField}
              <label className="grid gap-1 text-sm">
                <span className="text-zinc-400">Credential source for the role (where the base credentials come from)</span>
                <select value={form.credentialSource} onChange={(e) => set({ credentialSource: e.target.value })}>
                  {(aws.credentialSources || ["Ec2InstanceMetadata", "EcsContainer", "Environment"]).map((c: string) => <option key={c} value={c}>{c}{c === "Ec2InstanceMetadata" ? " (EC2 instance profile)" : c === "EcsContainer" ? " (ECS task role)" : " (AWS_* environment variables)"}</option>)}
                </select>
              </label>
            </>
          )}
          <div className="grid grid-cols-2 gap-3">
            <label className="grid gap-1 text-sm"><span className="text-zinc-400">Regions (comma separated, * for all)</span><input value={form.regions} onChange={(e) => set({ regions: e.target.value })} /></label>
            <label className="grid gap-1 text-sm"><span className="text-zinc-400">Default region</span><input value={form.defaultRegion} onChange={(e) => set({ defaultRegion: e.target.value })} /></label>
          </div>
          <div className="flex items-center gap-2">
            <Button type="submit" disabled={saving}>{saving ? "Saving and testing…" : "Save and test"}</Button>
            {aws.configured && <Button type="button" variant="ghost" onClick={test}>Test again</Button>}
            {aws.configured && <Button type="button" variant="danger" onClick={remove}>Remove</Button>}
          </div>
          {msg && <div className={`text-sm ${msg.ok ? "text-emerald-300" : "text-red-300"}`}>{msg.node || msg.text}</div>}
        </form>
      </Card>
            </>
          )}

          {section === "permissions" && <PermissionsCard />}

          {section === "probes" && (
            <>
              <ProbesCard />
              <RuntimeSettings keys={PROBE_CRONS} title="Probe schedules" note="One cron per probe kind; Run now runs the pass as the cron would." />
              <RuntimeSettings groups={["Probe pass"]} title="Probe passes" />
            </>
          )}

          {section === "benchmarks" && (
            <>
      <Card title="Thrifty benchmarks to run">
        <div className="grid grid-cols-3 gap-1 text-sm">
          {s.benchmarks.all.map((b: string) => (
            <label key={b} className="flex items-center gap-2"><input type="checkbox" checked={s.benchmarks.enabled.includes(b)} onChange={() => toggleBench(b)} /> {b}</label>
          ))}
        </div>
        <p className="mt-2 text-xs text-zinc-500">cloudwatch is off by default: its log-stream check returns hundreds of thousands of rows. Retention is covered by a custom query.</p>
      </Card>
              <p className="text-xs text-zinc-500">The security benchmarks (aws_compliance) are picked on the Security page; their cron and the collection run's are on the Schedules tab.</p>
            </>
          )}

          {section === "members" && <MemberAccountsCard parentAccountId={aws.accountId} />}
        </>
      )}

      {tab === "schedules" && (
        <>
          <RuntimeSettings groups={["Schedules"]} exclude={PROBE_CRONS} title="Schedules" note="The four probe passes are scheduled under Accounts › the AWS account › Probes." />
      <Card title="Schedule, watcher and MCP">
        <ul className="space-y-1 text-sm text-zinc-400">
          <li>Full run: {s.schedule?.runCron ? <>cron <code className="text-zinc-200">{s.schedule.runCron}</code></> : "disabled (RUN_CRON=off)"} · agent auto-dispatch <code className="text-zinc-200">{s.schedule?.agentAutoDispatch}</code></li>
          <li>Watcher: {s.schedule?.watchCron ? <>cron <code className="text-zinc-200">{s.schedule.watchCron}</code> (instances, NAT traffic, Savings Plans, EBS; alerts show on Overview)</> : "disabled (WATCH_CRON=off)"} · alert investigation <code className="text-zinc-200">{s.schedule?.alertInvestigate}</code></li>
          <li>MCP fact server for the agent: <code className="text-zinc-200">{s.mcp?.url}</code>{s.mcp?.protected ? " (bearer token)" : " (open: set MCP_TOKEN)"}</li>
        </ul>
      </Card>
        </>
      )}

      {tab === "auto-actions" && <RuntimeSettings groups={["Auto-actions"]} title="Auto-actions" />}

      {tab === "agent" && (
        <>
      <Card title="Agent (repo2graph)">
        <p className="text-sm text-zinc-400">
          {s.agent.configured ? <>Findings are handed to <code className="text-zinc-200">{s.agent.url}</code> after each run, model {s.agent.model}.</> : <>Not configured: set the repo2graph URL and token in the Agent settings below.</>}
        </p>
      </Card>
          <AgentPrompts />
      <Card title="Jev (TypeSafe)">
        {s.jev?.enabled ? (
          <ul className="space-y-1 text-sm text-zinc-400">
            <li>Enabled, model <code className="text-zinc-200">{s.jev.model}</code>, {s.jev.timeout_ms / 1000} s timeout, one retry on 429/5xx. Used for alert triage, resource roles and the tier check on agent recommendations; it never loosens a tier and never triggers an action.</li>
            <li>Today: <span className="text-zinc-200">{s.jev.today?.calls ?? 0}</span> calls{s.jev.today?.failed ? <span className="text-red-300"> ({s.jev.today.failed} failed)</span> : null}, <span className="text-zinc-200">{(s.jev.today?.input_tokens ?? 0).toLocaleString()}</span> input + <span className="text-zinc-200">{(s.jev.today?.output_tokens ?? 0).toLocaleString()}</span> output tokens{s.jev.today?.by_purpose?.length ? <> · {s.jev.today.by_purpose.map((p: any) => `${p.purpose} ${p.calls}`).join(", ")}</> : null}{s.jev.last_call_at ? <> · last call {when(s.jev.last_call_at)}</> : null}</li>
            <li>Last error: {s.jev.last_error ? <span className="text-red-300">{s.jev.last_error.purpose} at {when(s.jev.last_error.at)}: {s.jev.last_error.error}</span> : "none"}</li>
            <li className="text-xs text-zinc-500">Audit every call with <code className="text-zinc-300">GET /api/jev/calls?limit=50</code>.</li>
          </ul>
        ) : (
          <p className="text-sm text-zinc-400">Not configured: paste the TypeSafe API key in the Jev settings below.</p>
        )}
      </Card>
          <RuntimeSettings groups={["Agent", "Jev (TypeSafe)", "Graph mirror (Neo4j)"]} title="Agent, Jev and graph" />
        </>
      )}

      {tab === "notifications" && <RuntimeSettings groups={["Notifications (Sphinx)"]} title="Notifications" />}

      {tab === "other" && (
        <>
          <RuntimeSettings groups={["Quotas", "Inventory"]} title="Quotas and inventory" />
          <TransferCard />
      <Card title="API token (dev)">
        <p className="mb-2 text-xs text-zinc-500">Only needed when the backend runs with API_TOKEN set and you use the Vite dev server. The built app gets a token injected automatically.</p>
        <div className="flex gap-2"><input className="flex-1" value={tokenInput} onChange={(e) => setTokenInput(e.target.value)} placeholder="paste API_TOKEN" /><Button variant="ghost" onClick={() => { localStorage.setItem("advisor_token", tokenInput); location.reload(); }}>Use</Button></div>
      </Card>
        </>
      )}
    </div>
  );
}


type MemberAccount = { account_id: string; name: string; role_arn: string; act_role_arn: string | null; regions: string[] | null; enabled: boolean; is_parent: boolean; last_test?: { ok: boolean; arn?: string; error?: string; at: string } | null };

/** The credentials resolve to a different account than the one the advisor was collecting: say so, and offer the three ways out. Nothing happens by itself. */
function AccountChangeBanner({ change, parent, onDone }: { change: { from: string; to: string; at: string }; parent?: string; onDone: () => void }) {
  const [preview, setPreview] = useState<any>(null); const [confirm, setConfirm] = useState(""); const [busy, setBusy] = useState(false); const [msg, setMsg] = useState("");
  const [, setQ] = useSearchParams();
  useEffect(() => { api("/settings/aws/change").then((d) => setPreview(d.preview)).catch(() => {}); }, [change.from]);
  const rows = preview ? Object.values(preview.tables as Record<string, number>).reduce((a, b) => a + b, 0) + Object.values(preview.attributed as Record<string, number>).reduce((a, b) => a + b, 0) : null;
  const keep = async () => { setBusy(true); try { await api("/settings/aws/change", { method: "DELETE" }); onDone(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const purge = async () => { setBusy(true); setMsg(""); try { const r = await api("/settings/aws/purge", { method: "POST", body: JSON.stringify({ account: change.from, confirm }) }); setMsg(`removed ${Object.values(r.tables as Record<string, number>).reduce((a, b) => a + b, 0) + Object.values(r.attributed as Record<string, number>).reduce((a, b) => a + b, 0)} rows and ${r.graph_deleted} graph nodes`); onDone(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  return (
    <Card title={<span className="text-orange-300">The credentials now resolve to account {change.to}</span>}>
      <p className="text-sm text-zinc-300">Until {when(change.at)} the advisor was collecting account <span className="font-mono">{change.from}</span>{rows != null ? <>, and still holds <span className="text-zinc-100">{rows.toLocaleString()}</span> rows about it (inventory, findings, recommendations, alerts, actions, scans) plus its graph nodes</> : null}. Nothing is deleted on its own. Pick one:</p>
      <ul className="mt-2 space-y-2 text-sm">
        <li><span className="text-zinc-100">Make {change.from} a member of {change.to}.</span> <span className="text-zinc-400">Its rows already carry its account id, so they become the member's as soon as its read role exists and it is registered.</span> <button type="button" className="ml-1 text-sky-300 hover:underline" onClick={() => setQ({ tab: "accounts", account: parent || change.to, section: "access", setup: "member-role", memberName: change.from })}>Set it up as a member</button></li>
        <li><span className="text-zinc-100">Keep the data as it is.</span> <span className="text-zinc-400">The old account's rows stay; the next collection marks its resources gone.</span> <button type="button" className="ml-1 text-sky-300 hover:underline" disabled={busy} onClick={keep}>Keep and dismiss</button></li>
        <li><span className="text-zinc-100">Purge it.</span> <span className="text-zinc-400">Removes every row and graph node attributed to {change.from}: history, decisions and the ledger included. Irreversible.</span>
          <span className="ml-2 inline-flex items-center gap-2"><input className="w-40 rounded border border-zinc-700 bg-zinc-900 px-2 py-0.5 font-mono text-xs" placeholder={`type ${change.from}`} value={confirm} onChange={(e) => setConfirm(e.target.value)} /><Button type="button" variant="danger" disabled={busy || confirm !== change.from} onClick={purge}>Purge</Button></span></li>
      </ul>
      {msg && <div className="mt-2 text-xs text-zinc-300">{msg}</div>}
    </Card>
  );
}

/** The organisation's accounts as the parent sees them, with which are registered: the list to add members from. */
function OrganizationAccounts({ parent }: { parent?: string }) {
  const [d, setD] = useState<any>(null); const [, setQ] = useSearchParams();
  useEffect(() => { api("/accounts/organization").then(setD).catch((e) => setD({ ok: false, error: e.message, accounts: [] })); }, []);
  if (!d) return null;
  if (!d.ok) return <p className="mb-3 text-xs text-zinc-500">Organisation listing: {d.error}</p>;
  return (
    <div className="mb-3">
      <div className="mb-1 text-xs text-zinc-500">The organisation has {d.accounts.length} account{d.accounts.length === 1 ? "" : "s"}; each child needs its own read role (one script per account).</div>
      <table className="w-full text-sm"><thead><tr className="text-left text-xs text-zinc-500"><th className="py-1 pr-3">Account</th><th className="py-1 pr-3">Name</th><th className="py-1 pr-3">Status</th><th className="py-1 pr-3">In the advisor</th><th /></tr></thead>
        <tbody>{d.accounts.map((a: any) => <tr key={a.id} className="border-t border-zinc-800/60"><td className="py-1 pr-3 font-mono text-xs">{a.id}</td><td className="py-1 pr-3">{a.name || "—"}{a.email_domain ? <span className="text-xs text-zinc-500"> · {a.email_domain}</span> : null}</td><td className="py-1 pr-3 text-xs text-zinc-400">{a.status || "—"}</td><td className="py-1 pr-3 text-xs">{a.role === "parent" ? <span className="text-zinc-200">parent</span> : a.role === "member" ? <span className="text-emerald-300">member</span> : <span className="text-zinc-500">not registered</span>}</td><td className="py-1 text-right">{a.role === "not registered" && a.status !== "SUSPENDED" && <button type="button" className="text-xs text-sky-300 hover:underline" onClick={() => setQ({ tab: "accounts", account: parent || "", section: "access", setup: "member-role", memberName: a.name || a.id })}>Set up as member</button>}</td></tr>)}</tbody></table>
    </div>
  );
}

/** Member accounts: the children the parent reaches through a role (Steampipe and the SDK alike), with the trust policy their roles need. */
function MemberAccountsCard({ parentAccountId }: { parentAccountId?: string }) {
  const empty = { account_id: "", name: "", role_arn: "", act_role_arn: "", regions: "" };
  const [d, setD] = useState<{ accounts: MemberAccount[]; parent_identity: { ok: boolean; arn?: string; principal_arn?: string; error?: string }; trust_policy: any } | null>(null);
  const [form, setForm] = useState(empty);
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [showPolicy, setShowPolicy] = useState(false);
  const load = () => api("/accounts").then(setD).catch((e) => setMsg({ ok: false, text: e.message }));
  useEffect(() => { load(); }, []);
  const set = (patch: Partial<typeof empty>) => setForm((f) => ({ ...f, ...patch }));
  const save = async (e: React.FormEvent) => {
    e.preventDefault(); setBusy(true); setMsg(null);
    try {
      const r = await api("/accounts", { method: "POST", body: JSON.stringify({ ...form, act_role_arn: form.act_role_arn || undefined, regions: form.regions || undefined }) });
      setMsg(r.test?.ok ? { ok: true, text: `saved and tested: the parent assumed ${r.test.arn}${r.files_rewritten ? "; Steampipe connection rewritten (it reloads within seconds)" : "; save the parent's credentials first so the connection can be rewritten"}` } : { ok: false, text: `saved, but the test failed: ${r.test?.error}` });
      setForm(empty); load();
    } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); }
  };
  const test = async (id: string) => { setBusy(true); setMsg(null); try { const r = await api(`/accounts/${id}/test`, { method: "POST" }); setMsg({ ok: r.test.ok, text: r.test.ok ? `ok: ${r.test.arn}` : r.test.error }); load(); } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); } };
  const remove = async (id: string) => { setBusy(true); setMsg(null); try { await api(`/accounts/${id}`, { method: "DELETE" }); setMsg({ ok: true, text: `${id} removed; Steampipe connection rewritten` }); load(); } catch (e: any) { setMsg({ ok: false, text: e.message }); } finally { setBusy(false); } };
  const members = (d?.accounts || []).filter((a) => !a.is_parent);
  return (
    <Card title="Member accounts">
      <p className="mb-3 text-sm text-zinc-400">
        One parent, the children it reaches through a role. The credentials above are the parent{parentAccountId ? <> (account <span className="text-zinc-200">{parentAccountId}</span>)</> : ""}. In each child create two roles that trust the parent's read identity{d?.parent_identity?.ok ? <> (<span className="text-zinc-200">{d.parent_identity.principal_arn || d.parent_identity.arn}</span>)</> : ""}: a read role with the advisor's read policy (Permissions below), and an actuator role with the actuator policy (Auto-actions page) if the executor may change that account. Steampipe then queries every account through one schema (rows carry the account id), the inventories and rules span them, and the executor acts in a child under that child's actuator role only.
        {" "}<button type="button" className="text-sky-300 hover:underline" onClick={() => setShowPolicy((v) => !v)}>{showPolicy ? "Hide" : "Show"} the trust policy</button>
      </p>
      {showPolicy && d?.trust_policy && <pre className="mb-3 max-h-60 overflow-auto rounded border border-zinc-800 bg-zinc-950 p-2 text-xs text-zinc-300">{JSON.stringify(d.trust_policy, null, 2)}</pre>}
      <OrganizationAccounts parent={parentAccountId} />
      {members.length > 0 && (
        <table className="mb-3 w-full text-sm">
          <thead><tr className="text-left text-xs text-zinc-500"><th className="py-1 pr-3">Account</th><th className="py-1 pr-3">Name</th><th className="py-1 pr-3">Read role</th><th className="py-1 pr-3">Actuator role</th><th className="py-1 pr-3">Last test</th><th /></tr></thead>
          <tbody>
            {members.map((m) => (
              <tr key={m.account_id} className="border-t border-zinc-800/60 align-top">
                <td className="py-1 pr-3 font-mono text-zinc-200">{m.account_id}{!m.enabled && <span className="ml-1 text-xs text-zinc-500">(disabled)</span>}</td>
                <td className="py-1 pr-3">{m.name}</td>
                <td className="py-1 pr-3 break-all font-mono text-xs text-zinc-300">{m.role_arn}</td>
                <td className="py-1 pr-3 break-all font-mono text-xs text-zinc-300">{m.act_role_arn || <span className="text-zinc-500">none: dry runs only</span>}</td>
                <td className="py-1 pr-3 text-xs">{m.last_test ? <span className={m.last_test.ok ? "text-emerald-300" : "text-red-300"} title={m.last_test.arn || m.last_test.error}>{m.last_test.ok ? "ok" : "failed"} · {when(m.last_test.at)}</span> : <span className="text-zinc-500">never</span>}</td>
                <td className="py-1 text-right whitespace-nowrap"><Button type="button" variant="ghost" onClick={() => test(m.account_id)} disabled={busy}>Test</Button> <Button type="button" variant="danger" onClick={() => remove(m.account_id)} disabled={busy}>Remove</Button></td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
      <form onSubmit={save} className="grid gap-3">
        <div className="grid grid-cols-2 gap-3">
          <label className="grid gap-1 text-sm"><span className="text-zinc-400">Account id (12 digits)</span><input value={form.account_id} onChange={(e) => set({ account_id: e.target.value })} required pattern="\d{12}" /></label>
          <label className="grid gap-1 text-sm"><span className="text-zinc-400">Name</span><input value={form.name} onChange={(e) => set({ name: e.target.value })} placeholder="e.g. production" /></label>
        </div>
        <label className="grid gap-1 text-sm"><span className="text-zinc-400">Read role ARN in the child</span><input value={form.role_arn} onChange={(e) => set({ role_arn: e.target.value })} required placeholder="arn:aws:iam::<child>:role/aws-advisor-read" /></label>
        <label className="grid gap-1 text-sm"><span className="text-zinc-400">Actuator role ARN in the child (optional: without it the executor only dry-runs there)</span><input value={form.act_role_arn} onChange={(e) => set({ act_role_arn: e.target.value })} placeholder="arn:aws:iam::<child>:role/aws-advisor-act" /></label>
        <label className="grid gap-1 text-sm"><span className="text-zinc-400">Regions (comma separated; empty = the parent's)</span><input value={form.regions} onChange={(e) => set({ regions: e.target.value })} /></label>
        <div className="flex items-center gap-2"><Button type="submit" disabled={busy}>{busy ? "Saving and testing…" : "Add and test"}</Button></div>
        {msg && <div className={`text-sm ${msg.ok ? "text-emerald-300" : "text-red-300"}`}>{msg.text}</div>}
      </form>
    </Card>
  );
}


/**
 * Wiping what the advisor holds: one account's rows and graph nodes, or everything. Each wipe is confirmed by typing
 * (the account id, or WIPE), previews what goes, and is irreversible. Configuration, price lists, advisories and the
 * generated playbooks always stay; the Concepts and learnings stay when the switch is on.
 */
function DataCard({ accounts }: { accounts: { id: string; provider: string; name: string }[] }) {
  const [target, setTarget] = useState<string>("all");
  const [keepConcepts, setKeepConcepts] = useState(true);
  const [preview, setPreview] = useState<any>(null);
  const [confirm, setConfirm] = useState(""); const [busy, setBusy] = useState(false); const [msg, setMsg] = useState("");
  useEffect(() => { setPreview(null); setConfirm(""); api(`/settings/data/preview?target=${encodeURIComponent(target)}&preserve_concepts=${keepConcepts ? 1 : 0}`).then(setPreview).catch((e) => setMsg(e.message)); }, [target, keepConcepts]);
  const sum = (o?: Record<string, number>) => Object.values(o || {}).reduce((a, b) => a + b, 0);
  const rows = preview ? sum(preview.tables) + sum(preview.attributed) : null;
  const expected = target === "all" ? "WIPE" : target;
  const wipe = async () => {
    setBusy(true); setMsg("");
    try {
      const r = await api("/settings/data/wipe", { method: "POST", body: JSON.stringify({ target, confirm, preserve_concepts: keepConcepts }) });
      setMsg(target === "all" ? `wiped ${sum(r.tables)} rows across ${Object.keys(r.tables).length} tables and ${r.settings} state settings; ${r.graph_deleted} graph nodes removed, ${r.playbooks_remirrored} playbooks mirrored back. Start a run to collect again.` : `removed ${sum(r.tables) + sum(r.attributed)} rows and ${r.graph_deleted} graph nodes of ${target}.`);
      setConfirm(""); api(`/settings/data/preview?target=${encodeURIComponent(target)}&preserve_concepts=${keepConcepts ? 1 : 0}`).then(setPreview).catch(() => {});
    } catch (e: any) { setMsg(e.message); } finally { setBusy(false); }
  };
  return (
    <Card title={<span>Data <span className="font-normal text-zinc-500">· wipe what the advisor holds and start over; irreversible</span></span>}>
      <div className="grid gap-3 text-sm md:grid-cols-[auto_1fr]">
        <label className="text-zinc-400">Wipe</label>
        <select className="w-fit rounded border border-zinc-700 bg-zinc-900 px-2 py-1 text-sm" value={target} onChange={(e) => setTarget(e.target.value)}>
          <option value="all">everything, every account</option>
          {accounts.map((a) => <option key={a.id} value={a.id}>{a.provider.toUpperCase()} {a.id}{a.name ? ` · ${a.name}` : ""}</option>)}
        </select>
        <span className="text-zinc-400">Keeps</span>
        <div className="text-xs text-zinc-400">
          {target === "all" ? (
            <>
              <div>Credentials, registered accounts and runtime settings; price lists and Amazon Linux advisories; the generated playbooks and their sources.</div>
              <label className="mt-1 flex items-center gap-2 text-zinc-300"><input type="checkbox" checked={keepConcepts} onChange={(e) => setKeepConcepts(e.target.checked)} /> Keep the Concepts and learnings (the decisions the agents learned from; the Concepts in the graph are never deleted either way)</label>
            </>
          ) : <div>Every other account's rows. Removes this account's inventories, findings, recommendations, alerts, actions, history and graph nodes.</div>}
        </div>
        <span className="text-zinc-400">Goes</span>
        <div className="text-xs text-zinc-400">
          {preview ? rows ? <>{rows.toLocaleString()} rows: {Object.entries({ ...preview.tables, ...preview.attributed } as Record<string, number>).sort((a, b) => b[1] - a[1]).slice(0, 12).map(([t, n]) => `${t} ${n}`).join(", ")}{Object.keys({ ...preview.tables, ...preview.attributed }).length > 12 ? ", …" : ""}</> : "nothing stored for this target" : "counting…"}
        </div>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <input className="w-44 rounded border border-zinc-700 bg-zinc-900 px-2 py-1 font-mono text-xs" placeholder={`type ${expected}`} value={confirm} onChange={(e) => setConfirm(e.target.value)} />
        <Button onClick={wipe} disabled={busy || confirm.trim() !== expected || !rows}>{busy ? "Wiping…" : target === "all" ? "Wipe everything" : `Wipe ${target}`}</Button>
        <span className="text-xs text-zinc-500">Refused while a collection run is in progress. The next run rebuilds the inventories and the graph with every row stamped with its account.</span>
      </div>
      {msg && <div className="mt-2 text-xs text-zinc-300">{msg}</div>}
    </Card>
  );
}

type ImportPlan = {
  runtime: { key: string; label: string; group: string; secret: boolean; from_source: "setting" | "env"; current_source: "setting" | "env" | "default"; same: boolean; selected: boolean }[];
  aws: { mode: string; label: string; account_id: string | null; replaces: string | null; warning: string | null } | null;
  members: { account_id: string; name: string; enabled: boolean }[];
  benchmarks: boolean; compliance_benchmarks: boolean; prompts: string[]; probe_scripts: string[];
};

/** Moves this advisor's configuration (keys included, sealed with a passphrase) to another host. No data travels: the new host collects its own with a run. */
function TransferCard() {
  const [exportPass, setExportPass] = useState(""); const [busy, setBusy] = useState(false); const [msg, setMsg] = useState("");
  const [bundle, setBundle] = useState<any>(null); const [importPass, setImportPass] = useState("");
  const [plan, setPlan] = useState<ImportPlan | null>(null); const [pick, setPick] = useState<Set<string>>(new Set()); const [result, setResult] = useState<any>(null);
  const run = async (f: () => Promise<void>) => { setBusy(true); setMsg(""); try { await f(); } catch (e: any) { setMsg(e.message); } finally { setBusy(false); } };
  const doExport = () => run(async () => {
    const b = await api("/settings/export", { method: "POST", body: JSON.stringify({ passphrase: exportPass }) });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(new Blob([JSON.stringify(b, null, 2)], { type: "application/json" }));
    a.download = `cloud-advisor-settings-${b.exported_at.slice(0, 10)}.json`; a.click(); URL.revokeObjectURL(a.href);
    setExportPass(""); setMsg(`exported ${b.from.runtime} runtime settings, ${b.from.aws_mode ? `the ${b.from.aws_mode} credentials` : "no AWS credentials"} and ${b.from.members} member accounts`);
  });
  const readFile = (f: File | undefined) => { setPlan(null); setResult(null); setMsg(""); if (!f) return setBundle(null); f.text().then((t) => setBundle(JSON.parse(t))).catch(() => setMsg("that file is not JSON")); };
  const preview = () => run(async () => {
    const p: ImportPlan = await api("/settings/import/preview", { method: "POST", body: JSON.stringify({ bundle, passphrase: importPass }) });
    setPlan(p); setPick(new Set(p.runtime.filter((r) => r.selected).map((r) => r.key)));
  });
  const apply = () => run(async () => {
    setResult(await api("/settings/import", { method: "POST", body: JSON.stringify({ bundle, passphrase: importPass, runtime_keys: [...pick] }) }));
    setPlan(null); setImportPass("");
  });
  const toggle = (k: string) => setPick((s) => { const n = new Set(s); if (n.has(k)) n.delete(k); else n.add(k); return n; });
  const src = (s: string) => (s === "default" ? "default" : s === "env" ? "env" : "saved");
  return (
    <Card title={<span>Export / import settings <span className="font-normal text-zinc-500">· configuration and keys only, no data; run a collection on the new host afterwards</span></span>}>
      <div className="space-y-4 text-sm">
        <div>
          <div className="mb-1 text-zinc-300">Export</div>
          <p className="mb-2 text-xs text-zinc-500">Runtime settings with their secrets (saved and env-provided), the AWS credentials including static keys, member accounts, benchmarks, prompt and probe-script overrides. The file is encrypted with the passphrase; keep the two apart.</p>
          <div className="flex gap-2">
            <input type="password" autoComplete="new-password" className="flex-1" value={exportPass} onChange={(e) => setExportPass(e.target.value)} placeholder="passphrase (10+ characters)" />
            <Button onClick={doExport} disabled={busy || exportPass.length < 10}>Download export</Button>
          </div>
        </div>
        <div>
          <div className="mb-1 text-zinc-300">Import</div>
          <div className="flex flex-wrap gap-2">
            <input type="file" accept="application/json,.json" onChange={(e) => readFile(e.target.files?.[0])} className="text-xs" />
            <input type="password" autoComplete="off" className="flex-1" value={importPass} onChange={(e) => setImportPass(e.target.value)} placeholder="passphrase" />
            <Button variant="ghost" onClick={preview} disabled={busy || !bundle || !importPass}>Preview</Button>
          </div>
          {bundle?.from && <p className="mt-1 text-xs text-zinc-500">From {bundle.from.public_url}{bundle.from.account_id ? ` · account ${bundle.from.account_id}` : ""} · exported {when(bundle.exported_at)}</p>}
        </div>
        {plan && (
          <div className="space-y-2 rounded border border-zinc-800 p-3 text-xs">
            <div><span className="text-zinc-400">AWS credentials: </span>{plan.aws ? <>{plan.aws.label}{plan.aws.account_id ? ` (account ${plan.aws.account_id})` : ""}{plan.aws.replaces ? <span className="text-amber-300"> · replaces {plan.aws.replaces}</span> : ""}</> : "none in the export"}</div>
            {plan.aws?.warning && <div className="text-amber-300">{plan.aws.warning}</div>}
            <div><span className="text-zinc-400">Member accounts: </span>{plan.members.length ? plan.members.map((m) => `${m.name} ${m.account_id}${m.enabled ? "" : " (disabled)"}`).join(", ") : "none"} <span className="text-zinc-500">(replaces this host's list)</span></div>
            <div><span className="text-zinc-400">Overrides: </span>{[plan.benchmarks && "benchmarks", plan.compliance_benchmarks && "compliance benchmarks", ...plan.prompts.map((p) => `prompt ${p}`), ...plan.probe_scripts.map((p) => `probe script ${p}`)].filter(Boolean).join(", ") || "none"}</div>
            <table className="w-full">
              <thead><tr className="text-left text-zinc-500"><th className="w-6" /><th>Setting</th><th>In the export</th><th>Here now</th></tr></thead>
              <tbody>
                {plan.runtime.map((r) => (
                  <tr key={r.key} className="border-t border-zinc-900">
                    <td><input type="checkbox" checked={pick.has(r.key)} onChange={() => toggle(r.key)} /></td>
                    <td className="py-0.5">{r.group} › {r.label}{r.secret && <span className="ml-1 text-zinc-500">(secret)</span>}</td>
                    <td className="text-zinc-400">{src(r.from_source)}</td>
                    <td className={r.same ? "text-zinc-500" : r.current_source === "default" ? "text-zinc-400" : "text-amber-300"}>{r.same ? "same value" : src(r.current_source)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <p className="text-zinc-500">Ticked values are saved here and win over this host's env. Check the host-specific ones (Neo4j, doorman, link URL) before importing.</p>
            <Button onClick={apply} disabled={busy}>{busy ? "Importing…" : `Import ${pick.size} settings and the credentials`}</Button>
            {busy && <span className="ml-2 text-zinc-500">saving, restarting Steampipe and testing the new connection; up to three minutes</span>}
          </div>
        )}
        {result && (
          <div className="rounded border border-zinc-800 p-3 text-xs text-zinc-300">
            <div>Applied {result.runtime.applied.length} runtime settings, {result.members} member accounts{result.overrides.length ? `, ${result.overrides.join(", ")}` : ""}.</div>
            {result.runtime.failed.length > 0 && <div className="text-red-300">Failed: {result.runtime.failed.map((f: any) => `${f.key} (${f.error})`).join("; ")}</div>}
            {result.aws?.test && <div className="mt-1"><TestOutcome test={result.aws.test} sdk={result.aws.sdk} /></div>}
            <div className="mt-1 text-zinc-500">Next: start a run (Runs › Start) to collect the inventory and fill the graph.</div>
          </div>
        )}
        {msg && <div className="text-xs text-zinc-300">{msg}</div>}
      </div>
    </Card>
  );
}
