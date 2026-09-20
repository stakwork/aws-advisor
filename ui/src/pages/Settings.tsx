import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Button, Card, Empty } from "../components/ui";
import { PermissionsCard } from "../components/permissions";
import { SetupWizard } from "../components/setup";
import { AgentPrompts } from "../components/prompts";
import { RuntimeSettings } from "../components/runtimeSettings";

type Mode = "keys" | "profile" | "chain";

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
  useEffect(() => { load(); }, []);

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

  return (
    <div className="max-w-3xl space-y-6">
      <h1 className="text-xl font-semibold text-zinc-100">Settings</h1>

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

      <PermissionsCard />

      <Card title="Thrifty benchmarks to run">
        <div className="grid grid-cols-3 gap-1 text-sm">
          {s.benchmarks.all.map((b: string) => (
            <label key={b} className="flex items-center gap-2"><input type="checkbox" checked={s.benchmarks.enabled.includes(b)} onChange={() => toggleBench(b)} /> {b}</label>
          ))}
        </div>
        <p className="mt-2 text-xs text-zinc-500">cloudwatch is off by default: its log-stream check returns hundreds of thousands of rows. Retention is covered by a custom query.</p>
      </Card>

      <RuntimeSettings />

      <Card title="Agent (repo2graph)">
        <p className="text-sm text-zinc-400">
          {s.agent.configured ? <>Findings are handed to <code className="text-zinc-200">{s.agent.url}</code> after each run, model {s.agent.model}.</> : <>Not configured: set the repo2graph URL and token in Settings above.</>}
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
          <p className="text-sm text-zinc-400">Not configured: paste the TypeSafe API key in Settings above.</p>
        )}
      </Card>

      <Card title="Schedule, watcher and MCP">
        <ul className="space-y-1 text-sm text-zinc-400">
          <li>Full run: {s.schedule?.runCron ? <>cron <code className="text-zinc-200">{s.schedule.runCron}</code></> : "disabled (RUN_CRON=off)"} · agent auto-dispatch <code className="text-zinc-200">{s.schedule?.agentAutoDispatch}</code></li>
          <li>Watcher: {s.schedule?.watchCron ? <>cron <code className="text-zinc-200">{s.schedule.watchCron}</code> (instances, NAT traffic, Savings Plans, EBS; alerts show on Overview)</> : "disabled (WATCH_CRON=off)"} · alert investigation <code className="text-zinc-200">{s.schedule?.alertInvestigate}</code></li>
          <li>MCP fact server for the agent: <code className="text-zinc-200">{s.mcp?.url}</code>{s.mcp?.protected ? " (bearer token)" : " (open: set MCP_TOKEN)"}</li>
        </ul>
      </Card>

      <Card title="API token (dev)">
        <p className="mb-2 text-xs text-zinc-500">Only needed when the backend runs with API_TOKEN set and you use the Vite dev server. The built app gets a token injected automatically.</p>
        <div className="flex gap-2"><input className="flex-1" value={tokenInput} onChange={(e) => setTokenInput(e.target.value)} placeholder="paste API_TOKEN" /><Button variant="ghost" onClick={() => { localStorage.setItem("advisor_token", tokenInput); location.reload(); }}>Use</Button></div>
      </Card>
    </div>
  );
}
