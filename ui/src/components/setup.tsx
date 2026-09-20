import { useEffect, useState } from "react";
import { api, when } from "../api";
import { Button, Card, Code, CopyButton } from "./ui";

/**
 * Settings > Set up AWS access: the one-command onboarding. Pick a path, name things, get the plan and the
 * command (GET /api/setup/plan), run it in a terminal that has admin credentials, and watch GET /api/settings
 * until the script has saved the settings and the connection test passed. The app never receives the admin
 * credentials: the script only sends it the profile name / role ARN.
 */

type Path = "laptop-key" | "ec2-role";

const PATHS: { id: Path; label: string; hint: string }[] = [
  { id: "laptop-key", label: "Laptop / server with a long-lived key", hint: "A dedicated IAM user whose only permission is assuming a read-only role. Its key is written into ~/.aws/credentials on the machine running the advisor and never into the app." },
  { id: "ec2-role", label: "EC2 host with an instance role", hint: "No secret anywhere: the host's instance role assumes the read-only role. For the swarm host; the advisor must run on that instance." },
];

const NAME_RE = "^[A-Za-z0-9_.-]+$";
const DEFAULTS = { user: "aws-advisor", role: "aws-advisor-read", profile: "aws-advisor", region: "us-east-1", instanceRole: "aws-advisor-host", instanceId: "", adminProfile: "" };

const Field = ({ label, hint, value, onChange, pattern, placeholder, required = true }: { label: string; hint?: string; value: string; onChange: (v: string) => void; pattern?: string; placeholder?: string; required?: boolean }) => (
  <label className="grid gap-1 text-sm">
    <span className="text-zinc-400">{label}</span>
    <input autoComplete="off" value={value} onChange={(e) => onChange(e.target.value)} pattern={pattern} placeholder={placeholder} required={required} />
    {hint && <span className="text-xs text-zinc-500">{hint}</span>}
  </label>
);

export function SetupWizard({ aws, onSaved }: { aws: any; onSaved?: () => void }) {
  const [step, setStep] = useState(1);
  const [path, setPath] = useState<Path | null>(null);
  const [f, setF] = useState(DEFAULTS);
  const [dryRun, setDryRun] = useState(false);
  const [plan, setPlan] = useState<any>(null);
  const [err, setErr] = useState("");
  /** When the plan was first shown: settings saved after this moment are the script's. */
  const [since, setSince] = useState<number | null>(null);
  const [saved, setSaved] = useState<any>(null);
  const [check, setCheck] = useState<any>(null);
  const [checking, setChecking] = useState(false);
  const set = (patch: Partial<typeof DEFAULTS>) => setF((x) => ({ ...x, ...patch }));

  const query = () => {
    const q = new URLSearchParams({ path: path!, user: f.user, role: f.role, region: f.region, advisorUrl: location.origin });
    if (path === "laptop-key") q.set("profile", f.profile);
    if (path === "ec2-role") { q.set("instanceRole", f.instanceRole); if (f.instanceId.trim()) q.set("instanceId", f.instanceId.trim()); }
    if (f.adminProfile.trim()) q.set("adminProfile", f.adminProfile.trim());
    if (dryRun) q.set("dryRun", "1");
    return q.toString();
  };

  useEffect(() => {
    if (step !== 3 || !path) return;
    setErr("");
    api(`/setup/plan?${query()}`).then((p) => { setPlan(p); setSince((s) => s ?? Date.now()); }).catch((e) => setErr(e.message));
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, dryRun]);

  // Step 4: poll until the script has saved the settings (savedAt after the plan was shown) and the test passed (accountId set).
  useEffect(() => {
    if (step !== 4 || saved?.ok) return;
    const tick = async () => {
      try {
        const s = await api("/settings");
        const a = s.aws || {};
        const savedAt = a.savedAt ? new Date(a.savedAt).getTime() : 0;
        if (a.configured && since && savedAt >= since - 60_000) {
          const ok = Boolean(a.accountId);
          setSaved({ ok, meta: a });
          if (ok) onSaved?.();
        }
      } catch { /* the next tick retries */ }
    };
    tick();
    const id = setInterval(tick, 5000);
    return () => clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [step, saved?.ok]);

  const runCheck = async () => {
    setChecking(true); setErr("");
    try { setCheck(await api("/permissions/check", { method: "POST", body: "{}" })); }
    catch (e: any) { setErr(e.message); }
    finally { setChecking(false); }
  };

  const restart = () => { setStep(1); setPlan(null); setSaved(null); setCheck(null); setSince(null); setErr(""); };
  const counts = (check?.results || []).reduce((acc: Record<string, number>, r: any) => ({ ...acc, [r.status]: (acc[r.status] || 0) + 1 }), {} as Record<string, number>);
  const pills = ["Path", "Names", "Run", "Result"];

  return (
    <Card title="Set up AWS access">
      <p className="mb-3 text-sm text-zinc-400">
        One script does the whole onboarding: it creates the read-only role with the advisor's policy, the identity that assumes it, the SSM probe document, and points the advisor at the result.
        It runs in <em>your</em> terminal with <em>your</em> admin credentials; the advisor never receives them. Every step is skipped when the thing already exists, so rerunning is safe.
        {aws?.configured && <> Currently configured: <span className="text-zinc-200">{aws.label}</span>{aws.accountId ? ` (account ${aws.accountId})` : ""}; the wizard can still be used, it only adds what is missing.</>}
      </p>
      <div className="mb-4 flex flex-wrap gap-1 text-xs">
        {pills.map((p, i) => (
          <button key={p} type="button" disabled={i + 1 > step} onClick={() => setStep(i + 1)} className={`rounded px-2 py-1 ${i + 1 === step ? "bg-zinc-800 text-zinc-100" : i + 1 < step ? "text-zinc-300 hover:bg-zinc-800" : "text-zinc-600"}`}>
            {i + 1}. {p}
          </button>
        ))}
      </div>

      {step === 1 && (
        <div className="grid gap-3 md:grid-cols-2">
          {PATHS.map((p) => (
            <button key={p.id} type="button" onClick={() => { setPath(p.id); setStep(2); }} className={`rounded-lg border p-4 text-left hover:border-zinc-500 ${path === p.id ? "border-zinc-400 bg-zinc-800/60" : "border-zinc-700"}`}>
              <div className="text-sm font-medium text-zinc-100">{p.label}</div>
              <div className="mt-1 text-xs text-zinc-400">{p.hint}</div>
            </button>
          ))}
        </div>
      )}

      {step === 2 && path && (
        <form className="grid gap-3" onSubmit={(e) => { e.preventDefault(); setStep(3); }}>
          <div className="text-xs text-zinc-500">{PATHS.find((p) => p.id === path)!.label}: the defaults are fine; change them only when the names are taken.</div>
          <div className="grid gap-3 md:grid-cols-2">
            {path === "laptop-key" && <Field label="IAM user" value={f.user} onChange={(v) => set({ user: v })} pattern={NAME_RE} hint={`Its key goes under [${f.user || "aws-advisor"}-user] in ~/.aws/credentials`} />}
            <Field label="Read-only role" value={f.role} onChange={(v) => set({ role: v })} pattern={NAME_RE} hint="Gets the advisor's recommended policy" />
            {path === "laptop-key" && <Field label="AWS profile that assumes the role" value={f.profile} onChange={(v) => set({ profile: v })} pattern={NAME_RE} hint={`[profile ${f.profile || "aws-advisor"}] in ~/.aws/config; this is what the advisor is pointed at`} />}
            {path === "ec2-role" && <Field label="Instance role" value={f.instanceRole} onChange={(v) => set({ instanceRole: v })} pattern={NAME_RE} hint="The role the EC2 host runs with; created with an instance profile when missing, or an existing one" />}
            {path === "ec2-role" && <Field label="Instance id (optional)" value={f.instanceId} onChange={(v) => set({ instanceId: v })} pattern="^i-[0-9a-f]{8,17}$" placeholder="i-0123456789abcdef0" required={false} hint="Associates the instance profile with it (only if it has none) and sets the IMDS hop limit to 2" />}
            <Field label="Region" value={f.region} onChange={(v) => set({ region: v })} pattern="^[a-z]{2}(-[a-z0-9]+)+$" hint="Default region for the profile and the SSM document (documents are regional)" />
            <Field label="Admin profile (optional)" value={f.adminProfile} onChange={(v) => set({ adminProfile: v })} pattern={NAME_RE} placeholder="default profile" required={false} hint="--profile for the admin aws calls, when your admin credentials are not the terminal's default" />
          </div>
          <div className="flex gap-2">
            <Button type="button" variant="ghost" onClick={() => setStep(1)}>Back</Button>
            <Button type="submit">Show the plan</Button>
          </div>
        </form>
      )}

      {step === 3 && (
        <div className="grid gap-3">
          {err && <div className="text-sm text-red-300">{err}</div>}
          {!plan && !err && <div className="text-sm text-zinc-500">Loading the plan…</div>}
          {plan && (
            <>
              <div className="text-xs uppercase tracking-wide text-zinc-500">What the script does</div>
              <ol className="grid gap-1 text-sm">
                {plan.steps.map((s: any, i: number) => (
                  <li key={i} className="flex gap-2"><span className="w-5 shrink-0 text-right text-zinc-500">{i + 1}.</span><span><span className="text-zinc-200">{s.title}</span> <span className="text-zinc-500">— {s.detail}</span></span></li>
                ))}
              </ol>
              <div className="mt-1 flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs uppercase tracking-wide text-zinc-500">The command{dryRun ? " (dry run: prints what it would do, changes nothing)" : ""}</div>
                <label className="flex items-center gap-2 text-xs text-zinc-400"><input type="checkbox" checked={dryRun} onChange={(e) => setDryRun(e.target.checked)} /> Dry run</label>
              </div>
              <div className="flex items-start gap-2"><Code className="flex-1">{plan.command}</Code><CopyButton text={plan.command} /></div>
              <details className="text-xs text-zinc-500">
                <summary className="cursor-pointer">Or pipe it straight into bash (no reading first)</summary>
                <div className="mt-2 flex items-start gap-2"><Code className="flex-1">{plan.piped}</Code><CopyButton text={plan.piped} /></div>
              </details>
              <p className="text-xs text-zinc-500">
                Run it in a terminal that has <span className="text-zinc-300">admin credentials for the account</span> (<code className="text-zinc-300">aws sts get-caller-identity{f.adminProfile.trim() ? ` --profile ${f.adminProfile.trim()}` : ""}</code> must answer as an admin).
                The advisor itself never gets them: the script only calls back with the {path === "laptop-key" ? "profile name" : "role ARN"}. The read command opens the script in <code className="text-zinc-300">less</code> first (q to close, then it runs).
                {plan.protected && <> The URL carries a one-hour token because the API is protected.</>} Needs <code className="text-zinc-300">aws</code>, <code className="text-zinc-300">curl</code> and, for readable output, <code className="text-zinc-300">python3</code>.
              </p>
              <div className="flex flex-wrap gap-2">
                <Button type="button" variant="ghost" onClick={() => setStep(2)}>Back</Button>
                <a className="rounded border border-zinc-700 px-3 py-1.5 text-sm font-medium text-zinc-200 hover:bg-zinc-800" href={plan.scriptUrl} download="aws-advisor-setup.sh">Download script</a>
                <Button type="button" onClick={() => setStep(4)}>I ran it, wait for the result</Button>
              </div>
            </>
          )}
        </div>
      )}

      {step === 4 && (
        <div className="grid gap-3 text-sm">
          {!saved && (
            <div className="flex items-center gap-2 text-zinc-400"><span className="inline-block h-2 w-2 animate-pulse rounded-full bg-amber-400" /> Waiting for the script… (checking every 5 s{dryRun ? "; note the command is a dry run, it will not save anything" : ""})</div>
          )}
          {saved && saved.ok && (
            <div className="rounded border border-emerald-500/30 bg-emerald-500/10 p-3 text-emerald-300">
              Connected: account <span className="font-medium">{saved.meta.accountId}</span>, mode <span className="font-medium">{saved.meta.mode === "profile" ? `AWS profile ${saved.meta.profile}` : saved.meta.mode === "chain" ? `Instance / default chain${saved.meta.roleArn ? ` assuming ${saved.meta.roleArn}` : ""}` : saved.meta.label}</span>, saved {when(saved.meta.savedAt)}.
            </div>
          )}
          {saved && !saved.ok && (
            <div className="rounded border border-amber-500/30 bg-amber-500/10 p-3 text-amber-300">
              The script saved the settings ({saved.meta.label}) but the connection test did not pass yet. Look at the script's output; for the EC2 path that is expected when the advisor is not running on the instance. "Test again" in the credentials card below retries.
              <div className="mt-2"><Button type="button" variant="ghost" onClick={() => setSaved(null)}>Keep waiting</Button></div>
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" onClick={runCheck} disabled={checking || !saved?.ok}>{checking ? "Checking…" : "Check permissions"}</Button>
            <Button type="button" variant="ghost" onClick={() => setStep(3)}>Back to the command</Button>
            <Button type="button" variant="ghost" onClick={restart}>Start over</Button>
          </div>
          {err && <div className="text-red-300">{err}</div>}
          {check && (
            <div className={`rounded border p-3 ${check.missing?.length || check.credentials_error ? "border-amber-500/30 text-amber-300" : "border-emerald-500/30 text-emerald-300"}`}>
              {counts.ok || 0} ok, {counts.missing || 0} missing, {counts.error || 0} errors, {counts.skipped || 0} skipped ({check.took_ms} ms).
              {check.credentials_error && <div className="mt-1">{check.credentials_error}</div>}
              {check.missing?.length > 0 && <div className="mt-1">Missing: <code>{check.missing.join(", ")}</code></div>}
              <div className="mt-1 text-xs text-zinc-500">The Permissions card below has the per-capability detail after a reload.</div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
}
