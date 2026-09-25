import { GetCommandInvocationCommand, SSMClient, SendCommandCommand } from "@aws-sdk/client-ssm";
import { config } from "./config.js";
import { recordContainerSamples } from "./history.js";
import { db } from "./db.js";
import { AWS_RUN_SHELL_SCRIPT, PermissionIssue, explainPermissionError, recordPermissionIssue, remedyFor, usesCustomProbeDocument } from "./permissions.js";
import { NoSdkCredentials, credentialRemedy } from "./aws_config.js";
import { S, credentialsMeta, query, sdkCredentials } from "./steampipe.js";
import { checkProbeQuota } from "./quota.js";
import { checkDiskLevels } from "./disk_alerts.js";
import { applyProbeDisks } from "./ebs_inventory.js";
import { checkHostLevels } from "./host_alerts.js";

/**
 * Read-only host probe through AWS Systems Manager Run Command. The script below is fixed and versioned:
 * it only reads /proc, /sys, df and ps, and prints exactly one JSON object as its last line. Tested on
 * Amazon Linux 2023 and Ubuntu 24.04 (needs procps `ps --sort`).
 */
export const PROBE_VERSION = "aws-advisor/1.3";

export const PROBE_SCRIPT = [
  "# aws-advisor probe v1 (read-only). Prints exactly one JSON object on the last line.",
  "set -u",
  "LC_ALL=C; export LC_ALL",
  "esc() { printf '%s' \"$1\" | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g'; }",
  "mem_total=$(awk '/^MemTotal:/{printf \"%.0f\", $2*1024}' /proc/meminfo)",
  "mem_avail=$(awk '/^MemAvailable:/{printf \"%.0f\", $2*1024}' /proc/meminfo)",
  "[ -n \"$mem_avail\" ] || mem_avail=$(awk '/^MemFree:/{f=$2} /^Buffers:/{b=$2} /^Cached:/{c=$2} END{printf \"%.0f\", (f+b+c)*1024}' /proc/meminfo)",
  "mem_used=$((mem_total - mem_avail))",
  "swap_total=$(awk '/^SwapTotal:/{printf \"%.0f\", $2*1024}' /proc/meminfo)",
  "swap_free=$(awk '/^SwapFree:/{printf \"%.0f\", $2*1024}' /proc/meminfo)",
  "swap_used=$((swap_total - swap_free))",
  "read l1 l5 l15 rest < /proc/loadavg",
  "cpus=$(nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo)",
  "uptime_s=$(cut -d. -f1 /proc/uptime)",
  "# Which disk a mounted filesystem sits on: the partition's parent (or a device-mapper volume's single slave), then",
  "# the EBS volume id from the NVMe serial on Nitro (\"vol0123...\" -> \"vol-0123...\"); Xen disks have no serial, so",
  "# only the device name (xvda) is reported and the advisor matches it to the attachment (/dev/sda1).",
  "blk_of() { d=$(basename \"$(readlink -f \"$1\" 2>/dev/null || printf '%s' \"$1\")\"); [ -e \"/sys/class/block/$d\" ] || return 0",
  "  [ -e \"/sys/class/block/$d/partition\" ] && d=$(basename \"$(dirname \"$(readlink -f \"/sys/class/block/$d\")\")\")",
  "  if [ \"$(ls \"/sys/class/block/$d/slaves\" 2>/dev/null | wc -l | tr -d ' ')\" = 1 ]; then d=$(ls \"/sys/class/block/$d/slaves\"); [ -e \"/sys/class/block/$d/partition\" ] && d=$(basename \"$(dirname \"$(readlink -f \"/sys/class/block/$d\")\")\"); fi",
  "  printf '%s' \"$d\"; }",
  "vol_of() { s=$(tr -d ' ' < \"/sys/class/block/$1/device/serial\" 2>/dev/null); case \"$s\" in vol*) printf 'vol-%s' \"${s#vol}\";; esac; }",
  "jstr() { if [ -n \"$1\" ]; then printf '\"%s\"' \"$(esc \"$1\")\"; else printf 'null'; fi; }",
  "n=\"\"",
  "disks=$(df -P -k 2>/dev/null | awk 'NR>1 && $1 !~ /^(tmpfs|devtmpfs|udev|overlay|squashfs|shm|none)$/ && $1 !~ /^\\/dev\\/loop/ && $2 > 0 {print $1 \"\\t\" $2 \"\\t\" $3 \"\\t\" $6}' | while IFS=\"$(printf '\\t')\" read -r f t u m; do",
  "  b=$(blk_of \"$f\"); v=\"\"; [ -n \"$b\" ] && v=$(vol_of \"$b\")",
  "  printf '%s{\"mount\":%s,\"filesystem\":%s,\"device\":%s,\"volume_id\":%s,\"total_bytes\":%.0f,\"used_bytes\":%.0f,\"used_pct\":%s}' \"$n\" \"$(jstr \"$m\")\" \"$(jstr \"$f\")\" \"$(jstr \"$b\")\" \"$(jstr \"$v\")\" \"$((t*1024))\" \"$((u*1024))\" \"$(awk -v u=\"$u\" -v t=\"$t\" 'BEGIN{printf \"%.1f\", u*100/t}')\"; n=\",\"",
  "done)",
  "pslist() { ps -eo pid,pcpu,pmem,rss,comm --sort=\"$1\" 2>/dev/null | awk 'NR>1 && NR<=6 {",
  "  c=$5; for(i=6;i<=NF;i++) c=c\" \"$i; gsub(/\\\\/,\"\\\\\\\\\",c); gsub(/\"/,\"\\\\\\\"\",c);",
  "  printf \"%s{\\\"pid\\\":%d,\\\"cpu_pct\\\":%.1f,\\\"mem_pct\\\":%.1f,\\\"rss_bytes\\\":%.0f,\\\"command\\\":\\\"%s\\\"}\", (n++?\",\":\"\"), $1, $2, $3, $4*1024, c }'; }",
  "top_cpu=$(pslist -pcpu)",
  "top_mem=$(pslist -rss)",
  "containers=\"[]\"; docker_json='{\"available\":false,\"running\":0,\"total\":0}'",
  "if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then",
  "  stats=$(docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}' 2>/dev/null || true)",
  "  clist=$(docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.State}}\t{{.RunningFor}}' 2>/dev/null | head -40 | awk -F'\\t' -v stats=\"$stats\" 'BEGIN{ k=split(stats, L, \"\\n\"); for(i=1;i<=k;i++){ split(L[i],a,\"\\t\"); cpu[a[1]]=a[2]; mem[a[1]]=a[3]; memp[a[1]]=a[4] } }",
  "    function esc(x){ gsub(/\\\\/,\"\\\\\\\\\",x); gsub(/\"/,\"\\\\\\\"\",x); return x }",
  "    function bytes(x,  v,u){ sub(/ \\/.*/,\"\",x); v=x+0; u=x; sub(/^[0-9.]+/,\"\",u); if(u==\"KiB\"||u==\"kB\"||u==\"KB\")v*=1024; else if(u==\"MiB\"||u==\"MB\")v*=1048576; else if(u==\"GiB\"||u==\"GB\")v*=1073741824; return v }",
  "    { n++; c=cpu[$1]; sub(/%/,\"\",c); mp=memp[$1]; sub(/%/,\"\",mp);",
  "      printf \"%s{\\\"name\\\":\\\"%s\\\",\\\"image\\\":\\\"%s\\\",\\\"state\\\":\\\"%s\\\",\\\"running_for\\\":\\\"%s\\\",\\\"cpu_pct\\\":%s,\\\"mem_bytes\\\":%.0f,\\\"mem_pct\\\":%s}\", (n>1?\",\":\"\"), esc($1), esc($2), esc($3), esc($4), (c==\"\"?\"null\":c), bytes(mem[$1]), (mp==\"\"?\"null\":mp) }')",
  "  containers=\"[$clist]\"",
  "  running=$(docker ps -q 2>/dev/null | wc -l | tr -d ' '); total=$(docker ps -aq 2>/dev/null | wc -l | tr -d ' ')",
  "  docker_json=\"{\\\"available\\\":true,\\\"running\\\":${running:-0},\\\"total\\\":${total:-0}}\"",
  "fi",
  "printf '{\"probe\":\"aws-advisor/1\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"cpus\":%s,\"uptime_seconds\":%s,\"memory\":{\"total_bytes\":%s,\"used_bytes\":%s,\"available_bytes\":%s,\"swap_total_bytes\":%s,\"swap_used_bytes\":%s},\"load\":{\"1m\":%s,\"5m\":%s,\"15m\":%s},\"disks\":[%s],\"top_cpu\":[%s],\"top_mem\":[%s],\"docker\":%s,\"containers\":%s}\\n' \\",
  "  \"$(esc \"$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)\")\" \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"${cpus:-0}\" \"${uptime_s:-0}\" \\",
  "  \"${mem_total:-0}\" \"${mem_used:-0}\" \"${mem_avail:-0}\" \"${swap_total:-0}\" \"${swap_used:-0}\" \"$l1\" \"$l5\" \"$l15\" \"$disks\" \"$top_cpu\" \"$top_mem\" \"$docker_json\" \"$containers\""
].join("\n");

/**
 * The SSM Command document that embeds the probe script, for `aws ssm create-document`. With
 * PROBE_DOCUMENT set to its name the advisor sends it instead of AWS-RunShellScript and passes no
 * commands, so IAM can grant ssm:SendCommand on this document only and the credentials can never run
 * anything else on the fleet. Served by GET /api/probe/document.
 */
export function probeDocument() {
  return {
    schemaVersion: "2.2",
    description: `aws-advisor read-only probe ${PROBE_VERSION}`,
    mainSteps: [
      {
        action: "aws:runShellScript",
        name: "probe",
        inputs: { timeoutSeconds: "60", runCommand: PROBE_SCRIPT.split("\n") },
      },
    ],
  };
}

/** Name and, when custom, the CLI commands that create and update the document from GET /api/probe/document. */
export function probeDocumentInfo() {
  const name = config.probeDocument;
  const custom = usesCustomProbeDocument();
  return {
    name,
    custom,
    version: PROBE_VERSION,
    create_command: `curl -s ${config.publicUrl}/api/probe/document > probe-document.json && aws ssm create-document --name ${custom ? name : "AwsAdvisorProbe"} --document-type Command --document-format JSON --content file://probe-document.json`,
    update_command: `curl -s ${config.publicUrl}/api/probe/document > probe-document.json && aws ssm update-document --name ${custom ? name : "AwsAdvisorProbe"} --document-version '$LATEST' --document-format JSON --content file://probe-document.json && aws ssm update-document-default-version --name ${custom ? name : "AwsAdvisorProbe"} --document-version "$(aws ssm describe-document --name ${custom ? name : "AwsAdvisorProbe"} --query Document.LatestVersion --output text)"`,
  };
}

/** device is the whole disk in sysfs terms (nvme0n1, xvda); volume_id the EBS volume read from the NVMe serial, null on Xen and for anything that is not EBS. Both absent from probes before 1.3. */
export interface ProbeDisk { mount: string; filesystem: string; device?: string | null; volume_id?: string | null; total_bytes: number; used_bytes: number; used_pct: number }
export interface ProbeProcess { pid: number; cpu_pct: number; mem_pct: number; rss_bytes: number; command: string }
export interface ProbeContainer { name: string; image: string; state: string; running_for: string; cpu_pct: number | null; mem_bytes: number; mem_pct: number | null }

export interface ProbeResult {
  probe: string;
  hostname: string;
  collected_at: string;
  cpus: number;
  uptime_seconds: number;
  memory: { total_bytes: number; used_bytes: number; available_bytes: number; swap_total_bytes: number; swap_used_bytes: number };
  load: { "1m": number; "5m": number; "15m": number };
  disks: ProbeDisk[];
  top_cpu: ProbeProcess[];
  top_mem: ProbeProcess[];
  /** Present from probe 1.2: Docker daemon state and the containers on the box (running and stopped, up to 40). */
  docker?: { available: boolean; running: number; total: number };
  containers?: ProbeContainer[];
}

/** Compact view of a probe used by the idle-instance rule and the UI. */
export interface ProbeSummary {
  collected_at: string;
  memory_used_pct: number;
  memory_total_gb: number;
  memory_used_gb: number;
  load_1m: number;
  cpus: number;
  top_process: string | null;
  containers_running?: number | null;
  top_container?: string | null;
}

export type ProbeErrorCode = "no_credentials" | "not_managed" | "permission" | "timeout" | "failed" | "bad_output";

export class ProbeError extends Error {
  /** For code "permission": the missing IAM action and the statement that grants it (recorded in permission_issues). */
  issue?: PermissionIssue;
  constructor(public code: ProbeErrorCode, message: string, issue?: PermissionIssue) {
    super(message);
    this.name = "ProbeError";
    if (issue) this.issue = issue;
  }
}

/** HTTP status a ProbeError maps to in the API. */
export const probeErrorStatus = (e: ProbeError): number =>
  ({ no_credentials: 400, not_managed: 404, permission: 403, timeout: 504, failed: 502, bad_output: 502 })[e.code];

const num = (v: unknown, what: string): number => {
  const n = typeof v === "number" ? v : Number(v);
  if (!Number.isFinite(n)) throw new ProbeError("bad_output", `probe output: ${what} is not a number`);
  return n;
};

/** Parses the command's stdout: tolerates noise before the JSON line and validates the shape. */
export function parseProbeOutput(stdout: string): ProbeResult {
  const line = stdout.split("\n").map((l) => l.trim()).filter((l) => l.startsWith("{") && l.endsWith("}")).pop();
  if (!line) throw new ProbeError("bad_output", "probe output contained no JSON object");
  let raw: any;
  try { raw = JSON.parse(line); } catch (e: any) { throw new ProbeError("bad_output", `probe output is not valid JSON: ${e.message}`); }
  if (typeof raw?.probe !== "string" || !raw.probe.startsWith("aws-advisor/")) throw new ProbeError("bad_output", "probe output is not from the advisor probe");
  const proc = (p: any): ProbeProcess => ({ pid: num(p.pid, "pid"), cpu_pct: num(p.cpu_pct, "cpu_pct"), mem_pct: num(p.mem_pct, "mem_pct"), rss_bytes: num(p.rss_bytes, "rss_bytes"), command: String(p.command ?? "") });
  const disk = (d: any): ProbeDisk => ({ mount: String(d.mount ?? ""), filesystem: String(d.filesystem ?? ""), device: d.device == null ? null : String(d.device), volume_id: d.volume_id == null ? null : String(d.volume_id), total_bytes: num(d.total_bytes, "total_bytes"), used_bytes: num(d.used_bytes, "used_bytes"), used_pct: num(d.used_pct, "used_pct") });
  const m = raw.memory || {};
  const l = raw.load || {};
  return {
    probe: raw.probe,
    hostname: String(raw.hostname ?? ""),
    collected_at: String(raw.collected_at || new Date().toISOString()),
    cpus: num(raw.cpus, "cpus"),
    uptime_seconds: num(raw.uptime_seconds, "uptime_seconds"),
    memory: {
      total_bytes: num(m.total_bytes, "memory.total_bytes"), used_bytes: num(m.used_bytes, "memory.used_bytes"), available_bytes: num(m.available_bytes, "memory.available_bytes"),
      swap_total_bytes: num(m.swap_total_bytes ?? 0, "memory.swap_total_bytes"), swap_used_bytes: num(m.swap_used_bytes ?? 0, "memory.swap_used_bytes"),
    },
    load: { "1m": num(l["1m"], "load.1m"), "5m": num(l["5m"], "load.5m"), "15m": num(l["15m"], "load.15m") },
    disks: Array.isArray(raw.disks) ? raw.disks.map(disk) : [],
    top_cpu: Array.isArray(raw.top_cpu) ? raw.top_cpu.map(proc) : [],
    top_mem: Array.isArray(raw.top_mem) ? raw.top_mem.map(proc) : [],
    docker: raw.docker && typeof raw.docker === "object" ? { available: Boolean(raw.docker.available), running: Number(raw.docker.running || 0), total: Number(raw.docker.total || 0) } : undefined,
    containers: Array.isArray(raw.containers) ? raw.containers.map((c: any): ProbeContainer => ({
      name: String(c.name ?? ""), image: String(c.image ?? ""), state: String(c.state ?? ""), running_for: String(c.running_for ?? ""),
      cpu_pct: c.cpu_pct == null ? null : Number(c.cpu_pct), mem_bytes: Number(c.mem_bytes || 0), mem_pct: c.mem_pct == null ? null : Number(c.mem_pct),
    })) : undefined,
  };
}

export function summarizeProbe(p: ProbeResult): ProbeSummary {
  const gb = (b: number) => Math.round((b / 1024 ** 3) * 10) / 10;
  return {
    collected_at: p.collected_at,
    memory_used_pct: p.memory.total_bytes > 0 ? Math.round((100 * p.memory.used_bytes) / p.memory.total_bytes) : 0,
    memory_total_gb: gb(p.memory.total_bytes),
    memory_used_gb: gb(p.memory.used_bytes),
    load_1m: p.load["1m"],
    cpus: p.cpus,
    top_process: p.top_cpu[0]?.command || p.top_mem[0]?.command || null,
    containers_running: p.docker?.available ? p.docker.running : null,
    top_container: p.containers?.length ? [...p.containers].filter((c) => c.state === "running").sort((a, b) => (b.mem_bytes || 0) - (a.mem_bytes || 0))[0]?.name || null : null,
  };
}

export interface StoredProbe { id: number; instance_id: string; collected_at: string; data: ProbeResult }

type MetricsRow = { id: number; instance_id: string; collected_at: string; json: string };
const rowToProbe = (r: MetricsRow): StoredProbe => ({ id: r.id, instance_id: r.instance_id, collected_at: r.collected_at, data: JSON.parse(r.json) as ProbeResult });

export function latestProbe(instanceId: string): StoredProbe | null {
  const row = db.prepare("select id, instance_id, collected_at, json from instance_metrics where instance_id = ? order by id desc limit 1").get(instanceId) as MetricsRow | undefined;
  if (!row) return null;
  try { return rowToProbe(row); } catch { return null; }
}

/** Latest probe per instance, as summaries keyed by instance id (for the rules). */
export function latestProbeSummaries(): Record<string, ProbeSummary> {
  const rows = db.prepare("select id, instance_id, collected_at, json from instance_metrics where id in (select max(id) from instance_metrics group by instance_id)").all() as MetricsRow[];
  const out: Record<string, ProbeSummary> = {};
  for (const r of rows) {
    try { out[r.instance_id] = summarizeProbe(rowToProbe(r).data); } catch { /* skip malformed */ }
  }
  return out;
}

export function instanceMetrics(instanceId: string, limit = 20): StoredProbe[] {
  const rows = db.prepare("select id, instance_id, collected_at, json from instance_metrics where instance_id = ? order by id desc limit ?").all(instanceId, limit) as MetricsRow[];
  return rows.map(rowToProbe);
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sqlLit = (s: string) => `'${s.replace(/'/g, "''")}'`;

function classifyAwsError(e: any, instanceId: string, operation: "SendCommand" | "GetCommandInvocation"): ProbeError {
  const name: string = e?.name || e?.Code || "";
  const msg: string = e?.message || String(e);
  // A denial names the action in its message; when it does not (UnauthorizedOperation, AccessDeniedException alone), the context does.
  const issue = explainPermissionError(e, `ssm ${operation} ${instanceId} (ssm:${operation}, document ${config.probeDocument})`);
  if (issue) {
    recordPermissionIssue(issue);
    return new ProbeError("permission", `The advisor's AWS credentials cannot run SSM commands (${name || "AccessDenied"}); ssm:SendCommand on document ${config.probeDocument} and instance ${instanceId}, plus ssm:GetCommandInvocation, are required. ${msg.replace(/[.\s]+$/, "")}. ${remedyFor(issue)}`, issue);
  }
  if (/InvalidSignature|UnrecognizedClient|ExpiredToken|InvalidClientTokenId|SignatureDoesNotMatch|InvalidAccessKeyId|CredentialsProviderError|Could not load credentials|sso|Token is expired/i.test(`${name} ${msg}`)) {
    const meta = credentialsMeta();
    return new ProbeError("permission", `The advisor's AWS credentials were rejected by SSM (${name || "credential error"}); ${meta ? credentialRemedy(e, meta) : `save valid credentials in Settings. ${msg}`}`);
  }
  if (/InvalidInstanceId/i.test(name)) return new ProbeError("not_managed", `${instanceId} is not an SSM-managed instance or is not online (${msg})`);
  if (/InvalidDocument\b/i.test(name)) return new ProbeError("failed", `SSM document ${config.probeDocument} does not exist in this region or account; create it with the command on Settings > Permissions (GET /api/probe/document) or run the setup script. ${msg}`);
  return new ProbeError("failed", `${name ? name + ": " : ""}${msg}`);
}

/** Sends the probe to one SSM-managed instance, waits for it, parses and stores the result. */
export async function probeInstance(instanceId: string, opts: { timeoutMs?: number } = {}): Promise<StoredProbe> {
  if (!/^i-[0-9a-f]{8,17}$/.test(instanceId)) throw new ProbeError("not_managed", `"${instanceId}" is not an EC2 instance id`);
  checkProbeQuota(instanceId);
  // The same identity Steampipe uses (keys, profile or default chain, with the role when one is set), as an SDK provider.
  let creds: ReturnType<typeof sdkCredentials>;
  try { creds = sdkCredentials(); }
  catch (e: any) { throw new ProbeError("no_credentials", `${e instanceof NoSdkCredentials ? e.message : String(e?.message || e)}; the probe uses the credentials saved in Settings.`); }

  const managed = await query<{ ping_status: string; region: string; platform_type: string }>(
    `select ping_status, region, platform_type from ${S}.aws_ssm_managed_instance where instance_id = ${sqlLit(instanceId)} limit 1`);
  if (!managed.length) throw new ProbeError("not_managed", `${instanceId} is not registered with Systems Manager (no SSM agent, no instance profile, or outside the connection's regions)`);
  const m = managed[0];
  if (m.ping_status !== "Online") throw new ProbeError("not_managed", `${instanceId} is registered with SSM but its agent is ${m.ping_status}`);
  if (m.platform_type && m.platform_type !== "Linux") throw new ProbeError("not_managed", `${instanceId} runs ${m.platform_type}; the probe is Linux-only`);

  const client = new SSMClient({ region: m.region || creds.region, credentials: creds.provider });
  const timeoutMs = opts.timeoutMs ?? 90_000;
  try {
    let commandId = "";
    try {
      // A custom document embeds the script (see probeDocument()); only the stock document takes it as a parameter.
      const sent = await client.send(new SendCommandCommand({
        DocumentName: config.probeDocument,
        InstanceIds: [instanceId],
        ...(usesCustomProbeDocument() ? {} : { Parameters: { commands: [PROBE_SCRIPT], executionTimeout: ["60"] } }),
        TimeoutSeconds: 60,
        Comment: `aws-advisor probe ${PROBE_VERSION}`,
      }));
      commandId = sent.Command?.CommandId || "";
      if (!commandId) throw new ProbeError("failed", "SSM returned no command id");
    } catch (e: any) {
      if (e instanceof ProbeError) throw e;
      throw classifyAwsError(e, instanceId, "SendCommand");
    }

    const deadline = Date.now() + timeoutMs;
    let stdout = "";
    for (;;) {
      await sleep(2000);
      if (Date.now() > deadline) throw new ProbeError("timeout", `SSM command ${commandId} did not finish within ${Math.round(timeoutMs / 1000)}s`);
      let status = "";
      try {
        const inv = await client.send(new GetCommandInvocationCommand({ CommandId: commandId, InstanceId: instanceId }));
        status = inv.Status || "";
        if (status === "Success") { stdout = inv.StandardOutputContent || ""; break; }
        if (!["Pending", "InProgress", "Delayed", ""].includes(status)) {
          throw new ProbeError("failed", `SSM command ${commandId} ended with ${status}: ${(inv.StandardErrorContent || inv.StatusDetails || "").slice(0, 400)}`);
        }
      } catch (e: any) {
        if (e instanceof ProbeError) throw e;
        if (e?.name === "InvocationDoesNotExist") continue; // the invocation is not registered yet
        throw classifyAwsError(e, instanceId, "GetCommandInvocation");
      }
    }

    const data = parseProbeOutput(stdout);
    const collectedAt = data.collected_at;
    const id = Number(db.prepare("insert into instance_metrics(instance_id, collected_at, json) values (?, ?, ?)").run(instanceId, collectedAt, JSON.stringify(data)).lastInsertRowid);
    try { recordContainerSamples(instanceId, collectedAt, data); } catch (e: any) { console.error(`[probe] container samples not recorded for ${instanceId}: ${e?.message || e}`); }
    try { applyProbeDisks(instanceId, data.disks, collectedAt); } catch (e: any) { console.error(`[probe] disk usage not credited to volumes for ${instanceId}: ${e?.message || e}`); }
    try { const name = (db.prepare("select name from inventory_ec2 where instance_id = ?").get(instanceId) as { name: string | null } | undefined)?.name ?? null; checkDiskLevels(instanceId, name, data.disks as any, collectedAt); checkHostLevels(instanceId, name, id, collectedAt, data); } catch (e: any) { console.error(`[probe] disk or host levels not checked for ${instanceId}: ${e?.message || e}`); }
    return { id, instance_id: instanceId, collected_at: collectedAt, data };
  } finally {
    client.destroy();
  }
}
