/**
 * Whether a Linux box shows the conditions the two ksmbd advisories need: ZDI-CAN-33774 (pre-auth race in the
 * in-kernel SMB server) and ZDI-CAN-33549 (SMB Direct integer underflow). The reading comes from the software probe's
 * ksmbd section (src/probes.ts, software/4: module, service, listeners, RDMA devices, share definitions); the reach of
 * port 445 from the advisor's own port verdicts (src/instance_apps.ts); the kernel from the stored advisory matches.
 *
 * A verdict FLAGS, it never asserts. "flagged" means the conditions an advisory needs are present on the box; it does not
 * say the kernel is vulnerable, because ksmbd carries backports and the fixes are not in any version number we could
 * compare. "not_indicated" means a condition is missing on the box today. Patch status is never judged from a kernel
 * version: the only fix evidence used is a distribution advisory the existing feeds matched (software_vulns.ts), and
 * even that is reported with its caveats (the match covers installed packages, the running kernel may be another).
 * Pure functions at the top; the readers below only gather rows.
 */
import { db } from "./db.js";
import { ksmbdOf, type ProbeKsmbd } from "./software_inventory.js";
import { vulnerabilityMatches, type VulnMatch } from "./software_vulns.js";

export const ZDI_PRE_AUTH = "ZDI-CAN-33774";
export const ZDI_SMB_DIRECT = "ZDI-CAN-33549";
export const SMB_PORTS = [445, 139, 5445] as const;

export type KsmbdState = "unknown" | "not_present" | "present_not_loaded" | "loaded_not_serving" | "serving_internal" | "serving_exposed";
export type FlagStatus = "flagged" | "low" | "not_indicated" | "unknown";
export type Reach = "internet" | "network" | "group" | "closed" | "local";

export interface KsmbdPort { proto: string; port: number; scope: string; process: string | null; exposure: Reach | string | null }
export interface KernelAdvisory { vuln_id: string; cves: string[]; summary: string | null; package: string; packages: string[]; version: string; fixed_version: string | null }

export interface KsmbdFlag { id: string; status: FlagStatus; reasons: string[] }
export interface KsmbdVerdict {
  state: KsmbdState;
  /** ksmbd in the kernel and doing something: the module loaded (or built in with kernel threads) and a userspace or kernel worker seen. */
  active: boolean;
  shipped: boolean | null;
  smb_direct: { indicated: boolean; indicators: string[] };
  writable_shares: string[];
  listening: { port: number; scope: string; process: string | null; exposure: string | null; kernel_owned: boolean }[];
  flags: { pre_auth: KsmbdFlag; smb_direct: KsmbdFlag };
  /** What is and is not known about the kernel's fix status; never a version comparison. */
  kernel_note: string;
  notes: string[];
}

const REACHABLE: ReadonlySet<string> = new Set(["internet", "network", "group"]);
const RDMA_MODULES = ["rdma_rxe", "siw", "irdma", "mlx5_ib", "mlx4_ib"];

/** The running kernel's package among the packages a box has installed, by name (deb: linux-image-<release>) or version.arch (rpm). */
export function runningKernelPackage(kernel: string | null, pkgs: { name: string; version: string; arch?: string | null }[]): string | null {
  if (!kernel) return null;
  for (const p of pkgs) {
    if (p.name.endsWith(`-${kernel}`) && /(^|-)(linux|kernel)(-|$)/.test(p.name)) return p.name;
    if (/^kernel(-core)?$/.test(p.name) && (`${p.version}.${p.arch ?? ""}` === kernel || p.version === kernel || `${p.version.replace(/^\d+:/, "")}.${p.arch ?? ""}` === kernel)) return p.name;
  }
  return null;
}

/** The kernel note. `advisories` are the distribution advisories the feeds matched to this box's kernel packages that name ksmbd or SMB. */
export function kernelNote(kernel: string | null, running_pkg: string | null, advisories: KernelAdvisory[], shipped: boolean | null): string {
  const k = kernel ? `running kernel ${kernel}` : "running kernel unknown";
  if (shipped === false) return `${k}: no ksmbd in this kernel (not built, no module file), so the fix status does not matter here.`;
  if (!advisories.length) return `${k}: no distribution advisory naming ksmbd matched an installed kernel package. That is not evidence the kernel is fixed: the CVEs may not be published or the feed may lag or not cover this distribution (RHEL-family and SUSE are not matched). Fix status is not judged from the kernel version.`;
  const hit = advisories.map((a) => `${a.vuln_id}${a.fixed_version ? ` (fixed in ${a.fixed_version})` : ""}`).slice(0, 5).join(", ");
  if (running_pkg && advisories.some((a) => a.packages.includes(running_pkg))) return `${k}: the distribution lists ${hit} against the installed kernel package, which predates the fix the distribution published. If that package is the running one, the box is behind the fix; a reboot into a newer installed kernel may be pending. Not judged from the version string.`;
  return `${k}: the distribution lists ${hit} against an installed kernel package, but the running kernel's own package was not identified; the running kernel may be a different (older or newer) one than the matched package. Check whether a reboot is pending.`;
}

const noReading: KsmbdFlag = { id: "", status: "unknown", reasons: ["the software probe has not read ksmbd on this box yet (needs probe software/4 and its SSM document redeployed)"] };

/** The verdict from one box's ksmbd reading, its ports and the kernel advisories. Pure. */
export function ksmbdVerdict(input: { probe: ProbeKsmbd | null; ports: KsmbdPort[]; kernel: string | null; running_pkg?: string | null; advisories?: KernelAdvisory[] }): KsmbdVerdict {
  const k = input.probe;
  const advisories = input.advisories ?? [];
  if (!k) return {
    state: "unknown", active: false, shipped: null, smb_direct: { indicated: false, indicators: [] }, writable_shares: [], listening: [],
    flags: { pre_auth: { ...noReading, id: ZDI_PRE_AUTH }, smb_direct: { ...noReading, id: ZDI_SMB_DIRECT } },
    kernel_note: kernelNote(input.kernel, input.running_pkg ?? null, advisories, null), notes: [],
  };
  const modLoaded = k.module_loaded || k.modules.includes("ksmbd");
  const shipped = k.module_loaded || k.module_sysfs || k.module_file || k.builtin || k.config === "y" || k.config === "m" ? true : (k.config === "n" ? false : (k.config === null ? null : false));
  // ksmbd works when its module (or built-in code) is there and something drives it: kernel threads, or the userspace daemon ksmbd.mountd
  const present = modLoaded || k.module_sysfs;
  const daemon = k.daemons.includes("ksmbd.mountd");
  const active = present && (k.kthreads > 0 || daemon || k.listeners.some((l) => l.port === 445 && !l.process));
  const notes: string[] = [];
  // listeners: the probe's own reading, with the advisor's exposure verdict for the same port when it has one
  const listening = k.listeners.filter((l) => l.port === 445 || l.port === 139 || l.port === 5445).map((l) => {
    const seen = input.ports.find((p) => p.port === l.port && p.proto === "tcp");
    const exposure = seen?.exposure ?? (l.scope === "loopback" ? "local" : null);
    // a socket with no owning process on 445/139/5445 is a kernel one: ksmbd is the usual suspect (a user process shows its name)
    return { port: l.port, scope: l.scope, process: l.process, exposure, kernel_owned: !l.process };
  });
  const smb = listening.filter((l) => l.port === 445 || l.port === 139);
  const ksmbdListener = smb.filter((l) => l.kernel_owned || l.process === "ksmbd.mountd");
  const reachable = (l: { exposure: string | null; scope: string }) => (l.exposure ? REACHABLE.has(l.exposure) : l.scope !== "loopback");
  const serving = active && (ksmbdListener.length > 0 || (daemon && smb.length > 0));
  const servingReach = ksmbdListener.concat(daemon ? smb : []).some(reachable);
  const sambaListener = smb.some((l) => l.process === "smbd");
  if (sambaListener && !serving) notes.push("445 is owned by Samba (smbd), a userspace server: not ksmbd.");
  if (present && !active) notes.push("the ksmbd module is loaded but nothing drives it (no ksmbd kernel thread, no ksmbd.mountd).");
  if (k.autoload && !present) notes.push("ksmbd is set to load at boot (modules-load) but is not loaded now.");
  if (k.units_enabled.some((u) => u === "ksmbd")) notes.push("the ksmbd service is enabled at boot (wants symlink).");
  if (!k.conf_files.length && present) notes.push("no ksmbd.conf or smb.conf was readable: share definitions unknown.");

  let state: KsmbdState;
  if (serving) state = servingReach ? "serving_exposed" : "serving_internal";
  else if (active || present) state = "loaded_not_serving";
  else if (shipped === false) state = "not_present";
  else if (shipped === true) state = "present_not_loaded";
  else state = "not_present";

  const writable = k.shares.filter((s) => !s.read_only).map((s) => s.name);
  const indicators: string[] = [];
  if (k.rdma_devices.length) indicators.push(`RDMA device ${k.rdma_devices.slice(0, 3).join(", ")}`);
  const rm = k.modules.filter((m) => RDMA_MODULES.includes(m)); if (rm.length) indicators.push(`RDMA module ${rm.join(", ")}`);
  if (k.smb_direct_cfg === true) indicators.push("smb direct = yes in the share config");
  if (listening.some((l) => l.port === 5445)) indicators.push("tcp 5445 (iWARP SMB Direct) listening");
  const direct = indicators.length > 0;
  // SMB Direct needs an RDMA transport to attach to; a kernel built without SMB_SERVER_SMBDIRECT cannot do it
  const directBuilt = k.config_smbdirect !== "n";

  const pre: KsmbdFlag = { id: ZDI_PRE_AUTH, status: "not_indicated", reasons: [] };
  if (!present && shipped !== true) pre.reasons.push(shipped === false ? "this kernel has no ksmbd" : "ksmbd not loaded and no sign the kernel carries it");
  else if (!present) pre.reasons.push("ksmbd is shipped (module available) but not loaded; loading it and starting ksmbd.mountd would expose 445");
  else if (!active) pre.reasons.push("ksmbd module loaded, but no worker or daemon is running");
  else if (serving && servingReach) { pre.status = "flagged"; pre.reasons.push(`ksmbd is active and ${smb.filter(reachable).map((l) => `tcp ${l.port} (${l.exposure ?? l.scope})`).join(", ")} is reachable beyond the box: the conditions for a pre-auth bug are present`); }
  else if (serving) { pre.status = "low"; pre.reasons.push("ksmbd is active but its SMB port answers on loopback or is closed by the security group"); }
  else { pre.status = "low"; pre.reasons.push("ksmbd is active but no listener on 445/139 was seen (the listener may not be open yet, or the probe ran before ksmbd.mountd bound)"); }

  const dir: KsmbdFlag = { id: ZDI_SMB_DIRECT, status: "not_indicated", reasons: [] };
  if (!active) dir.reasons.push(!present ? "ksmbd not loaded" : "ksmbd loaded but not active");
  else if (!directBuilt) dir.reasons.push("this kernel is built without CONFIG_SMB_SERVER_SMBDIRECT");
  else if (!direct) dir.reasons.push("ksmbd is active, but no RDMA device, RDMA module or SMB Direct setting was seen (typical EC2 instances have none)");
  else if (writable.length) { dir.status = "flagged"; dir.reasons.push(`ksmbd is active with SMB Direct indicators (${indicators.join("; ")}) and writable share(s): ${writable.slice(0, 5).join(", ")}`); }
  else if (!k.conf_files.length) { dir.status = "low"; dir.reasons.push(`ksmbd is active with SMB Direct indicators (${indicators.join("; ")}) but share definitions could not be read, so a writable share is unknown`); }
  else { dir.status = "low"; dir.reasons.push(`ksmbd is active with SMB Direct indicators (${indicators.join("; ")}) but every defined share is read-only`); }

  return { state, active, shipped, smb_direct: { indicated: direct, indicators }, writable_shares: writable, listening, flags: { pre_auth: pre, smb_direct: dir }, kernel_note: kernelNote(input.kernel, input.running_pkg ?? null, advisories, shipped), notes };
}

// ---- readers ------------------------------------------------------------------------------------------------------

const KSMBD_WORDS = /ksmbd|smb[ _-]?server|cifs|smb2?|zdi-can-3(3774|3549)/i;

/** The distribution advisories matched to a box's kernel packages that name ksmbd or SMB. */
function kernelAdvisories(matches: VulnMatch[]): KernelAdvisory[] {
  return matches.filter((m) => m.scope === "kernel" && KSMBD_WORDS.test(`${m.summary ?? ""} ${m.cves.join(" ")} ${m.vuln_id}`))
    .map((m) => ({ vuln_id: m.vuln_id, cves: m.cves, summary: m.summary, package: m.package, packages: m.packages, version: m.version, fixed_version: m.fixed_version }));
}

export interface InstanceKsmbd { instance_id: string; instance_name: string | null; kernel: string | null; os: string | null; probed_at: string | null; reading: ProbeKsmbd | null; verdict: KsmbdVerdict; advisories: KernelAdvisory[] }

/** One box's ksmbd verdict from what is stored: the probe section, its port rows, its kernel packages and advisory matches. */
export function ksmbdOn(instanceId: string, matches?: VulnMatch[]): InstanceKsmbd {
  const os = db.prepare("select os_name, os_id, kernel from instance_os where instance_id = ?").get(instanceId) as { os_name: string | null; os_id: string | null; kernel: string | null } | undefined;
  const r = ksmbdOf(instanceId);
  const ports = db.prepare("select proto, port, scope, process, exposure from instance_ports where instance_id = ? and gone = 0 and port in (139, 445, 5445)").all(instanceId) as KsmbdPort[];
  const pkgs = db.prepare("select name, version, arch from instance_packages where instance_id = ? and gone = 0 and (name like '%linux%' or name like 'kernel%')").all(instanceId) as { name: string; version: string; arch: string | null }[];
  const adv = kernelAdvisories(matches ?? vulnerabilityMatches([instanceId]));
  const name = (db.prepare("select name from inventory_ec2 where instance_id = ?").get(instanceId) as { name: string | null } | undefined)?.name ?? null;
  const verdict = ksmbdVerdict({ probe: r?.probe ?? null, ports, kernel: os?.kernel ?? null, running_pkg: runningKernelPackage(os?.kernel ?? null, pkgs), advisories: adv });
  return { instance_id: instanceId, instance_name: name, kernel: os?.kernel ?? null, os: os?.os_name ?? os?.os_id ?? null, probed_at: r?.collected_at ?? null, reading: r?.probe ?? null, verdict, advisories: adv };
}

/** Every box the software probe has read, flagged ones first. `only` narrows to boxes with a flag. */
export function fleetKsmbd(opts: { only?: "flagged" | "active" | "all" } = {}): { summary: Record<string, number>; instances: InstanceKsmbd[] } {
  const ids = (db.prepare("select instance_id from instance_os").all() as { instance_id: string }[]).map((r) => r.instance_id);
  const matches = ids.length ? vulnerabilityMatches(ids) : [];
  const by = new Map<string, VulnMatch[]>(); for (const m of matches) by.set(m.instance_id, [...(by.get(m.instance_id) ?? []), m]);
  const rank: Record<FlagStatus, number> = { flagged: 0, low: 1, unknown: 2, not_indicated: 3 };
  const all = ids.map((id) => ksmbdOn(id, by.get(id) ?? []));
  const worst = (i: InstanceKsmbd) => Math.min(rank[i.verdict.flags.pre_auth.status], rank[i.verdict.flags.smb_direct.status]);
  const summary: Record<string, number> = { instances: all.length, never_read: 0, pre_auth_flagged: 0, smb_direct_flagged: 0 };
  for (const i of all) {
    summary[i.verdict.state] = (summary[i.verdict.state] ?? 0) + 1;
    if (i.verdict.state === "unknown") summary.never_read++;
    if (i.verdict.flags.pre_auth.status === "flagged") summary.pre_auth_flagged++;
    if (i.verdict.flags.smb_direct.status === "flagged") summary.smb_direct_flagged++;
  }
  const keep = (i: InstanceKsmbd) => (opts.only === "all" ? true : opts.only === "active" ? i.verdict.active : worst(i) === 0);
  return { summary, instances: all.filter(keep).sort((a, b) => worst(a) - worst(b) || a.instance_id.localeCompare(b.instance_id)) };
}
