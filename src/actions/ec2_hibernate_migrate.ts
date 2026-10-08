/**
 * Making an EC2 instance hibernation-ready. Hibernation can only be turned on when an instance is launched, and
 * the root volume must be encrypted and large enough to hold the RAM, so the only way there is a new instance:
 * an image of the old one, launched with HibernationOptions.Configured and every EBS mapping encrypted (the
 * launch encrypts from an unencrypted snapshot, so there is no CopyImage), then the Elastic IP, the A records
 * that named the old addresses and the target group registrations moved across. The old instance is stopped,
 * never terminated: it is what Revert goes back to, tagged advisor:migrated-to so nothing plans on it again.
 *
 * Opt-in by tag, `advisor:hibernate`:
 *   stop  downtime is fine: stop → image → launch → move. Downtime is the whole image of the disks.
 *   live  downtime is not: a warm image is taken with no reboot while the box runs; the cut-over (stop → a
 *         second image, incremental over the warm one so minutes, not hours → launch → move) waits for a person
 *         to click Cut over. The warm image is only crash-consistent, which is why the final one is taken stopped.
 *
 * A staged change (src/executor.ts `advance`): apply starts it, the driver moves it stage by stage, and the row
 * stays `applied` until the new box passes its status checks and everything is moved. The images are kept.
 */
import {
  AssociateAddressCommand, CreateImageCommand, CreateTagsCommand, DeleteTagsCommand, DescribeAddressesCommand, DescribeImagesCommand, DescribeInstanceAttributeCommand,
  DescribeInstanceCreditSpecificationsCommand, DescribeInstancesCommand, DescribeInstanceStatusCommand, DescribeInstanceTypesCommand, DescribeVolumesCommand,
  EC2Client, StartInstancesCommand, StopInstancesCommand, type BlockDeviceMapping, type Image, type Instance, type InstanceTypeInfo, type RunInstancesCommandInput, RunInstancesCommand, type Tag,
} from "@aws-sdk/client-ec2";
import { DeregisterTargetsCommand, DescribeTargetGroupsCommand, DescribeTargetHealthCommand, ElasticLoadBalancingV2Client, RegisterTargetsCommand } from "@aws-sdk/client-elastic-load-balancing-v2";
import { ChangeResourceRecordSetsCommand, Route53Client } from "@aws-sdk/client-route-53";
import type { AwsCredentialIdentityProvider } from "@aws-sdk/types";
import { db } from "../db.js";
import { config } from "../config.js";
import type { ActionModule, Advance, Creds, Proposal } from "../executor.js";
import { guestHibernation } from "../guest_hibernation.js";
import { recordsNamingIp, upsertChange, IP_WAIT_MS, type DnsRecord } from "./schedule_hours.js";

export const KIND = "ec2_hibernate_migrate" as const;
export const HIBERNATE_TAG = "advisor:hibernate";
/** `advisor:hibernate=no`: the owner keeps stop/start; parking never hibernates the box and the page stops suggesting the migration. */
export const NO_HIBERNATE = "no";
export const MIGRATED_TO_TAG = "advisor:migrated-to";
export const MIGRATED_FROM_TAG = "advisor:migrated-from";
/** AWS limits for hibernation: RAM of the instance, Linux and Windows. */
export const MAX_RAM_GIB_LINUX = 150;
export const MAX_RAM_GIB_WINDOWS = 16;
export const EBS_GP3_USD_GB_MONTH = 0.08;
/** A migration someone reverted is not proposed again for this long: the revert says something did not work. */
export const REVERT_COOLDOWN_DAYS = 7;
/** Tags that are not carried to the new instance: AWS's own, the opt-in (the new box is done) and the markers of other actions. */
const DROP_TAGS = /^(aws:|advisor:hibernate$|advisor:parked$|advisor:migrated-)/;

export type Mode = "stop" | "live";
export type Stage = "warm_image" | "awaiting_cutover" | "stopping_old" | "final_image" | "launching" | "done" | "reverted";

export interface Candidate {
  mode: Mode | null; tag_value: string | null; state: string; hands_off: boolean; configured: boolean; root_device_type: string | null; spot: boolean;
  managed_by: string | null; enis: number; private_ips: number; source_dest_check: boolean; instance_store: boolean;
  type_supports: boolean | null; ram_gib: number | null; windows: boolean; migrated_to: string | null; in_flight: boolean;
  /** When a migration of it was last reverted, if within REVERT_COOLDOWN_DAYS. */
  reverted_at?: string | null;
  /** AdvisorAutoPark=ON: the box has an Auto-park grant, which is where the actuator's right to re-point its A records lives. */
  auto_park?: boolean;
  /** The A record names that name the box's addresses now (what the relaunch moves). */
  dns_names?: string[];
  /** Why the guest OS cannot finish a hibernate (src/guest_hibernation.ts), when the software probe saw it cannot: the relaunch keeps the OS as it is. */
  guest_reason?: string | null;
}

/** Why an instance cannot be migrated as it is, or null. Pure. */
export function skipReason(c: Candidate): string | null {
  if (!c.mode) return c.tag_value === NO_HIBERNATE ? `${HIBERNATE_TAG}=${NO_HIBERNATE}: the owner keeps stop/start` : c.tag_value != null ? `${HIBERNATE_TAG}=${c.tag_value}: expected "stop" (downtime fine), "live" (warm image, cut-over on a click) or "${NO_HIBERNATE}" (keep stop/start)` : `not tagged ${HIBERNATE_TAG}`;
  if (c.hands_off) return "tagged advisor:hands-off";
  if (c.migrated_to) return `already migrated to ${c.migrated_to} (this is the stopped original, kept for Revert)`;
  if (c.configured) return `already hibernation-ready (launched with hibernation on); remove the ${HIBERNATE_TAG} tag`;
  if (c.in_flight) return "a migration of it is under way";
  if (c.guest_reason) return `the guest cannot hibernate (${c.guest_reason}); the relaunch keeps the OS as it is, so fix that first`;
  // the relaunch re-points the A records at the new box, and the actuator may touch exactly the records in the instance's Auto-park grant
  if (c.dns_names?.length && !c.auto_park) return `${c.dns_names.length} A record${c.dns_names.length > 1 ? "s" : ""} (${c.dns_names.join(", ")}) would move to the new box, and the actuator may re-point them only through the Auto-park grant: switch Auto-park on first`;
  if (c.reverted_at) return `a migration was reverted ${c.reverted_at.slice(0, 16)} UTC: not proposed again for ${REVERT_COOLDOWN_DAYS} days (remove the tag to stop it for good)`;
  if (c.state !== "running" && !(c.mode === "stop" && c.state === "stopped")) return `state ${c.state}${c.mode === "live" ? " (a live migration needs it running)" : ""}`;
  if (c.root_device_type !== "ebs") return "root device is not EBS";
  if (c.spot) return "a Spot instance: its request would have to be recreated, not the instance";
  if (c.managed_by) return `managed by ${c.managed_by}: turn hibernation on in its launch template instead`;
  if (c.enis > 1) return `${c.enis} network interfaces: only single-interface instances are moved`;
  if (c.private_ips > 1) return `${c.private_ips} private addresses on the interface: only the primary one is carried`;
  if (!c.source_dest_check) return "source/destination check is off (a NAT or router box): move it by hand";
  if (c.instance_store) return "the type has instance-store volumes: their data does not come across";
  if (c.type_supports === false) return "the instance type does not support hibernation (the migration keeps the type)";
  const limit = c.windows ? MAX_RAM_GIB_WINDOWS : MAX_RAM_GIB_LINUX;
  if (c.ram_gib != null && c.ram_gib > limit) return `${c.ram_gib} GiB of RAM: hibernation stops at ${limit} GiB on ${c.windows ? "Windows" : "Linux"}`;
  return null;
}

/**
 * The root volume size that holds the RAM on top of what is on the disk now, with a GiB to spare. With the
 * probe's used percentage the growth is only what is missing; without it the RAM is added whole. Pure.
 */
export function rootTargetGib(sizeGib: number, ramGib: number, usedPct: number | null): number {
  const ram = Math.ceil(ramGib);
  if (usedPct == null || !Number.isFinite(usedPct)) return sizeGib + ram;
  const used = (sizeGib * Math.min(100, Math.max(0, usedPct))) / 100;
  return Math.max(sizeGib, Math.ceil(used + ram + 1));
}

/** The launch mappings: every EBS mapping of the image encrypted, the root grown to `rootGib`, ephemeral ones dropped. Pure. */
export function launchMappings(image: Pick<Image, "BlockDeviceMappings" | "RootDeviceName">, rootGib: number): BlockDeviceMapping[] {
  return (image.BlockDeviceMappings ?? []).filter((m) => m.Ebs).map((m) => {
    const { OutpostArn: _o, AvailabilityZone: _a, ...ebs } = m.Ebs as any;
    const root = m.DeviceName === image.RootDeviceName;
    return { DeviceName: m.DeviceName, Ebs: { ...ebs, Encrypted: true, ...(root ? { VolumeSize: Math.max(rootGib, Number(ebs.VolumeSize) || 0) } : {}) } };
  });
}

/** The tags the new instance and its volumes get: the old instance's, minus AWS's own and the opt-in, plus where it came from. Pure. */
export function carriedTags(tags: Tag[] | undefined, oldId: string, actionRef: string): Tag[] {
  const kept = (tags ?? []).filter((t) => t.Key && !DROP_TAGS.test(t.Key));
  return [...kept, { Key: MIGRATED_FROM_TAG, Value: oldId }, { Key: "advisor:hibernate-migration", Value: actionRef }];
}

/** The RunInstances call that recreates the old instance from the image with hibernation on. Pure. */
export function launchInput(old: Instance, image: Pick<Image, "ImageId" | "BlockDeviceMappings" | "RootDeviceName">, f: Record<string, any>, clientToken: string): RunInstancesCommandInput {
  const eni = old.NetworkInterfaces?.[0];
  const tags = carriedTags(old.Tags, old.InstanceId!, clientToken);
  return {
    ImageId: image.ImageId, InstanceType: old.InstanceType, MinCount: 1, MaxCount: 1, ClientToken: clientToken,
    KeyName: old.KeyName, EbsOptimized: old.EbsOptimized, Monitoring: { Enabled: old.Monitoring?.State === "enabled" },
    ...(old.IamInstanceProfile?.Arn ? { IamInstanceProfile: { Arn: old.IamInstanceProfile.Arn } } : {}),
    NetworkInterfaces: [{
      DeviceIndex: 0, SubnetId: old.SubnetId, Groups: (old.SecurityGroups ?? []).map((g) => g.GroupId!).filter(Boolean),
      // An Elastic IP is moved across afterwards; a plain public address is asked for again (it will differ, and the A records follow).
      AssociatePublicIpAddress: Boolean(old.PublicIpAddress) && !f.eip,
      ...(eni?.Ipv6Addresses?.length ? { Ipv6AddressCount: eni.Ipv6Addresses.length } : {}),
    }],
    Placement: { ...(old.Placement?.Tenancy && old.Placement.Tenancy !== "default" ? { Tenancy: old.Placement.Tenancy } : {}), ...(old.Placement?.GroupName ? { GroupName: old.Placement.GroupName } : {}) },
    ...(old.MetadataOptions ? { MetadataOptions: { HttpTokens: old.MetadataOptions.HttpTokens, HttpEndpoint: old.MetadataOptions.HttpEndpoint, HttpPutResponseHopLimit: old.MetadataOptions.HttpPutResponseHopLimit, InstanceMetadataTags: old.MetadataOptions.InstanceMetadataTags } } : {}),
    ...(f.cpu_credits ? { CreditSpecification: { CpuCredits: f.cpu_credits } } : {}),
    ...(f.termination_protection ? { DisableApiTermination: true } : {}),
    HibernationOptions: { Configured: true },
    BlockDeviceMappings: launchMappings(image, Number(f.root_target_gib) || 0),
    TagSpecifications: [{ ResourceType: "instance", Tags: tags }, { ResourceType: "volume", Tags: tags }],
  };
}

/** The address a recorded A record should name after the move: the new public one for a record of the old public address, the new private one for the private. Pure. */
export function movedIp(r: Pick<DnsRecord, "old_ip">, from: { public_ip?: string | null; private_ip?: string | null }, to: { public_ip?: string | null; private_ip?: string | null }): string | null {
  if (from.public_ip && r.old_ip === from.public_ip) return to.public_ip ?? null;
  if (from.private_ip && r.old_ip === from.private_ip) return to.private_ip ?? null;
  return null;
}

// ---- AWS helpers -------------------------------------------------------------------------------------------------------

const tagOf = (i: Instance, key: string) => i.Tags?.find((t) => t.Key === key)?.Value ?? null;
const hasTag = (i: Instance, key: string) => Boolean(i.Tags?.some((t) => t.Key === key));
const gib = (mib: number | undefined) => (mib ? Math.round((mib / 1024) * 10) / 10 : null);

/** What the eligibility rules (skipReason) need about one instance, from EC2's view of it, its type and the ledger. */
export function candidateFor(inst: Instance, t: InstanceTypeInfo | undefined, poolKind: string | null, instanceId: string): Candidate {
  const tagValue = tagOf(inst, HIBERNATE_TAG);
  const inFlight = Boolean(db.prepare("select 1 from actions where kind = ? and resource = ? and (status = 'applied' or (status = 'failed' and json_extract(facts_json, '$.stage') is not null and json_extract(facts_json, '$.stage') != 'reverted')) limit 1").get(KIND, instanceId));
  return {
    mode: tagValue === "stop" || tagValue === "live" ? tagValue : null, tag_value: tagValue, state: String(inst.State?.Name), hands_off: hasTag(inst, "advisor:hands-off"),
    configured: Boolean(inst.HibernationOptions?.Configured), root_device_type: inst.RootDeviceType ?? null, spot: inst.InstanceLifecycle === "spot",
    managed_by: poolKind ? `a ${poolKind} pool` : tagOf(inst, "aws:autoscaling:groupName") ? `Auto Scaling group ${tagOf(inst, "aws:autoscaling:groupName")}` : tagOf(inst, "elasticbeanstalk:environment-name") ? `Beanstalk ${tagOf(inst, "elasticbeanstalk:environment-name")}` : null,
    enis: inst.NetworkInterfaces?.length ?? 1, private_ips: inst.NetworkInterfaces?.[0]?.PrivateIpAddresses?.length ?? 1, source_dest_check: inst.SourceDestCheck !== false,
    instance_store: Boolean(t?.InstanceStorageSupported), type_supports: t ? Boolean(t.HibernationSupported) : null, ram_gib: gib(t?.MemoryInfo?.SizeInMiB),
    windows: /windows/i.test(inst.PlatformDetails || inst.Platform || ""), migrated_to: tagOf(inst, MIGRATED_TO_TAG), in_flight: inFlight,
    auto_park: /^(on|true|yes|1)$/i.test(tagOf(inst, "AdvisorAutoPark") ?? ""),
    dns_names: [...new Set([...recordsNamingIp(inst.PublicIpAddress), ...recordsNamingIp(inst.PrivateIpAddress)].map((r) => r.name))].sort(),
    reverted_at: (db.prepare("select reverted_at from actions where kind = ? and resource = ? and status = 'reverted' and datetime(reverted_at) > datetime('now', ?) order by id desc limit 1").get(KIND, instanceId, `-${REVERT_COOLDOWN_DAYS} days`) as { reverted_at: string } | undefined)?.reverted_at ?? null,
  };
}

async function describe(ec2: EC2Client, id: string): Promise<Instance | null> {
  return (await ec2.send(new DescribeInstancesCommand({ InstanceIds: [id] }))).Reservations?.[0]?.Instances?.[0] ?? null;
}
async function imageOf(ec2: EC2Client, id: string): Promise<Image | null> {
  return (await ec2.send(new DescribeImagesCommand({ ImageIds: [id] }))).Images?.[0] ?? null;
}

/** The instance-type target groups the instance is registered in, with the port of each registration. */
async function targetsOf(region: string, read: AwsCredentialIdentityProvider, instanceId: string): Promise<{ arn: string; port: number | null }[]> {
  const elb = new ElasticLoadBalancingV2Client({ region, credentials: read });
  const out: { arn: string; port: number | null }[] = [];
  try {
    let marker: string | undefined;
    do {
      const page = await elb.send(new DescribeTargetGroupsCommand({ Marker: marker }));
      for (const tg of page.TargetGroups ?? []) {
        if (tg.TargetType !== "instance" || !tg.TargetGroupArn) continue;
        const h = await elb.send(new DescribeTargetHealthCommand({ TargetGroupArn: tg.TargetGroupArn }));
        for (const d of h.TargetHealthDescriptions ?? []) if (d.Target?.Id === instanceId) out.push({ arn: tg.TargetGroupArn, port: d.Target.Port ?? null });
      }
      marker = page.NextMarker;
    } while (marker);
  } finally { elb.destroy(); }
  return out;
}

/** UPSERTs the recorded A records so each names `ipFor(record)` instead of its recorded address; returns the names moved. Throws when a zone refuses. */
async function moveDns(records: DnsRecord[], ipFor: (r: DnsRecord) => string | null, act: AwsCredentialIdentityProvider, comment: string): Promise<string[]> {
  const byZone = new Map<string, { r: DnsRecord; ip: string }[]>();
  for (const r of records) { const ip = ipFor(r); if (!ip || ip === r.old_ip) continue; byZone.set(r.zone_id, [...(byZone.get(r.zone_id) || []), { r, ip }]); }
  if (!byZone.size) return [];
  const r53 = new Route53Client({ region: "us-east-1", credentials: act });
  const done: string[] = [];
  try {
    for (const [zone, recs] of byZone) {
      await r53.send(new ChangeResourceRecordSetsCommand({ HostedZoneId: zone, ChangeBatch: { Comment: comment.slice(0, 256), Changes: recs.map(({ r, ip }) => upsertChange(r, ip)) } }));
      done.push(...recs.map(({ r }) => r.name));
    }
  } finally { r53.destroy(); }
  return [...new Set(done)];
}

/** The records naming the old addresses now (the inventory), with those the plan saw: one entry per record and address. */
function currentRecords(f: Record<string, any>): DnsRecord[] {
  const all = [...(Array.isArray(f.dns_records) ? f.dns_records : []), ...recordsNamingIp(f.eip ? null : f.public_ip), ...recordsNamingIp(f.private_ip)] as DnsRecord[];
  const seen = new Set<string>();
  return all.filter((r) => { const k = `${r.zone_id}|${r.name}|${JSON.stringify(r.routing)}|${r.old_ip}`; if (seen.has(k)) return false; seen.add(k); return true; });
}

const stamp = () => new Date().toISOString();
const setStage = (f: Record<string, any>, stage: Stage) => { f.stage = stage; f.stage_at = stamp(); };
const imageName = (which: "warm" | "final", oldId: string) => `advisor-hibernate-${which}-${oldId}-${stamp().slice(0, 16).replace(/[:T]/g, "")}`;
const imageTags = (oldId: string, which: string): Tag[] => [{ Key: "advisor:hibernate-of", Value: oldId }, { Key: "advisor:image-stage", Value: which }];

async function createImage(ec2: EC2Client, oldId: string, which: "warm" | "final"): Promise<string> {
  const r = await ec2.send(new CreateImageCommand({
    InstanceId: oldId, Name: imageName(which, oldId), NoReboot: true,
    Description: which === "warm" ? `aws-advisor: warm image of ${oldId} (no reboot) for a hibernation-ready relaunch` : `aws-advisor: final image of ${oldId} (stopped) for a hibernation-ready relaunch`,
    TagSpecifications: [{ ResourceType: "image", Tags: imageTags(oldId, which) }, { ResourceType: "snapshot", Tags: imageTags(oldId, which) }],
  }));
  return r.ImageId!;
}

/** Waits for an instance to report a public address (after a start), up to IP_WAIT_MS. */
async function waitPublicIp(ec2: EC2Client, id: string): Promise<string | null> {
  const until = Date.now() + IP_WAIT_MS;
  while (Date.now() < until) {
    try { const i = await describe(ec2, id); if (i?.State?.Name === "running" && i.PublicIpAddress) return i.PublicIpAddress; } catch { /* keep waiting */ }
    await new Promise((r) => setTimeout(r, 5000));
  }
  return null;
}

// ---- the module ----------------------------------------------------------------------------------------------------------

export const ec2HibernateMigrateAction: ActionModule = {
  kind: KIND,
  label: "Make an instance hibernation-ready (relaunch from an image, encrypted root)",
  grace_hours: () => config.actHibernateGraceHours,
  announce: true,

  async plan(creds, log) {
    const proposals: Proposal[] = []; const notes: string[] = [];
    const rows = db.prepare("select instance_id, account_id, name, instance_type, region, monthly_usd, pool_kind from inventory_ec2 where gone = 0 and state in ('running', 'stopped') order by name").all() as { instance_id: string; account_id: string | null; name: string | null; instance_type: string | null; region: string | null; monthly_usd: number | null; pool_kind: string | null }[];
    const byRegion = new Map<string, typeof rows>();
    for (const r of rows) { const key = `${r.account_id || ""}|${r.region || creds.region}`; if (!byRegion.has(key)) byRegion.set(key, []); byRegion.get(key)!.push(r); }
    let tagged = 0, couldBe = 0;
    for (const [key, list] of byRegion) {
      const [account, region] = key.split("|");
      const read = creds.forAccount(account || null).read;
      const ec2 = new EC2Client({ region, credentials: read });
      try {
        const live = new Map<string, Instance>();
        for (let i = 0; i < list.length; i += 100) {
          const r = await ec2.send(new DescribeInstancesCommand({ InstanceIds: list.slice(i, i + 100).map((x) => x.instance_id) }));
          for (const res of r.Reservations ?? []) for (const inst of res.Instances ?? []) live.set(inst.InstanceId!, inst);
        }
        const types = new Map<string, InstanceTypeInfo>();
        const wanted = [...new Set([...live.values()].map((i) => i.InstanceType!).filter(Boolean))];
        for (let i = 0; i < wanted.length; i += 100) for (const t of (await ec2.send(new DescribeInstanceTypesCommand({ InstanceTypes: wanted.slice(i, i + 100) as any }))).InstanceTypes ?? []) types.set(String(t.InstanceType), t);
        for (const r of list) {
          const inst = live.get(r.instance_id); if (!inst) continue;
          const name = r.name || r.instance_id;
          const t = types.get(String(inst.InstanceType));
          const guest = guestHibernation(r.instance_id);
          const c = { ...candidateFor(inst, t, r.pool_kind, r.instance_id), guest_reason: guest.ready === false ? guest.reason : null };
          const why = skipReason(c);
          if (why) {
            if (c.mode || (c.tag_value != null && c.tag_value !== NO_HIBERNATE)) { notes.push(`${name}: ${why}`); log(`${name}: ${why}`); }
            else if (c.tag_value !== NO_HIBERNATE && !skipReason({ ...c, mode: "stop" })) couldBe++;
            continue;
          }
          tagged++;
          // What has to come across: the root size, the Elastic IP, the A records, the target groups, the attributes RunInstances takes.
          const rootMap = inst.BlockDeviceMappings?.find((m) => m.DeviceName === inst.RootDeviceName);
          const volumeIds = (inst.BlockDeviceMappings ?? []).map((m) => m.Ebs?.VolumeId).filter((x): x is string => Boolean(x));
          const vols = volumeIds.length ? (await ec2.send(new DescribeVolumesCommand({ VolumeIds: volumeIds }))).Volumes ?? [] : [];
          const root = vols.find((v) => v.VolumeId === rootMap?.Ebs?.VolumeId);
          const usedPct = (db.prepare("select disk_pct_max from instance_daily where instance_id = ? and disk_pct_max is not null order by day desc limit 1").get(r.instance_id) as { disk_pct_max: number } | undefined)?.disk_pct_max ?? null;
          const rootSize = root?.Size ?? 8;
          const rootTarget = rootTargetGib(rootSize, c.ram_gib ?? 0, usedPct);
          const eip = (await ec2.send(new DescribeAddressesCommand({ Filters: [{ Name: "instance-id", Values: [r.instance_id] }] }))).Addresses?.[0] ?? null;
          const userData = (await ec2.send(new DescribeInstanceAttributeCommand({ InstanceId: r.instance_id, Attribute: "userData" }))).UserData?.Value;
          const protection = (await ec2.send(new DescribeInstanceAttributeCommand({ InstanceId: r.instance_id, Attribute: "disableApiTermination" }))).DisableApiTermination?.Value;
          let cpuCredits: string | null = null;
          if (t?.BurstablePerformanceSupported) { try { cpuCredits = (await ec2.send(new DescribeInstanceCreditSpecificationsCommand({ InstanceIds: [r.instance_id] }))).InstanceCreditSpecifications?.[0]?.CpuCredits ?? null; } catch { /* the type's default then */ } }
          let targets: { arn: string; port: number | null }[] = [];
          try { targets = await targetsOf(region, read, r.instance_id); } catch (e: any) { notes.push(`${name}: target groups not read (${String(e?.message || e).slice(0, 100)}); none will be moved`); }
          const dns = [...(eip ? [] : recordsNamingIp(inst.PublicIpAddress)), ...recordsNamingIp(inst.PrivateIpAddress)];
          const unencrypted = vols.filter((v) => !v.Encrypted).length;
          const extraGib = rootTarget - rootSize;
          const mode = c.mode!;
          const downtime = mode === "live" ? "a few minutes at the cut-over (stop, an incremental image over the warm one, boot, status checks), when a person clicks Cut over" : `from the stop until the new box passes its status checks: the whole image of ${vols.reduce((s, v) => s + (v.Size ?? 0), 0)} GiB is taken while it is down`;
          proposals.push({
            kind: KIND, resource: r.instance_id, resource_name: r.name, region, account_id: r.account_id ?? null,
            dedupe: `${KIND}:${r.instance_id}`,
            title: `relaunch ${name} (${inst.InstanceType}) hibernation-ready, ${mode === "live" ? "warm image now, cut-over on a click" : "stop and relaunch"}`,
            reason: [
              `Tagged ${HIBERNATE_TAG}=${mode}. Hibernation can only be turned on at launch with an encrypted root big enough for the RAM (${c.ram_gib ?? "?"} GiB), so the box is relaunched from an image of itself with hibernation on and ${unencrypted ? `its ${unencrypted} unencrypted volume(s) encrypted` : "its volumes encrypted as they are"}${extraGib > 0 ? `, root ${rootSize} → ${rootTarget} GiB (≈ ${(extraGib * EBS_GP3_USD_GB_MONTH).toFixed(2)} USD/month more)` : ""}.`,
              `Downtime: ${downtime}.`,
              `Carried across: ${eip ? `Elastic IP ${eip.PublicIp}` : inst.PublicIpAddress ? `the public address changes (${dns.filter((d) => d.old_ip === inst.PublicIpAddress).length} A record(s) follow)` : "no public address"}; the private address changes (${dns.filter((d) => d.old_ip === inst.PrivateIpAddress).length} A record(s) follow)${targets.length ? `; ${targets.length} target group registration(s)` : ""}; type, subnet, security groups, instance profile, key, IMDS options${cpuCredits ? `, CPU credits ${cpuCredits}` : ""}, tags.`,
              userData ? "The old user data is NOT passed to the new box (it would run again on a new instance id); the disk already has what it set up." : "",
              "The OS must run the hibernation agent (preinstalled on Amazon Linux 2/2023; ec2-hibinit-agent on Ubuntu); the read-back checks the flag and the encryption, hibernate once by hand to prove it. The old instance is stopped and kept, never terminated; the images are kept.",
            ].filter(Boolean).join(" "),
            before: { hibernation: false, root_encrypted: Boolean(root?.Encrypted), root_gib: rootSize, instance: r.instance_id },
            after: { hibernation: true, root_encrypted: true, root_gib: rootTarget, instance: "new, same type and subnet", old_instance: "stopped, kept" },
            facts: {
              mode, instance_type: inst.InstanceType, ram_gib: c.ram_gib, root_size_gib: rootSize, root_target_gib: rootTarget, disk_used_pct: usedPct, unencrypted_volumes: unencrypted,
              volumes: vols.map((v) => ({ id: v.VolumeId, size: v.Size, type: v.VolumeType, encrypted: Boolean(v.Encrypted) })),
              eip: eip ? { allocation_id: eip.AllocationId, public_ip: eip.PublicIp } : null, public_ip: inst.PublicIpAddress ?? null, private_ip: inst.PrivateIpAddress ?? null,
              dns_records: dns.length ? dns : null, target_groups: targets.length ? targets : null, user_data_present: Boolean(userData), termination_protection: Boolean(protection), cpu_credits: cpuCredits,
              image_id: inst.ImageId, platform: inst.PlatformDetails ?? null, was_state: inst.State?.Name,
            },
            rollback: "start the old instance again and move the Elastic IP, A records and target groups back to it; the new instance is stopped (not terminated) and the images are kept",
            est_usd_month: null,
          });
        }
      } catch (e: any) { const m = String(e?.message || e); notes.push(`${region}: ${m.slice(0, 160)}`); log(`${region}: ${m}`); }
      finally { ec2.destroy(); }
    }
    if (!tagged) notes.push(`no instance tagged ${HIBERNATE_TAG}=stop|live is ready to migrate${couldBe ? ` (${couldBe} instance(s) qualify: tag one "stop" if downtime is fine, "live" for a warm image and a cut-over on a click)` : ""}`);
    return { proposals, notes };
  },

  async apply(p, creds) {
    const f = p.facts as Record<string, any>;
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try {
      f.old_was_running = f.was_state === "running";
      if (f.mode === "live") {
        f.warm_image_id = await createImage(ec2, p.resource, "warm");
        setStage(f, "warm_image");
        return `CreateImage (no reboot): warm image ${f.warm_image_id} of the running box; the cut-over waits for a person once it is available`;
      }
      if (f.was_state === "running") await ec2.send(new StopInstancesCommand({ InstanceIds: [p.resource] }));
      setStage(f, "stopping_old");
      return f.was_state === "running" ? "StopInstances: the old box is stopping; the image follows once it is stopped" : "the old box was already stopped; the image follows";
    } finally { ec2.destroy(); }
  },

  async advance(p, creds): Promise<Advance> {
    const f = p.facts as Record<string, any>;
    const read = new EC2Client({ region: p.region, credentials: creds.read });
    const wait = (note: string, ms: number): Advance => ({ note, changed: false, wait_ms: ms });
    try {
      switch (f.stage as Stage) {
        case "warm_image": {
          const img = await imageOf(read, f.warm_image_id);
          if (!img || img.State === "failed" || img.State === "invalid" || img.State === "deregistered") throw new Error(`warm image ${f.warm_image_id} is ${img?.State ?? "gone"}${img?.StateReason?.Message ? `: ${img.StateReason.Message}` : ""}`);
          if (img.State !== "available") return wait(`warm image ${f.warm_image_id} ${img.State}`, 60_000);
          setStage(f, "awaiting_cutover");
          f.offers = [{ name: "cutover", label: "Cut over", title: "stop the old box, take the final (incremental) image, launch the hibernation-ready box and move the addresses: a few minutes of downtime" }];
          return { note: `warm image ${f.warm_image_id} available; waiting for a person to click Cut over`, changed: true, wait_ms: null,
            announce: `🛌 Warm image of ${p.resource_name || p.resource} is ready: click Cut over on the page when a few minutes of downtime suit (stop, incremental image, relaunch with hibernation on).` };
        }
        case "awaiting_cutover":
          return { note: "waiting for Cut over", changed: false, wait_ms: null };
        case "stopping_old": {
          const old = await describe(read, p.resource);
          const state = old?.State?.Name;
          if (state === "stopping" || state === "pending") return wait(`old box ${state}`, 10_000);
          if (state !== "stopped") throw new Error(`the old box is ${state ?? "gone"}, not stopped: somebody started it; Revert, then apply again`);
          const act = new EC2Client({ region: p.region, credentials: creds.act() });
          try { f.final_image_id = await createImage(act, p.resource, "final"); } finally { act.destroy(); }
          setStage(f, "final_image");
          return { note: `old box stopped; final image ${f.final_image_id}${f.warm_image_id ? ` (incremental over ${f.warm_image_id})` : ""}`, changed: true, wait_ms: 30_000 };
        }
        case "final_image": {
          const img = await imageOf(read, f.final_image_id);
          if (!img || img.State === "failed" || img.State === "invalid" || img.State === "deregistered") throw new Error(`final image ${f.final_image_id} is ${img?.State ?? "gone"}${img?.StateReason?.Message ? `: ${img.StateReason.Message}` : ""}`);
          if (img.State !== "available") return wait(`final image ${f.final_image_id} ${img.State}`, 30_000);
          const old = await describe(read, p.resource);
          if (!old) throw new Error("the old instance is gone");
          const act = new EC2Client({ region: p.region, credentials: creds.act() });
          try {
            // The client token makes the launch idempotent: a retried stage finds the same instance instead of a second one.
            const token = `advhib-${p.resource}-${f.final_image_id}`.slice(0, 64);
            const r = await act.send(new RunInstancesCommand(launchInput(old, img, f, token)));
            f.new_instance_id = r.Instances?.[0]?.InstanceId;
          } finally { act.destroy(); }
          if (!f.new_instance_id) throw new Error("RunInstances returned no instance");
          setStage(f, "launching");
          return { note: `launched ${f.new_instance_id} from ${f.final_image_id} with hibernation on, volumes encrypted`, changed: true, wait_ms: 20_000 };
        }
        case "launching": {
          const st = (await read.send(new DescribeInstanceStatusCommand({ InstanceIds: [f.new_instance_id], IncludeAllInstances: true }))).InstanceStatuses?.[0];
          const state = st?.InstanceState?.Name;
          if (state && !["pending", "running"].includes(state)) {
            const inst = await describe(read, f.new_instance_id);
            throw new Error(`new instance ${f.new_instance_id} is ${state}${inst?.StateReason?.Message ? `: ${inst.StateReason.Message}` : ""}`);
          }
          if (state !== "running" || st?.InstanceStatus?.Status !== "ok" || st?.SystemStatus?.Status !== "ok") return wait(`new instance ${state ?? "pending"}, status checks ${st?.InstanceStatus?.Status ?? "?"}/${st?.SystemStatus?.Status ?? "?"}`, 15_000);
          const inst = await describe(read, f.new_instance_id);
          f.new_private_ip = inst?.PrivateIpAddress ?? null;
          f.new_public_ip = inst?.PublicIpAddress ?? null;
          f.moved = f.moved || {};
          const act = new EC2Client({ region: p.region, credentials: creds.act() });
          const done: string[] = [];
          try {
            if (f.eip && !f.moved.eip) {
              await act.send(new AssociateAddressCommand({ AllocationId: f.eip.allocation_id, InstanceId: f.new_instance_id, AllowReassociation: true }));
              f.moved.eip = true; f.new_public_ip = f.eip.public_ip; done.push(`Elastic IP ${f.eip.public_ip}`);
            }
            const records = currentRecords(f);
            if (records.length && !f.moved.dns) {
              const names = await moveDns(records, (r) => movedIp(r, f, { public_ip: f.new_public_ip, private_ip: f.new_private_ip }), creds.act(), `aws-advisor: ${p.resource} → ${f.new_instance_id} (hibernation-ready relaunch)`);
              f.moved.dns = records; if (names.length) done.push(`DNS ${names.join(", ")}`);
            }
            const targets = (f.target_groups ?? []) as { arn: string; port: number | null }[];
            if (targets.length && !f.moved.targets) {
              const elb = new ElasticLoadBalancingV2Client({ region: p.region, credentials: creds.act() });
              try {
                for (const t of targets) await elb.send(new RegisterTargetsCommand({ TargetGroupArn: t.arn, Targets: [{ Id: f.new_instance_id, ...(t.port ? { Port: t.port } : {}) }] }));
                for (const t of targets) { try { await elb.send(new DeregisterTargetsCommand({ TargetGroupArn: t.arn, Targets: [{ Id: p.resource, ...(t.port ? { Port: t.port } : {}) }] })); } catch { /* the old one is stopped: unhealthy, harmless */ } }
              } finally { elb.destroy(); }
              f.moved.targets = true; done.push(`${targets.length} target group(s)`);
            }
            try { await act.send(new CreateTagsCommand({ Resources: [p.resource], Tags: [{ Key: MIGRATED_TO_TAG, Value: f.new_instance_id }] })); } catch { /* the marker is a courtesy; the ledger row is the record */ }
          } finally { act.destroy(); }
          setStage(f, "done"); f.offers = [];
          return { note: `${f.new_instance_id} passed its status checks; moved ${done.length ? done.join(", ") : "nothing (no address, record or target group to move)"}; old ${p.resource} stays stopped`, changed: true, done: true, wait_ms: null,
            announce: `🛌 ${p.resource_name || p.resource} now runs as ${f.new_instance_id}, hibernation-ready (encrypted root ${f.root_target_gib} GiB). Old ${p.resource} is stopped and kept for Revert.` };
        }
        case "done":
          return { note: "done", changed: false, done: true, wait_ms: null };
        default:
          return { note: `stage ${f.stage}`, changed: false, wait_ms: null };
      }
    } finally { read.destroy(); }
  },

  async step(name, p, creds, by) {
    const f = p.facts as Record<string, any>;
    if (name !== "cutover") throw new Error(`no step "${name}"`);
    if (f.stage !== "awaiting_cutover") throw new Error(`the migration is at ${f.stage}, not waiting for the cut-over`);
    const ec2 = new EC2Client({ region: p.region, credentials: creds.act() });
    try { await ec2.send(new StopInstancesCommand({ InstanceIds: [p.resource] })); } finally { ec2.destroy(); }
    f.cutover_by = by; f.cutover_at = stamp(); f.offers = [];
    setStage(f, "stopping_old");
    return { note: `cut-over by ${by}: the old box is stopping; final image, launch and move follow`, changed: true, wait_ms: 10_000 };
  },

  async verify(p, creds) {
    const f = p.facts as Record<string, any>;
    if (f.stage !== "done") return { ok: null, note: `stage ${f.stage}` };
    const ec2 = new EC2Client({ region: p.region, credentials: creds.read });
    try {
      const inst = await describe(ec2, f.new_instance_id);
      if (!inst) return { ok: false, note: `new instance ${f.new_instance_id} not found` };
      if (!inst.HibernationOptions?.Configured) return { ok: false, note: `${f.new_instance_id} reads hibernation off` };
      const rootId = inst.BlockDeviceMappings?.find((m) => m.DeviceName === inst.RootDeviceName)?.Ebs?.VolumeId;
      const root = rootId ? (await ec2.send(new DescribeVolumesCommand({ VolumeIds: [rootId] }))).Volumes?.[0] : undefined;
      if (!root?.Encrypted) return { ok: false, note: `${f.new_instance_id} root volume is not encrypted` };
      if (f.eip && inst.PublicIpAddress !== f.eip.public_ip) return { ok: false, note: `Elastic IP ${f.eip.public_ip} is not on ${f.new_instance_id} (reads ${inst.PublicIpAddress ?? "none"})` };
      const old = await describe(ec2, p.resource);
      return { ok: true, note: `read back: ${f.new_instance_id} ${inst.State?.Name}, hibernation configured, root ${root.Size} GiB encrypted${f.ram_gib ? ` (RAM ${f.ram_gib} GiB)` : ""}; old ${p.resource} ${old?.State?.Name ?? "gone"}` };
    } finally { ec2.destroy(); }
  },

  async revert(p, creds) {
    const f = p.facts as Record<string, any>;
    const act = new EC2Client({ region: p.region, credentials: creds.act() });
    const lines: string[] = [];
    try {
      const old = await describe(act, p.resource);
      // The old box comes back first, so the addresses have somewhere to go.
      let oldPublic: string | null = old?.PublicIpAddress ?? null;
      if (f.old_was_running && old && ["stopped", "stopping"].includes(String(old.State?.Name))) {
        if (old.State?.Name === "stopping") { for (let i = 0; i < 24; i++) { await new Promise((r) => setTimeout(r, 5000)); if ((await describe(act, p.resource))?.State?.Name === "stopped") break; } }
        await act.send(new StartInstancesCommand({ InstanceIds: [p.resource] }));
        lines.push(`started ${p.resource}`);
        if (!f.eip && f.public_ip) oldPublic = await waitPublicIp(act, p.resource);
      }
      const moved = f.moved || {};
      if (moved.eip && f.eip) { await act.send(new AssociateAddressCommand({ AllocationId: f.eip.allocation_id, InstanceId: p.resource, AllowReassociation: true })); lines.push(`Elastic IP ${f.eip.public_ip} back`); }
      if (Array.isArray(moved.dns) && moved.dns.length) {
        // The records now name the new addresses; each goes back to the old box's address (a new public one if it had no Elastic IP).
        const now = (moved.dns as DnsRecord[]).map((r) => { const ip = movedIp(r, f, { public_ip: f.new_public_ip, private_ip: f.new_private_ip }); return ip ? { ...r, values: r.values.map((v) => (v === r.old_ip ? ip : v)), old_ip: ip, back_to: r.old_ip === f.public_ip ? oldPublic : r.old_ip } : null; }).filter(Boolean) as (DnsRecord & { back_to: string | null })[];
        const names = await moveDns(now, (r) => (r as any).back_to, creds.act(), `aws-advisor: revert ${f.new_instance_id} → ${p.resource}`);
        if (names.length) lines.push(`DNS back: ${names.join(", ")}`);
        const lost = now.filter((r) => !r.back_to).map((r) => r.name);
        if (lost.length) lines.push(`no public address yet for ${lost.join(", ")}: fix by hand`);
      }
      if (moved.targets && Array.isArray(f.target_groups)) {
        const elb = new ElasticLoadBalancingV2Client({ region: p.region, credentials: creds.act() });
        try {
          for (const t of f.target_groups) await elb.send(new RegisterTargetsCommand({ TargetGroupArn: t.arn, Targets: [{ Id: p.resource, ...(t.port ? { Port: t.port } : {}) }] }));
          if (f.new_instance_id) for (const t of f.target_groups) { try { await elb.send(new DeregisterTargetsCommand({ TargetGroupArn: t.arn, Targets: [{ Id: f.new_instance_id, ...(t.port ? { Port: t.port } : {}) }] })); } catch { /* already gone */ } }
        } finally { elb.destroy(); }
        lines.push(`${f.target_groups.length} target group(s) back`);
      }
      if (f.new_instance_id) {
        try { await act.send(new StopInstancesCommand({ InstanceIds: [f.new_instance_id] })); lines.push(`stopped ${f.new_instance_id} (kept, not terminated)`); }
        catch (e: any) { lines.push(`${f.new_instance_id} not stopped (${String(e?.message || e).slice(0, 100)}): stop it by hand`); }
      }
      try { await act.send(new DeleteTagsCommand({ Resources: [p.resource], Tags: [{ Key: MIGRATED_TO_TAG }] })); } catch { /* informational */ }
    } finally { act.destroy(); }
    const images = [f.warm_image_id, f.final_image_id].filter(Boolean);
    setStage(f, "reverted"); f.offers = [];
    return `${lines.length ? lines.join("; ") : "nothing had moved yet"}${images.length ? `; image(s) ${images.join(", ")} kept (deregister them by hand when no longer wanted)` : ""}`;
  },
};
