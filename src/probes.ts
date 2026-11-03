import { createHash } from "node:crypto";
import { config } from "./config.js";
import { db, getSetting, setSetting } from "./db.js";
import { DEFAULT_SIGNALS_STRING } from "./signals.js";

/**
 * The probes: read-only shell scripts (the sbom one also keeps, and removes, a scratch directory for syft: SBOM_BODY) the advisor runs on a box through AWS Systems Manager Run Command, one per
 * concern so each can run on its own cadence and each SSM document stays small and scoped:
 *
 *  - host:     memory, swap, load, CPUs, uptime, disks and the top processes (the hourly statistics behind the alerts and charts)
 *  - docker:   the containers and the activity around them (logs, use signals, connections, the front door, logins, traffic)
 *  - apps:     what runs (process groups), what listens (ports), where the log agents ship
 *  - software: what is installed and at which version (packages, kernel, OS with the CPE it declares, well-known binaries, container images) for vulnerability matching
 *  - sbom:     what runs on the box beyond the OS packages, read in place by syft (https://github.com/anchore/syft): the executables of the running
 *              processes (host and container), the running images through their container roots and the host filesystem when asked, as package
 *              URLs each with the CPEs syft assigns; nothing is pulled or saved on a box. The probe reports "not available" where syft is missing
 *  - images:   the same for container images pulled from their registries by digest, run on the one designated scanner instance (src/image_pass.ts)
 *              once per distinct image the fleet runs; not a per-box probe (PROBE_DEFS per_box), the sbom pass drives it
 *
 * Every script prints exactly one JSON object on its last line (gzip+base64 behind a marker when big), carrying
 * `probe` ("aws-advisor/<kind>/<version>") and `kind`. The text here is the default; Settings > Probes may override a
 * script (saved as a setting), and the SSM document embeds the effective text, so an edit means redeploying that
 * kind's document (the hash in the document description says whether it is current). Scripts only read /proc, /sys,
 * df, ps, ss, the package database and the version flags of known programs; nothing is written or changed on the box,
 * with one exception a person switches off: the sbom probe installs the pinned syft release where it is missing
 * (PROBE_SBOM_INSTALL, the document's `install` parameter).
 *
 * Quoting note: the setup script embeds the documents in a bash heredoc inside $( ), so single quotes must pair up
 * on every line and never sit alone in a comment.
 */

export const PROBE_KINDS = ["host", "docker", "apps", "software", "sbom", "images"] as const;
export type ProbeKind = (typeof PROBE_KINDS)[number];
/** The kinds the pre-2.0 combined document (one row of kind "all") covered; the other kinds only ever had a document and rows of their own. */
const COMBINED_KINDS: ReadonlySet<string> = new Set(["host", "docker", "apps"]);
/** The row kind a pre-2.0 combined probe stored for this kind: "all" for the kinds it covered, the kind itself for the rest (nothing older exists). */
export const legacyKindOf = (kind: ProbeKind): string => (COMBINED_KINDS.has(kind) ? "all" : kind);
/** The probe family version: the documents and the parser moved to per-kind scripts here. */
export const PROBE_VERSION = "aws-advisor/2.0";
/** GetCommandInvocation returns at most this many characters of stdout; the agent appends "---Output truncated---" past it. */
export const SSM_OUTPUT_CAP = 24000;
/** A probe whose JSON is large prints it gzip-compressed and base64-encoded on one line after this marker (probe 1.7). */
export const GZ_MARKER = "aws-advisor-gz:";

export interface ProbeDef {
  kind: ProbeKind; title: string; what: string; version: string;
  /** The top-level keys of the JSON this kind owns; the merged view of an instance takes each section from its kind's latest row. */
  sections: readonly string[];
  /** How long SSM gives the script. */
  timeout_seconds: number;
  /** How many boxes a pass has in flight at once. The work happens on the boxes and SSM runs any number of commands side by side; the advisor only
   *  sends and waits, so a long document (sbom: minutes per box, a 20-minute budget) takes many at a time or a fleet-wide pass lasts hours. */
  concurrency: number;
  /** The runtime setting that holds its cron and the one for its scope. */
  cron_key: string; scope_key: string;
  /** Whether the script takes the use-signal patterns (docker only). */
  takes_signals: boolean;
  /** Whether a pass sends the document to every box in scope (probeTargets); false for the images kind, which runs on the one scanner instance with a batch of images as its parameter. */
  per_box: boolean;
}

export const PROBE_DEFS: Record<ProbeKind, ProbeDef> = {
  host: { kind: "host", title: "Host", what: "memory, swap, load, CPUs, uptime, disks and the top processes: the hourly statistics behind the disk, memory and load alerts and the utilisation charts", version: "2.0", sections: ["cpus", "uptime_seconds", "memory", "load", "disks", "top_cpu", "top_mem"], timeout_seconds: 60, cron_key: "probeCron", scope_key: "probeScope", takes_signals: false, concurrency: 3, per_box: true },
  docker: { kind: "docker", title: "Containers and activity", what: "the containers (state, CPU, memory, network; image, health, restarts, ports, mounts, source repository and revision) and whether anyone uses the box: container logs and use signals, established connections, the front door, logins, traffic; the usage profiles and the swarm costs read it", version: "2.1", sections: ["docker", "containers", "container_details", "activity"], timeout_seconds: 90, cron_key: "probeDockerCron", scope_key: "probeScope", takes_signals: true, concurrency: 3, per_box: true },
  apps: { kind: "apps", title: "Programs, ports, log shipping and the host firewall", what: "every user-space program with its user, count, CPU and memory; every port the box answers on and who owns it (exposure comes from the security groups); the log groups its agents ship to; the host packet filter (the iptables rules and the native nftables tables, read-only), which the graph keeps as one filter node per distinct ruleset shared by the boxes that run it", version: "2.1", sections: ["processes", "listeners", "log_shipping", "firewall"], timeout_seconds: 60, cron_key: "probeAppsCron", scope_key: "probeScope", takes_signals: false, concurrency: 3, per_box: true },
  software: { kind: "software", title: "Installed software", what: "the OS and kernel, every installed package with its version (dpkg, rpm or apk), the version of well-known programs read from the binary, the images behind the running containers, the libraries the runtimes bundle (Node's process.versions) and the dependencies of the packages that own the probed programs: the inventory a CVE is matched against, each with the CPE the distribution declares for itself (os-release CPE_NAME) or the advisor forms; and whether the guest can hibernate", version: "1.7", sections: ["os", "kernel", "kernel_upstream", "kernel_package", "arch", "package_manager", "packages", "binaries", "images", "bundles", "depends", "hibernation"], timeout_seconds: 120, cron_key: "probeSoftwareCron", scope_key: "probeSoftwareScope", takes_signals: false, concurrency: 3, per_box: true },
  sbom: { kind: "sbom", title: "Software bill of materials (syft)", what: "what runs on the box beyond the OS packages, as package URLs read by syft (https://github.com/anchore/syft) in place, each with the CPEs syft assigns it (the NVD dictionary match first, its own name guesses after): the executables of the running processes, host and container alike (the host parameter, processes by default: a container process is read through the root filesystem the daemon keeps mounted for it, never by entering the container; what the binary is, its version, and for a Go or Rust program the modules compiled into it), the host filesystem for language packages when the host parameter says filesystem or both, and the running images through the same container roots when the images parameter says so. Nothing is pulled, saved or unpacked on a box: the registry images are the image scanner instance's. A box without syft gets the pinned release installed into /usr/local/bin by the official installer (checksum verified) when the install parameter is yes (Settings > Probe pass > Install syft where missing, on by default; the one lasting write a probe makes), and is reported as not available otherwise. Processes first, then the images, then the filesystem, within a 20-minute budget. With an image scanner instance configured (Settings > Probe pass) the images parameter is local: the box reads only images that have no registry digest (built or loaded on the box itself), the scanner reads the rest once for the whole fleet; all (the default, and what a box gets when no scanner is set) reads every running image here, through its container's root. A Kubernetes node (containerd, no docker command) lists no images to either: the cluster inventory lists its pods' images from the cluster API and the scanner reads them; its running executables are still read here, through the containerd task roots. With an upload bucket configured (Settings > Probe pass) the whole result goes to S3 and nothing is trimmed; otherwise the lists are trimmed to fit SSM's output cap and every scan reports its true count", version: "1.7", sections: ["sbom"], timeout_seconds: 1500, cron_key: "probeSbomCron", scope_key: "probeSbomScope", takes_signals: false, concurrency: 20, per_box: true },
  images: { kind: "images", title: "Container images (syft, from the registries)", what: "the packages inside container images, read by syft on the one designated scanner instance (Settings > Probe pass > Image scanner instance) rather than on every box: the sbom pass lists the distinct images the fleet runs (their registry digest and platform, from the software probe), skips the ones scanned within the interval and sends the scanner batches of them as the images parameter; the scanner pulls each by digest straight from its registry (no Docker daemon: syft's registry source, with the box's platform so a multi-arch tag resolves to what the box runs) and answers with the same scan records as the sbom probe (purls with their CPEs). Registry access is the scanner's own: its instance role for ECR (the script fetches a token per ECR registry with the AWS CLI), its docker config and credential helpers for Docker Hub logins and private registries; a box's locally built images stay with the box. One image at a time, each within the timeout parameter (up to 30 minutes: an 8 GB image means some 50 GB of scratch traffic on the scanner's volume before a package is read), the batch within a 40-minute budget; the scratch directory, the free-space check and the S3 upload are the sbom probe's", version: "1.2", sections: [], timeout_seconds: 2700, cron_key: "probeSbomCron", scope_key: "probeSbomScope", takes_signals: false, concurrency: 1, per_box: false },
};

// ---- the scripts --------------------------------------------------------------------------------------------------------

const PREAMBLE = [
  "set -u",
  "LC_ALL=C; export LC_ALL",
  "esc() { printf '%s' \"$1\" | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g'; }",
  "jstr() { if [ -n \"$1\" ]; then printf '\"%s\"' \"$(esc \"$1\")\"; else printf 'null'; fi; }",
  "hn=$(esc \"$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)\"); now=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "# whether the inline object would be cut by the 24,000-character cap once compressed and base64-encoded (16,000 raw is where EMIT compresses)",
  "toobig() { if command -v gzip >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1; then [ ${#out} -gt 16000 ] && [ \"$(printf '%s' \"$out\" | gzip -c -9 | base64 | tr -d '\\n' | wc -c | tr -d ' ')\" -gt 22000 ]; else [ ${#out} -gt 23000 ]; fi; }",
];

const HOST_BODY = [
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
];

const HOST_OUT = [
  "out=$(printf '{\"probe\":\"aws-advisor/host/2\",\"kind\":\"host\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"cpus\":%s,\"uptime_seconds\":%s,\"memory\":{\"total_bytes\":%s,\"used_bytes\":%s,\"available_bytes\":%s,\"swap_total_bytes\":%s,\"swap_used_bytes\":%s},\"load\":{\"1m\":%s,\"5m\":%s,\"15m\":%s},\"disks\":[%s],\"top_cpu\":[%s],\"top_mem\":[%s]}' \\",
  "  \"$hn\" \"$now\" \"${cpus:-0}\" \"${uptime_s:-0}\" \"${mem_total:-0}\" \"${mem_used:-0}\" \"${mem_avail:-0}\" \"${swap_total:-0}\" \"${swap_used:-0}\" \"$l1\" \"$l5\" \"$l15\" \"$disks\" \"$top_cpu\" \"$top_mem\")",
];

const DOCKER_BODY = [
  "containers=\"[]\"; docker_json='{\"available\":false,\"running\":0,\"total\":0}'",
  "if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then",
  "  stats=$(docker stats --no-stream --format '{{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}\t{{.MemPerc}}\t{{.NetIO}}' 2>/dev/null || true)",
  "  clist=$(docker ps -a --format '{{.Names}}\t{{.Image}}\t{{.State}}\t{{.RunningFor}}' 2>/dev/null | head -40 | awk -F'\\t' -v stats=\"$stats\" 'BEGIN{ k=split(stats, L, \"\\n\"); for(i=1;i<=k;i++){ split(L[i],a,\"\\t\"); cpu[a[1]]=a[2]; mem[a[1]]=a[3]; memp[a[1]]=a[4]; net[a[1]]=a[5] } }",
  "    function esc(x){ gsub(/\\\\/,\"\\\\\\\\\",x); gsub(/\"/,\"\\\\\\\"\",x); return x }",
  "    function bytes(x,  v,u){ sub(/ \\/.*/,\"\",x); v=x+0; u=x; sub(/^[0-9.]+/,\"\",u); if(u==\"KiB\"||u==\"kB\"||u==\"KB\")v*=1024; else if(u==\"MiB\"||u==\"MB\")v*=1048576; else if(u==\"GiB\"||u==\"GB\")v*=1073741824; else if(u==\"TiB\"||u==\"TB\")v*=1099511627776; return v }",
  "    function txb(x){ sub(/^.*\\/ */,\"\",x); return bytes(x) }",
  "    { n++; c=cpu[$1]; sub(/%/,\"\",c); mp=memp[$1]; sub(/%/,\"\",mp);",
  "      printf \"%s{\\\"name\\\":\\\"%s\\\",\\\"image\\\":\\\"%s\\\",\\\"state\\\":\\\"%s\\\",\\\"running_for\\\":\\\"%s\\\",\\\"cpu_pct\\\":%s,\\\"mem_bytes\\\":%.0f,\\\"mem_pct\\\":%s,\\\"net_rx_bytes\\\":%.0f,\\\"net_tx_bytes\\\":%.0f}\", (n>1?\",\":\"\"), esc($1), esc($2), esc($3), esc($4), (c==\"\"?\"null\":c), bytes(mem[$1]), (mp==\"\"?\"null\":mp), bytes(net[$1]), txb(net[$1]) }')",
  "  containers=\"[$clist]\"",
  "  running=$(docker ps -q 2>/dev/null | wc -l | tr -d ' '); total=$(docker ps -aq 2>/dev/null | wc -l | tr -d ' ')",
  "  docker_json=\"{\\\"available\\\":true,\\\"running\\\":${running:-0},\\\"total\\\":${total:-0}}\"",
  "fi",
  "# ---- container details (probe docker 2.1): what each container is, from docker inspect: its id, image reference and image id, state, health, exit",
  "# ---- code, restart count and policy, the program it starts, its networks, published ports and mounts, and a fixed list of labels (the image source",
  "# ---- repository and revision, the compose project and service). Never the environment, the command arguments or any other label: those hold secrets.",
  "cdetail=\"\"",
  "if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then",
  "  cids=$(docker ps -aq 2>/dev/null | head -n 40)",
  String.raw`  [ -n "$cids" ] && cdetail=$(docker inspect --format '{"id":{{json .Id}},"name":{{json .Name}},"created":{{json .Created}},"image":{{json .Config.Image}},"image_id":{{json .Image}},"state":{{json .State.Status}},"health":"{{with index .State "Health"}}{{index . "Status"}}{{- end}}","exit_code":{{json .State.ExitCode}},"oom_killed":{{json .State.OOMKilled}},"started_at":{{json .State.StartedAt}},"finished_at":{{json .State.FinishedAt}},"restarts":{{json .RestartCount}},"restart_policy":{{json .HostConfig.RestartPolicy.Name}},"privileged":{{json .HostConfig.Privileged}},"network_mode":{{json .HostConfig.NetworkMode}},"user":{{json .Config.User}},"entrypoint":{{json .Path}},"networks":"{{range $k, $v := .NetworkSettings.Networks}}{{$k}},{{- end}}","ports":{{json .NetworkSettings.Ports}},"mounts":[{{range $i, $m := .Mounts}}{{if $i}},{{- end}}{"type":{{json $m.Type}},"name":{{json (index $m "Name")}},"source":{{json $m.Source}},"destination":{{json $m.Destination}},"rw":{{json $m.RW}}}{{- end}}],"labels":{"source":{{json (index .Config.Labels "org.opencontainers.image.source")}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"version":{{json (index .Config.Labels "org.opencontainers.image.version")}},"built":{{json (index .Config.Labels "org.opencontainers.image.created")}},"title":{{json (index .Config.Labels "org.opencontainers.image.title")}},"vcs_url":{{json (index .Config.Labels "org.label-schema.vcs-url")}},"vcs_ref":{{json (index .Config.Labels "org.label-schema.vcs-ref")}},"compose_project":{{json (index .Config.Labels "com.docker.compose.project")}},"compose_service":{{json (index .Config.Labels "com.docker.compose.service")}},"compose_dir":{{json (index .Config.Labels "com.docker.compose.project.working_dir")}},"compose_files":{{json (index .Config.Labels "com.docker.compose.project.config_files")}}}}' $cids 2>/dev/null | tr -cd '\12\40-\176' | grep '^{' | paste -sd, -)`,
  "fi",
  "# ---- activity (probe 1.4): is anyone actually using this box? Counts and timestamps only; log text stays on the box,",
  "# ---- except the last three lines of each container (capped, printable ASCII), shown in the UI and never sent to a model.",
  "# the patterns come from the document parameter `signals` (Settings > Probe pass); the advisor passes the current list on every probe",
  "SIGS=$(printf '%s' '__SIGNALS__' | sed 's/;;/\\n/g')",
  "SIG_RE=$(printf '%s\\n' \"$SIGS\" | cut -d= -f2- | paste -sd'|' -)",
  "HB_RE='(health|ping|pong|heartbeat|keepalive|/metrics|/status|readiness|liveness|ELB-HealthChecker|swarm-checker|UptimeRobot|kube-probe)'",
  "ts_of() { printf '%s' \"$1\" | grep -oE '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}' | head -n 1; }",
  "jts() { t=$(ts_of \"$1\"); if [ -n \"$t\" ]; then printf '\"%sZ\"' \"$t\"; else printf 'null'; fi; }",
  "act_containers=\"\"; act_front='{\"source\":null,\"requests\":0,\"health\":0,\"last_request_at\":null,\"last_request_raw\":null,\"window\":null}'",
  "if docker info >/dev/null 2>&1; then",
  "  n=\"\"",
  "  for c in $(docker ps --format '{{.Names}}' 2>/dev/null | head -20); do",
  "    logs=$(docker logs --since 24h --tail 2000 --timestamps \"$c\" 2>&1 | tr -cd '\\12\\40-\\176')",
  "    lines=$(printf '%s\\n' \"$logs\" | grep -c .)",
  "    last_log=$(printf '%s\\n' \"$logs\" | grep . | tail -n 1)",
  "    errs=$(printf '%s\\n' \"$logs\" | grep -ciE '\\b(error|err|fatal|panic|exception)\\b')",
  "    warns=$(printf '%s\\n' \"$logs\" | grep -ciE '\\b(warn|warning)\\b')",
  "    clean=$(printf '%s\\n' \"$logs\" | grep -viE \"$HB_RE\" | grep -viE '\\b(error|exception|traceback|panic|fatal)\\b|^[^ ]+ +(from |at )')",
  "    sig=$(printf '%s\\n' \"$clean\" | grep -iE \"$SIG_RE\")",
  "    kinds=$(printf '%s\\n' \"$SIGS\" | while IFS='=' read -r nm re; do [ -n \"$nm\" ] || continue; k=$(printf '%s\\n' \"$clean\" | grep -ciE \"$re\"); [ \"${k:-0}\" -gt 0 ] && printf ',\"%s\":%s' \"$nm\" \"$k\"; done)",
  "    kinds=\"{${kinds#,}}\"",
  "    samples=$(printf '%s\\n' \"$sig\" | grep . | tail -n 60 | awk '{ $1=\"\"; sub(/^ /,\"\"); if(!($0 in seen)){ seen[$0]=1; out[++n]=$0 } } END { for(i=(n>5?n-4:1); i<=n; i++) print out[i] }' | cut -c1-160 | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g' | awk '{ printf \"%s\\\"%s\\\"\", (NR>1?\",\":\"\"), $0 }')",
  "    sigs=$(printf '%s\\n' \"$sig\" | grep -c .)",
  "    last_sig=$(printf '%s\\n' \"$sig\" | grep . | tail -n 1)",
  "    ins=$(docker inspect --format '{{.State.StartedAt}} {{.RestartCount}} {{.Config.Image}}' \"$c\" 2>/dev/null)",
  "    started=$(printf '%s' \"$ins\" | awk '{print $1}'); restarts=$(printf '%s' \"$ins\" | awk '{print $2}'); img=$(printf '%s' \"$ins\" | awk '{print $3}')",
  "    tail3=$(printf '%s\\n' \"$logs\" | grep . | tail -n 3 | cut -c1-160 | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g' | awk '{ printf \"%s\\\"%s\\\"\", (NR>1?\",\":\"\"), $0 }')",
  "    case \"$img\" in *nginx*|*caddy*|*traefik*|*haproxy*|*proxy*|*ingress*)",
  "      if [ \"$act_front\" = '{\"source\":null,\"requests\":0,\"health\":0,\"last_request_at\":null,\"last_request_raw\":null,\"window\":null}' ]; then",
  "        acc=$(printf '%s\\n' \"$logs\" | grep -E '\" [0-9]{3} |HTTP/[0-9.]+\" [0-9]{3}|\"status\":[0-9]{3}|status=[0-9]{3}')",
  "        reqs=$(printf '%s\\n' \"$acc\" | grep -c .); hb=$(printf '%s\\n' \"$acc\" | grep -ciE \"$HB_RE\")",
  "        lastreq=$(printf '%s\\n' \"$acc\" | grep -viE \"$HB_RE\" | grep . | tail -n 1)",
  "        act_front=\"{\\\"source\\\":\\\"container:$(esc \"$c\")\\\",\\\"requests\\\":$((reqs - hb)),\\\"health\\\":${hb:-0},\\\"last_request_at\\\":$(jts \"$lastreq\"),\\\"last_request_raw\\\":null,\\\"window\\\":\\\"24h\\\"}\"",
  "      fi;;",
  "    esac",
  "    act_containers=\"$act_containers$n{\\\"name\\\":\\\"$(esc \"$c\")\\\",\\\"started_at\\\":$(jts \"$started\"),\\\"restarts\\\":${restarts:-0},\\\"log_lines\\\":${lines:-0},\\\"last_log_at\\\":$(jts \"$last_log\"),\\\"errors\\\":${errs:-0},\\\"warns\\\":${warns:-0},\\\"signal_lines\\\":${sigs:-0},\\\"last_signal_at\\\":$(jts \"$last_sig\"),\\\"last_lines\\\":[$tail3],\\\"signal_kinds\\\":$kinds,\\\"signal_samples\\\":[$samples]}\"",
  "    n=\",\"",
  "  done",
  "fi",
  "if [ \"$act_front\" = '{\"source\":null,\"requests\":0,\"health\":0,\"last_request_at\":null,\"last_request_raw\":null,\"window\":null}' ]; then",
  "  for f in /var/log/nginx/access.log /var/log/caddy/access.log /var/log/apache2/access.log /var/log/httpd/access_log; do",
  "    if [ -r \"$f\" ]; then",
  "      acc=$(tail -n 5000 \"$f\" 2>/dev/null | tr -cd '\\12\\40-\\176')",
  "      reqs=$(printf '%s\\n' \"$acc\" | grep -c .); hb=$(printf '%s\\n' \"$acc\" | grep -ciE \"$HB_RE\")",
  "      lastreq=$(printf '%s\\n' \"$acc\" | grep -viE \"$HB_RE\" | grep . | tail -n 1 | grep -oE '\\[[^]]+\\]' | head -n 1 | tr -d '[]')",
  "      act_front=\"{\\\"source\\\":\\\"file:$(esc \"$f\")\\\",\\\"requests\\\":$((reqs - hb)),\\\"health\\\":${hb:-0},\\\"last_request_at\\\":null,\\\"last_request_raw\\\":$(jstr \"$lastreq\"),\\\"window\\\":\\\"last 5000 lines\\\"}\"",
  "      break",
  "    fi",
  "  done",
  "fi",
  "# established TCP flows: conntrack sees the DNAT'd container traffic the host's own sockets do not; ss covers host services and ssh",
  "conns=\"\"; src=\"none\"",
  "if [ -r /proc/net/nf_conntrack ]; then conns=$(grep -E '^ipv[46] +[0-9]+ +tcp .*ESTABLISHED' /proc/net/nf_conntrack 2>/dev/null | awk '{ for(i=1;i<=NF;i++){ if($i ~ /^src=/ && s==\"\") s=substr($i,5); if($i ~ /^dport=/ && d==\"\") d=substr($i,7) } print s, d; s=\"\"; d=\"\" }'); src=\"conntrack\"",
  "elif command -v conntrack >/dev/null 2>&1; then conns=$(conntrack -L -p tcp --state ESTABLISHED 2>/dev/null | awk '{ for(i=1;i<=NF;i++){ if($i ~ /^src=/ && s==\"\") s=substr($i,5); if($i ~ /^dport=/ && d==\"\") d=substr($i,7) } print s, d; s=\"\"; d=\"\" }'); src=\"conntrack\"",
  "elif command -v ss >/dev/null 2>&1; then conns=$(ss -Htn state established 2>/dev/null | awk '{ l=$3; p=$4; sub(/.*:/,\"\",l); sub(/:[0-9]+$/,\"\",p); gsub(/[\\[\\]]/,\"\",p); sub(/^::ffff:/,\"\",p); print p, l }'); src=\"ss\"",
  "fi",
  "ssh_n=$(ss -Htn state established '( sport = :22 )' 2>/dev/null | grep -c .)",
  "# which container answers on each published host port, so a flow to :443 can be named",
  "port_map=$(docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null | awk -F'\t' '{ n=split($2, P, \", \"); for(i=1;i<=n;i++){ if(match(P[i], /:[0-9]+->/)){ hp=substr(P[i], RSTART+1, RLENGTH-3); if(!(hp in seen)){ seen[hp]=1; nm=$1; gsub(/[\"\\\\]/, \"\", nm); printf \"%s\\\"%s\\\":\\\"%s\\\"\", (c++?\",\":\"\"), hp, nm } } } }')",
  "act_conns=$(printf '%s\\n' \"$conns\" | awk -v src=\"$src\" -v ssh=\"${ssh_n:-0}\" -v pmap=\"$port_map\" '",
  "  function kind(ip){ if(ip==\"\" ) return \"x\"; if(ip ~ /^127\\./ || ip==\"::1\" || ip ~ /^169\\.254\\./ || ip ~ /^fe80/) return \"x\"; if(ip ~ /^172\\.(1[6-9]|2[0-9]|3[01])\\./) return \"x\"; if(ip ~ /^10\\./ || ip ~ /^192\\.168\\./) return \"internal\"; return \"external\" }",
  "  NF==2 { k=kind($1); if(k==\"x\") next; total++; if(k==\"external\") ext++; else int_++; ports[$2]++; peers[$1]=1; pair[$1 \" \" $2]++; pk[$1 \" \" $2]=k }",
  "  END { np=0; for(p in ports) np++; printf \"{\\\"source\\\":\\\"%s\\\",\\\"established\\\":%d,\\\"external\\\":%d,\\\"internal\\\":%d,\\\"peers\\\":%d,\\\"ssh\\\":%d,\\\"by_port\\\":{\", src, total, ext, int_, length(peers), ssh; first=1; for(p in ports){ if(p ~ /^[0-9]+$/){ printf \"%s\\\"%s\\\":%d\", (first?\"\":\",\"), p, ports[p]; first=0 } }",
  "    printf \"},\\\"top_peers\\\":[\"; for(t=0;t<8;t++){ best=\"\"; bn=0; for(q in pair){ if(!(q in done) && pair[q]>bn){ best=q; bn=pair[q] } } if(best==\"\") break; done[best]=1; split(best, ab, \" \"); if(ab[2] !~ /^[0-9]+$/) continue; printf \"%s{\\\"ip\\\":\\\"%s\\\",\\\"port\\\":%d,\\\"flows\\\":%d,\\\"kind\\\":\\\"%s\\\"}\", (t?\",\":\"\"), ab[1], ab[2], bn, pk[best] }",
  "    printf \"],\\\"port_map\\\":{%s}}\", pmap }')",
  "users_now=$(who 2>/dev/null | grep -c .)",
  "lastl=$(last -n 8 --time-format iso 2>/dev/null | grep -vE '^(reboot|shutdown|wtmp|btmp|$)' | head -n 1)",
  "last_user=$(printf '%s' \"$lastl\" | awk '{print $1}'); last_at=$(printf '%s' \"$lastl\" | grep -oE '[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}[+-][0-9]{2}:?[0-9]{2}' | head -n 1)",
  "act_logins=\"{\\\"users_now\\\":${users_now:-0},\\\"last_login_user\\\":$(jstr \"$last_user\"),\\\"last_login_at\\\":$(jstr \"$last_at\")}\"",
  "act_net=$(awk -F'[: ]+' 'NR>2 && $2 !~ /^(lo|docker|br-|veth|virbr)/ { rx+=$3; tx+=$11 } END { printf \"{\\\"rx_bytes\\\":%.0f,\\\"tx_bytes\\\":%.0f}\", rx, tx }' /proc/net/dev 2>/dev/null)",
  "activity=\"{\\\"version\\\":1,\\\"containers\\\":[$act_containers],\\\"connections\\\":${act_conns:-null},\\\"front_door\\\":$act_front,\\\"logins\\\":$act_logins,\\\"net\\\":${act_net:-null}}\"",
];

const DOCKER_OUT = [
  "out=$(printf '{\"probe\":\"aws-advisor/docker/3\",\"kind\":\"docker\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"docker\":%s,\"containers\":%s,\"container_details\":[%s],\"activity\":%s}' \"$hn\" \"$now\" \"$docker_json\" \"$containers\" \"$cdetail\" \"$activity\")",
];

const APPS_BODY = [
  "# ---- log shipping (probe 1.6): the CloudWatch log groups this box's agents are configured to write to, read from their config files",
  "# ---- (CloudWatch agent, the old awslogs agent, Fluent Bit, Fluentd, the Docker daemon and each running container with the awslogs driver). Templated names are skipped.",
  "# ---- Quoting note: the setup script embeds this document in a bash heredoc inside $( ), so single quotes must pair up on every line and never sit alone in a comment.",
  "ship=\"\"; shipn=\"\"; shipseen=\"|\"",
  "addship() { g=$(printf '%s' \"$1\" | tr -d '\"\\047,; ' | cut -c1-200); [ -n \"$g\" ] || return 0; case \"$g\" in *\\$*|*\\{*|*%*) return 0;; esac",
  "  case \"$shipseen\" in *\"|$2=$g|\"*) return 0;; esac; shipseen=\"$shipseen$2=$g|\"",
  "  ship=\"$ship$shipn{\\\"group\\\":\\\"$(esc \"$g\")\\\",\\\"via\\\":\\\"$(esc \"$2\")\\\",\\\"source\\\":\\\"$(esc \"$3\")\\\"}\"; shipn=\",\"; }",
  "for f in /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.d/* /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.toml /etc/awslogs/awslogs.conf /var/awslogs/etc/awslogs.conf /etc/fluent-bit/*.conf /etc/fluent-bit/*.yaml /etc/fluent-bit/*.yml /etc/fluent-bit/conf.d/* /etc/td-agent-bit/*.conf /etc/td-agent/td-agent.conf /etc/fluent/fluent.conf /etc/fluentd/fluent.conf; do",
  "  [ -r \"$f\" ] || continue",
  "  case \"$f\" in *amazon-cloudwatch-agent*) via=cloudwatch-agent;; *awslogs*) via=awslogs;; *fluent-bit*|*td-agent-bit*) via=fluent-bit;; *) via=fluentd;; esac",
  "  for g in $(grep -ioE 'log_group_name\"?[[:space:]]*[:=]?[[:space:]]*\"?[^\",[:space:]]+' \"$f\" 2>/dev/null | sed -E 's/^[^:=[:space:]]+[[:space:]]*[:=]?[[:space:]]*\"?//' | head -n 50); do addship \"$g\" \"$via\" \"$f\"; done",
  "done",
  "if [ -r /etc/docker/daemon.json ]; then for g in $(grep -oE '\"awslogs-group\"[[:space:]]*:[[:space:]]*\"[^\"]+\"' /etc/docker/daemon.json 2>/dev/null | sed -E 's/^.*:[[:space:]]*\"//; s/\"$//'); do addship \"$g\" docker-daemon /etc/docker/daemon.json; done; fi",
  "if docker info >/dev/null 2>&1; then for c in $(docker ps --format '{{.Names}}' 2>/dev/null | head -40); do l=$(docker inspect --format '{{.HostConfig.LogConfig.Type}} {{index .HostConfig.LogConfig.Config \"awslogs-group\"}}' \"$c\" 2>/dev/null); case \"$l\" in \"awslogs \"?*) addship \"${l#awslogs }\" \"docker:$c\" 'log driver';; esac; done; fi",
  "# ---- processes (probe 1.6): every user-space process grouped by command and user, so the advisor knows what runs on the box. Kernel threads",
  "# ---- are left out here; the advisor sets the OS daemons aside (src/instance_apps.ts). Names, counts, CPU, memory and age only: no arguments beyond the program and its first words.",
  "procs=$(ps -eo pid,ppid,user,pcpu,rss,etimes,comm,args --no-headers 2>/dev/null | tr -cd '\\12\\40-\\176' | awk '",
  "  $1==2 || $2==2 { next }",
  "  { w=\"\"; if($7 ~ /^(python[0-9.]*|node|nodejs|java|ruby|php[0-9.]*|perl|dotnet|bun|deno|uwsgi|gunicorn|celery|npm|yarn|pnpm)$/){ for(i=9;i<=NF && i<=14;i++) if($i !~ /^-/){ w=$i; sub(/.*\\//,\"\",w); break } }",
  "    nm=(w==\"\"?$7:$7 \" \" w); k=$3 \"\\t\" nm; n[k]++; cpu[k]+=$4; rss[k]+=$5; if($6+0>old[k]) old[k]=$6+0; if(!(k in a)){ a[k]=$8; for(i=9;i<=NF && i<=12;i++) a[k]=a[k] \" \" $i } }",
  "  END { for(k in n){ split(k, p, \"\\t\"); cmd=substr(a[k],1,120); gsub(/[\\\\\"]/,\"\",cmd); c=p[2]; gsub(/[\\\\\"]/,\"\",c); u=p[1]; gsub(/[\\\\\"]/,\"\",u);",
  "    printf \"%012.0f\\t{\\\"name\\\":\\\"%s\\\",\\\"user\\\":\\\"%s\\\",\\\"count\\\":%d,\\\"cpu_pct\\\":%.1f,\\\"rss_bytes\\\":%.0f,\\\"oldest_seconds\\\":%d,\\\"command\\\":\\\"%s\\\"}\\n\", rss[k]*1024, c, u, n[k], cpu[k], rss[k]*1024, old[k], cmd } }' | sort -rn | head -n 80 | cut -f2- | paste -sd, -)",
  "# ---- listeners (probe 1.8): every port the box answers on and which program owns it, from the listening sockets (ss) and the ports",
  "# ---- containers publish (docker ps). scope: all = every interface, loopback = the box only, address = one interface. The advisor matches",
  "# ---- each port to the app or container behind it and to the security group rules that let traffic in (src/instance_apps.ts).",
  "lsn=\"\"; dports=\"\"",
  "if command -v ss >/dev/null 2>&1; then lsn=$(ss -Hlntup 2>/dev/null | tr -cd '\\12\\40-\\176' | awk '{ proto=$1; if(proto!=\"tcp\" && proto!=\"udp\") next; l=$5; p=l; sub(/.*:/,\"\",p); if(p !~ /^[0-9]+$/) next; a=l; sub(/:[0-9]+$/,\"\",a); gsub(/[\\[\\]]/,\"\",a); sub(/%.*/,\"\",a); if(a==\"*\"||a==\"0.0.0.0\"||a==\"::\"||a==\"\") s=\"all\"; else if(a ~ /^127\\./||a==\"::1\") s=\"loopback\"; else s=\"address\"; nm=\"\"; pid=\"\"; if(match($0,/users:\\(\\(\"[^\"]*\",pid=[0-9]+/)){ u=substr($0,RSTART,RLENGTH); nm=u; sub(/^users:\\(\\(\"/,\"\",nm); sub(/\",pid=.*/,\"\",nm); pid=u; sub(/.*pid=/,\"\",pid) } k=proto \":\" p \":\" a; if(k in seen) next; seen[k]=1; n++; if(n>80) exit; gsub(/[\\\\\"]/,\"\",nm); printf \"%s{\\\"proto\\\":\\\"%s\\\",\\\"port\\\":%d,\\\"bind\\\":\\\"%s\\\",\\\"scope\\\":\\\"%s\\\",\\\"process\\\":%s,\\\"pid\\\":%s,\\\"container\\\":null,\\\"container_port\\\":null}\", (n>1?\",\":\"\"), proto, p, a, s, (nm==\"\"?\"null\":\"\\\"\" nm \"\\\"\"), (pid==\"\"?\"null\":pid) }'); fi",
  "dports=$(docker ps --format '{{.Names}}\\t{{.Ports}}' 2>/dev/null | awk -F'\\t' '{ n=split($2, P, \", \"); for(i=1;i<=n;i++){ if(match(P[i], /:[0-9]+->[0-9]+\\/(tcp|udp)/)){ m=substr(P[i],RSTART+1,RLENGTH-1); hp=m; sub(/->.*/,\"\",hp); cp=m; sub(/.*->/,\"\",cp); pr=cp; sub(/.*\\//,\"\",pr); sub(/\\/.*/,\"\",cp); b=P[i]; sub(/:[0-9]+->.*/,\"\",b); gsub(/[\\[\\]]/,\"\",b); if(b==\"0.0.0.0\"||b==\"::\"||b==\"\") s=\"all\"; else if(b ~ /^127\\./) s=\"loopback\"; else s=\"address\"; nm=$1; gsub(/[\\\\\"]/,\"\",nm); k=pr \":\" hp; if(k in seen) continue; seen[k]=1; c++; if(c>80) exit; printf \"%s{\\\"proto\\\":\\\"%s\\\",\\\"port\\\":%d,\\\"bind\\\":\\\"%s\\\",\\\"scope\\\":\\\"%s\\\",\\\"process\\\":null,\\\"pid\\\":null,\\\"container\\\":\\\"%s\\\",\\\"container_port\\\":%d}\", (c>1?\",\":\"\"), pr, hp, b, s, nm, cp } } }')",
  "listeners=\"$lsn\"; if [ -n \"$lsn\" ] && [ -n \"$dports\" ]; then listeners=\"$lsn,$dports\"; elif [ -z \"$lsn\" ]; then listeners=\"$dports\"; fi",
  "# ---- host firewall (probe apps 2.1): the packet filter on the box, from iptables-save and ip6tables-save (one text format for the legacy and",
  "# ---- nf_tables backends) and from nft list ruleset wherever nft exists (the native nftables tables: firewalld, a hand-written inet table; the",
  "# ---- advisor drops the ip/ip6 tables iptables-nft mirrors there). Read-only. Counters, handles and timestamp comments are dropped so two boxes",
  "# ---- with the same rules print the same lines (the advisor hashes them: src/host_firewall.ts); 300 lines per family (400 for nft) at most, the true count alongside.",
  "fw_avail=false; fw_backend=\"\"; fw4=\"\"; fw6=\"\"; fwnft=\"\"; fw4n=0; fw6n=0; fwnn=0",
  "fwclean() { grep -v '^#' | grep . | sed -E 's/ \\[[0-9]+:[0-9]+\\]$//; s/^[[:space:]]+//' | tr -cd '\\12\\40-\\176'; }",
  "fwjson() { head -n \"${1:-300}\" | cut -c1-400 | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g' | awk '{ printf \"%s\\\"%s\\\"\", (NR>1?\",\":\"\"), $0 }'; }",
  "if command -v iptables-save >/dev/null 2>&1; then fw_avail=true; t=$(iptables-save 2>/dev/null | fwclean); fw4n=$(printf '%s\\n' \"$t\" | grep -c .); fw4=$(printf '%s\\n' \"$t\" | fwjson); fi",
  "if command -v ip6tables-save >/dev/null 2>&1; then fw_avail=true; t=$(ip6tables-save 2>/dev/null | fwclean); fw6n=$(printf '%s\\n' \"$t\" | grep -c .); fw6=$(printf '%s\\n' \"$t\" | fwjson); fi",
  "if command -v iptables >/dev/null 2>&1; then case \"$(iptables -V 2>/dev/null)\" in *nf_tables*) fw_backend=nf_tables;; *legacy*) fw_backend=legacy;; *) fw_backend=iptables;; esac; fi",
  "if command -v nft >/dev/null 2>&1; then t=$(nft list ruleset 2>/dev/null | sed -E 's/ counter packets [0-9]+ bytes [0-9]+//; s/ # handle [0-9]+$//' | fwclean); fwnn=$(printf '%s\\n' \"$t\" | grep -c .); fwnft=$(printf '%s\\n' \"$t\" | fwjson 400); if [ \"$fw_avail\" = false ]; then fw_avail=true; fw_backend=nftables; fi; fi",
  "firewall=$(printf '{\"available\":%s,\"backend\":%s,\"v4\":[%s],\"v6\":[%s],\"nft\":[%s],\"v4_lines\":%s,\"v6_lines\":%s,\"nft_lines\":%s}' \"$fw_avail\" \"$(jstr \"$fw_backend\")\" \"$fw4\" \"$fw6\" \"$fwnft\" \"$fw4n\" \"$fw6n\" \"$fwnn\")",
  "# a ruleset the output cap could not carry even compressed (kube-proxy hosts) is reported by its counts alone",
  "[ ${#firewall} -gt 40000 ] && firewall=$(printf '{\"available\":%s,\"backend\":%s,\"v4\":[],\"v6\":[],\"nft\":[],\"v4_lines\":%s,\"v6_lines\":%s,\"nft_lines\":%s,\"oversize\":true}' \"$fw_avail\" \"$(jstr \"$fw_backend\")\" \"$fw4n\" \"$fw6n\" \"$fwnn\")",
];

const APPS_OUT = [
  "out=$(printf '{\"probe\":\"aws-advisor/apps/3\",\"kind\":\"apps\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"log_shipping\":[%s],\"processes\":[%s],\"listeners\":[%s],\"firewall\":%s}' \"$hn\" \"$now\" \"$ship\" \"$procs\" \"$listeners\" \"$firewall\")",
];

const SOFTWARE_BODY = [
  "# ---- software (probe 2.0): what is installed and which version, for vulnerability matching. Read-only: package database, /etc/os-release,",
  "# ---- uname, the version flag of well-known programs, and the images of the running containers. Names, versions and the CPE os-release declares; nothing is executed beyond --version.",
  "os_id=\"\"; os_ver=\"\"; os_name=\"\"; os_cpe=\"\"",
  "# the distribution names its own CPE in os-release on Amazon Linux, Fedora, RHEL, Rocky, Alma and SUSE (CPE_NAME; software/7): read as is, the advisor forms one for the rest",
  "if [ -r /etc/os-release ]; then os_id=$(. /etc/os-release 2>/dev/null; printf '%s' \"${ID:-}\"); os_ver=$(. /etc/os-release 2>/dev/null; printf '%s' \"${VERSION_ID:-}\"); os_name=$(. /etc/os-release 2>/dev/null; printf '%s' \"${PRETTY_NAME:-}\"); os_cpe=$(. /etc/os-release 2>/dev/null; printf '%s' \"${CPE_NAME:-}\" | tr -cd '\\40-\\176' | cut -c1-200); fi",
  "kernel=$(uname -r 2>/dev/null); arch=$(uname -m 2>/dev/null)",
  "# the running kernel (probe software/6): uname -r is the boot image's name, on Debian and Ubuntu an ABI (6.1.0-54-cloud-amd64, 6.8.0-45-generic) that never carries the point release,",
  "# so two more facts ride with it: the installed package that owns the booted image (what the distribution's advisories name, and which of several installed kernels is",
  "# the one running) and the upstream version (the x.y.z the kernel CNA's ranges name). Read from the package database and /proc; nothing is executed",
  "kp=\"\"; kpv=\"\"; kps=\"\"; kup=\"\"",
  "if [ -n \"$kernel\" ]; then",
  "  if command -v dpkg-query >/dev/null 2>&1; then for c in \"linux-image-$kernel\" \"linux-image-unsigned-$kernel\"; do r=$(dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${source:Package}\\n' \"$c\" 2>/dev/null | head -n 1 | tr -cd '\\11\\40-\\176'); case \"$r\" in ?i*) kp=$(printf '%s' \"$r\" | cut -f2); kpv=$(printf '%s' \"$r\" | cut -f3); kps=$(printf '%s' \"$r\" | cut -f4); break;; esac; done",
  "  elif command -v rpm >/dev/null 2>&1; then r=$(rpm -qf \"/lib/modules/$kernel\" --qf '%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\t%{SOURCERPM}\\n' 2>/dev/null | head -n 1 | tr -cd '\\11\\40-\\176'); case \"$r\" in ''|*'not owned'*) ;; *) kp=$(printf '%s' \"$r\" | cut -f1); kpv=$(printf '%s' \"$r\" | cut -f2 | sed 's/^(none)://'); kps=$(printf '%s' \"$r\" | cut -f3 | sed -E 's/-[^-]*-[^-]*\\.src\\.rpm$//');; esac",
  "  elif command -v apk >/dev/null 2>&1; then r=$(apk info -W \"/boot/vmlinuz-${kernel##*-}\" 2>/dev/null | sed -n 's/.* is owned by //p' | head -n 1 | tr -cd '\\40-\\176'); case \"$r\" in *-[0-9]*) kp=$(printf '%s' \"$r\" | sed -E 's/-[0-9].*$//'); kpv=${r#\"$kp-\"};; esac; fi",
  "  # the upstream version: Ubuntu names it in /proc/version_signature (its package version carries the ABI, 6.8.0-45.45, so that is never read); elsewhere the package version",
  "  # starts with it (Debian 6.1.176-1, Amazon Linux 6.1.134-150.224.amzn2023, Alpine 6.6.30-r0), as does /proc/version on a Debian kernel without its package, and uname -r on any kernel not named by an ABI",
  "  kup=$(awk '{print $NF}' /proc/version_signature 2>/dev/null)",
  "  [ -z \"$kup\" ] && [ -n \"$kpv\" ] && [ \"$os_id\" != ubuntu ] && kup=$(printf '%s' \"$kpv\" | sed -E 's/^[0-9]+://; s/^([0-9]+\\.[0-9]+(\\.[0-9]+)?).*$/\\1/')",
  "  [ -z \"$kup\" ] && kup=$(sed -n 's/.* Debian \\([0-9][0-9.]*\\)-.*/\\1/p' /proc/version 2>/dev/null | head -n 1)",
  "  [ -z \"$kup\" ] && case \"$kernel\" in *.0-[0-9]*-*) ;; *) kup=$(printf '%s' \"$kernel\" | sed -E 's/^([0-9]+\\.[0-9]+(\\.[0-9]+)?).*$/\\1/');; esac",
  "  case \"$kup\" in [0-9]*.[0-9]*) kup=$(printf '%s' \"$kup\" | tr -cd '0-9.');; *) kup=\"\";; esac",
  "fi",
  "kpj=null; [ -n \"$kp\" ] && kpj=$(printf '{\"n\":%s,\"v\":%s,\"s\":%s}' \"$(jstr \"$kp\")\" \"$(jstr \"$kpv\")\" \"$(jstr \"$kps\")\")",
  "pm=\"\"; pkgs=\"\"",
  "# every installed package: name, version, architecture and, when it differs from the name, the source package (s): the distribution advisories (OSV, USN, DSA) name the source, openssh, not the binary, openssh-server",
  "if command -v dpkg-query >/dev/null 2>&1; then pm=deb; pkgs=$(dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\n' 2>/dev/null | tr -cd '\\11\\12\\40-\\176' | awk -F'\\t' '$1 ~ /^.i/ { gsub(/[\\\\\"]/,\"\",$2); gsub(/[\\\\\"]/,\"\",$3); gsub(/[\\\\\"]/,\"\",$4); gsub(/[\\\\\" ]/,\"\",$5); printf \"%s{\\\"n\\\":\\\"%s\\\",\\\"v\\\":\\\"%s\\\",\\\"a\\\":\\\"%s\\\"%s}\", (n++?\",\":\"\"), $2, $3, $4, ($5!=\"\" && $5!=$2 ? \",\\\"s\\\":\\\"\" $5 \"\\\"\" : \"\") }')",
  "elif command -v rpm >/dev/null 2>&1; then pm=rpm; pkgs=$(rpm -qa --qf '%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n' 2>/dev/null | tr -cd '\\11\\12\\40-\\176' | awk -F'\\t' '{ v=$2; sub(/^\\(none\\):/,\"\",v); s=$4; sub(/-[^-]*-[^-]*\\.src\\.rpm$/,\"\",s); gsub(/[\\\\\"]/,\"\",$1); gsub(/[\\\\\"]/,\"\",v); gsub(/[\\\\\"]/,\"\",$3); gsub(/[\\\\\"]/,\"\",s); printf \"%s{\\\"n\\\":\\\"%s\\\",\\\"v\\\":\\\"%s\\\",\\\"a\\\":\\\"%s\\\"%s}\", (n++?\",\":\"\"), $1, v, $3, (s!=\"\" && s!=$1 && s!=\"(none)\" ? \",\\\"s\\\":\\\"\" s \"\\\"\" : \"\") }')",
  "elif command -v apk >/dev/null 2>&1; then pm=apk; pkgs=$( (apk list -I 2>/dev/null || apk info -v 2>/dev/null) | tr -cd '\\12\\40-\\176' | awk '{ p=$1; gsub(/[\\\\\"]/,\"\",p); if(match(p,/-[0-9][^-]*(-r[0-9]+)?$/)){ n=substr(p,1,RSTART-1); v=substr(p,RSTART+1) } else { n=p; v=\"\" } s=\"\"; if(match($0,/\\{[^}]*\\}/)){ s=substr($0,RSTART+1,RLENGTH-2); gsub(/[\\\\\"]/,\"\",s) } printf \"%s{\\\"n\\\":\\\"%s\\\",\\\"v\\\":\\\"%s\\\",\\\"a\\\":\\\"\\\"%s}\", (c++?\",\":\"\"), n, v, (s!=\"\" && s!=n ? \",\\\"s\\\":\\\"\" s \"\\\"\" : \"\") }')",
  "fi",
  "# the version string of the programs a CVE usually names, from the binary itself (one line, printable ASCII, 100 chars)",
  "bins=\"\"; bn=\"\"; seenp=\"\"",
  "# one row per program file (software 1.5): nodejs is a link to node on Debian, python to python3, httpd to apache2; a name that resolves to a file already listed is the same program, not a second one",
  "# where a program may live besides PATH (the agent runs as root with a short PATH): /usr/local, /opt, snap, and every user's nvm tree — a Node installed by a person is as real as one from a package (probe software/5). Symlinks resolved, duplicates dropped",
  "pathsof() { ( command -v \"$1\" 2>/dev/null; for c in /usr/local/bin/\"$1\" /usr/local/sbin/\"$1\" /opt/*/bin/\"$1\" /snap/bin/\"$1\" /home/*/.nvm/versions/node/*/bin/\"$1\" /root/.nvm/versions/node/*/bin/\"$1\" /home/*/.local/bin/\"$1\" /usr/local/n/versions/node/*/bin/\"$1\"; do [ -x \"$c\" ] && printf '%s\\n' \"$c\"; done ) | while read -r c; do readlink -f \"$c\" 2>/dev/null || printf '%s\\n' \"$c\"; done | awk '!s[$0]++'; }",
  "vof() { \"$@\" 2>&1 </dev/null | head -n 1 | tr -cd '\\40-\\176' | cut -c1-100; }",
  "addbin() { [ -n \"$2\" ] || return 0; bins=\"$bins$bn{\\\"name\\\":\\\"$(esc \"$1\")\\\",\\\"version\\\":\\\"$(esc \"$2\")\\\",\\\"path\\\":\\\"$(esc \"$3\")\\\"}\"; bn=\",\"; }",
  "for b in sshd nginx apache2 httpd openssl node nodejs python3 python docker containerd postgres redis-server mysqld mariadbd mongod java ruby go caddy haproxy traefik bitcoind lnd php perl git curl; do",
  "  for p in $(pathsof \"$b\"); do case \" $seenp \" in *\" $p \"*) continue;; esac; seenp=\"$seenp $p\"; v=\"\"",
  "    case \"$b\" in sshd) v=$(vof ssh -V);; nginx) v=$(vof \"$p\" -v);; openssl) v=$(vof \"$p\" version);; go) v=$(vof \"$p\" version);; java) v=$(vof \"$p\" -version);; apache2|httpd) v=$(vof \"$p\" -v);; *) v=$(vof \"$p\" --version);; esac",
  "    addbin \"$b\" \"$v\" \"$p\"",
  "  done",
  "done",
  "# what the runtimes bundle (probe software/4): the libraries compiled into Node, from the binary itself (process.versions) — what a CVE in brotli or OpenSSL reaches through a Node that ships its own copy",
  "bund=\"\"; bd=\"\"",
  "for p in $( (pathsof node; pathsof nodejs) | awk '!s[$0]++'); do pv=$(\"$p\" -p 'JSON.stringify(process.versions)' 2>/dev/null </dev/null | head -c 4000 | tr -cd '\\40-\\176'); case \"$pv\" in \\{*\\}) bund=\"$bund$bd{\\\"name\\\":\\\"node\\\",\\\"path\\\":\\\"$(esc \"$p\")\\\",\\\"versions\\\":$pv}\"; bd=\",\";; esac; done",
  "# the dependencies of the packages that own the probed programs (dpkg only for now; probe software/4): the chain a CVE in a shared library reaches a service through. Bounded: a few dozen packages, never the whole database",
  "deps=\"\"; dd=\"\"",
  "if command -v dpkg-query >/dev/null 2>&1; then owners=$(for b in sshd nginx apache2 httpd openssl node nodejs python3 python docker containerd postgres redis-server mysqld mariadbd mongod java ruby go caddy haproxy traefik bitcoind lnd php perl git curl; do p=$(command -v \"$b\" 2>/dev/null) || continue; dpkg -S \"$(readlink -f \"$p\")\" 2>/dev/null | head -n 1 | cut -d: -f1; done | sort -u); for o in $owners; do d=$(dpkg-query -W -f='${Depends}' \"$o\" 2>/dev/null | tr -cd '\\40-\\176' | cut -c1-2000); [ -n \"$d\" ] || continue; deps=\"$deps$dd{\\\"n\\\":\\\"$(esc \"$o\")\\\",\\\"d\\\":\\\"$(esc \"$d\")\\\"}\"; dd=\",\"; done; fi",
  "# the images behind the running containers: name, id, digest, build date, platform",
  "imgs=\"\"",
  "if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then imgs=$(docker ps --format '{{.Image}}' 2>/dev/null | sort -u | head -60 | while read -r im; do [ -n \"$im\" ] || continue; ins=$(docker image inspect --format '{{.Id}}|{{join .RepoDigests \",\"}}|{{.Created}}|{{.Os}}/{{.Architecture}}' \"$im\" 2>/dev/null | head -n 1); printf '%s\\t%s\\n' \"$im\" \"$ins\"; done | tr -cd '\\11\\12\\40-\\176' | awk -F'\\t' '{ split($2, f, \"|\"); gsub(/[\\\\\"]/,\"\",$1); gsub(/[\\\\\"]/,\"\",f[2]); printf \"%s{\\\"image\\\":\\\"%s\\\",\\\"id\\\":\\\"%s\\\",\\\"digests\\\":\\\"%s\\\",\\\"created\\\":\\\"%s\\\",\\\"platform\\\":\\\"%s\\\"}\", (n++?\",\":\"\"), $1, f[1], f[2], f[3], f[4] }'); fi",
  "# hibernation setup (probe software/3): whether EC2's hibernate can finish in this guest. Read-only: /sys/power, /proc/cmdline, the swap sizes,",
  "# what answers the ACPI sleep button EC2 presses (the hibernation agent's service enabled, an acpid rule, or logind with HandleSuspendKey=hibernate)",
  "hz_disk=false; grep -qw disk /sys/power/state 2>/dev/null && hz_disk=true",
  "hz_cmd=false; grep -q 'resume=' /proc/cmdline 2>/dev/null && hz_cmd=true",
  "hz_res=$(cat /sys/power/resume 2>/dev/null | tr -cd '0-9:')",
  "hz_agent=\"\"; for s in hibinit-agent hibagent; do for w in /etc/systemd/system/*.wants/\"$s\".service; do if [ -e \"$w\" ]; then hz_agent=$s; fi; done; [ -n \"$hz_agent\" ] && break; done",
  "hz_acpi=false; grep -qs 'button/sleep' /etc/acpi/events/* && hz_acpi=true",
  "hz_key=$( (systemd-analyze cat-config systemd/logind.conf 2>/dev/null || cat /etc/systemd/logind.conf /etc/systemd/logind.conf.d/*.conf 2>/dev/null) | sed -n 's/^[[:space:]]*HandleSuspendKey=[[:space:]]*//p' | tail -n 1 | tr -cd 'a-z-')",
  "hz_swap=$(awk 'NR>1{s+=$3} END{printf \"%.0f\", s*1024}' /proc/swaps 2>/dev/null)",
  "hz_file=0; for f in /swap /swapfile; do if [ -f \"$f\" ]; then z=$(stat -c %s \"$f\" 2>/dev/null); [ -n \"$z\" ] && [ \"$z\" -gt \"$hz_file\" ] && hz_file=$z; fi; done",
  "hz_mem=$(awk '/^MemTotal:/{printf \"%.0f\", $2*1024}' /proc/meminfo 2>/dev/null)",
  "hib=$(printf '{\"kernel_disk\":%s,\"cmdline_resume\":%s,\"sys_resume\":%s,\"agent\":%s,\"acpi_sleep_handler\":%s,\"logind_suspend_key\":%s,\"swap_active_bytes\":%s,\"swap_file_bytes\":%s,\"mem_bytes\":%s}' \\",
  "  \"$hz_disk\" \"$hz_cmd\" \"$(jstr \"$hz_res\")\" \"$(jstr \"$hz_agent\")\" \"$hz_acpi\" \"$(jstr \"$hz_key\")\" \"${hz_swap:-0}\" \"$hz_file\" \"${hz_mem:-0}\")",
  "out=$(printf '{\"probe\":\"aws-advisor/software/7\",\"kind\":\"software\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"os\":{\"id\":%s,\"version\":%s,\"name\":%s,\"cpe\":%s},\"kernel\":%s,\"kernel_upstream\":%s,\"kernel_package\":%s,\"arch\":%s,\"package_manager\":%s,\"packages\":[%s],\"binaries\":[%s],\"images\":[%s],\"bundles\":[%s],\"depends\":[%s],\"hibernation\":%s}' \\",
  "  \"$hn\" \"$now\" \"$(jstr \"$os_id\")\" \"$(jstr \"$os_ver\")\" \"$(jstr \"$os_name\")\" \"$(jstr \"$os_cpe\")\" \"$(jstr \"$kernel\")\" \"$(jstr \"$kup\")\" \"$kpj\" \"$(jstr \"$arch\")\" \"$(jstr \"$pm\")\" \"$pkgs\" \"$bins\" \"$imgs\" \"$bund\" \"$deps\" \"$hib\")",
  "full=$out",
];

/** The lines the sbom and images scripts share, byte for byte: the syft environment, the scratch directory and its guarded removals (the only `rm`
 *  a probe makes; ssm.test.ts and setProbeScriptOverride know these exact lines), the time budget, finding or installing syft, and the scan
 *  function that turns one syft run into S and P records. */
const SBOM_COMMON = [
  "SYFT_CHECK_FOR_APP_UPDATE=false; export SYFT_CHECK_FOR_APP_UPDATE",
  "SYFT_QUIET=true; export SYFT_QUIET",
  "SYFT_LINUX_KERNEL_CATALOG_MODULES=false; export SYFT_LINUX_KERNEL_CATALOG_MODULES",
  "tmo() { if command -v timeout >/dev/null 2>&1; then timeout \"$@\"; else shift; \"$@\"; fi; }",
  "# scratch space (sbom 1.5): a directory of the probe's own on disk (/var/tmp first: /tmp may be memory) for the output template, the registry config of",
  "# the images probe, and what syft unpacks when the images probe pulls an image from its registry (stereoscope-*, about twice the image's size; a scan",
  "# the time budget kills leaves that behind, and enough runs filled /tmp). Emptied after every scan and when the probe exits; the images probe skips an",
  "# image the free space cannot hold. The box's own sbom probe saves nothing there since sbom 1.7 (it reads executables and container roots in place).",
  "# What earlier runs left is removed too: stereoscope-* directories in /tmp and /var/tmp untouched for an hour (a scan of this probe's own never lasts",
  "# that long). AWS_ADVISOR_SBOM_TMP names the directory (tests). The only removals a probe makes, and each guards itself: the scratch functions touch",
  "# nothing but a path that ends in /aws-advisor-sbom, the sweep nothing but a stereoscope-* directory",
  "sbtmp=${AWS_ADVISOR_SBOM_TMP:-}; if [ -z \"$sbtmp\" ]; then for d in /var/tmp /tmp; do if [ -z \"$sbtmp\" ] && [ -d \"$d\" ] && [ -w \"$d\" ]; then sbtmp=$d/aws-advisor-sbom; fi; done; fi",
  "scratch_reset() { case \"$sbtmp\" in */aws-advisor-sbom) rm -rf \"$sbtmp\" 2>/dev/null; mkdir -p \"$sbtmp\" 2>/dev/null || sbtmp=\"\";; *) sbtmp=\"\";; esac; return 0; }",
  "scratch_drop() { case \"$sbtmp\" in */aws-advisor-sbom) rm -rf \"$sbtmp\" 2>/dev/null;; esac; return 0; }",
  "scratch_reset; if [ -n \"$sbtmp\" ]; then TMPDIR=$sbtmp; export TMPDIR; fi",
  "trap scratch_drop EXIT",
  "find /tmp /var/tmp -maxdepth 1 -name 'stereoscope-*' -mmin +60 -exec rm -rf {} \\; 2>/dev/null",
  "start=$(date +%s); budget=1200",
  "syft=\"\"; for c in $(command -v syft 2>/dev/null) /usr/local/bin/syft /usr/bin/syft /opt/syft/syft /snap/bin/syft /root/.local/bin/syft; do if [ -z \"$syft\" ] && [ -x \"$c\" ]; then syft=$c; fi; done",
  "# syft install (sbom 1.1): a box without syft gets the pinned release when the install parameter says yes (PROBE_SBOM_INSTALL): the official",
  "# installer fetches it from GitHub, verifies its checksum and puts it in /usr/local/bin. The one lasting write a probe makes (the scratch directory it unpacks images in is emptied after every scan); it counts against the",
  "# time budget, and a box without curl, egress to get.anchore.io and github.com, or a writable /usr/local/bin stays as it is and says so",
  "install=__INSTALL__; SYFT_VERSION=v1.55.0; bindir=${AWS_ADVISOR_SYFT_DIR:-/usr/local/bin}; inst=\"\"",
  "if [ -z \"$syft\" ] && [ \"$install\" = yes ]; then",
  "  if command -v curl >/dev/null 2>&1 && curl -sSfL --max-time 60 https://get.anchore.io/syft 2>/dev/null | tmo 180 sh -s -- -b \"$bindir\" \"$SYFT_VERSION\" >/dev/null 2>&1 && [ -x \"$bindir/syft\" ]; then syft=$bindir/syft; inst=\"installed $SYFT_VERSION\"; else inst=\"install failed: curl, egress to get.anchore.io and github.com, and a writable $bindir are needed\"; fi",
  "elif [ -z \"$syft\" ]; then inst=\"not installed; the install parameter is no\"",
  "fi",
  "tool=\"\"; [ -n \"$syft\" ] && tool=$(\"$syft\" version 2>/dev/null </dev/null | awk '/^Version:/{print \"syft \" $2; exit}' | tr -cd '\\40-\\176' | cut -c1-40)",
  "avail=false; [ -n \"$syft\" ] && avail=true",
  "pm=\"\"; for c in dpkg-query rpm apk; do command -v \"$c\" >/dev/null 2>&1 && pm=$c; done",
  "# the time budget in seconds (start above, before the install): the images get two thirds of it, the filesystem what is left; the document timeout sits above the whole",
  "left() { l=$(( start + $1 - $(date +%s) )); if [ \"$l\" -gt 5 ]; then printf '%s' \"$l\"; else printf '5'; fi; }",
  "# what the scans gather, one record per line: S<tab>source<tab>ref<tab>status<tab>total<tab>image id<tab>digest<tab>note<tab>platform<tab>container<tab>sha256<tab>size<tab>package for each scan (source",
  "# image, dir or proc: a running executable, sbom 1.7, whose ref is host:<path> or container:<id>:<path>; the last three only for an executable nothing identified), P<tab>source<tab>ref<tab>purl<tab>cpes for each package",
  "lines=\"\"; cur_id=\"\"; cur_dg=\"\"; cur_pl=\"\"; cur_ct=\"\"; cur_file=\"\"",
  "# a Chromium build syft has no classifier for (sbom 1.7): the headless shell Playwright and Puppeteer download (headless_shell, chrome-headless-shell), Chrome for",
  "# Testing, a chromium binary under a distribution name. The version is plain text inside the file (Chrome/153.0.8010.12), read with grep, nothing executed; it is the",
  "# same code as Chrome at that version and NVD files Chromium CVEs against google:chrome, so that is the CPE. Only when syft found nothing in a running executable",
  "# the package that owns a host executable (dpkg, rpm or apk; a container's cannot be asked without entering it), for an executable nothing identified",
  "owner_of() { o=\"\"; if command -v dpkg >/dev/null 2>&1; then o=$(dpkg -S \"$1\" 2>/dev/null | head -n 1 | cut -d: -f1); elif command -v rpm >/dev/null 2>&1; then o=$(rpm -qf \"$1\" --qf '%{NAME}\\n' 2>/dev/null | head -n 1); case \"$o\" in *'not owned'*|*'No such'*) o=\"\";; esac; elif command -v apk >/dev/null 2>&1; then o=$(apk info -W \"$1\" 2>/dev/null | sed -n 's/.* is owned by //p' | head -n 1 | sed -E 's/-[0-9].*$//'); fi; printf '%s' \"$o\" | tr -cd '\\40-\\176' | cut -c1-120; }",
  "sniff() { case \"${1##*/}\" in chrome|chrome-headless-shell|headless_shell|chromium|chromium-browser|google-chrome|google-chrome-stable|google-chrome-beta|google-chrome-unstable) v=$(grep -a -o -m1 -E 'Chrome/[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+' \"$1\" 2>/dev/null | head -n 1 | cut -d/ -f2); [ -n \"$v\" ] && printf 'pkg:generic/chrome@%s\\tcpe:2.3:a:google:chrome:%s:*:*:*:*:*:*:*\\n' \"$v\" \"$v\";; esac; return 0; }",
  "# the output (sbom 1.7): one line per package, its purl and the CPEs syft assigned it, space-separated: the NVD dictionary match or a binary classifier",
  "# declaration first, the name permutations syft generates after. A Go template over the syft JSON model, written to the scratch directory before",
  "# every scan (the directory is emptied after each); without scratch space, or on a syft too old for the template model, the purls alone",
  "tpl=\"\"; [ -n \"$sbtmp\" ] && tpl=$sbtmp/purlcpe.tmpl",
  "# the template's closing token is assembled here: an SSM document reads a word in double braces anywhere in its script as one of its own parameters and refuses an undeclared one; the docker format strings pass only because their names start with a dot",
  "E=$(printf '{{%s}}' end)",
  "writetpl() { if [ -n \"$tpl\" ]; then printf '%s%s%s%s%s%s' '{{range .artifacts}}{{.purl}}{{\"\\t\"}}{{range $i, $c := .cpes}}{{if ne $c.source \"syft-generated\"}}{{$c.cpe}} ' \"$E$E\" '{{range $i, $c := .cpes}}{{if eq $c.source \"syft-generated\"}}{{$c.cpe}} ' \"$E$E\" '{{\"\\n\"}}' \"$E\" > \"$tpl\" 2>/dev/null || tpl=\"\"; fi; return 0; }",
  "scan() { k=$1; r=$2; secs=$3; shift 3",
  "  writetpl",
  "  if [ -n \"$tpl\" ]; then raw=$(tmo \"$secs\" \"$syft\" scan \"$@\" -o template -t \"$tpl\" -q 2>/dev/null </dev/null); rc=$?; else raw=$(tmo \"$secs\" \"$syft\" scan \"$@\" -o purls -q 2>/dev/null </dev/null); rc=$?; fi",
  "  # the template refused (a syft before 1.0 renders the legacy model): the purls alone, within what is left of the budget",
  "  if [ \"$rc\" -ne 0 ] && [ \"$rc\" -ne 124 ] && [ -n \"$tpl\" ]; then t=$(left \"$budget\"); [ \"$t\" -gt \"$secs\" ] && t=$secs; raw=$(tmo \"$t\" \"$syft\" scan \"$@\" -o purls -q 2>/dev/null </dev/null); rc=$?; fi",
  "  st=ok; [ \"$rc\" -eq 124 ] && st=timeout; [ \"$rc\" -ne 0 ] && [ \"$rc\" -ne 124 ] && st=error",
  "  pl=$(printf '%s\\n' \"$raw\" | tr -cd '\\11\\12\\40-\\176' | grep '^pkg:' | awk -F'\\t' '!s[$1]++')",
  "  # the OS packages of the host are the software probe reading (dpkg, rpm, apk); the filesystem scan keeps the rest",
  "  [ \"$k\" = dir ] && [ -n \"$pm\" ] && pl=$(printf '%s\\n' \"$pl\" | grep -v -E '^pkg:(deb|rpm|apk)/')",
  "  n=$(printf '%s\\n' \"$pl\" | grep -c '^pkg:'); snote=\"\"",
  "  if [ \"$n\" -eq 0 ] && [ \"$st\" = ok ] && [ \"$k\" = proc ] && [ -n \"$cur_file\" ]; then pl=$(sniff \"$cur_file\"); n=$(printf '%s\\n' \"$pl\" | grep -c '^pkg:'); [ \"$n\" -gt 0 ] && snote=\"version read from the text inside the binary (syft has no classifier for it)\"; fi",
  "  # an executable nothing identified (sbom 1.7): its hash, size and, on the host, owning package travel with the record, so the graph keeps it as an unclassified",
  "  # component a rule can be written for later (what the file is, which build) rather than losing it",
  "  sha=\"\"; sz=\"\"; own=\"\"",
  "  if [ \"$n\" -eq 0 ] && [ \"$st\" = ok ] && [ \"$k\" = proc ] && [ -n \"$cur_file\" ]; then sha=$( (sha256sum \"$cur_file\" 2>/dev/null || shasum -a 256 \"$cur_file\" 2>/dev/null) | head -n 1 | cut -c1-64 | tr -cd '0-9a-f'); sz=$(stat -c %s \"$cur_file\" 2>/dev/null || stat -f %z \"$cur_file\" 2>/dev/null); case \"$sz\" in ''|*[!0-9]*) sz=\"\";; esac; [ -z \"$cur_ct\" ] && own=$(owner_of \"$cur_file\"); fi",
  "  lines=$(printf '%s\\nS\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\t%s\\n%s' \"$lines\" \"$k\" \"$r\" \"$st\" \"$n\" \"$cur_id\" \"$cur_dg\" \"$snote\" \"$cur_pl\" \"$cur_ct\" \"$sha\" \"$sz\" \"$own\" \"$(printf '%s\\n' \"$pl\" | awk -F'\\t' -v k=\"$k\" -v r=\"$r\" '/^pkg:/{print \"P\\t\" k \"\\t\" r \"\\t\" $1 \"\\t\" $2}')\")",
  "  scratch_reset",
  "}",
];

/** The JSON of both scripts: `mk` (defined by each, with its probe id) wraps what `build` prints under the output cap. */
const SBOM_JSON = [
  "# the JSON under the SSM output cap: every scan with its status and true count, the package lists trimmed to one shared budget (cap) that shrinks until the compressed line fits;",
  "# cpes maps each listed purl to its CPEs (at most 8, best first; a purl without any is left out of the map). A backslash or quote in a CPE is escaped, not dropped (CPE escapes",
  "# punctuation with a backslash), character by character: awks disagree on backslashes in a gsub replacement (mawk halves them, BSD awk keeps them), concatenation they agree on",
  "build() { printf '%s\\n' \"$lines\" | awk -F'\\t' -v cap=\"$1\" 'function esc(s, o, i, ch) { o=\"\"; for (i=1; i<=length(s); i++) { ch=substr(s, i, 1); if (ch==\"\\\\\" || ch==\"\\\"\") o=o \"\\\\\" ch; else o=o ch } return o } $1==\"S\" { ns++; key[ns]=$2 \"\\t\" $3; src[ns]=$2; ref[ns]=$3; st[ns]=$4; tot[ns]=$5+0; iid[ns]=$6; dg[ns]=$7; nt[ns]=$8; pf[ns]=$9; ct[ns]=$10; sh[ns]=$11; sz[ns]=$12; ow[ns]=$13; next } $1==\"P\" { k=$2 \"\\t\" $3; if (used < cap) { used++; p=$4; gsub(/[\\\\\"]/, \"\", p); pl[k]=pl[k] (n[k]?\",\":\"\") \"\\\"\" p \"\\\"\"; n[k]++; if ($5 != \"\") { m=split($5, cp, \" \"); cl=\"\"; cn=0; for (j=1; j<=m && cn<8; j++) { c=cp[j]; if (c == \"\") continue; c=esc(c); cl=cl (cn?\",\":\"\") \"\\\"\" c \"\\\"\"; cn++ } if (cn) { ce[k]=ce[k] (cm[k]?\",\":\"\") \"\\\"\" p \"\\\":[\" cl \"]\"; cm[k]++ } } } } END { for (i=1;i<=ns;i++) { r=ref[i]; gsub(/[\\\\\"]/, \"\", r); x=iid[i]; gsub(/[\\\\\"]/, \"\", x); y=dg[i]; gsub(/[\\\\\"]/, \"\", y); z=nt[i]; gsub(/[\\\\\"]/, \"\", z); q=pf[i]; gsub(/[\\\\\"]/, \"\", q); w=ct[i]; gsub(/[\\\\\"]/, \"\", w); h=sh[i]; gsub(/[^0-9a-f]/, \"\", h); o=ow[i]; gsub(/[\\\\\"]/, \"\", o); printf \"%s{\\\"source\\\":\\\"%s\\\",\\\"ref\\\":\\\"%s\\\",\\\"image_id\\\":\\\"%s\\\",\\\"digest\\\":\\\"%s\\\",\\\"platform\\\":\\\"%s\\\",\\\"container\\\":\\\"%s\\\",\\\"status\\\":\\\"%s\\\",\\\"total\\\":%d,\\\"note\\\":\\\"%s\\\",\\\"sha256\\\":\\\"%s\\\",\\\"size\\\":%s,\\\"package\\\":\\\"%s\\\",\\\"purls\\\":[%s],\\\"cpes\\\":{%s}}\", (i>1?\",\":\"\"), src[i], r, x, y, q, w, st[i], tot[i], z, h, (sz[i]==\"\"?\"null\":sz[i]), o, pl[key[i]], ce[key[i]] } }'; }",
  "# the whole, untrimmed (cap 0) for the upload; then the inline object under the cap",
  "full=$(mk 0 \"$(build 100000000)\")",
  "cap=3000; out=$(mk $cap \"$(build $cap)\")",
  "while [ $cap -gt 100 ] && toobig; do cap=$((cap * 2 / 3)); out=$(mk $cap \"$(build $cap)\"); done",
];

const SBOM_BODY = [
  "# ---- sbom (probe 2.0): what runs on the box beyond the OS packages, as package URLs read by syft (https://github.com/anchore/syft) in place: the",
  "# ---- executables of the running processes (host and container alike: a container process through the root filesystem the daemon keeps mounted",
  "# ---- for it), the running images read through that same root when asked, and the host filesystem when asked. Nothing is pulled, saved or unpacked",
  "# ---- on the box: the registry images are the image scanner instance reading (the images probe). Read-only: syft only reads files where they are, docker",
  "# ---- is only asked what runs, and syft is told not to check for its own updates (no network). Kernel modules are left out: the kernel is the software probe reading.",
  "# ---- sbom 1.6: the images parameter. local = only images with no registry digest (built or loaded on this box); the ones pulled from a registry",
  "# ---- are the image scanner instance reading (the images probe), once for every box that runs them. all = every running image, here.",
  "# ---- sbom 1.7: the host parameter. processes (the default) reads the executables of the running processes; filesystem walks the host filesystem",
  "# ---- for language packages as before; both does both; none leaves the box to its images. Every purl comes with the CPEs syft assigned it.",
  ...SBOM_COMMON,
  "imgmode=__IMAGES_MODE__; case \"$imgmode\" in local) ;; *) imgmode=all;; esac",
  "hostmode=__HOST_MODE__; case \"$hostmode\" in filesystem|both|none) ;; *) hostmode=processes;; esac",
  "procroot=${AWS_ADVISOR_PROC:-/proc}",
  "# the running containers as the daemon knows them (at most 200): id and image name as docker ps lists them, then in one inspect call the image id and the root",
  "# filesystem the daemon keeps mounted on the host (overlay2 MergedDir). A daemon on the containerd snapshotter, and a Kubernetes node with no docker at all,",
  "# keep that root under the containerd task directory instead, found by the container id; a container process is reached through it, never by entering the container",
  "cl=\"\"; cins=\"\"",
  "if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then cl=$(docker ps --no-trunc --format '{{.ID}}\\t{{.Image}}' 2>/dev/null | head -200 | tr -cd '\\11\\12\\40-\\176'); ids=$(printf '%s\\n' \"$cl\" | cut -f1 | tr '\\n' ' '); [ -n \"${ids% }\" ] && cins=$(docker inspect --format '{{.Id}}|{{.Image}}|{{.GraphDriver.Data.MergedDir}}' $ids 2>/dev/null | tr -cd '\\11\\12\\40-\\176'); fi",
  "ct_ins() { printf '%s\\n' \"$cins\" | awk -F'|' -v c=\"$1\" '$1==c{print; exit}'; }",
  "rootfs_of() { r=\"\"; i=$(ct_ins \"$1\"); case \"$i\" in *\\|*\\|*) r=${i##*|};; esac; if [ -n \"$r\" ] && [ -d \"$r\" ]; then printf '%s' \"$r\"; return 0; fi",
  "  for c in /run/containerd/io.containerd.runtime.v2.task/*/\"$1\"/rootfs /run/docker/containerd/daemon/io.containerd.runtime.v2.task/moby/\"$1\"/rootfs; do if [ -d \"$c\" ]; then printf '%s' \"$c\"; return 0; fi; done; return 0; }",
  "if [ -n \"$syft\" ] && { [ \"$hostmode\" = processes ] || [ \"$hostmode\" = both ]; }; then",
  "  # the executables of the running processes (sbom 1.7), each read once where it is: a host process at its path, a container process through its container root",
  "  # (/proc/<pid>/exe names the path inside the container, the cgroup names the container). Kernel threads have no executable; this shell is skipped; one binary seen",
  "  # through many processes, or one image through many containers, is read once. At most 200 executables, each within a minute, within half the budget",
  "  seenx=\" \"; nx=0",
  "  for d in \"$procroot\"/[0-9]*; do pid=${d##*/}; [ \"$pid\" = \"$$\" ] && continue",
  "    exe=$(readlink \"$d/exe\" 2>/dev/null); [ -n \"$exe\" ] || continue",
  "    gone=\"\"; case \"$exe\" in *' (deleted)') exe=${exe% (deleted)}; gone=yes;; esac",
  "    cid=$(grep -o -E '[0-9a-f]{64}' \"$d/cgroup\" 2>/dev/null | head -n 1)",
  "    cur_id=\"\"; cur_dg=\"\"; cur_pl=\"\"; cur_ct=\"\"; root=\"\"; where=host; key=\"host|$exe\"",
  "    if [ -n \"$cid\" ]; then cur_ct=$(printf '%s' \"$cid\" | cut -c1-12); i=$(ct_ins \"$cid\"); case \"$i\" in *\\|*) x=${i#*|}; cur_id=${x%%|*};; esac; root=$(rootfs_of \"$cid\"); where=container:$cur_ct; key=\"${cur_id:-$cid}|$exe\"; fi",
  "    case \"$seenx\" in *\" $key \"*) continue;; esac; seenx=\"$seenx$key \"",
  "    [ \"$nx\" -ge 200 ] && break; nx=$((nx+1)); ref=\"$where:$exe\"",
  "    if [ -n \"$cid\" ] && [ -z \"$root\" ]; then lines=$(printf '%s\\nS\\tproc\\t%s\\tskipped\\t0\\t%s\\t\\tthe container root filesystem is not mounted where the daemon or containerd keep it\\t\\t%s' \"$lines\" \"$ref\" \"$cur_id\" \"$cur_ct\")",
  "    elif [ -n \"$gone\" ] || [ ! -f \"$root$exe\" ]; then lines=$(printf '%s\\nS\\tproc\\t%s\\tskipped\\t0\\t%s\\t\\tthe executable is gone from disk (replaced or removed while running)\\t\\t%s' \"$lines\" \"$ref\" \"$cur_id\" \"$cur_ct\")",
  "    elif [ \"$(left $((budget / 2)))\" -gt 5 ]; then t=$(left $((budget / 2))); [ \"$t\" -gt 60 ] && t=60; cur_file=$root$exe; scan proc \"$ref\" \"$t\" \"file:$root$exe\"; cur_file=\"\"",
  "    else lines=$(printf '%s\\nS\\tproc\\t%s\\tskipped\\t0\\t%s\\t\\tthe time budget ran out\\t\\t%s' \"$lines\" \"$ref\" \"$cur_id\" \"$cur_ct\"); fi",
  "  done",
  "fi",
  "if [ -n \"$syft\" ] && [ -n \"$cl\" ]; then",
  "  # the images behind the running containers (the list the software probe reports), each read in place through the root filesystem of one container that runs it",
  "  # (sbom 1.7: nothing is saved or unpacked; an image whose container root is not mounted where the daemon or containerd keep it is skipped and says so); at most 30, while two thirds of the budget last",
  "  for im in $(printf '%s\\n' \"$cl\" | cut -f2 | sort -u | head -30); do",
  "    # the image behind the name: its id and its registry digest (none for a build that never left the box) identify it when a tag such as latest moves; its platform tells a multi-arch digest apart",
  "    ins=$(docker image inspect --format '{{.Id}}|{{join .RepoDigests \",\"}}|{{.Os}}/{{.Architecture}}' \"$im\" 2>/dev/null | head -n 1 | tr -cd '\\40-\\176'); cur_id=\"\"; cur_dg=\"\"; cur_pl=\"\"; cur_ct=\"\"",
  "    case \"$ins\" in *\\|*\\|*) cur_id=${ins%%|*}; rest=${ins#*|}; cur_dg=${rest%%|*}; cur_dg=${cur_dg%%,*}; cur_dg=${cur_dg#*@}; cur_pl=${rest#*|};; esac",
  "    # local mode: an image with a registry digest is the scanner's; it is not listed here, so the scanner's record of it stands",
  "    if [ \"$imgmode\" = local ] && [ -n \"$cur_dg\" ]; then continue; fi",
  "    root=\"\"; for c in $(printf '%s\\n' \"$cl\" | awk -F'\\t' -v i=\"$im\" '$2==i{print $1}'); do root=$(rootfs_of \"$c\"); if [ -n \"$root\" ]; then cur_ct=$(printf '%s' \"$c\" | cut -c1-12); break; fi; done",
  "    if [ -z \"$root\" ]; then lines=$(printf '%s\\nS\\timage\\t%s\\tskipped\\t0\\t%s\\t%s\\tthe container root filesystem is not mounted where the daemon or containerd keep it (nothing is pulled or saved on a box)\\t%s\\t' \"$lines\" \"$im\" \"$cur_id\" \"$cur_dg\" \"$cur_pl\")",
  "    elif [ \"$(left $((budget * 2 / 3)))\" -gt 5 ]; then scan image \"$im\" \"$(left $((budget * 2 / 3)))\" \"dir:$root\" --base-path \"$root\"; else lines=$(printf '%s\\nS\\timage\\t%s\\tskipped\\t0\\t%s\\t%s\\tthe time budget ran out\\t%s\\t' \"$lines\" \"$im\" \"$cur_id\" \"$cur_dg\" \"$cur_pl\"); fi",
  "  done",
  "fi",
  "if [ -n \"$syft\" ] && { [ \"$hostmode\" = filesystem ] || [ \"$hostmode\" = both ]; }; then",
  "  # the host filesystem, without the kernel and device trees, runtime state, caches, logs, the container stores (read above as images), and every",
  "  # mount that is not a local disk (network and FUSE filesystems, squashfs snaps, bind mounts) as /proc/mounts lists them; globbing is off while the list is passed",
  "  ex=\"\"; for d in proc sys dev run tmp var/tmp var/cache var/log var/lib/docker var/lib/containerd var/lib/snapd snap boot mnt media lost+found root/.cache 'home/*/.cache'; do ex=\"$ex --exclude ./$d/**\"; done",
  "  # syft is a Go binary with a few hundred modules of its own: the tool does not catalog itself",
  "  [ -n \"$syft\" ] && ex=\"$ex --exclude .$syft\"",
  "  for mp in $(awk '$2 != \"/\" && $3 !~ /^(ext[234]|xfs|btrfs|zfs|f2fs|jfs)$/ && $2 !~ /\\\\/ {print $2}' /proc/mounts 2>/dev/null | sort -u); do ex=\"$ex --exclude .$mp/**\"; done",
  "  cur_id=\"\"; cur_dg=\"\"; cur_pl=\"\"; cur_ct=\"\"",
  "  if [ \"$(left $budget)\" -gt 5 ]; then set -f; scan dir / \"$(left $budget)\" dir:/ $ex; set +f; else lines=$(printf '%s\\nS\\tdir\\t/\\tskipped\\t0\\t\\t\\tthe time budget ran out\\t\\t' \"$lines\"); fi",
  "fi",
  "mk() { printf '{\"probe\":\"aws-advisor/sbom/5\",\"kind\":\"sbom\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"sbom\":{\"available\":%s,\"tool\":%s,\"install\":%s,\"images_mode\":\"%s\",\"host_mode\":\"%s\",\"cap\":%s,\"sources\":[%s]}}' \"$hn\" \"$now\" \"$avail\" \"$(jstr \"$tool\")\" \"$(jstr \"$inst\")\" \"$imgmode\" \"$hostmode\" \"$1\" \"$2\"; }",
  ...SBOM_JSON,
];

const IMAGES_BODY = [
  "# ---- images (probe 1.0): the packages inside container images pulled from their registries by digest, read by syft on the designated scanner",
  "# ---- instance once per distinct image the fleet runs (the sbom pass sends the batches: src/image_pass.ts). No Docker daemon is involved: syft reads",
  "# ---- the registry itself (source registry:), with the platform the box reported so a multi-arch digest resolves to what that box runs.",
  "# ---- Registry access is this instance's own: its docker config and credential helpers for any registry, and for ECR a token per registry from",
  "# ---- its instance role through the AWS CLI, written to a syft config file in the scratch directory (gone with it). Nothing leaves this box but the result.",
  ...SBOM_COMMON,
  "# the scanner's budget (images 1.2): 40 minutes, twice the sbom probe's, since nothing else waits on this box and a large image needs most of it (IMAGES_BUDGET_SECONDS in src/image_pass.ts)",
  "budget=2400",
  "images='__IMAGES__'; itmo=__IMAGE_TIMEOUT__; case \"$itmo\" in ''|*[!0-9]*) itmo=180;; esac",
  "inlist() { case \"$2\" in *\" $1 \"*) return 0;; esac; return 1; }",
  "# the syft config: one registry.auth entry per ECR host in the batch; rewritten before every scan because the scratch directory is emptied after each",
  "cfg=\"\"; [ -n \"$sbtmp\" ] && cfg=$sbtmp/syft.yaml; cfgtext=$(printf 'registry:\\n  auth:\\n')",
  "writecfg() { if [ -n \"$cfg\" ]; then (umask 077; printf '%s\\n' \"$cfgtext\" > \"$cfg\"); fi; return 0; }",
  "regs=\" \"; noauth=\" \"",
  "if [ -n \"$syft\" ]; then for e in $images; do ref=${e%%|*}; host=${ref%%/*}",
  "  case \"$host\" in *.dkr.ecr.*.amazonaws.com|*.dkr.ecr.*.amazonaws.com.cn|public.ecr.aws) ;; *) continue;; esac",
  "  if inlist \"$host\" \"$regs\" || inlist \"$host\" \"$noauth\"; then continue; fi",
  "  tok=\"\"; if command -v aws >/dev/null 2>&1 && [ -n \"$cfg\" ]; then case \"$host\" in public.ecr.aws) tok=$(tmo 30 aws ecr-public get-login-password --region us-east-1 2>/dev/null </dev/null);; *) reg=${host#*.dkr.ecr.}; reg=${reg%%.*}; tok=$(tmo 30 aws ecr get-login-password --region \"$reg\" 2>/dev/null </dev/null);; esac; fi",
  "  tok=$(printf '%s' \"$tok\" | tr -cd 'A-Za-z0-9+/=._-' | head -c 20000)",
  "  if [ -n \"$tok\" ]; then cfgtext=$(printf '%s\\n    - authority: %s\\n      username: AWS\\n      password: \"%s\"' \"$cfgtext\" \"$host\" \"$tok\"); regs=\"$regs$host \"; else noauth=\"$noauth$host \"; fi",
  "done; fi",
  "# the batch, one image at a time: its digest from the entry, its platform after the bar; the free-space floor is 2 GB (an image's size is not known before the pull)",
  "min_kb=${AWS_ADVISOR_SBOM_MIN_FREE_KB:-2097152}",
  "if [ -n \"$syft\" ]; then for e in $images; do ref=${e%%|*}; plat=${e#*|}; [ \"$plat\" = \"$e\" ] && plat=\"\"; host=${ref%%/*}; cur_id=\"\"; cur_dg=${ref##*@}; cur_pl=$plat; cur_ct=\"\"",
  "  case \"$cur_dg\" in sha256:*) ;; *) cur_dg=\"\";; esac",
  "  free_kb=$(df -Pk \"${sbtmp:-/tmp}\" 2>/dev/null | awk 'NR==2{print $4}'); case \"$free_kb\" in ''|*[!0-9]*) free_kb=\"\";; esac",
  "  if inlist \"$host\" \"$noauth\"; then lines=$(printf '%s\\nS\\timage\\t%s\\tskipped\\t0\\t\\t%s\\tECR auth needs the AWS CLI on the scanner and an instance role that may pull from %s\\t%s\\t' \"$lines\" \"$ref\" \"$cur_dg\" \"$host\" \"$cur_pl\")",
  "  elif [ -n \"$free_kb\" ] && [ \"$free_kb\" -lt \"$min_kb\" ]; then lines=$(printf '%s\\nS\\timage\\t%s\\tskipped\\t0\\t\\t%s\\tneeds about %s MB of scratch space under %s, %s MB free\\t%s\\t' \"$lines\" \"$ref\" \"$cur_dg\" \"$((min_kb / 1024))\" \"${sbtmp:-/tmp}\" \"$((free_kb / 1024))\" \"$cur_pl\")",
  "  elif [ \"$(left $budget)\" -gt 5 ]; then writecfg; t=$(left $budget); [ \"$t\" -gt \"$itmo\" ] && t=$itmo; set --; [ -n \"$cfg\" ] && set -- -c \"$cfg\"; [ -n \"$plat\" ] && set -- \"$@\" --platform \"$plat\"; scan image \"$ref\" \"$t\" \"$@\" \"registry:$ref\"",
  "  else lines=$(printf '%s\\nS\\timage\\t%s\\tskipped\\t0\\t\\t%s\\tthe time budget ran out\\t%s\\t' \"$lines\" \"$ref\" \"$cur_dg\" \"$cur_pl\"); fi",
  "done; fi",
  "mk() { printf '{\"probe\":\"aws-advisor/images/2\",\"kind\":\"images\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"sbom\":{\"available\":%s,\"tool\":%s,\"install\":%s,\"cap\":%s,\"sources\":[%s]}}' \"$hn\" \"$now\" \"$avail\" \"$(jstr \"$tool\")\" \"$(jstr \"$inst\")\" \"$1\" \"$2\"; }",
  ...SBOM_JSON,
];

const UPLOAD = [
  "# ---- upload (probe 2.1): when the advisor passed a presigned S3 URL (the upload parameter), the whole object goes there gzip-compressed, so nothing is",
  "# ---- lost to the 24,000-character cap of the inline answer; the inline line then carries the receipt (bytes, sha256) and stays the fallback. The object",
  "# ---- is spooled through a temp file (curl needs its size) that is emptied afterwards. An inline object the cap would cut becomes a stub once the whole is in S3.",
  "# quoted: a presigned URL is full of & and = (the parameter pattern admits no quote character)",
  "upload='__UPLOAD__'; up=\"\"; case \"$upload\" in https://*) ;; *) upload=\"\";; esac",
  "if [ -n \"$upload\" ] && [ -n \"${full:-}\" ] && ! command -v curl >/dev/null 2>&1; then up=\"upload failed (curl is needed on the box)\"",
  "elif [ -n \"$upload\" ] && [ -n \"${full:-}\" ] && ! command -v gzip >/dev/null 2>&1; then up=\"upload failed (gzip is needed on the box)\"",
  "elif [ -n \"$upload\" ] && [ -n \"${full:-}\" ]; then",
  "  tmp=$(mktemp 2>/dev/null || printf '/tmp/aws-advisor-probe.%s' \"$$\")",
  "  if printf '%s' \"$full\" | gzip -c -9 > \"$tmp\" && curl -sSf -X PUT --max-time 180 --data-binary @\"$tmp\" \"$upload\" >/dev/null 2>&1; then",
  "    h=$( (sha256sum \"$tmp\" 2>/dev/null || shasum -a 256 \"$tmp\" 2>/dev/null || openssl dgst -r -sha256 \"$tmp\" 2>/dev/null) | head -n 1 | cut -c1-64 | tr -cd '0-9a-f')",
  "    up=\"uploaded $(wc -c < \"$tmp\" | tr -d ' ')${h:+ $h}\"",
  "  else up=\"upload failed (curl and egress to S3 are needed)\"; fi",
  "  : > \"$tmp\"",
  "fi",
  "if [ -n \"$up\" ]; then out=\"${out%\\}},\\\"upload\\\":$(jstr \"$up\")}\"; fi",
  "case \"$up\" in uploaded*) if toobig; then out=$(printf '{\"probe\":\"%s\",\"kind\":\"%s\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"inline\":false,\"upload\":%s}' \"$(printf '%s' \"$out\" | head -c 300 | sed -n 's/^{\"probe\":\"\\([^\"]*\\)\".*/\\1/p')\" \"$(printf '%s' \"$out\" | head -c 300 | sed -n 's/^{\"probe\":\"[^\"]*\",\"kind\":\"\\([^\"]*\\)\".*/\\1/p')\" \"$hn\" \"$now\" \"$(jstr \"$up\")\"); fi;; esac",
];

const EMIT = [
  "# ---- exactly one JSON object on the last line. GetCommandInvocation returns only the first 24,000 characters of stdout, so a big result",
  "# ---- prints the object gzip-compressed and base64-encoded on one marked line instead (probe 1.7); the advisor decodes it (parseProbeOutput).",
  "if [ ${#out} -gt 16000 ] && command -v gzip >/dev/null 2>&1 && command -v base64 >/dev/null 2>&1; then printf 'aws-advisor-gz:%s\\n' \"$(printf '%s' \"$out\" | gzip -c -9 | base64 | tr -d '\\n')\"; else printf '%s\\n' \"$out\"; fi",
];

const header = (kind: ProbeKind) => `# aws-advisor probe ${kind} ${PROBE_DEFS[kind].version} (read-only). Prints exactly one JSON object on the last line.`;
const DEFAULT_LINES: Record<ProbeKind, string[]> = {
  host: [header("host"), ...PREAMBLE, ...HOST_BODY, ...HOST_OUT, ...EMIT],
  docker: [header("docker"), ...PREAMBLE, ...DOCKER_BODY, ...DOCKER_OUT, ...EMIT],
  apps: [header("apps"), ...PREAMBLE, ...APPS_BODY, ...APPS_OUT, ...EMIT],
  software: [header("software"), ...PREAMBLE, ...SOFTWARE_BODY, ...UPLOAD, ...EMIT],
  sbom: [header("sbom"), ...PREAMBLE, ...SBOM_BODY, ...UPLOAD, ...EMIT],
  images: [header("images"), ...PREAMBLE, ...IMAGES_BODY, ...UPLOAD, ...EMIT],
};

/** The default script of a kind, with `__SIGNALS__` still in place for the docker kind. */
export const defaultProbeScript = (kind: ProbeKind): string => DEFAULT_LINES[kind].join("\n");
const overrideKey = (kind: ProbeKind) => `probe_script:${kind}`;
/** A script saved from Settings > Probes, or null when the default is in force. */
export const probeScriptOverride = (kind: ProbeKind): string | null => getSetting(overrideKey(kind));
/** The script in force: the override when one is saved, else the default; `__SIGNALS__` still unresolved. */
export const probeScriptTemplate = (kind: ProbeKind): string => probeScriptOverride(kind) ?? defaultProbeScript(kind);
/** The kinds that can outgrow SSM's inline output cap: their documents take the `upload` parameter (a presigned S3 URL) and their scripts post the whole result there. */
export const UPLOAD_KINDS: readonly ProbeKind[] = ["software", "sbom", "images"];
/** The value the sbom and images documents' `install` parameter gets from the setting. */
export const probeInstallValue = (): "yes" | "no" => (config.probeSbomInstall === "off" ? "no" : "yes");
/** The placeholders each script carries and the document parameter each stands for (`probeDocument` maps them; `probeScript` inlines a default). */
const PLACEHOLDERS: { token: string; parameter: string; inline: () => string; kinds: readonly ProbeKind[] }[] = [
  { token: "__SIGNALS__", parameter: "signals", inline: () => config.probeSignals, kinds: ["docker"] },
  { token: "__INSTALL__", parameter: "install", inline: probeInstallValue, kinds: ["sbom", "images"] },
  { token: "__IMAGES_MODE__", parameter: "images", inline: () => "all", kinds: ["sbom"] },
  { token: "__HOST_MODE__", parameter: "host", inline: () => config.probeSbomHost, kinds: ["sbom"] },
  { token: "__IMAGES__", parameter: "images", inline: () => "", kinds: ["images"] },
  { token: "__IMAGE_TIMEOUT__", parameter: "timeout", inline: () => "180", kinds: ["images"] },
  { token: "__UPLOAD__", parameter: "upload", inline: () => "", kinds: UPLOAD_KINDS },
];
/** The script as sent inline (tests, the stock-document fallback): every placeholder replaced by its default (the signals by `signals`). */
export const probeScript = (kind: ProbeKind, signals: string = config.probeSignals): string => PLACEHOLDERS.reduce((s, p) => s.replace(p.token, p.token === "__SIGNALS__" ? signals : p.inline()), probeScriptTemplate(kind));

/** Saves a script override after the checks a read-only probe must pass; throws with the reason otherwise. */
export function setProbeScriptOverride(kind: ProbeKind, text: string): void {
  const t = String(text ?? "").replace(/\r\n/g, "\n");
  if (!t.trim()) throw new Error("the script is empty; reset it to go back to the default");
  if (t.length > 60_000) throw new Error("the script is too long for an SSM document (60,000 characters at most)");
  // the words a read-only probe never needs (reboot and shutdown appear as log words in the docker script, so they are not on the list)
  // the stock script's own lines are trusted (the sbom one removes the scratch directory it gives syft and what earlier runs left in /tmp, on lines that guard themselves); what an edit adds must pass the word list
  const stock = new Set(defaultProbeScript(kind).split("\n"));
  const body = t.split("\n").filter((l) => !stock.has(l)).join("\n");
  for (const re of [/\brm\b/, /\bkill(all)?\b/, /\bsystemctl\b/, /\bsudo\b/, /\bmkfs\b/, /\bdd\s+if=/, /\bchmod\b/, /\bchown\b/, /\bapt(-get)?\s+(install|remove|purge)\b/, /\byum\s+(install|remove)\b/, /\bdnf\s+(install|remove)\b/, /\bdocker\s+(rm|rmi|stop|kill|exec|run|prune)\b/, />\s*\/(etc|var|usr|boot|bin|sbin|lib)/]) if (re.test(body)) throw new Error(`the script contains "${t.match(re)![0]}": probes are read-only, that word is refused`);
  if (!t.includes('"probe":"aws-advisor/')) throw new Error('the script must print a JSON object with "probe":"aws-advisor/<kind>/<version>" on its last line');
  if (!t.includes(`"kind":"${kind}"`)) throw new Error(`the script must print "kind":"${kind}" in its JSON`);
  for (const p of PLACEHOLDERS) if (p.kinds.includes(kind) && !t.includes(p.token)) throw new Error(`the ${kind} script must keep the ${p.token} placeholder for the document's ${p.parameter} parameter`);
  if (t === defaultProbeScript(kind)) { resetProbeScript(kind); return; }
  setSetting(overrideKey(kind), t);
}
export const resetProbeScript = (kind: ProbeKind): void => { db.prepare("delete from settings where key = ?").run(overrideKey(kind)); };

/** Eight hex characters of the effective script's hash: the document description carries it, so a deployed document can be told current or stale. */
export const probeScriptHash = (kind: ProbeKind): string => createHash("sha1").update(probeScriptTemplate(kind)).digest("hex").slice(0, 8);

/** The SSM document name of a kind: the configured base (PROBE_DOCUMENT, default AwsAdvisorProbe) with the kind appended. */
export const probeDocumentName = (kind: ProbeKind): string => `${config.probeDocument}-${kind}`;
/** The pre-2.0 combined document (the base name alone): still accepted as a fallback for host, docker and apps while it exists. */
export const legacyProbeDocumentName = (): string => config.probeDocument;
/** The text the document description carries; `probeDocumentStatus` reads the hash back from it. */
export const probeDocumentDescription = (kind: ProbeKind): string => `aws-advisor probe ${kind} ${PROBE_DEFS[kind].version} ${probeScriptHash(kind)} (read-only)`;

/**
 * The SSM Command document that embeds one kind's script, for `aws ssm create-document`. The advisor sends the
 * document by name and passes no commands, so IAM can grant ssm:SendCommand on the advisor's documents only and the
 * credentials can never run anything else on the fleet. Served by GET /api/probes/:kind/document.
 */
export function probeDocument(kind: ProbeKind) {
  const def = PROBE_DEFS[kind];
  const script = PLACEHOLDERS.reduce((s, p) => s.replace(p.token, `{{ ${p.parameter} }}`), probeScriptTemplate(kind));
  // SSM validates allowedPattern with RE2, which caps a repeat count at 1000: no counts here (the SendCommand parameter limit bounds the length)
  const SPECS: Record<string, unknown> = {
    signals: { type: "String", description: "Use-signal patterns: name=regex entries joined by ;; (the advisor passes its current list; this default applies when a caller sends none).", default: DEFAULT_SIGNALS_STRING, allowedPattern: "^[^\\n]*$" },
    install: { type: "String", description: "yes installs the pinned syft release into /usr/local/bin where it is missing (the one lasting write a probe makes); no leaves such a box alone. The advisor passes PROBE_SBOM_INSTALL.", default: "yes", allowedValues: ["yes", "no"] },
    images: kind === "sbom"
      ? { type: "String", description: "all scans every running image on the box; local only the images with no registry digest (built or loaded here), leaving the rest to the image scanner instance. The advisor passes local while a scanner is configured and answered this pass.", default: "all", allowedValues: ["all", "local"] }
      : { type: "String", description: "The images to read, space-separated: <repository>@sha256:<digest> optionally followed by |<os>/<arch> (the platform of the box that runs it). The advisor sends one batch per command.", default: "", allowedPattern: "^[A-Za-z0-9._:/@|\\- ]*$" },
    host: { type: "String", description: "What syft reads of the box itself: processes (the executables of the running processes, host and container alike, each read in place), filesystem (the host filesystem walked for language packages), both, or none. The advisor passes PROBE_SBOM_HOST.", default: "processes", allowedValues: ["processes", "filesystem", "both", "none"] },
    timeout: { type: "String", description: "Seconds syft gets per image (the whole batch stays within the document's budget). The advisor passes PROBE_IMAGES_TIMEOUT_SECONDS.", default: "180", allowedPattern: "^[0-9]{2,4}$" },
    upload: { type: "String", description: "A presigned S3 PUT URL the whole result is posted to, gzip-compressed (the advisor signs one per run when an upload bucket is configured); empty keeps the result inline, under SSM's output cap.", default: "", allowedPattern: "^(https://[A-Za-z0-9._~:/?#@!$&()*+,;=%-]*)?$" },
  };
  const order = ["signals", "install", "images", "host", "timeout", "upload"].filter((p) => PLACEHOLDERS.some((x) => x.parameter === p && x.kinds.includes(kind)));
  return {
    schemaVersion: "2.2",
    description: probeDocumentDescription(kind),
    parameters: Object.fromEntries(order.map((p) => [p, SPECS[p]])),
    mainSteps: [{ action: "aws:runShellScript", name: `probe_${kind}`, inputs: { timeoutSeconds: String(def.timeout_seconds), runCommand: script.split("\n") } }],
  };
}

export interface ProbeDocumentInfo { kind: ProbeKind; name: string; version: string; hash: string; edited: boolean; create_command: string; update_command: string }

/** Name, version, hash and the CLI commands that create and update one kind's document. */
export function probeDocumentInfo(kind: ProbeKind): ProbeDocumentInfo {
  const name = probeDocumentName(kind);
  const url = `${config.publicUrl}/api/probes/${kind}/document`;
  return {
    kind, name, version: PROBE_DEFS[kind].version, hash: probeScriptHash(kind), edited: probeScriptOverride(kind) != null,
    create_command: `curl -s -H "x-api-token: $API_TOKEN" ${url} > probe-${kind}.json && aws ssm create-document --name ${name} --document-type Command --document-format JSON --content file://probe-${kind}.json`,
    update_command: `curl -s -H "x-api-token: $API_TOKEN" ${url} > probe-${kind}.json && aws ssm update-document --name ${name} --document-version '$LATEST' --document-format JSON --content file://probe-${kind}.json && aws ssm update-document-default-version --name ${name} --document-version "$(aws ssm describe-document --name ${name} --query Document.LatestVersion --output text)"`,
  };
}
export const probeDocumentsInfo = (): ProbeDocumentInfo[] => PROBE_KINDS.map(probeDocumentInfo);

/** Which kind a probe's JSON belongs to, from its `kind` or its `probe` string; the pre-2.0 combined probe is "all". */
export function probeKindOf(raw: { probe?: unknown; kind?: unknown }): ProbeKind | "all" {
  const k = typeof raw.kind === "string" ? raw.kind : "";
  if ((PROBE_KINDS as readonly string[]).includes(k)) return k as ProbeKind;
  const m = /^aws-advisor\/([a-z]+)\//.exec(String(raw.probe || ""));
  if (m && (PROBE_KINDS as readonly string[]).includes(m[1])) return m[1] as ProbeKind;
  return "all";
}
