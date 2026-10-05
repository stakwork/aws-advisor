import { createHash } from "node:crypto";
import { config } from "./config.js";
import { db, getSetting, setSetting } from "./db.js";
import { DEFAULT_SIGNALS_STRING } from "./signals.js";

/**
 * The probes: read-only shell scripts the advisor runs on a box through AWS Systems Manager Run Command, one per
 * concern so each can run on its own cadence and each SSM document stays small and scoped:
 *
 *  - host:     memory, swap, load, CPUs, uptime, disks and the top processes (the hourly statistics behind the alerts and charts)
 *  - docker:   the containers and the activity around them (logs, use signals, connections, the front door, logins, traffic)
 *  - apps:     what runs (process groups), what listens (ports), where the log agents ship
 *  - software: what is installed and at which version (packages, kernel, OS, well-known binaries, container images) for vulnerability matching
 *
 * Every script prints exactly one JSON object on its last line (gzip+base64 behind a marker when big), carrying
 * `probe` ("aws-advisor/<kind>/<version>") and `kind`. The text here is the default; Settings > Probes may override a
 * script (saved as a setting), and the SSM document embeds the effective text, so an edit means redeploying that
 * kind's document (the hash in the document description says whether it is current). Scripts only read /proc, /sys,
 * df, ps, ss, the package database and the version flags of known programs; nothing is written or changed on the box.
 *
 * Quoting note: the setup script embeds the documents in a bash heredoc inside $( ), so single quotes must pair up
 * on every line and never sit alone in a comment.
 */

export const PROBE_KINDS = ["host", "docker", "apps", "software"] as const;
export type ProbeKind = (typeof PROBE_KINDS)[number];
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
  /** The runtime setting that holds its cron and the one for its scope. */
  cron_key: string; scope_key: string;
  /** Whether the script takes the use-signal patterns (docker only). */
  takes_signals: boolean;
}

export const PROBE_DEFS: Record<ProbeKind, ProbeDef> = {
  host: { kind: "host", title: "Host", what: "memory, swap, load, CPUs, uptime, disks and the top processes: the hourly statistics behind the disk, memory and load alerts and the utilisation charts", version: "2.0", sections: ["cpus", "uptime_seconds", "memory", "load", "disks", "top_cpu", "top_mem"], timeout_seconds: 60, cron_key: "probeCron", scope_key: "probeScope", takes_signals: false },
  docker: { kind: "docker", title: "Containers and activity", what: "the containers (state, CPU, memory, network; image, health, restarts, ports, mounts, source repository and revision) and whether anyone uses the box: container logs and use signals, established connections, the front door, logins, traffic; the usage profiles and the swarm costs read it", version: "2.1", sections: ["docker", "containers", "container_details", "activity"], timeout_seconds: 90, cron_key: "probeDockerCron", scope_key: "probeScope", takes_signals: true },
  apps: { kind: "apps", title: "Programs, ports and log shipping", what: "every user-space program with its user, count, CPU and memory; every port the box answers on and who owns it (exposure comes from the security groups); the log groups its agents ship to", version: "2.0", sections: ["processes", "listeners", "log_shipping"], timeout_seconds: 60, cron_key: "probeAppsCron", scope_key: "probeScope", takes_signals: false },
  software: { kind: "software", title: "Installed software", what: "the OS and kernel, every installed package with its version (dpkg, rpm or apk), the version of well-known programs read from the binary, and the images behind the running containers: the inventory a CVE is matched against", version: "1.0", sections: ["os", "kernel", "arch", "package_manager", "packages", "binaries", "images"], timeout_seconds: 120, cron_key: "probeSoftwareCron", scope_key: "probeSoftwareScope", takes_signals: false },
};

// ---- the scripts --------------------------------------------------------------------------------------------------------

const PREAMBLE = [
  "set -u",
  "LC_ALL=C; export LC_ALL",
  "esc() { printf '%s' \"$1\" | sed 's/\\\\/\\\\\\\\/g; s/\"/\\\\\"/g'; }",
  "jstr() { if [ -n \"$1\" ]; then printf '\"%s\"' \"$(esc \"$1\")\"; else printf 'null'; fi; }",
  "hn=$(esc \"$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || echo unknown)\"); now=$(date -u +%Y-%m-%dT%H:%M:%SZ)",
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
];

const APPS_OUT = [
  "out=$(printf '{\"probe\":\"aws-advisor/apps/2\",\"kind\":\"apps\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"log_shipping\":[%s],\"processes\":[%s],\"listeners\":[%s]}' \"$hn\" \"$now\" \"$ship\" \"$procs\" \"$listeners\")",
];

const SOFTWARE_BODY = [
  "# ---- software (probe 2.0): what is installed and which version, for vulnerability matching. Read-only: package database, /etc/os-release,",
  "# ---- uname, the version flag of well-known programs, and the images of the running containers. Names and versions only; nothing is executed beyond --version.",
  "os_id=\"\"; os_ver=\"\"; os_name=\"\"",
  "if [ -r /etc/os-release ]; then os_id=$(. /etc/os-release 2>/dev/null; printf '%s' \"${ID:-}\"); os_ver=$(. /etc/os-release 2>/dev/null; printf '%s' \"${VERSION_ID:-}\"); os_name=$(. /etc/os-release 2>/dev/null; printf '%s' \"${PRETTY_NAME:-}\"); fi",
  "kernel=$(uname -r 2>/dev/null); arch=$(uname -m 2>/dev/null)",
  "pm=\"\"; pkgs=\"\"",
  "# every installed package: name, version, architecture and, when it differs from the name, the source package (s): the distribution advisories (OSV, USN, DSA) name the source, openssh, not the binary, openssh-server",
  "if command -v dpkg-query >/dev/null 2>&1; then pm=deb; pkgs=$(dpkg-query -W -f='${db:Status-Abbrev}\\t${Package}\\t${Version}\\t${Architecture}\\t${source:Package}\\n' 2>/dev/null | tr -cd '\\11\\12\\40-\\176' | awk -F'\\t' '$1 ~ /^.i/ { gsub(/[\\\\\"]/,\"\",$2); gsub(/[\\\\\"]/,\"\",$3); gsub(/[\\\\\"]/,\"\",$4); gsub(/[\\\\\" ]/,\"\",$5); printf \"%s{\\\"n\\\":\\\"%s\\\",\\\"v\\\":\\\"%s\\\",\\\"a\\\":\\\"%s\\\"%s}\", (n++?\",\":\"\"), $2, $3, $4, ($5!=\"\" && $5!=$2 ? \",\\\"s\\\":\\\"\" $5 \"\\\"\" : \"\") }')",
  "elif command -v rpm >/dev/null 2>&1; then pm=rpm; pkgs=$(rpm -qa --qf '%{NAME}\\t%{EPOCH}:%{VERSION}-%{RELEASE}\\t%{ARCH}\\t%{SOURCERPM}\\n' 2>/dev/null | tr -cd '\\11\\12\\40-\\176' | awk -F'\\t' '{ v=$2; sub(/^\\(none\\):/,\"\",v); s=$4; sub(/-[^-]*-[^-]*\\.src\\.rpm$/,\"\",s); gsub(/[\\\\\"]/,\"\",$1); gsub(/[\\\\\"]/,\"\",v); gsub(/[\\\\\"]/,\"\",$3); gsub(/[\\\\\"]/,\"\",s); printf \"%s{\\\"n\\\":\\\"%s\\\",\\\"v\\\":\\\"%s\\\",\\\"a\\\":\\\"%s\\\"%s}\", (n++?\",\":\"\"), $1, v, $3, (s!=\"\" && s!=$1 && s!=\"(none)\" ? \",\\\"s\\\":\\\"\" s \"\\\"\" : \"\") }')",
  "elif command -v apk >/dev/null 2>&1; then pm=apk; pkgs=$( (apk list -I 2>/dev/null || apk info -v 2>/dev/null) | tr -cd '\\12\\40-\\176' | awk '{ p=$1; gsub(/[\\\\\"]/,\"\",p); if(match(p,/-[0-9][^-]*(-r[0-9]+)?$/)){ n=substr(p,1,RSTART-1); v=substr(p,RSTART+1) } else { n=p; v=\"\" } s=\"\"; if(match($0,/\\{[^}]*\\}/)){ s=substr($0,RSTART+1,RLENGTH-2); gsub(/[\\\\\"]/,\"\",s) } printf \"%s{\\\"n\\\":\\\"%s\\\",\\\"v\\\":\\\"%s\\\",\\\"a\\\":\\\"\\\"%s}\", (c++?\",\":\"\"), n, v, (s!=\"\" && s!=n ? \",\\\"s\\\":\\\"\" s \"\\\"\" : \"\") }')",
  "fi",
  "# the version string of the programs a CVE usually names, from the binary itself (one line, printable ASCII, 100 chars)",
  "bins=\"\"; bn=\"\"",
  "vof() { \"$@\" 2>&1 </dev/null | head -n 1 | tr -cd '\\40-\\176' | cut -c1-100; }",
  "addbin() { [ -n \"$2\" ] || return 0; bins=\"$bins$bn{\\\"name\\\":\\\"$(esc \"$1\")\\\",\\\"version\\\":\\\"$(esc \"$2\")\\\",\\\"path\\\":\\\"$(esc \"$3\")\\\"}\"; bn=\",\"; }",
  "for b in sshd nginx apache2 httpd openssl node nodejs python3 python docker containerd postgres redis-server mysqld mariadbd mongod java ruby go caddy haproxy traefik bitcoind lnd php perl git curl; do",
  "  p=$(command -v \"$b\" 2>/dev/null) || continue; v=\"\"",
  "  case \"$b\" in sshd) v=$(vof ssh -V);; openssl) v=$(vof \"$p\" version);; go) v=$(vof \"$p\" version);; java) v=$(vof \"$p\" -version);; apache2|httpd) v=$(vof \"$p\" -v);; *) v=$(vof \"$p\" --version);; esac",
  "  addbin \"$b\" \"$v\" \"$p\"",
  "done",
  "# the images behind the running containers: name, id, digest, build date, platform",
  "imgs=\"\"",
  "if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then imgs=$(docker ps --format '{{.Image}}' 2>/dev/null | sort -u | head -60 | while read -r im; do [ -n \"$im\" ] || continue; ins=$(docker image inspect --format '{{.Id}}|{{join .RepoDigests \",\"}}|{{.Created}}|{{.Os}}/{{.Architecture}}' \"$im\" 2>/dev/null | head -n 1); printf '%s\\t%s\\n' \"$im\" \"$ins\"; done | tr -cd '\\11\\12\\40-\\176' | awk -F'\\t' '{ split($2, f, \"|\"); gsub(/[\\\\\"]/,\"\",$1); gsub(/[\\\\\"]/,\"\",f[2]); printf \"%s{\\\"image\\\":\\\"%s\\\",\\\"id\\\":\\\"%s\\\",\\\"digests\\\":\\\"%s\\\",\\\"created\\\":\\\"%s\\\",\\\"platform\\\":\\\"%s\\\"}\", (n++?\",\":\"\"), $1, f[1], f[2], f[3], f[4] }'); fi",
  "out=$(printf '{\"probe\":\"aws-advisor/software/2\",\"kind\":\"software\",\"hostname\":\"%s\",\"collected_at\":\"%s\",\"os\":{\"id\":%s,\"version\":%s,\"name\":%s},\"kernel\":%s,\"arch\":%s,\"package_manager\":%s,\"packages\":[%s],\"binaries\":[%s],\"images\":[%s]}' \\",
  "  \"$hn\" \"$now\" \"$(jstr \"$os_id\")\" \"$(jstr \"$os_ver\")\" \"$(jstr \"$os_name\")\" \"$(jstr \"$kernel\")\" \"$(jstr \"$arch\")\" \"$(jstr \"$pm\")\" \"$pkgs\" \"$bins\" \"$imgs\")",
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
  software: [header("software"), ...PREAMBLE, ...SOFTWARE_BODY, ...EMIT],
};

/** The default script of a kind, with `__SIGNALS__` still in place for the docker kind. */
export const defaultProbeScript = (kind: ProbeKind): string => DEFAULT_LINES[kind].join("\n");
const overrideKey = (kind: ProbeKind) => `probe_script:${kind}`;
/** A script saved from Settings > Probes, or null when the default is in force. */
export const probeScriptOverride = (kind: ProbeKind): string | null => getSetting(overrideKey(kind));
/** The script in force: the override when one is saved, else the default; `__SIGNALS__` still unresolved. */
export const probeScriptTemplate = (kind: ProbeKind): string => probeScriptOverride(kind) ?? defaultProbeScript(kind);
/** The script as sent inline (tests, the stock-document fallback): the use-signal patterns inlined. */
export const probeScript = (kind: ProbeKind, signals: string = config.probeSignals): string => probeScriptTemplate(kind).replace("__SIGNALS__", signals);

/** Saves a script override after the checks a read-only probe must pass; throws with the reason otherwise. */
export function setProbeScriptOverride(kind: ProbeKind, text: string): void {
  const t = String(text ?? "").replace(/\r\n/g, "\n");
  if (!t.trim()) throw new Error("the script is empty; reset it to go back to the default");
  if (t.length > 60_000) throw new Error("the script is too long for an SSM document (60,000 characters at most)");
  // the words a read-only probe never needs (reboot and shutdown appear as log words in the docker script, so they are not on the list)
  for (const re of [/\brm\b/, /\bkill(all)?\b/, /\bsystemctl\b/, /\bsudo\b/, /\bmkfs\b/, /\bdd\s+if=/, /\bchmod\b/, /\bchown\b/, /\bapt(-get)?\s+(install|remove|purge)\b/, /\byum\s+(install|remove)\b/, /\bdnf\s+(install|remove)\b/, /\bdocker\s+(rm|rmi|stop|kill|exec|run|prune)\b/, />\s*\/(etc|var|usr|boot|bin|sbin|lib)/]) if (re.test(t)) throw new Error(`the script contains "${t.match(re)![0]}": probes are read-only, that word is refused`);
  if (!t.includes('"probe":"aws-advisor/')) throw new Error('the script must print a JSON object with "probe":"aws-advisor/<kind>/<version>" on its last line');
  if (!t.includes(`"kind":"${kind}"`)) throw new Error(`the script must print "kind":"${kind}" in its JSON`);
  if (kind === "docker" && !t.includes("__SIGNALS__")) throw new Error("the docker script must keep the __SIGNALS__ placeholder for the use-signal patterns");
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
  const script = probeScriptTemplate(kind).replace("__SIGNALS__", "{{ signals }}");
  return {
    schemaVersion: "2.2",
    description: probeDocumentDescription(kind),
    parameters: def.takes_signals ? {
      signals: { type: "String", description: "Use-signal patterns: name=regex entries joined by ;; (the advisor passes its current list; this default applies when a caller sends none).", default: DEFAULT_SIGNALS_STRING, allowedPattern: "^[^\\n]*$" }, // SSM validates with RE2, which caps a repeat count at 1000: no count here (the SendCommand parameter limit bounds the length)
    } : {},
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
