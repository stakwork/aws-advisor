import { slug } from "./sec/purl.js";

/**
 * Two things the software layer of the graph says about a package so the vulnerability match (a strut workflow walking
 * the public graph, docs/vulnerability-graph-plan.md) and the PROVIDES edges need no lookup: the advisory ecosystem a
 * distribution's packages belong to, spelled the way OSV indexes them (`Ubuntu:24.04:LTS`, `Debian:12`, `Alpine:v3.19`,
 * `Rocky Linux:9`, `AlmaLinux:9`; Amazon Linux 2 and 2023 as `Amazon Linux:2`/`:2023`), and what kind of thing a
 * package is (a service that may listen, with the process names the apps probe sees; a library; the kernel; a tool).
 * The advisor matches nothing against these itself; the matcher that did lived in src/software_vulns.ts until 2026-10-29.
 */

export interface Ecosystem { feed: "osv" | "alas"; ecosystem: string; release?: "2" | "2023" }

/** The release-qualified advisory ecosystem of a box's packages, or null for a distribution no public feed covers (RHEL, CentOS, Fedora, SUSE, ...). */
export function ecosystemOf(pm: string | null | undefined, osId: string | null | undefined, osVersion: string | null | undefined): Ecosystem | null {
  const id = slug(String(osId ?? "")); const ver = String(osVersion ?? "").trim();
  if (id === "amzn") return ver === "2" || ver === "2023" ? { feed: "alas", ecosystem: `Amazon Linux:${ver}`, release: ver } : null;
  if (pm === "deb") {
    if (id === "ubuntu" && /^\d\d\.\d\d$/.test(ver)) { const [yy, mm] = ver.split(".").map(Number); return { feed: "osv", ecosystem: yy! % 2 === 0 && mm === 4 ? `Ubuntu:${ver}:LTS` : `Ubuntu:${ver}` }; }
    if (id === "debian" && /^\d+/.test(ver)) return { feed: "osv", ecosystem: `Debian:${ver.split(".")[0]}` };
    return null;
  }
  if (pm === "apk") { const m = /^(\d+\.\d+)/.exec(ver); return id === "alpine" && m ? { feed: "osv", ecosystem: `Alpine:v${m[1]}` } : null; }
  if (pm === "rpm") {
    const major = ver.split(".")[0];
    if (id === "rocky" && major) return { feed: "osv", ecosystem: `Rocky Linux:${major}` };
    if (id === "almalinux" && major) return { feed: "osv", ecosystem: `AlmaLinux:${major}` };
    return null;
  }
  return null;
}

// ---- which program a package provides ------------------------------------------------------------------------------------

/** Source or binary package names → the process names the apps probe sees listening (instance_ports.process). */
export const PROCESSES_OF: [RegExp, string[]][] = [
  [/^openssh/, ["sshd"]], [/^nginx/, ["nginx"]], [/^(apache2|httpd)/, ["apache2", "httpd"]], [/^postgresql/, ["postgres", "postmaster"]], [/^redis/, ["redis-server", "redis-serve"]],
  [/^(mysql|mariadb|percona)/, ["mysqld", "mariadbd"]], [/^mongodb/, ["mongod"]], [/^haproxy/, ["haproxy"]], [/^traefik/, ["traefik"]], [/^caddy/, ["caddy"]], [/^(nodejs|node)\d*$/, ["node"]],
  [/^(docker|containerd|moby)/, ["dockerd", "containerd", "docker-proxy"]], [/^memcached/, ["memcached"]], [/^rabbitmq/, ["beam.smp"]], [/^bind9?$/, ["named"]], [/^postfix/, ["master"]], [/^exim4/, ["exim4"]],
  [/^dovecot/, ["dovecot"]], [/^samba/, ["smbd"]], [/^vsftpd/, ["vsftpd"]], [/^openvpn/, ["openvpn"]], [/^squid/, ["squid"]], [/^varnish/, ["varnishd"]], [/^(tomcat|jenkins|elasticsearch|opensearch|kafka|java-|openjdk)/, ["java"]],
  [/^grafana/, ["grafana", "grafana-server"]], [/^prometheus/, ["prometheus"]], [/^python3?(\.\d+)?$/, ["python3", "python"]], [/^php/, ["php-fpm"]], [/^ruby/, ["ruby", "puma", "unicorn"]], [/^bitcoin/, ["bitcoind"]], [/^lnd$/, ["lnd"]],
  [/^unbound/, ["unbound"]], [/^dnsmasq/, ["dnsmasq"]], [/^chrony/, ["chronyd"]], [/^rpcbind/, ["rpcbind"]], [/^cups/, ["cupsd"]], [/^zabbix/, ["zabbix_agentd"]], [/^(telegraf|prometheus-node-exporter|node-exporter)/, ["telegraf", "node_exporter"]],
  [/^amazon-ssm-agent/, ["amazon-ssm-agent", "ssm-agent-worker"]], [/^rsyslog/, ["rsyslogd"]], [/^systemd-resolved|^systemd$/, ["systemd-resolve"]], [/^(cockpit)/, ["cockpit-ws"]], [/^(rpcbind|nfs-utils|nfs-kernel-server)/, ["rpc.mountd", "rpcbind"]],
];
const LIBRARY = /^(openssl|libssl|glibc|libc6|zlib|libxml2|curl|libcurl|gnutls|libgnutls|libssh|libgcrypt|expat|libexpat|libpng|libjpeg|pcre|libpcre|sqlite|libsqlite|ncurses|libtasn1|nettle|krb5|p11-kit|ca-certificates|busybox|libtiff|libwebp|freetype|harfbuzz|glib2?|libgd|gdk-pixbuf|openldap|libldap|cyrus-sasl|libsasl|libyaml|jansson|json-c|libarchive|xz|bzip2|gzip|tar|libzstd|zstd|libnghttp2|nghttp2|pam|libpam|shadow|util-linux|coreutils|bash|dash|perl|libperl|libxslt|libgcc|gcc|binutils|libstdc|readline|gmp|libgmp|libidn|libunistring|libffi|libseccomp|libcap|dbus|avahi|libuv|c-ares|libevent|libev|icu|libicu|openjpeg|libvpx|ffmpeg|imagemagick|ghostscript|poppler|libxml|libxslt|python3-.*|golang|rust|libtomcrypt|mbedtls|wolfssl|libsodium|protobuf|grpc|libgit2|libmicrohttpd|libmodsecurity)/;
const KERNEL = /^(linux|kernel|linux-image|linux-aws|linux-signed|linux-meta|linux-headers|kernel-livepatch)/;

export type PackageScope = "service" | "library" | "kernel" | "tool";
/** What kind of thing a package is for the verdict: a program that may listen, a library linked by others, the kernel, or a tool nothing listens as. */
export function packageScope(name: string): { scope: PackageScope; processes: string[] } {
  const n = name.toLowerCase();
  for (const [re, procs] of PROCESSES_OF) if (re.test(n)) return { scope: "service", processes: procs };
  if (KERNEL.test(n)) return { scope: "kernel", processes: [] };
  if (LIBRARY.test(n)) return { scope: "library", processes: [] };
  return { scope: "tool", processes: [] };
}
