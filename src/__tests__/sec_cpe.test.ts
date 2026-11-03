import assert from "node:assert/strict";
import { test } from "node:test";
import { KNOWN_PRODUCTS, componentCpe, cpe23, cpeKey, cpeValue, normalizeCpe, sbomCpe } from "../sec/cpe.js";

// The CPE an installed thing carries next to its purl: syft's for what syft read, the distribution's own for the OS,
// NVD's name for a program the probe named, syft-style guesses for the rest. The purl stays the key; these are properties.

test("cpeValue and cpe23 bind a value the way the CPE 2.3 formatted string does: lowercase, whitespace to _, punctuation escaped, empty is any", () => {
  assert.equal(cpeValue("Node.js"), "node.js"); assert.equal(cpeValue("libstdc++6"), "libstdc\\+\\+6"); assert.equal(cpeValue("Bitcoin Core"), "bitcoin_core");
  assert.equal(cpeValue("3.0.15+quic"), "3.0.15\\+quic"); assert.equal(cpeValue("1:9.2p1-2+deb12u3"), "1\\:9.2p1-2\\+deb12u3"); assert.equal(cpeValue(""), "*"); assert.equal(cpeValue(null), "*");
  assert.equal(cpe23("a", "nodejs", "node.js", "22.12.0"), "cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*");
  assert.equal(cpe23("o", "linux", "linux_kernel", null), "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*");
  assert.equal(cpeKey("cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*"), "a:nodejs:node.js"); assert.equal(cpeKey("nonsense"), null);
});

test("normalizeCpe: a 2.2 URI from os-release becomes the 2.3 string, a 2.3 string is kept whole and padded, anything else is null", () => {
  assert.equal(normalizeCpe("cpe:/o:amazon:amazon_linux:2023"), "cpe:2.3:o:amazon:amazon_linux:2023:*:*:*:*:*:*:*");
  assert.equal(normalizeCpe("cpe:/o:rocky:rocky:9::baseos"), "cpe:2.3:o:rocky:rocky:9:*:baseos:*:*:*:*:*", "update empty, edition baseos");
  assert.equal(normalizeCpe('"cpe:/o:fedoraproject:fedora:40"'), "cpe:2.3:o:fedoraproject:fedora:40:*:*:*:*:*:*:*", "quotes as a sloppy os-release leaves them");
  assert.equal(normalizeCpe("cpe:2.3:o:amazon:amazon_linux:2023"), "cpe:2.3:o:amazon:amazon_linux:2023:*:*:*:*:*:*:*", "a short 2.3 string is padded to 13 fields");
  assert.equal(normalizeCpe("CPE:2.3:a:F5:Nginx:1.27.0:*:*:*:*:*:*:*"), "cpe:2.3:a:f5:nginx:1.27.0:*:*:*:*:*:*:*");
  assert.equal(normalizeCpe("cpe:2.3:a:openssl:openssl:3.0.11-1~deb12u2:*:*:*:*:*:*:*"), "cpe:2.3:a:openssl:openssl:3.0.11-1~deb12u2:*:*:*:*:*:*:*");
  assert.equal(normalizeCpe("nonsense"), null); assert.equal(normalizeCpe(""), null); assert.equal(normalizeCpe(null), null);
});

test("componentCpe: what each kind of row the software probe reads is known by", () => {
  // a program the probe asked by name: NVD's vendor and product, as syft's binary classifier declares them, so the probe's node and syft's agree
  assert.deepEqual(componentCpe({ ecosystem: "binary", name: "node", version: "22.12.0" }), { cpe: "cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*", cpes: ["cpe:2.3:a:nodejs:node.js:22.12.0:*:*:*:*:*:*:*"] });
  assert.deepEqual(componentCpe({ ecosystem: "binary", name: "nginx", version: "1.26.3" }).cpes, ["cpe:2.3:a:f5:nginx:1.26.3:*:*:*:*:*:*:*", "cpe:2.3:a:nginx:nginx:1.26.3:*:*:*:*:*:*:*"], "both spellings NVD has used, the current first");
  assert.equal(componentCpe({ ecosystem: "binary", name: "sshd", version: "9.2p1" }).cpe, "cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*");
  assert.equal(componentCpe({ ecosystem: "binary", name: "OpenSSL", version: "3.0.15+quic" }).cpe, "cpe:2.3:a:openssl:openssl:3.0.15\\+quic:*:*:*:*:*:*:*", "the name is matched case-insensitively, the version escaped");
  // a library Node bundles (process.versions), a binary component with source_kind process_versions
  assert.equal(componentCpe({ ecosystem: "binary", name: "brotli", version: "1.1.0" }).cpe, "cpe:2.3:a:google:brotli:1.1.0:*:*:*:*:*:*:*");
  assert.equal(componentCpe({ ecosystem: "binary", name: "uv", version: "1.46.0" }).cpe, "cpe:2.3:a:libuv:libuv:1.46.0:*:*:*:*:*:*:*");
  assert.equal(componentCpe({ ecosystem: "binary", name: "icu", version: "74.2" }).cpe, "cpe:2.3:a:icu-project:international_components_for_unicode:74.2:*:*:*:*:*:*:*");
  // a program nobody named: its name as vendor and product (syft's guess for the same)
  assert.deepEqual(componentCpe({ ecosystem: "binary", name: "lnd", version: "0.18.3" }), { cpe: "cpe:2.3:a:lnd:lnd:0.18.3:*:*:*:*:*:*:*", cpes: ["cpe:2.3:a:lnd:lnd:0.18.3:*:*:*:*:*:*:*"] });
  assert.equal(componentCpe({ ecosystem: "npm", name: "express", version: "4.19.2" }).cpe, "cpe:2.3:a:express:express:4.19.2:*:*:*:*:*:*:*");
  // the kernel
  assert.deepEqual(componentCpe({ ecosystem: "kernel", name: "linux", version: "6.1.176" }), { cpe: "cpe:2.3:o:linux:linux_kernel:6.1.176:*:*:*:*:*:*:*", cpes: ["cpe:2.3:o:linux:linux_kernel:6.1.176:*:*:*:*:*:*:*"] });
  // a distribution package: syft's permutations, the name first, then the source package as vendor
  assert.deepEqual(componentCpe({ ecosystem: "deb", name: "openssh-server", version: "1:9.2p1-2+deb12u3", source: "openssh" }).cpes, [
    "cpe:2.3:a:openssh-server:openssh-server:1\\:9.2p1-2\\+deb12u3:*:*:*:*:*:*:*", "cpe:2.3:a:openssh:openssh-server:1\\:9.2p1-2\\+deb12u3:*:*:*:*:*:*:*", "cpe:2.3:a:openssh:openssh:1\\:9.2p1-2\\+deb12u3:*:*:*:*:*:*:*"]);
  assert.deepEqual(componentCpe({ ecosystem: "rpm", name: "openssl", version: "3.0.8-1.amzn2023", source: null }).cpes, ["cpe:2.3:a:openssl:openssl:3.0.8-1.amzn2023:*:*:*:*:*:*:*"], "no source: one guess");
  assert.deepEqual(componentCpe({ ecosystem: "apk", name: "musl", version: "1.2.4-r4", source: "musl" }).cpes, ["cpe:2.3:a:musl:musl:1.2.4-r4:*:*:*:*:*:*:*"], "a source equal to the name adds nothing");
  // the operating system: what os-release declares (CPE_NAME, software/7) first, NVD's name for the distribution after; a 2.2 URI is rewritten
  assert.deepEqual(componentCpe({ ecosystem: "os", name: "Amazon Linux 2023", version: "2023", source: "amzn", declared: "cpe:2.3:o:amazon:amazon_linux:2023" }).cpes, ["cpe:2.3:o:amazon:amazon_linux:2023:*:*:*:*:*:*:*"], "the declared one and the rule's agree: one candidate");
  assert.deepEqual(componentCpe({ ecosystem: "os", name: "Rocky Linux 9.4 (Blue Onyx)", version: "9.4", source: "rocky", declared: "cpe:/o:rocky:rocky:9::baseos" }).cpes, ["cpe:2.3:o:rocky:rocky:9:*:baseos:*:*:*:*:*"], "the 2.2 URI rewritten; the rule's candidate names the same vendor and product, so the declared one stands alone");
  assert.deepEqual(componentCpe({ ecosystem: "os", name: "Red Hat Enterprise Linux 9.4", version: "9.4", source: "rhel", declared: "cpe:/o:redhat:enterprise_linux:9::baseos" }).cpes, ["cpe:2.3:o:redhat:enterprise_linux:9:*:baseos:*:*:*:*:*"]);
  assert.deepEqual(componentCpe({ ecosystem: "os", name: "Some Linux", version: "1.0", source: "somelinux", declared: "cpe:2.3:o:some:linux:1.0:*:*:*:*:*:*:*" }).cpes, ["cpe:2.3:o:some:linux:1.0:*:*:*:*:*:*:*"], "a distribution nobody named here but that declares its own");
  assert.deepEqual(componentCpe({ ecosystem: "os", name: "Ubuntu 24.04.1 LTS", version: "24.04", source: "ubuntu", declared: null }), { cpe: "cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:*:*:*:*", cpes: ["cpe:2.3:o:canonical:ubuntu_linux:24.04:*:*:*:*:*:*:*"] }, "Ubuntu declares none: NVD's name");
  assert.equal(componentCpe({ ecosystem: "os", name: "Debian GNU/Linux 12 (bookworm)", version: "12", source: "debian" }).cpe, "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*");
  assert.equal(componentCpe({ ecosystem: "os", name: "Alpine Linux", version: "3.19.1", source: "alpine" }).cpe, "cpe:2.3:o:alpinelinux:alpine_linux:3.19.1:*:*:*:*:*:*:*");
  assert.deepEqual(componentCpe({ ecosystem: "os", name: "Some Linux", version: "unknown", source: "somelinux" }), { cpe: null, cpes: [] }, "a distribution nobody named and that declares none: nothing, never a guess with the o part");
  assert.equal(componentCpe({ ecosystem: "os", name: "Ubuntu", version: "unknown", source: "ubuntu" }).cpe, "cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*", "an unknown version is any");
  for (const [name, pairs] of Object.entries(KNOWN_PRODUCTS)) for (const [v, p] of pairs) assert.match(`${v}:${p}`, /^[a-z0-9_.-]+:[a-z0-9_.-]+$/, `${name}: a vendor and product spelled as NVD binds them`);
});

test("sbomCpe: the CPEs a syft row stores (a JSON list or a list), typed, bounded and best first; the rule's candidates when it has none", () => {
  const fallback = { ecosystem: "npm", name: "express", version: "4.19.2" };
  assert.deepEqual(sbomCpe(JSON.stringify(["cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*", "cpe:2.3:a:express:express:4.19.2:*:*:*:*:*:*:*"]), fallback), { cpe: "cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*", cpes: ["cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*", "cpe:2.3:a:express:express:4.19.2:*:*:*:*:*:*:*"] });
  assert.deepEqual(sbomCpe(["cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*", "junk", "cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*"], fallback).cpes, ["cpe:2.3:a:expressjs:express:4.19.2:*:*:*:*:*:*:*"], "a list as such; junk and repeats of one vendor:product dropped");
  assert.deepEqual(sbomCpe(null, fallback), componentCpe(fallback), "an older probe stored none: the rule");
  assert.deepEqual(sbomCpe("not json", fallback), componentCpe(fallback)); assert.deepEqual(sbomCpe("[]", fallback), componentCpe(fallback));
  assert.equal(sbomCpe(JSON.stringify(Array.from({ length: 12 }, (_, i) => `cpe:2.3:a:v${i}:p:1:*:*:*:*:*:*:*`)), fallback).cpes.length, 8, "at most eight");
});

test("componentCpe: a package or program named like an Object.prototype member gets the plain guess, not the prototype's member", () => {
  for (const name of ["constructor", "__proto__", "hasOwnProperty", "toString"]) {
    const r = componentCpe({ ecosystem: "binary", name, version: "1.0" });
    assert.deepEqual(r.cpes, [cpe23("a", name, name, "1.0")], name);
    assert.deepEqual(componentCpe({ ecosystem: "os", name, version: "1.0", source: name }).cpes, [], `${name} as an os id`);
  }
});
