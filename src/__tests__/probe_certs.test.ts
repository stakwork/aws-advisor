import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";

process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-certs-test-"));
process.env.TYPESAFE_API_KEY = "";

const pr = await import("../probes.js");
const sw = await import("../software_inventory.js");
const ic = await import("../instance_certs.js");
const { parseProbeOutput } = await import("../ssm.js");
const { db } = await import("../db.js");

const hasOpenssl = spawnSync("openssl", ["version"]).status === 0;
const lines = pr.defaultProbeScript("software").split("\n");
const start = lines.findIndex((l) => l.startsWith("# ---- certificates (probe software/9)"));
const end = lines.findIndex((l, i) => i > start && l.startsWith("out=$(printf"));
const certLines = lines.slice(start, end);

test("the software script carries the certificate section: syntax, quoting rule, read-only words, never a private key", () => {
  assert.ok(start > 0 && end > start, "the section sits before the output line");
  assert.equal(pr.PROBE_DEFS.software.version, "1.9");
  assert.ok(pr.PROBE_DEFS.software.sections.includes("certs") && pr.PROBE_DEFS.software.sections.includes("tls_live"));
  const script = pr.probeScript("software");
  for (const sh of ["sh", "bash"]) assert.equal(spawnSync(sh, ["-n"], { input: script, encoding: "utf8" }).status, 0, `${sh} -n`);
  // the setup script embeds the document in a heredoc inside $( ): single quotes pair up on every line, and no backtick appears
  for (const l of certLines) { assert.equal((l.match(/'/g) ?? []).length % 2, 0, `odd quotes: ${l}`); assert.ok(!l.includes("`"), `backtick: ${l}`); }
  // the words setProbeScriptOverride refuses: the stock lines pass untouched, but the section stays inside the list
  const body = certLines.join("\n");
  for (const re of [/\brm\b/, /\bkill(all)?\b/, /\bsystemctl\b/, /\bsudo\b/, /\bchmod\b/, /\bchown\b/, /\bdocker\s+(rm|rmi|stop|kill|exec|run|prune)\b/, />\s*\/(etc|var|usr|boot|bin|sbin|lib)/]) assert.ok(!re.test(body), `${re} in the certificate section`);
  // public parts only: no cat, no key tools, no ssl_certificate_key, key files are excluded by name; the one PEM read is openssl x509
  assert.ok(!/\bcat\s+[^|]*\.(pem|crt|key)/.test(body) && !/openssl\s+(rsa|pkey|ec|genrsa|req)\b/.test(body) && !/ssl_certificate_key|SSLCertificateKeyFile/.test(body));
  assert.ok(/openssl x509 -in "\$path"/.test(body) && /privkey\|private\|\\\.key\$/.test(body));
  assert.ok(body.includes("-fingerprint -sha256") && body.includes("s_client") && body.includes("acme.json") && body.includes("providers\\.file\\.(directory|filename)"));
  assert.ok(/"certificate" \*: \*/.test(body), "acme.json: only the certificate fields are matched");
});

const freePort = () => new Promise<number>((resolve) => { const s = net.createServer(); s.listen(0, "127.0.0.1", () => { const p = (s.address() as net.AddressInfo).port; s.close(() => resolve(p)); }); });
const waitPort = async (port: number) => { for (let i = 0; i < 50; i++) { if (await new Promise<boolean>((r) => { const c = net.connect(port, "127.0.0.1", () => { c.destroy(); r(true); }); c.on("error", () => r(false)); })) return; await new Promise((r) => setTimeout(r, 100)); } throw new Error("s_server did not start"); };
const gen = (dir: string, name: string, days: number, san: string) => {
  const r = spawnSync("openssl", ["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", path.join(dir, `${name}.key`), "-out", path.join(dir, `${name}.crt`), "-days", String(days), "-subj", `/CN=${name}.example.test`, "-addext", `subjectAltName=${san}`], { encoding: "utf8" });
  assert.equal(r.status, 0, r.stderr);
};

test("the certificate part runs against a temp dir of self-signed certificates: fields, acme.json certificate fields only, live check, no key material", { skip: !hasOpenssl }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-certs-fixture-"));
  const files = path.join(dir, "certs"); fs.mkdirSync(files); fs.mkdirSync(path.join(dir, "traefik"));
  gen(files, "wild", 20, "DNS:*.wild.test,DNS:wild.test"); gen(files, "other", 400, "DNS:other.test");
  const acmeDir = path.join(dir, "traefik"); gen(acmeDir, "acme", 5, "DNS:acme.test");
  const acmePem = fs.readFileSync(path.join(acmeDir, "acme.crt"));
  const keyBody = fs.readFileSync(path.join(files, "wild.key"), "utf8").split("\n")[1]!; // the first line of a private key's base64
  fs.writeFileSync(path.join(acmeDir, "acme.json"), JSON.stringify({ le: { Certificates: [{ domain: { main: "acme.test" }, certificate: acmePem.toString("base64"), key: "KEYFIELDMARKER" + Buffer.from(keyBody).toString("base64"), Store: "default" }] } }));
  for (const f of ["acme.crt", "acme.key"]) fs.rmSync(path.join(acmeDir, f)); // only acme.json holds it
  // a copied certificate: the file is much newer than its start (here the clock is moved forward, as a certificate cannot be backdated)
  const old = Date.now() / 1000 + 10 * 86400; fs.utimesSync(path.join(files, "other.crt"), old, old);
  // the port serves a certificate that is NOT the file's one for the name the wildcard covers (a mismatch), and no key leaves the fixture directory
  const served = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-certs-served-")); gen(served, "served", 90, "DNS:served.test");
  const port = await freePort();
  const srv = spawn("openssl", ["s_server", "-accept", String(port), "-cert", path.join(served, "served.crt"), "-key", path.join(served, "served.key"), "-www"], { stdio: "ignore" });
  try {
    await waitPort(port);
    const script = [...lines.slice(0, lines.findIndex((l) => l.startsWith("os_id=\"\""))), ...certLines, 'printf \'{"certs":%s,"certs_total":%s,"tls_live":[%s]}\\n\' "$certs_json" "$certs_total" "$tls_json"'].join("\n");
    const r = spawnSync("sh", [], { input: script, encoding: "utf8", env: { ...process.env, AWS_ADVISOR_CERT_ROOTS: dir, AWS_ADVISOR_CERT_PORTS: String(port) }, timeout: 120_000 });
    assert.ok(!r.stdout.includes("KEYFIELDMARKER") && !r.stdout.includes(Buffer.from(keyBody).toString("base64")) && !r.stdout.includes(keyBody), "no key material in the output");
    const j = JSON.parse(r.stdout.trim().split("\n").pop()!);
    const by = (cn: string) => j.certs.find((c: any) => c.cn === cn);
    assert.equal(j.certs.length, 3); assert.equal(j.certs_total, 3);
    assert.ok(j.certs.every((c: any) => /^[0-9a-f]{64}$/.test(c.fingerprint) && (c.source === "traefik-acme" || (c.provenance === "managed_elsewhere" && c.renewer_found === false)) && !String(c.path).endsWith(".key")), "64-hex fingerprints, no renewer on this box, no key files");
    const wild = by("wild.example.test");
    assert.deepEqual(wild.sans, ["*.wild.test", "wild.test"]); assert.equal(wild.source, "pem-sweep");
    assert.ok(wild.days_left >= 18 && wild.days_left <= 20, `days_left ${wild.days_left}`);
    assert.ok(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(wild.not_after) && /^\d{4}-\d\d-\d\dT/.test(wild.not_before) && wild.issuer_cn === "wild.example.test" && wild.serial);
    const other = by("other.example.test"); assert.ok(other.days_left >= 398); assert.ok(Date.parse(other.file_mtime) > Date.now() + 9 * 86400, "the file mtime is reported");
    const acme = by("acme.example.test"); assert.equal(acme.source, "traefik-acme"); assert.ok(acme.path.endsWith("acme.json#1")); assert.equal(acme.renewer, "traefik"); assert.equal(acme.renewer_found, true); assert.equal(acme.provenance, "local");
    assert.ok(acme.days_left <= 5);
    // live: the no-SNI answer is the served certificate (unknown: no file holds it), a name the wildcard covers got another one: mismatch
    assert.ok(j.tls_live.length >= 2 && j.tls_live.every((l: any) => l.port === port && /^[0-9a-f]{64}$/.test(l.fingerprint)));
    assert.equal(j.tls_live.find((l: any) => l.sni === null).match, "unknown");
    assert.equal(j.tls_live.find((l: any) => l.sni === "probe.wild.test").match, "mismatch");
    assert.ok(j.certs.every((c: any) => c.served === false), "no file certificate is the served one");
    // ingest: the section survives parseProbeOutput, the rows, the alerts, the groups, the graph rows
    const line = JSON.stringify({ probe: "aws-advisor/software/9", kind: "software", hostname: "box", collected_at: new Date().toISOString(), os: { id: "debian", version: "12", name: "Debian" }, packages: [], certs: j.certs, certs_total: j.certs_total, tls_live: j.tls_live });
    const parsed = parseProbeOutput(line);
    assert.equal(parsed.certs!.length, 3); assert.equal(parsed.tls_live!.length, j.tls_live.length);
    const iid = "i-certbox1";
    db.prepare("insert or replace into inventory_ec2(instance_id, name, state, snapshot) values (?, 'proxy-1', 'running', '{}')").run(iid);
    const res = sw.recordSoftware(iid, parsed.collected_at, { os: parsed.os, package_manager: "deb", packages: [{ n: "curl", v: "8", a: "amd64" }], certs: parsed.certs, tls_live: parsed.tls_live });
    assert.equal(res!.certs, 3); assert.equal(res!.cert_alerts, 2, "the 20-day and 5-day certificates alert");
    const alerts = db.prepare("select message, details from alerts where kind = 'cert_expiring' and resource = ? and acknowledged = 0").all(iid) as { message: string; details: string }[];
    assert.deepEqual(alerts.map((a) => JSON.parse(a.details).level).sort(), ["alarm", "warning"]);
    assert.ok(alerts.some((a) => /proxy-1: TLS certificate for acme\.test expires in [0-4] day/.test(a.message)));
    assert.equal(sw.recordSoftware(iid, parsed.collected_at, { os: parsed.os, package_manager: "deb", packages: [{ n: "curl", v: "8", a: "amd64" }], certs: parsed.certs, tls_live: parsed.tls_live })!.cert_alerts, 0, "no second alert while one is open");
    const mine = sw.softwareOn(iid); assert.equal(mine.certs.length, 3); assert.equal(mine.tls_live.length, j.tls_live.length);
    assert.ok(mine.certs.find((c) => c.cn === "other.example.test")!.copied_after_days! > 5, "the gap between issue and file shows a copy");
    // a second box with the same wildcard: one group, two instances
    sw.recordSoftware("i-certbox2", parsed.collected_at, { os: parsed.os, package_manager: "deb", packages: [{ n: "curl", v: "8", a: "amd64" }], certs: parsed.certs!.filter((c) => c.cn === "wild.example.test"), tls_live: [] });
    const g = ic.certGroups().find((x) => x.fingerprint === wild.fingerprint)!;
    assert.equal(g.id, `cert:${wild.fingerprint}`); assert.deepEqual(g.instances.map((i) => i.instance_id).sort(), ["i-certbox1", "i-certbox2"]); assert.equal(g.level, "warning"); assert.deepEqual(g.domains, ["*.wild.test", "wild.test"]);
    const rows = ic.certGraphRows(); const mineRows = rows.filter((r) => r.instance_id === "i-certbox1");
    assert.equal(mineRows.length, 3);
    const gr = mineRows.find((r) => r.fingerprint === wild.fingerprint)!;
    assert.equal(gr.id, `cert:${wild.fingerprint}`); assert.deepEqual(gr.domains, ["*.wild.test", "wild.test"]); assert.equal(gr.issuer, "wild.example.test"); assert.equal(gr.source, "pem-sweep"); assert.equal(gr.wildcard, true);
    assert.equal(gr.path, wild.path); assert.equal(gr.container, null); assert.ok(gr.days_left! <= 20 && gr.not_after);
    // renewal: the certificate replaced on the box closes its alert; a probe without a list changes nothing
    assert.equal(sw.recordSoftware(iid, parsed.collected_at, { os: parsed.os, package_manager: "deb", packages: [{ n: "curl", v: "8", a: "amd64" }], certs: null })!.certs, undefined);
    assert.equal(sw.softwareOn(iid).certs.length, 3);
    sw.recordSoftware(iid, parsed.collected_at, { os: parsed.os, package_manager: "deb", packages: [{ n: "curl", v: "8", a: "amd64" }], certs: parsed.certs!.filter((c) => c.cn === "other.example.test") });
    assert.equal((db.prepare("select count(*) as n from alerts where kind = 'cert_expiring' and resource = ? and acknowledged = 0").get(iid) as { n: number }).n, 0);
    assert.equal(sw.softwareOn(iid).certs.length, 1);
  } finally { srv.kill(); }
});

test("expiry levels: warn at 30 days, alarm at 7 and when expired; nothing beyond", () => {
  assert.deepEqual([null, 400, 31, 30, 8, 7, 0, -3].map((d) => ic.certLevel(d)), [null, null, null, "warning", "warning", "alarm", "alarm", "alarm"]);
  assert.equal(ic.daysLeft("2026-12-01T00:00:00Z", Date.parse("2026-11-25T12:00:00Z")), 5);
  assert.equal(ic.daysLeft("2026-11-24T00:00:00Z", Date.parse("2026-11-25T12:00:00Z")), -2);
  const v = ic.expiryVerdicts([{ fingerprint: "a", cn: "x.test", not_after: "2026-12-01T00:00:00Z" }, { fingerprint: "b", not_after: "2027-12-01T00:00:00Z" }, { fingerprint: "a", cn: "x.test", not_after: "2026-12-01T00:00:00Z" }], Date.parse("2026-11-25T12:00:00Z"));
  assert.deepEqual(v.map((x) => [x.fingerprint, x.level, x.days_left]), [["a", "alarm", 5]]);
});
