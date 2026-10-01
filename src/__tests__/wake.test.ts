import { test } from "node:test";
import assert from "node:assert";
import http from "node:http";

const I = "i-0f0000000000d0001", I2 = "i-0f0000000000d0002";

test("wake profiles: validation normalises what the form sends and blocks what cannot work", async () => {
  const { validateProfile } = await import("../wake_profiles.js");
  const { profile, errors } = validateProfile({
    enabled: true, domains: "App.Example.com., *.example.org", ports: [{ port: "443", proto: "tcp", behaviour: "page" }, { port: 7881, proto: "tcp", behaviour: "hold" }, { port: 50000, proto: "udp", behaviour: "ignore" }],
    ready: { scheme: "https", port: 443, path: "health", expect: "2xx" }, wake_with: "i-0f0000000000d0002", hold_seconds: 60,
  }, I);
  assert.deepEqual(errors, []);
  assert.deepEqual(profile.domains, ["app.example.com", "*.example.org"]);
  assert.equal(profile.ready.path, "/health");
  assert.equal(profile.ports[0].port, 443);
  assert.equal(profile.sleep_mode, "auto");
  const bad = validateProfile({ enabled: true, domains: "not a domain", ports: [{ port: 53, proto: "udp", behaviour: "page" }, { port: 70000 }], ready: {}, wake_with: [I], hold_seconds: 5000, filter: { ignore_user_agents: "(" } }, I);
  assert.ok(bad.errors.some((e) => /"not" is not a domain name/.test(e)));
  assert.ok(bad.errors.some((e) => /53\/udp can only be ignored/.test(e)));
  assert.ok(bad.errors.some((e) => /70000 is not a port number/.test(e)));
  assert.ok(bad.errors.some((e) => /cannot wake itself/.test(e)));
  assert.ok(bad.errors.some((e) => /hold time/.test(e)));
  assert.ok(bad.errors.some((e) => /not a valid regular expression/.test(e)));
  assert.ok(validateProfile({ enabled: true, domains: ["a.example.com"], ports: [{ port: 22, behaviour: "ignore" }] }, I).errors.some((e) => /at least one port the doorman answers on/.test(e)));
});

test("wake filter: host, ignored paths, scanners and the daily cap", async () => {
  const { filterReason, statusMatches, isPrivateAddress, wantsPage } = await import("../doorman.js");
  const p = { domains: ["app.example.com", "*.example.org"], filter: { require_host_match: true, ignore_paths: ["/favicon.ico", "/.git/"], ignore_user_agents: "(bot|curl/)", max_wakes_per_day: 3 } };
  const ua = "Mozilla/5.0 (Macintosh)";
  assert.equal(filterReason(p, { host: "app.example.com:443", path: "/room/1?x=1", ua }, 0), null);
  assert.equal(filterReason(p, { host: "meet.example.org", path: "/", ua }, 0), null);
  assert.match(filterReason(p, { host: "203.0.113.5", path: "/", ua }, 0)!, /not one of the profile's domains/);
  assert.match(filterReason(p, { host: "app.example.com", path: "/favicon.ico", ua }, 0)!, /ignored/);
  assert.match(filterReason(p, { host: "app.example.com", path: "/.git/config", ua }, 0)!, /ignored/);
  assert.match(filterReason(p, { host: "app.example.com", path: "/", ua: "Googlebot/2.1" }, 0)!, /bot or a scanner/);
  assert.match(filterReason(p, { host: "app.example.com", path: "/", ua: "" }, 0)!, /no user agent/);
  assert.match(filterReason(p, { host: "app.example.com", path: "/", ua }, 3)!, /3 times today/);
  assert.ok(statusMatches(204, "200-399")); assert.ok(!statusMatches(404, "200-399")); assert.ok(statusMatches(301, "3xx")); assert.ok(statusMatches(200, "200"));
  assert.ok(isPrivateAddress("10.9.0.4")); assert.ok(isPrivateAddress("::ffff:172.17.0.1")); assert.ok(isPrivateAddress("127.0.0.1")); assert.ok(!isPrivateAddress("203.0.113.9"));
  assert.ok(wantsPage("GET", "text/html,application/xhtml+xml")); assert.ok(!wantsPage("GET", "application/json")); assert.ok(!wantsPage("POST", "text/html"));
});

test("doorman: unknown hosts, the waiting page, held API calls, the private test page, and the proxy once the box is ready", async () => {
  const { db } = await import("../db.js");
  const { saveProfile, profileForHost, deleteProfile } = await import("../wake_profiles.js");
  const { createDoorman, primeBoxState } = await import("../doorman.js");
  for (const id of [I, I2]) db.prepare("insert or replace into inventory_ec2(instance_id, name, state, region, snapshot, gone) values (?, ?, 'stopped', 'us-east-1', '{}', 0)").run(id, id === I ? "box-a" : "box-b");

  // the box as a local server standing in for its private address
  const upstream = http.createServer((req, res) => {
    if (req.url === "/health") { res.writeHead(200); return res.end("ok"); }
    res.writeHead(200, { "content-type": "text/plain", "x-seen-host": String(req.headers.host) }); res.end(`hello from the box ${req.url}`);
  });
  await new Promise<void>((r) => upstream.listen(0, "127.0.0.1", r));
  const upPort = (upstream.address() as any).port;

  saveProfile(I, { enabled: false, domains: ["app.example.com"], ports: [{ port: 443, proto: "tcp", behaviour: "page" }], ready: { scheme: "http", port: upPort, path: "/health" }, hold_seconds: 5 }, "test");
  assert.equal(profileForHost("APP.example.com:443")?.instance_id, I);
  assert.throws(() => saveProfile(I2, { domains: ["app.example.com"], ports: [{ port: 443, behaviour: "page" }] }, "test"), /already belongs to the profile of box-a/);

  const door = createDoorman();
  await new Promise<void>((r) => door.listen(0, "127.0.0.1", r));
  const port = (door.address() as any).port;
  const get = (path: string, headers: Record<string, string>, method = "GET") => new Promise<{ status: number; body: string; headers: http.IncomingHttpHeaders }>((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port, path, method, headers }, (res) => { let b = ""; res.on("data", (c) => (b += c)); res.on("end", () => resolve({ status: res.statusCode!, body: b, headers: res.headers })); });
    req.on("error", reject); req.end();
  });
  try {
    assert.equal((await get("/", { host: "stranger.example.net" })).status, 404);
    primeBoxState(I, { state: "stopped", private_ip: null, ready: false, detail: "instance stopped" });
    const page = await get("/room/1", { host: "app.example.com", accept: "text/html", "user-agent": "Mozilla/5.0" });
    assert.equal(page.status, 503); assert.equal(page.headers["retry-after"], "15");
    assert.match(page.body, /app\.example\.com is waking up/);
    const apiCall = await get("/rtc", { host: "app.example.com", accept: "application/json", "user-agent": "Mozilla/5.0" });
    assert.equal(apiCall.status, 503); assert.match(apiCall.body, /waking up/);
    const status = JSON.parse((await get("/__wake/status", { host: "app.example.com" })).body);
    assert.equal(status.phase, "asleep"); assert.equal(status.enabled, false);
    // nothing woke it: the profile's switch is off
    assert.equal((db.prepare("select count(*) as n from wake_events where instance_id = ?").get(I) as any).n, 0);

    // the test page, from a private address (the test connects over loopback)
    const tp = await get(`/__wake/test/${I}`, { host: `127.0.0.1:${port}` });
    assert.equal(tp.status, 200); assert.match(tp.body, /Test page for box-a/); assert.match(tp.body, /Start it now/);
    assert.equal((await get(`/__wake/test/${I}`, { host: `127.0.0.1:${port}`, "x-forwarded-for": "203.0.113.9" })).status, 403, "anything that came through a proxy is refused");
    assert.equal((await get(`/__wake/test/${I2}`, { host: `127.0.0.1:${port}` })).status, 404, "no profile, no page");
    assert.equal((await get(`/__wake/test/${I}`, { host: "app.example.com" })).status, 503, "a profile's own host never gets the test page");

    // ready: requests pass through to the box with their host name
    primeBoxState(I, { state: "running", private_ip: "127.0.0.1", ready: true, detail: "http ready" });
    const through = await get("/room/1", { host: "app.example.com", accept: "text/html", "user-agent": "Mozilla/5.0" });
    assert.equal(through.status, 200); assert.equal(through.body, "hello from the box /room/1"); assert.equal(through.headers["x-seen-host"], "app.example.com");
  } finally {
    door.close(); upstream.close();
    deleteProfile(I); deleteProfile(I2);
    for (const id of [I, I2]) { db.prepare("delete from inventory_ec2 where instance_id = ?").run(id); db.prepare("delete from wake_events where instance_id = ?").run(id); }
  }
});

test("doorman: the ready check reads a real answer, and a closed port is not ready", async () => {
  const { readyCheck } = await import("../doorman.js");
  const s = http.createServer((req, res) => { res.writeHead(req.url === "/up" ? 200 : 500); res.end(); });
  await new Promise<void>((r) => s.listen(0, "127.0.0.1", r));
  const port = (s.address() as any).port;
  try {
    assert.equal((await readyCheck({ domains: ["app.example.com"], ready: { scheme: "http", port, path: "/up", host: null, expect: "200-399" } }, "127.0.0.1")).ok, true);
    assert.equal((await readyCheck({ domains: ["app.example.com"], ready: { scheme: "http", port, path: "/down", host: null, expect: "200-399" } }, "127.0.0.1")).ok, false);
    assert.equal((await readyCheck({ domains: [], ready: { scheme: "tcp", port, path: "", host: null, expect: "" } }, "127.0.0.1")).ok, true);
  } finally { s.close(); }
  const closed = await readyCheck({ domains: [], ready: { scheme: "tcp", port: 9, path: "", host: null, expect: "" } }, "127.0.0.1", 1000);
  assert.equal(closed.ok, false);
});
