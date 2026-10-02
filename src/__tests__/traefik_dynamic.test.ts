import assert from "node:assert/strict";
import { test } from "node:test";
import { entrypointFor, ruleFor, traefikDynamicConfig } from "../traefik_dynamic.js";

test("traefik routes: one router per DNS-flip profile domain and open port, to the doorman, on the swarm's entrypoints", () => {
  const profiles: any[] = [
    { instance_id: "i-0f0000000000a0001", front_door: "dns", domains: ["app.example.com", "*.example.com"], ports: [{ port: 443, proto: "tcp", behaviour: "page" }, { port: 8000, proto: "tcp", behaviour: "hold" }, { port: 80, proto: "tcp", behaviour: "redirect" }, { port: 22, proto: "tcp", behaviour: "ignore" }, { port: 500, proto: "udp", behaviour: "ignore" }] },
    { instance_id: "i-0f0000000000a0002", front_door: "eip", domains: ["eip.example.com"], ports: [{ port: 443, proto: "tcp", behaviour: "page" }] },
  ];
  const d = traefikDynamicConfig(profiles, "http://advisor.sphinx:9035");
  const keys = Object.keys(d.http.routers).sort();
  assert.deepEqual(keys, ["doorman-i-0f0000000000a0001-0-443", "doorman-i-0f0000000000a0001-0-80", "doorman-i-0f0000000000a0001-0-8000", "doorman-i-0f0000000000a0001-1-443", "doorman-i-0f0000000000a0001-1-80", "doorman-i-0f0000000000a0001-1-8000"], "ignored and UDP ports left out, the EIP profile left out");
  const r: any = d.http.routers["doorman-i-0f0000000000a0001-0-8000"];
  assert.deepEqual(r, { entryPoints: ["port8000"], rule: "Host(`app.example.com`)", service: "advisor-doorman", priority: 1000, tls: { certResolver: "myresolver" } });
  assert.equal((d.http.routers["doorman-i-0f0000000000a0001-0-80"] as any).tls, undefined, "plain http on 80");
  const w: any = d.http.routers["doorman-i-0f0000000000a0001-1-443"];
  assert.equal(w.rule, "HostRegexp(`{sub:[a-z0-9-]+}.example.com`)"); assert.deepEqual(w.tls.domains, [{ main: "example.com", sans: ["*.example.com"] }]);
  assert.deepEqual(d.http.services, { "advisor-doorman": { loadBalancer: { servers: [{ url: "http://advisor.sphinx:9035" }], passHostHeader: true } } });
  assert.deepEqual(traefikDynamicConfig([profiles[1]], "http://x").http, { routers: {}, services: {} }, "nothing to route: an empty document");
  assert.equal(entrypointFor(443), "websecure"); assert.equal(entrypointFor(80), "web"); assert.equal(entrypointFor(3000), "port3000");
  assert.equal(ruleFor("a.b.example.com"), "Host(`a.b.example.com`)");
});
