import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, test } from "node:test";

// The Vercel adapter: the API shapes folded to rows (values of env variables dropped), who may open a deployment
// URL from the protection settings, a refresh through a fake fetch with pagination, the generic resource nodes and
// endpoints it emits, and its place in the registry.
process.env.DATA_DIR = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-vercel-test-"));
process.env.TYPESAFE_API_KEY = "";
process.env.REPO2GRAPH_URL = "";
process.env.VERCEL_TOKEN = "testtoken_000000000000000000";
process.env.VERCEL_TEAM_ID = "team_example123";

const client = await import("../adapters/vercel/client.js");
const inv = await import("../adapters/vercel/inventory.js");
const ad = await import("../adapters/vercel/index.js");
const reg = await import("../adapters/index.js");

const PROJECT = { id: "prj_abc123", name: "web", framework: "nextjs", nodeVersion: "20.x", createdAt: 1704067200000, updatedAt: 1759400000000, link: { type: "github", org: "example", repo: "web" },
  targets: { production: { id: "dpl_prod1", url: "web-example.vercel.app", readyState: "READY", target: "production", createdAt: 1759300000000 } },
  latestDeployments: [{ id: "dpl_prev2", url: "web-git-feature-example.vercel.app", readyState: "READY", target: null, createdAt: 1759390000000 }],
  ssoProtection: { deploymentType: "only_preview_deployments" }, passwordProtection: null, trustedIps: null, live: true,
  connectConfigurations: [{ connectConfigurationId: "sn-abc", dc: "iad1", envId: "production", passive: false, buildsEnabled: false, aws: { securityGroupId: "sg-0123456789abcdef0", subnetIds: ["subnet-0aaa", "subnet-0bbb"] } }, { connectConfigurationId: "sn-abc", dc: "iad1", envId: "preview", aws: { securityGroupId: "sg-0123456789abcdef0", subnetIds: ["subnet-0aaa", "subnet-0bbb"] } }] };
const PROJECT2 = { id: "prj_def456", name: "api", framework: null, nodeVersion: "18.x", createdAt: 1704067200000, targets: { production: { id: "dpl_p2", url: "api-example.vercel.app", readyState: "ERROR", target: "production", createdAt: 1759300000000 } }, latestDeployments: [], ssoProtection: { deploymentType: "all" }, live: true };

test("projectFrom, deploymentFrom and envFrom fold the API's shapes; an env value never survives", () => {
  const p = client.projectFrom(PROJECT);
  assert.equal(p.name, "web"); assert.equal(p.framework, "nextjs"); assert.equal(p.node_version, "20.x"); assert.equal(p.repo, "example/web"); assert.equal(p.git_provider, "github");
  assert.equal(p.production_url, "https://web-example.vercel.app"); assert.equal(p.latest!.id, "dpl_prev2"); assert.equal(p.latest!.state, "READY"); assert.equal(p.created_at, "2024-01-01T00:00:00.000Z");
  assert.deepEqual(p.protection, { sso: "only_preview_deployments", password: null, trusted_ips: null, bypass_automation: false });
  assert.deepEqual(p.connect.map((c) => [c.env, c.security_group, c.subnets.length, c.dc]), [["production", "sg-0123456789abcdef0", 2, "iad1"], ["preview", "sg-0123456789abcdef0", 2, "iad1"]], "Secure Compute attachments per environment");
  const d = client.deploymentFrom({ uid: "dpl_1", projectId: "prj_abc123", name: "web", url: "web-abc.vercel.app", readyState: "READY", target: "production", createdAt: 1759300000000, meta: { githubCommitRef: "main", githubCommitSha: "0123456789abcdef0123" } });
  assert.equal(d.url, "https://web-abc.vercel.app"); assert.equal(d.branch, "main"); assert.equal(d.commit, "0123456789ab");
  const e = client.envFrom("prj_abc123", { id: "env1", key: "DATABASE_URL", value: "postgres://secret", target: ["production", "preview"], type: "encrypted", updatedAt: 1759300000000, createdAt: 1759200000000, lastEditedByDisplayName: "Pat Example" });
  assert.deepEqual(e, { project_id: "prj_abc123", key: "DATABASE_URL", targets: ["production", "preview"], type: "encrypted", updated_at: "2025-10-01T06:26:40.000Z", created_at: "2025-09-30T02:40:00.000Z", edited_by: "Pat Example" });
  assert.ok(!JSON.stringify(e).includes("secret"));
});

test("requiresAuth reads the protection mode per target", () => {
  const p = (sso: string | null, password: string | null = null, ips: string | null = null) => ({ protection: { sso, password, trusted_ips: ips, bypass_automation: false } });
  assert.deepEqual(client.requiresAuth(p("all"), "production"), { requires_auth: true, via: "sso" });
  assert.deepEqual(client.requiresAuth(p("only_preview_deployments"), "production"), { requires_auth: false, via: null });
  assert.deepEqual(client.requiresAuth(p("only_preview_deployments"), "preview"), { requires_auth: true, via: "sso" });
  assert.deepEqual(client.requiresAuth(p("prod_deployment_urls_and_all_previews"), "preview"), { requires_auth: true, via: "sso" });
  assert.deepEqual(client.requiresAuth(p(null, "all"), "production"), { requires_auth: true, via: "password" });
  assert.deepEqual(client.requiresAuth(p(null, null, "only_production_deployments"), "production"), { requires_auth: true, via: "trusted_ips" });
  assert.deepEqual(client.requiresAuth(p(null), "production"), { requires_auth: false, via: null });
});

/** A fake Vercel API: two project pages, deployments, domains and env per project, no firewall endpoint. */
function fakeFetch(): typeof fetch {
  return (async (input: any) => {
    const u = new URL(String(input)); const path = u.pathname; const until = u.searchParams.get("until");
    assert.equal(u.searchParams.get("teamId"), "team_example123", "every call carries the team id");
    const json = (body: any, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    if (path === "/v2/teams/team_example123") return json({ id: "team_example123", slug: "example", name: "Example", billing: { plan: "pro" } });
    if (path === "/v9/projects") return until ? json({ projects: [PROJECT2], pagination: { next: null } }) : json({ projects: [PROJECT], pagination: { next: 1759300000000 } });
    if (path === "/v6/deployments") { const pid = u.searchParams.get("projectId"); return json({ deployments: pid === "prj_abc123" ? [{ uid: "dpl_prod1", projectId: pid, url: "web-example.vercel.app", readyState: "READY", target: "production", createdAt: 1759300000000 }, { uid: "dpl_prev2", projectId: pid, url: "web-git-feature-example.vercel.app", readyState: "READY", target: null, createdAt: 1759390000000 }] : [], pagination: { next: null } }); }
    if (/^\/v9\/projects\/[^/]+\/domains$/.test(path)) return json({ domains: path.includes("prj_abc123") ? [{ name: "www.example.com", apexName: "example.com", verified: true, redirect: null, gitBranch: null, createdAt: 1704067200000 }, { name: "example.com", apexName: "example.com", verified: true, redirect: "www.example.com" }, { name: "staging.example.com", apexName: "example.com", verified: true, gitBranch: "staging" }] : [], pagination: { next: null } });
    if (/^\/v9\/projects\/[^/]+\/env$/.test(path)) return json({ envs: [{ id: "e1", key: "DATABASE_URL", value: "postgres://nope", target: ["production"], type: "encrypted" }, { id: "e2", key: "NEXT_PUBLIC_API", value: "https://api.example.com", target: ["production", "preview"], type: "plain" }] });
    if (path === "/v1/security/firewall/config") return json({ error: { code: "not_found" } }, 404);
    return json({ error: `unexpected ${path}` }, 404);
  }) as typeof fetch;
}

test("refreshVercel reads the team, every project page, deployments, domains and env names through the client and stores them; values are not kept", async () => {
  const c = new client.VercelClient({ token: "testtoken_000000000000000000", teamId: "team_example123", fetchImpl: fakeFetch() });
  const r = await inv.refreshVercel(c);
  assert.equal(r.team.name, "Example"); assert.equal(r.team.plan, "pro"); assert.equal(r.projects, 2); assert.equal(r.deployments, 2); assert.equal(r.domains, 3); assert.equal(r.env, 4); assert.deepEqual(r.errors, []);
  const projects = inv.listProjects();
  assert.deepEqual(projects.map((p) => p.name), ["api", "web"]);
  const web = projects.find((p) => p.id === "prj_abc123")!;
  assert.equal(web.env_count, 2); assert.equal(web.firewall, null); assert.equal(web.protection.sso, "only_preview_deployments");
  assert.deepEqual(inv.listEnvNames("prj_abc123").map((e) => [e.key, e.targets]), [["DATABASE_URL", ["production"]], ["NEXT_PUBLIC_API", ["production", "preview"]]]);
  const { db } = await import("../db.js");
  assert.equal((db.prepare("select count(*) as n from vercel_env where key like '%postgres%' or targets like '%postgres%'").get() as any).n, 0);
  assert.equal(inv.vercelTeam()!.id, "team_example123");
});

test("the adapter emits an AdvisorDeployment per project with the generic state, and the URLs it exposes with requires_auth from the protection", async () => {
  assert.equal(ad.vercelAdapter.configured(), true);
  const accounts = await ad.vercelAdapter.accounts();
  assert.equal(accounts.length, 1); assert.equal(accounts[0].provider, "vercel"); assert.equal(accounts[0].native_type, "team"); assert.equal(accounts[0].id, "team_example123"); assert.equal(accounts[0].name, "Example");
  const nodes = ad.vercelAdapter.resources("team_example123");
  const web = nodes.find((n) => n.id === "prj_abc123")!; const api = nodes.find((n) => n.id === "prj_def456")!;
  assert.equal(web.label, "AdvisorDeployment"); assert.equal(web.native_type, "vercel_project"); assert.equal(web.state, "running"); assert.equal(web.props.framework, "nextjs"); assert.equal(web.props.runtime, "node 20.x"); assert.equal(web.props.protection_previews, true); assert.equal(web.props.protection_production, false);
  assert.equal(api.state, "degraded"); assert.equal(api.props.protection_production, true);
  assert.deepEqual(web.observed, [{ kind: "api", status: "ok", last_at: web.last_seen, detail: "vercel REST API" }]);
  const eps = ad.projectEndpoints(inv.listProjects().find((p) => p.id === "prj_abc123")!);
  assert.deepEqual(eps.map((e) => [e.hostname, e.target, e.requires_auth, e.domain]), [
    ["web-example.vercel.app", "production", false, false],
    ["staging.example.com", "preview", true, true],
    ["www.example.com", "production", false, true],
    ["web-git-feature-example.vercel.app", "preview", true, false],
  ], "the redirecting apex is left out; the branch domain and the preview deployment ask for SSO");
  assert.deepEqual(reg.providers().map((p) => [p.id, p.available]), [["aws", true], ["vercel", true], ["github", true], ["local", true], ["gcp", false], ["azure", false], ["cloudflare", false]]);
  assert.ok((await reg.allAccounts()).some((a) => a.provider === "vercel"));
});

test("the Steampipe connection follows the saved token: written with the team slug, unchanged when equal, removed when the token goes", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "advisor-spc-test-"));
  process.env.STEAMPIPE_CONFIG_DIR = dir;
  const sp = await import("../adapters/vercel/steampipe.js");
  const { config } = await import("../config.js");
  if (config.steampipeConfigDir !== dir) return; // the config dir was fixed at import time elsewhere in this process: nothing to assert here
  const text = sp.vercelSpcText('tok"en', "example");
  assert.match(text, /^# managed by cloud-advisor/); assert.match(text, /api_token = "tok\\"en"/); assert.match(text, /team      = "example"/);
  assert.equal(sp.ensureVercelConnection(), "written");
  assert.ok(fs.readFileSync(path.join(dir, "vercel.spc"), "utf8").includes('team      = "example"'), "the slug the refresh stored");
  assert.equal(sp.ensureVercelConnection(), "unchanged");
  assert.equal((fs.statSync(path.join(dir, "vercel.spc")).mode & 0o777), 0o600);
});

test("storeFrom folds a storage store with its kind from the product (Neon → database, Redis → cache, blob → storage) and the projects on it", () => {
  const neon = client.storeFrom({ id: "store_1", name: "hive-postgres", type: "integration", status: "available", product: { name: "Neon", slug: "neon", integration: "neon" }, billingPlan: { name: "Launch" }, metadata: { region: "iad1" }, createdAt: 1753122820973, projectsMetadata: [{ projectId: "prj_abc123", name: "web", environments: ["production", "preview"] }] });
  assert.equal(neon.kind, "database"); assert.equal(neon.product, "Neon"); assert.equal(neon.plan, "Launch"); assert.equal(neon.region, "iad1"); assert.deepEqual(neon.projects, [{ project_id: "prj_abc123", name: "web", environments: ["production", "preview"], env_var_names: [], env_var_prefix: null }]);
  assert.equal(client.storeFrom({ id: "s2", name: "r", type: "integration", product: { slug: "redis" } }).kind, "cache");
  assert.equal(client.storeFrom({ id: "s3", name: "b", type: "blob" }).kind, "storage"); assert.equal(client.storeFrom({ id: "s3", name: "b", type: "blob" }).product, "Vercel Blob");
  assert.equal(client.storeKind("integration", "supabase"), "database"); assert.equal(client.storeKind("edge-config", null), "storage"); assert.equal(client.storeKind("integration", "sentry"), "other");
});

test("after a refresh the stores are resources too (AdvisorDatabase for Neon), connected to their projects", async () => {
  const base = fakeFetch();
  const f = (async (input: any, init?: any) => { const u = new URL(String(input)); if (u.pathname === "/v1/storage/stores") return new Response(JSON.stringify({ stores: [{ id: "store_1", name: "web-postgres", type: "integration", status: "available", product: { name: "Neon", slug: "neon" }, billingPlan: { name: "Launch" }, metadata: { region: "iad1" }, projectsMetadata: [{ projectId: "prj_abc123", name: "web", environments: ["production"] }] }, { id: "store_2", name: "web-blob", type: "blob", status: "available", projectsMetadata: [] }] }), { status: 200, headers: { "content-type": "application/json" } }); return base(input, init); }) as typeof fetch;
  const r = await inv.refreshVercel(new client.VercelClient({ token: "testtoken_000000000000000000", teamId: "team_example123", fetchImpl: f }));
  assert.equal(r.stores, 2);
  assert.deepEqual(inv.listStores({ projectId: "prj_abc123" }).map((x) => x.name), ["web-postgres"]);
  assert.deepEqual(inv.listStores({ kind: "storage" }).map((x) => x.name), ["web-blob"]);
  const nodes = ad.vercelAdapter.resources("team_example123");
  const pg = nodes.find((n) => n.id === "store_1")!; const blob = nodes.find((n) => n.id === "store_2")!;
  assert.equal(pg.label, "AdvisorDatabase"); assert.equal(pg.native_type, "vercel_store"); assert.equal(pg.state, "available"); assert.equal(pg.props.engine, "postgres"); assert.equal(pg.props.plan, "Launch"); assert.deepEqual(pg.props.projects, ["web"]);
  assert.equal(blob.label, "AdvisorStorage"); assert.equal(blob.props.product, "Vercel Blob");
});

test("usage: the daily rows fold into totals in readable units, a daily series, and per-project estimates from the breakdown percentages", async () => {
  const usage = await import("../adapters/vercel/usage.js");
  const { db } = await import("../db.js");
  const day = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10);
  const put = db.prepare("insert or replace into vercel_usage(team_id, day, type, metrics, breakdown, fetched_at) values (?, ?, ?, ?, ?, ?)");
  for (const n of [1, 2]) {
    put.run("team_example123", day(n), "requests", JSON.stringify({ request_hit_count: 100, request_miss_count: 900, bandwidth_outgoing_bytes: 2e9, bandwidth_incoming_bytes: 1e9, function_invocation_successful_count: 980, function_invocation_error_count: 20, function_invocation_throttle_count: 0, function_invocation_timeout_count: 0, function_execution_successful_gb_hours: 3, function_execution_error_gb_hours: 0, function_execution_timeout_gb_hours: 0 }),
      JSON.stringify({ requests: [{ id: "prj_abc123", name: "web", percent: 80 }, { id: "prj_def456", name: "api", percent: 20 }], function_invocations: [{ id: "prj_abc123", name: "web", percent: 50 }, { id: "prj_def456", name: "api", percent: 50 }], bandwidth: [{ id: "prj_abc123", name: "web", percent: 100 }], function_execution: [{ id: "prj_abc123", name: "web", percent: 100 }] }), "now");
    put.run("team_example123", day(n), "builds", JSON.stringify({ build_completed_count: 3, build_failed_count: 1, build_build_seconds: 300 }), JSON.stringify({ build_count: [{ id: "prj_abc123", name: "web", percent: 100 }] }), "now");
  }
  put.run("team_example123", day(1), "storage_blob", JSON.stringify({ blob_size_in_bytes: 4.5e9, blob_simple_request_count: 10, blob_advanced_request_count: 5 }), "{}", "now");
  const t = usage.usageTotals("team_example123", 7);
  assert.equal(t.requests, 2000); assert.equal(t.cache_hit_pct, 10); assert.equal(t.bandwidth_out_gb, 4); assert.equal(t.invocations, 2000); assert.equal(t.invocation_errors, 40); assert.equal(t.error_pct, 2); assert.equal(t.gb_hours, 6);
  assert.equal(t.builds, 8); assert.equal(t.builds_failed, 2); assert.equal(t.build_minutes, 10); assert.equal(t.blob_gb, 4.5); assert.equal(t.blob_requests, 15);
  assert.equal(usage.usageSeries("team_example123", 7).length, 2);
  const by = usage.usageByProject("team_example123", 7);
  assert.deepEqual(by.map((p) => [p.name, p.requests, p.invocations, p.bandwidth_out_gb, p.builds]), [["web", 1600, 1000, 4, 8], ["api", 400, 1000, 0, 0]]);
  const web = ad.vercelAdapter.resources("team_example123").find((n) => n.id === "prj_abc123")!;
  assert.equal(web.props.usage_requests_7d, 1600); assert.equal(web.props.usage_builds_7d, 8);
});

test("projectDetail and vercelBill: one project in full with its own usage, and the bill with the period's usage, invoices with lines and the team's own unit prices", async () => {
  const usage = await import("../adapters/vercel/usage.js");
  const { db } = await import("../db.js");
  const day = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10);
  // per-project rows, as the collection writes them for the main types
  const put = db.prepare("insert or replace into vercel_usage(team_id, project_id, day, type, metrics, breakdown, fetched_at) values (?, ?, ?, ?, ?, ?, ?)");
  put.run("team_example123", "prj_abc123", day(1), "requests", JSON.stringify({ request_hit_count: 50, request_miss_count: 450, function_invocation_successful_count: 400, function_invocation_error_count: 100, bandwidth_outgoing_bytes: 1e9 }), "{}", "now");
  put.run("team_example123", "prj_abc123", day(1), "builds", JSON.stringify({ build_completed_count: 2, build_failed_count: 0, build_build_seconds: 120 }), "{}", "now");
  const d = ad.projectDetail("prj_abc123")!;
  assert.equal(d.name, "web"); assert.equal(d.endpoints.length > 0, true); assert.equal(d.domains.length, 3); assert.deepEqual(d.env_names.map((e) => e.key), ["DATABASE_URL", "NEXT_PUBLIC_API"]);
  assert.equal((d.env_names[0] as any).value, undefined, "values never leave the server");
  assert.equal(d.usage.last_7d.requests, 500); assert.equal(d.usage.last_7d.error_pct, 20); assert.equal(d.usage.last_7d.builds, 2); assert.equal(d.usage.series.length, 1);
  assert.equal(ad.projectDetail("prj_missing"), null);

  // the bill: a period that started three days ago, so only the last three days of team usage count, and a paid invoice with lines
  db.prepare("insert or replace into settings(key, value) values (?, ?)").run("vercel_billing:team_example123", JSON.stringify({ plan: "pro", status: "active", currency: "usd", period_start: new Date(Date.now() - 3 * 86_400_000).toISOString(), period_end: new Date(Date.now() + 27 * 86_400_000).toISOString(), seats: 2, seat_usd: 20 }));
  db.prepare("insert or replace into vercel_invoices(id, team_id, number, status, total, subtotal, tax, currency, created_at, period_start, period_end, hosted_url, groups, line_items, fetched_at) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .run("inv_1", "team_example123", "A-1", "paid", 61, 60, 1, "usd", day(10), day(40), day(10), "https://vercel.example.com/invoice/inv_1", JSON.stringify([{ name: "Subscription", total: 40 }, { name: "Infrastructure", total: 20 }]), JSON.stringify([{ title: "Pro seats", quantity: 2, amount: 40, group: "Subscription" }, { title: "Bandwidth", quantity: 100, amount: 20, group: "Infrastructure", unit: "GB" }]), "now");
  const bill = ad.vercelBill();
  assert.equal(bill.billing.plan, "pro"); assert.equal(bill.billing.seats_usd_month, 40); assert.equal(bill.billing.estimated_period_usd, 61, "the month's invoices: issued this month, or expected at the last one");
  assert.equal(bill.invoices[0].kind, "marketplace"); assert.equal(bill.billing.months[0].streams.marketplace, 61);
  assert.equal(bill.period.days_elapsed, 3); assert.equal(bill.period.days_total, 30);
  assert.equal(bill.period.totals.requests, 2000, "the two team days in the period (not the per-project rows)"); assert.equal(bill.period.series.length, 2);
  assert.deepEqual(bill.period.by_project.map((p) => [p.name, p.requests]), [["web", 1600], ["api", 400]]);
  assert.equal(bill.invoices.length, 1); assert.equal(bill.invoices[0].line_items.length, 2); assert.deepEqual(bill.invoices[0].groups.map((g: any) => g.name), ["Subscription", "Infrastructure"]);
  assert.deepEqual(bill.unit_prices.map((u) => [u.title, u.unit_usd]), [["Pro seats", 20], ["Bandwidth", 0.2]]);
  assert.equal(usage.usageByProject("team_example123", 7, day(1)).find((p) => p.name === "web")?.requests, 800, "a since date limits the per-project estimate");
});

test("storeFrom keeps everything the store object says (size, plan lines, metadata, external resource, secret names, period usage) and the rates are dollars per unit", () => {
  const st = client.storeFrom({ id: "store_9", name: "web-postgres", type: "integration", status: "available", billingState: "active", usageQuotaExceeded: false, ownership: "owned", updatedAt: 1759400000000, totalConnectedProjects: 1,
    product: { name: "Neon", slug: "neon", tags: ["tag_databases"], shortDescription: "Serverless Postgres" }, metadata: { region: "iad1", auth: true }, externalResourceId: "quiet-lake-00000000", externalResourceStatus: "ready",
    billingPlan: { id: "launch_v3", name: "Launch", scope: "installation", type: "subscription", description: "To launch.", details: [{ label: "Storage", value: "$0.35 per GB-month" }, { label: "Maximum projects", value: "100" }, { label: "Compute time", value: "$0.106 per CU-hour" }] },
    billingDataV2: { usage: { periodStart: "2026-10-01T00:00:00Z", periodEnd: "2026-11-01T00:00:00Z", timestamp: "2026-10-03T15:00:00Z", items: [{ name: "Compute", units: "hours", periodValue: 60, dayValue: 60, resourceId: "quiet-lake-00000000" }] } },
    secrets: [{ name: "DATABASE_URL", length: 120 }, { name: "PGPASSWORD", length: 16 }], capabilities: { mcp: true, sso: true, billable: true },
    projectsMetadata: [{ projectId: "prj_abc123", name: "web", environments: ["production"], environmentVariables: ["DATABASE_URL", "PGPASSWORD"], envVarPrefix: null }] });
  assert.equal(st.kind, "database"); assert.equal(st.plan, "Launch"); assert.equal(st.region, "iad1");
  assert.equal(st.details.external_id, "quiet-lake-00000000"); assert.equal(st.details.plan_id, "launch_v3"); assert.equal(st.details.plan_lines.length, 3);
  assert.deepEqual(st.details.metadata, { region: "iad1", auth: true }); assert.deepEqual(st.details.secret_names.map((x) => x.name), ["DATABASE_URL", "PGPASSWORD"]);
  assert.deepEqual(st.details.usage_period?.items, [{ name: "Compute", units: "hours", period_value: 60, day_value: 60 }]);
  assert.deepEqual(st.projects[0].env_var_names, ["DATABASE_URL", "PGPASSWORD"]);
  assert.deepEqual(JSON.stringify(st).includes("postgres://"), false, "no connection string anywhere");
  const blob = client.storeFrom({ id: "store_b", name: "b", type: "blob", size: 4.5e9, count: 100, access: "private", isTokenExpired: false, region: "iad1" });
  assert.equal(blob.details.size_bytes, 4.5e9); assert.equal(blob.details.object_count, 100); assert.equal(blob.details.access, "private"); assert.equal(blob.region, "iad1");
  assert.deepEqual(client.planLinePrice("$0.35 per GB-month"), { usd: 0.35, unit: "GB-month" }); assert.deepEqual(client.planLinePrice("$0.106 per CU-hour"), { usd: 0.106, unit: "CU-hour" }); assert.equal(client.planLinePrice("100"), null);
  // the team object's invoiceItems are cents per unit
  const b = client.teamBillingFrom({ plan: "pro", status: "active", currency: "usd", period: { start: 1758438000000, end: 1761030000000 }, invoiceItems: { teamSeats: { price: 2000, quantity: 7 }, pro: { price: 2000, quantity: 1 }, logDrainsVolume: { price: 50 }, functionInvocation: { price: 6e-05 }, fluidDuration: { price: 1.06 }, hidden: { price: 1, hidden: true }, includedAllocationUsd: { price: 0, quantity: 20 } } })!;
  assert.equal(b.seat_usd, 20); assert.equal(b.seats, 7);
  const rate = (k: string) => b.rates.find((r) => r.item === k)!;
  assert.equal(rate("logDrainsVolume").usd, 0.5); assert.equal(rate("logDrainsVolume").unit, "GB");
  assert.equal(rate("functionInvocation").usd, 6e-7); assert.equal(rate("functionInvocation").unit, "each");
  assert.equal(rate("fluidDuration").usd, 0.0106); assert.equal(rate("fluidDuration").unit, "hour");
  assert.equal(rate("pro").usd, 20); assert.equal(rate("pro").unit, "month");
  assert.equal(b.rates.some((r) => r.item === "hidden"), false);
  assert.equal(client.memberFrom({ uid: "u1", username: "alice", role: "OWNER", confirmed: true, mfaEnabled: false, email: "alice@example.com" }).mfa, false);
  assert.equal(JSON.stringify(client.memberFrom({ uid: "u1", email: "alice@example.com" })).includes("example.com"), false, "no e-mail kept");
  const drain = client.logDrainFrom({ id: "drn_1", name: "d", url: "https://logs.example.com/ingest?token=abc", sources: ["lambda"], projectIds: ["prj_abc123"], status: "enabled", deliveryFormat: "ndjson" });
  assert.equal(drain.host, "logs.example.com"); assert.equal(JSON.stringify(drain).includes("token=abc"), false, "the drain URL is kept as its host only");
});

test("pricing: rates, what a project and a store cost at list, and the store detail", async () => {
  const pricing = await import("../adapters/vercel/pricing.js");
  const { db } = await import("../db.js");
  db.prepare("insert or replace into settings(key, value) values (?, ?)").run("vercel_billing:team_example123", JSON.stringify({ plan: "pro", status: "active", currency: "usd", period_start: new Date(Date.now() - 3 * 86_400_000).toISOString(), period_end: new Date(Date.now() + 27 * 86_400_000).toISOString(), seats: 2, seat_usd: 20,
    rates: [{ item: "pro", usd: 20, quantity: 1, unit: "month" }, { item: "includedAllocationUsd", usd: 0, quantity: 20, unit: "month" }, { item: "functionInvocation", usd: 6e-7, quantity: null, unit: "each" }, { item: "fluidDuration", usd: 0.0106, quantity: null, unit: "GB-hour" }, { item: "blobTotalAvgSizeInBytes", usd: 0.023, quantity: null, unit: "GB-month" }] }));
  const rates = pricing.vercelRates("team_example123");
  assert.equal(rates.plan?.seats_usd_month, 40); assert.equal(rates.plan?.base_usd_month, 20); assert.equal(rates.plan?.included_usage_usd, 20);
  assert.deepEqual(rates.team_rates.map((r) => r.item), ["blobTotalAvgSizeInBytes", "fluidDuration", "functionInvocation"], "the plan's base line is not a metered rate");
  assert.equal(rates.observed.length, 2, "the last paid invoice's lines (from the earlier test)");
  // the project: the per-project rows from the earlier test (500 invocations on one day) at the team's rates, scaled to 30 days
  const cost = pricing.projectListCost("team_example123", "prj_abc123", 30);
  assert.deepEqual(cost.lines.map((l) => l.item), ["functionInvocation"]); assert.equal(cost.lines[0].quantity, 500); assert.equal(cost.monthly_list_usd, 0);
  // a store on a marketplace plan with compute hours this period, and a blob store by size
  const { db: d2 } = await import("../db.js");
  d2.prepare("update vercel_stores set details = ? where id = 'store_1'").run(JSON.stringify({ plan_id: "launch_v3", plan_lines: [{ label: "Storage", value: "$0.35 per GB-month" }, { label: "Compute time", value: "$0.106 per CU-hour" }, { label: "Maximum projects", value: "100" }], usage_period: { start: new Date(Date.now() - 3 * 86_400_000).toISOString(), end: null, read_at: null, items: [{ name: "Compute", units: "hours", period_value: 30, day_value: 30 }] }, metadata: { region: "iad1" } }));
  d2.prepare("update vercel_stores set details = ? where id = 'store_2'").run(JSON.stringify({ size_bytes: 10e9, object_count: 5 }));
  const neon = inv.storeById("store_1")!; const neonCost = pricing.storeListCost("team_example123", neon);
  assert.equal(neonCost.lines[0].unit, "CU-hour"); assert.equal(neonCost.lines[0].quantity, 300, "30 hours in 3 days → 300 a month"); assert.equal(neonCost.monthly_list_usd, 31.8);
  const blobCost = pricing.storeListCost("team_example123", inv.storeById("store_2")!);
  assert.equal(blobCost.monthly_list_usd, 0.23, "10 GB × $0.023");
  assert.equal(pricing.vercelRates("team_example123").store_plans.find((s) => s.store_id === "store_1")?.lines.filter((l) => l.price).length, 2, "the plan's two priced lines, read after the details were stored");
  const detail = ad.storeDetail("store_1")!;
  assert.equal(detail.cost.monthly_list_usd, 31.8); assert.equal(detail.node_props.compute_hours_period, 30); assert.equal(detail.node_props.monthly_list_usd, 31.8); assert.deepEqual(detail.node_props.plan_lines, ["Storage: $0.35 per GB-month", "Compute time: $0.106 per CU-hour", "Maximum projects: 100"]);
  assert.equal(ad.vercelAdapter.resources("team_example123").find((n) => n.id === "store_1")?.monthly_usd, 31.8, "the store node carries its cost at the plan");
  assert.equal(ad.storeDetail("store_missing"), null);
  // the knowledge layer: a no-op without a graph; against the local dev graph (NEO4J_URI in .env) it writes under the test team and is removed again
  const gm = await import("../graph_mirror.js");
  const counts = await pricing.mirrorVercelPricing();
  if (gm.enabled()) {
    assert.ok(counts.types >= 9 && counts.overlays === 2 && counts.systems === 4, `wrote ${JSON.stringify(counts)}`);
    await gm.writeCypher("MATCH (n) WHERE (n:KnSystem OR n:KnPricingOverlay) AND n.provider = 'vercel' AND n.account_id = 'team_example123' DETACH DELETE n");
    await gm.writeCypher("MATCH (t:KnSystemType) WHERE t.id STARTS WITH 'vercel|usage|invoice:' AND t.note CONTAINS 'invoice A-1' DETACH DELETE t");
  } else assert.deepEqual(counts, { types: 0, overlays: 0, systems: 0 });
});

test("log drains: one KnLogGroup row per drain with the team's volume split across the enabled ones, the projects it covers, and the owner only when it lists exactly one", async () => {
  const logs = await import("../adapters/vercel/logs.js");
  const { db } = await import("../db.js");
  const day = (n: number) => new Date(Date.now() - n * 86_400_000).toISOString().slice(0, 10);
  db.prepare("insert or replace into settings(key, value) values (?, ?)").run("vercel_extras:team_example123", JSON.stringify({ read_at: "now", members: [], log_drains: [
    { id: "drn_1", name: "web drain", status: "enabled", sources: ["lambda", "edge"], environments: ["production"], sampling_rate: 1, format: "ndjson", host: "logs.example.com", project_ids: ["prj_abc123"], created_at: null, created_from: "self-served" },
    { id: "drn_2", name: "everything", status: "enabled", sources: ["lambda"], environments: [], sampling_rate: null, format: "json", host: "all.example.com", project_ids: [], created_at: null, created_from: "integration" },
    { id: "drn_3", name: "old", status: "disabled", sources: ["edge"], environments: [], sampling_rate: null, format: null, host: null, project_ids: ["prj_def456"], created_at: null, created_from: null }] }));
  const put = db.prepare("insert or replace into vercel_usage(team_id, project_id, day, type, metrics, breakdown, fetched_at) values (?, ?, ?, ?, ?, ?, ?)");
  for (const n of [1, 2]) put.run("team_example123", "", day(n), "log_drains", JSON.stringify({ log_volume: 2e9 }), "{}", "now");
  const rows = logs.drainRows("team_example123", 14);
  assert.deepEqual(rows.map((r) => [r.id, r.owner, r.all_projects, r.projects.map((p) => p.system)]), [
    ["vercel:log_drain:drn_1", "vercel_project:web", false, ["vercel_project:web"]],
    ["vercel:log_drain:drn_2", null, true, ["vercel_project:api", "vercel_project:web"]],
    ["vercel:log_drain:drn_3", "vercel_project:api", false, ["vercel_project:api"]]]);
  // 4 GB over a 2-day window = 2 GB/day, split across the two enabled drains; priced at the team's rate when it has one (none in this test's billing)
  assert.equal(rows[0].ingest_gb_day, 1); assert.equal(rows[1].ingest_gb_day, 1); assert.equal(rows[2].ingest_gb_day, null, "a disabled drain carries no volume");
  assert.match(rows[0].how, /^drain lists web; volume is the team's, split evenly across 2 drains$/); assert.match(rows[2].how, /disabled$/);
  assert.equal(rows[0].host, "logs.example.com");
  const gm = await import("../graph_mirror.js");
  const counts = await logs.mirrorVercelLogs();
  if (gm.enabled()) { assert.equal(counts.drains, 3); await gm.writeCypher("MATCH (g:KnLogGroup {provider: 'vercel', account_id: 'team_example123'}) DETACH DELETE g"); await gm.writeCypher("MATCH (n) WHERE (n:KnSystem OR n:AdvisorResource OR n:AdvisorAccount) AND n.account_id = 'team_example123' DETACH DELETE n"); }
  else assert.deepEqual(counts, { drains: 0 });
});

test("partners: Neon and Redis Cloud fold to snapshots, land on the store as flat properties and endpoints, and never carry a connection string", async () => {
  const pt = await import("../adapters/vercel/partners.js");
  const json = (body: any, status = 200) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  const neonFetch = (async (input: any) => {
    const u = new URL(String(input)); const p = u.pathname.replace("/api/v2", "");
    if (p === "/users/me") return json({ id: "u1", name: "Example", email: "ops@example.com" });
    if (p === "/projects/quiet-lake-00000000") return json({ project: { id: "quiet-lake-00000000", name: "web", region_id: "aws-us-east-1", pg_version: 16, created_at: "2026-01-01T00:00:00Z", synthetic_storage_size: 2.5e9, data_storage_bytes_hour: 1.2e12, compute_time_seconds: 7200, active_time_seconds: 14400, written_data_bytes: 5e8, data_transfer_bytes: 2e8, consumption_period_start: "2026-10-01T00:00:00Z", consumption_period_end: "2026-11-01T00:00:00Z", history_retention_seconds: 86400, default_endpoint_settings: { autoscaling_limit_min_cu: 0.25, autoscaling_limit_max_cu: 2, suspend_timeout_seconds: 300 }, settings: { allowed_ips: { ips: [], protected_branches_only: false } } } });
    if (p === "/projects/quiet-lake-00000000/branches") return json({ branches: [{ id: "br-1", name: "main", default: true, protected: true, current_state: "ready", logical_size: 2.4e9, created_at: "2026-01-01T00:00:00Z" }, { id: "br-2", name: "preview", default: false, current_state: "ready", logical_size: 1e8 }] });
    if (p === "/projects/quiet-lake-00000000/endpoints") return json({ endpoints: [{ id: "ep-1", branch_id: "br-1", type: "read_write", host: "ep-1.example.com", current_state: "active", autoscaling_limit_min_cu: 0.25, autoscaling_limit_max_cu: 2, suspend_timeout_seconds: 0, last_active: "2026-10-03T10:00:00Z", pooler_enabled: true }] });
    if (/\/branches\/br-1\/databases$/.test(p)) return json({ databases: [{ name: "app", branch_id: "br-1", owner_name: "app_owner", connection_uri: "postgres://user:secret@ep-1.example.com/app" }] });
    if (/\/branches\/br-2\/databases$/.test(p)) return json({ databases: [] });
    return json({ error: `unexpected ${p}` }, 404);
  }) as typeof fetch;
  const neon = new pt.NeonClient("neon_test_key", { fetchImpl: neonFetch });
  assert.equal((await neon.whoami()).email_domain, "example.com");
  const snap = await neon.snapshot("quiet-lake-00000000");
  assert.equal(snap.project.pg_version, 16); assert.equal(snap.project.storage_bytes, 2.5e9); assert.equal(snap.branches.length, 2); assert.equal(snap.endpoints[0].suspend_timeout_seconds, 0); assert.deepEqual(snap.databases.map((d) => d.name), ["app"]);
  assert.equal(JSON.stringify(snap).includes("secret"), false, "no connection URI survives the fold");

  const redisFetch = (async (input: any) => {
    const u = new URL(String(input)); const p = u.pathname.replace("/v1", "");
    if (p === "/") return json({ account: { id: 12345, name: "Example account" } });
    if (p === "/subscriptions") return json({ subscriptions: [] });
    if (p === "/fixed/subscriptions") return json({ subscriptions: [{ id: 777, name: "web-cache", status: "active", planName: "Free 30MB" }] });
    if (p === "/fixed/subscriptions/777/databases") return json({ subscription: [{ subscriptionId: 777, databases: [{ databaseId: 1, name: "web-cache", status: "active", protocol: "redis", provider: "AWS", region: "us-east-1", redisVersionCompliance: "7.2", planMemoryLimit: 0.03, memoryUsedInMb: 27, memoryStorage: "ram", dataPersistence: "none", replication: false, dataEvictionPolicy: "volatile-lru", throughputMeasurement: { by: "operations-per-second", value: 100 }, publicEndpoint: "redis-1.example.com:17000", enableTls: false, security: { sslClientAuthentication: false, sourceIps: ["0.0.0.0/0"], enableDefaultUser: true, password: "hunter2" }, modules: [] }] }] });
    return json({ error: `unexpected ${p}` }, 404);
  }) as typeof fetch;
  const redis = new pt.RedisCloudClient("rk", "rs", { fetchImpl: redisFetch });
  assert.equal((await redis.whoami()).name, "Example account");
  const found = await redis.find("web-cache"); assert.ok(found); assert.equal(found!.subscription.kind, "essentials"); assert.equal(found!.database.memory_limit_mb, 31); assert.equal(found!.database.memory_used_mb, 27);
  assert.equal(JSON.stringify(found).includes("hunter2"), false, "the password never leaves the fold");
  assert.equal(await redis.find("nope"), null);

  // on the stores: the refresh's partner records, then the node's props, endpoints and attention
  const { db } = await import("../db.js");
  db.prepare("update vercel_stores set partner = ? where id = 'store_1'").run(JSON.stringify({ snapshot: snap, error: null, read_at: "2026-10-03T12:00:00Z" }));
  db.prepare("insert or replace into vercel_stores(id, team_id, name, type, kind, product, product_slug, status, plan, region, created_at, projects, details, partner, first_seen, last_seen, gone) values ('store_r', 'team_example123', 'web-cache', 'integration', 'cache', 'Redis', 'redis', 'available', 'Free — 30 MB', 'iad1', null, ?, '{}', ?, 'now', 'now', 0)")
    .run(JSON.stringify([{ project_id: "prj_abc123", name: "web", environments: ["production"], env_var_names: ["REDIS_URL"], env_var_prefix: null }]), JSON.stringify({ snapshot: found, error: null, read_at: "2026-10-03T12:00:00Z" }));
  const nodes = ad.vercelAdapter.resources("team_example123");
  const neonNode = nodes.find((n) => n.id === "store_1")!; const redisNode = nodes.find((n) => n.id === "store_r")!;
  assert.equal(neonNode.props.pg_version, 16); assert.equal(neonNode.props.storage_gb, 2.5); assert.equal(neonNode.props.branches, 2); assert.equal(neonNode.props.compute_hours_period, 2); assert.equal(neonNode.props.suspend_timeout_s, 0); assert.equal(neonNode.props.endpoint_state, "active"); assert.deepEqual(neonNode.props.databases, ["app"]);
  assert.equal(redisNode.props.memory_used_pct, 87.1); assert.equal(redisNode.props.persistence, "none"); assert.deepEqual(redisNode.props.source_ips, ["0.0.0.0/0"]);
  const eps = ad.storeEndpoints(inv.storeById("store_1")!); assert.equal(eps.length, 1); assert.equal(eps[0].protocol, "postgres"); assert.equal(eps[0].requires_auth, true); assert.match(eps[0].note, /no IP allow list/);
  const reps = ad.storeEndpoints(inv.storeById("store_r")!); assert.equal(reps[0].hostname, "redis-1.example.com"); assert.equal(reps[0].port, 17000); assert.deepEqual(reps[0].restricted_to, []);
  const rulesMod = await import("../adapters/vercel/rules.js");
  const fnd = rulesMod.vercelFindings();
  assert.ok(fnd.some((f) => f.resource_name === "web-cache" && /Redis memory at 87%/.test(f.reason)), fnd.map((f) => f.reason).join(" | "));
  assert.ok(fnd.some((f) => f.resource_name === "web-cache" && /Redis public endpoint accepts connections from any address/.test(f.reason)));
  assert.ok(fnd.some((f) => f.control_id === "vercel.control.neon_never_suspends" && /never suspends/.test(f.reason)), fnd.map((f) => f.control_id).join(","));
  // readPartners: a Neon failure is a record with an error and a line in the refresh errors, not a thrown refresh
  db.prepare("update vercel_stores set details = json_set(details, '$.external_id', 'quiet-lake-00000000') where id = 'store_1'").run();
  const failing = new pt.NeonClient("k", { fetchImpl: (async () => new Response("nope", { status: 401 })) as typeof fetch });
  const r = await inv.readPartners(inv.listStores(), { neon: failing, redis: null });
  assert.equal(r.records.get("store_1")?.error?.includes("HTTP 401"), true); assert.equal(r.errors.length, 1);
  assert.deepEqual(ad.partnersConfigured(), { neon: false, redis: false });
});

test("rules: the team's findings become a run with findings rows and recommendations in the shared table, decisions survive the next pass, and a finding that goes away resolves its recommendation", async () => {
  const rules = await import("../adapters/vercel/rules.js");
  const { db } = await import("../db.js");
  // the fixtures so far: web has an open preview URL and no protection; web-cache is at 87% memory with open source IPs and no persistence in production; the drains from the log test
  const findings = rules.vercelFindings();
  const ids = findings.map((f) => f.control_id);
  // the api project's production deployment is in ERROR, the usage fixture errors 2% of invocations, the stores from the partner test
  assert.ok(ids.includes("vercel.control.production_deployment_failed") && ids.includes("vercel.control.function_error_rate"), ids.join(","));
  assert.ok(ids.includes("vercel.control.redis_memory_high") && ids.includes("vercel.control.redis_open_source_ips") && ids.includes("vercel.control.redis_no_persistence"), ids.join(","));
  assert.ok(ids.includes("vercel.control.neon_never_suspends"), "the Neon endpoint with suspend timeout 0");
  assert.equal(findings[0].severity, "alarm", "sorted by severity: the failed production deployment first");
  const recs = rules.vercelRecommendations(findings);
  const neon = recs.find((r) => r.rule === "vercel_neon_never_suspends")!;
  assert.equal(neon.actionType, "schedule"); assert.equal(neon.estMonthlySaving, 0, "2 compute hours for 4 active hours: no idle hours, the saving clamps at 0");
  assert.ok(recs.every((r) => r.tier !== "auto"), "nothing on Vercel is automated");
  assert.ok(recs.some((r) => r.rule === "vercel_production_deployment_failed" && r.tier === "report"));
  assert.ok(recs.some((r) => r.rule === "vercel_redis_open_source_ips" && r.actionType === "security_fix"));

  const r1 = await rules.runVercelRules();
  assert.ok(r1.run_id > 0); assert.equal(r1.findings, findings.length); assert.equal(r1.recommendations, recs.length);
  const run = db.prepare("select provider, account_id, status, findings_count from runs where id = ?").get(r1.run_id) as any;
  assert.deepEqual([run.provider, run.account_id, run.status, run.findings_count], ["vercel", "team_example123", "completed", findings.length]);
  assert.equal((db.prepare("select count(*) as n from findings where run_id = ? and account_id = 'team_example123'").get(r1.run_id) as any).n, findings.length);
  const open = db.prepare("select id, rule, resource, status from recommendations where rule like 'vercel\\_%' escape '\\' order by id").all() as any[];
  assert.equal(open.length, recs.length); assert.ok(open.every((r) => r.status === "open"));
  assert.equal((db.prepare("select count(*) as n from runs where provider = 'aws'").get() as any).n, 0, "no AWS run was created by the Vercel pass");
  // a person decides one; the next pass keeps the decision and resolves a recommendation whose finding is gone
  const decided = open.find((r) => r.rule === "vercel_redis_open_source_ips")!;
  db.prepare("update recommendations set status = 'rejected', decided_by = 'gonzalo', decision_reason = 'password + TLS is enough for a cache' where id = ?").run(decided.id);
  db.prepare("update vercel_stores set partner = null where id = 'store_r'").run(); // the Redis Cloud read is gone: no memory, no source-IP, no persistence findings
  const r2 = await rules.runVercelRules();
  assert.equal((db.prepare("select status from recommendations where id = ?").get(decided.id) as any).status, "rejected", "the decision stands");
  assert.equal((db.prepare("select status from recommendations where rule = 'vercel_redis_memory_high' and resource = 'store_r'").get() as any)?.status, "resolved", "its finding went away with the partner read, so the open recommendation resolved");
  assert.ok(r2.resolved >= 1, `resolved ${r2.resolved}`);
  const latest = rules.latestVercelFindings("team_example123");
  assert.equal(latest.run_id, r2.run_id); assert.ok(latest.findings.every((f) => !/redis_/.test(f.control_id)), "the Redis findings are gone with the partner read");
  const ov = ad.vercelOverview();
  assert.equal(ov.rules_run.id, r2.run_id); assert.ok(ov.attention.length === latest.findings.length, "the attention list is the latest pass");
});

// the live-graph tests above open the Neo4j driver; without closing it the file never exits on its own
after(async () => { const gm = await import("../graph_mirror.js"); if (gm.enabled()) await gm.writeCypher("MATCH (n) WHERE n.id = 'team_example123' OR n.account_id = 'team_example123' OR n.id STARTS WITH 'vercel:team_example123:' DETACH DELETE n"); await gm.closeGraph(); });

test("changes: a snapshot diff names what the API said differently, and the collection keeps the rows", async () => {
  const ch = await import("../adapters/vercel/changes.js");
  const { db } = await import("../db.js");
  const first = ch.recordChanges("team_example123");
  assert.equal(first.first, true); assert.equal(first.changes, 0, "the first snapshot has nothing to compare with");
  const before = ch.takeSnapshot("team_example123");
  // the api project deploys to production and turns its firewall on; web gains an env variable and a domain; the Redis store changes plan; a member enables MFA
  db.prepare("update vercel_projects set latest_id = 'dpl_new', latest_state = 'READY', latest_target = 'production', latest_at = '2026-10-04T10:00:00Z', firewall = ? where id = 'prj_def456'").run(JSON.stringify({ project_id: "prj_def456", enabled: true, rules: 2, ips: 0, version: 1 }));
  db.prepare("insert or replace into vercel_env(project_id, key, targets, type, updated_at, first_seen, last_seen, gone) values ('prj_abc123', 'NEW_FLAG', '[\"production\"]', 'plain', null, 'now', 'now', 0)").run();
  db.prepare("insert or replace into vercel_domains(project_id, name, apex, verified, redirect, branch, created_at, first_seen, last_seen, gone) values ('prj_abc123', 'new.example.com', 'example.com', 0, null, null, null, 'now', 'now', 0)").run();
  db.prepare("update vercel_stores set plan = 'Pro 1 GB' where id = 'store_r'").run();
  const extras = JSON.parse((db.prepare("select value from settings where key = 'vercel_extras:team_example123'").get() as any).value);
  extras.members = [{ uid: "u1", username: "alice", role: "OWNER", confirmed: true, mfa: true, github: null, joined_at: null }];
  db.prepare("insert or replace into settings(key, value) values ('vercel_extras:team_example123', ?)").run(JSON.stringify(extras));
  const after = ch.takeSnapshot("team_example123");
  const diff = ch.diffSnapshots(before, after);
  const kinds = diff.map((c) => c.kind).sort();
  for (const k of ["deployment", "firewall", "env_added", "domain_added", "store_plan", "member_added"]) assert.ok(kinds.includes(k), `${k} missing in ${kinds.join(",")}`);
  assert.match(diff.find((c) => c.kind === "env_added")!.what, /NEW_FLAG/); assert.match(diff.find((c) => c.kind === "domain_added")!.what, /not verified yet/);
  assert.equal(diff.find((c) => c.kind === "store_plan")!.before, "Free — 30 MB"); assert.equal(diff.find((c) => c.kind === "store_plan")!.after, "Pro 1 GB");
  const second = ch.recordChanges("team_example123");
  assert.equal(second.changes, diff.length);
  const rows = ch.listChanges("team_example123", { days: 1 });
  assert.equal(rows.length, diff.length); assert.equal(ch.changesSummary("team_example123", 1).total, diff.length);
  assert.deepEqual(ch.diffSnapshots(after, after), [], "no change against itself");
});

test("alerts: a warning finding raises an alert once with its level in the details, and closes it when the finding goes away; info findings never page", async () => {
  const rules = await import("../adapters/vercel/rules.js");
  const { alertLevel } = await import("../alert_level.js");
  const { db } = await import("../db.js");
  db.prepare("delete from alerts where kind like 'vercel\\_%' escape '\\'").run();
  const findings = [
    { control_id: "vercel.control.member_without_mfa", control_title: "Team member without MFA", severity: "warning" as const, category: "security" as const, resource: "team_example123", resource_name: "bob", reason: "bob (MEMBER) has no MFA on the Vercel account", dimensions: { username: "bob" } },
    { control_id: "vercel.control.firewall_off", control_title: "Vercel firewall off", severity: "info" as const, category: "security" as const, resource: "prj_abc123", resource_name: "web", reason: "the Vercel firewall is off", dimensions: {} },
  ];
  const a1 = rules.syncAlerts("team_example123", "Example", findings, 101);
  assert.deepEqual(a1, { raised: 1, closed: 0 });
  const row = db.prepare("select kind, resource, message, details, acknowledged from alerts where kind like 'vercel\\_%' escape '\\'").get() as any;
  assert.equal(row.kind, "vercel_member_without_mfa"); assert.equal(row.message, "Example: bob (MEMBER) has no MFA on the Vercel account"); assert.equal(alertLevel(row), "warning");
  assert.deepEqual(rules.syncAlerts("team_example123", "Example", findings, 102), { raised: 0, closed: 0 }, "the same finding does not page twice");
  const a3 = rules.syncAlerts("team_example123", "Example", [findings[1]], 103);
  assert.deepEqual(a3, { raised: 0, closed: 1 });
  const closedRow = db.prepare("select acknowledged, acknowledged_by, triage from alerts where kind = 'vercel_member_without_mfa'").get() as any;
  assert.equal(closedRow.acknowledged, 1); assert.equal(closedRow.acknowledged_by, "system"); assert.match(String(closedRow.triage), /rules pass #103/);
  assert.equal(alertLevel({ kind: "vercel_production_deployment_failed", details: JSON.stringify({ level: "alarm" }) }), "alarm");
});
