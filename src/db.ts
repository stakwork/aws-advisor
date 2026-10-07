import Database from "better-sqlite3";
import fs from "node:fs";
import path from "node:path";
import { config, registerSettingsResolver } from "./config.js";

fs.mkdirSync(config.dataDir, { recursive: true, mode: 0o700 });
try { fs.chmodSync(config.dataDir, 0o700); } catch { /* not ours to change (mounted volume) */ }
export const db = new Database(path.join(config.dataDir, "advisor.db"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");

db.exec(`
create table if not exists settings (key text primary key, value text not null);

create table if not exists runs (
  id integer primary key autoincrement,
  started_at text not null default (datetime('now')),
  finished_at text,
  status text not null default 'running',
  trigger text not null default 'manual',
  account_id text,
  findings_count integer not null default 0,
  recommendations_count integer not null default 0,
  error text,
  log text not null default ''
);

create table if not exists findings (
  id integer primary key autoincrement,
  run_id integer not null references runs(id) on delete cascade,
  source text not null,
  benchmark text,
  control_id text not null,
  control_title text,
  status text not null,
  resource text,
  reason text,
  dimensions text,
  account_id text,
  region text,
  fingerprint text not null
);
create index if not exists findings_run on findings(run_id);
create index if not exists findings_fp on findings(fingerprint);

create table if not exists metrics (
  id integer primary key autoincrement,
  run_id integer not null references runs(id) on delete cascade,
  key text not null,
  label text,
  value real,
  dims text
);
create index if not exists metrics_run on metrics(run_id, key);

create table if not exists recommendations (
  id integer primary key autoincrement,
  fingerprint text not null unique,
  run_id integer not null,
  source text not null default 'rules',
  rule text not null,
  title text not null,
  resource text,
  resource_name text,
  action_type text not null,
  est_monthly_saving real,
  tier text not null default 'approve',
  confidence real,
  rationale text,
  evidence text,
  status text not null default 'open',
  decided_at text,
  decided_by text,
  decision_reason text,
  agent_request_id text,
  created_at text not null default (datetime('now')),
  updated_at text not null default (datetime('now'))
);

create table if not exists agent_runs (
  id integer primary key autoincrement,
  kind text not null default 'findings',
  run_id integer references runs(id) on delete cascade,
  alert_id integer references alerts(id) on delete cascade,
  request_id text unique,
  session_id text,
  events_token text,
  status text not null default 'pending',
  result text,
  error text,
  created_at text not null default (datetime('now')),
  finished_at text
);

create table if not exists learnings (
  id integer primary key autoincrement,
  learning_id text not null,
  recommendation_id integer,
  rule text not null,
  scopes text not null,
  status text not null default 'pending',
  error text,
  created_at text not null default (datetime('now'))
);

create table if not exists run_changes (
  id integer primary key autoincrement,
  run_id integer not null references runs(id) on delete cascade,
  prev_run_id integer,
  kind text not null,
  control_id text,
  control_title text,
  resource text,
  reason text,
  key text,
  label text,
  prev_value real,
  value real,
  delta real,
  pct real,
  flagged integer not null default 0
);
create index if not exists run_changes_run on run_changes(run_id, kind);

create table if not exists instance_metrics (
  id integer primary key autoincrement,
  instance_id text not null,
  collected_at text not null default (datetime('now')),
  json text not null
);
create index if not exists instance_metrics_instance on instance_metrics(instance_id, collected_at);


create table if not exists watch_samples (
  id integer primary key autoincrement,
  sample_id integer not null,
  collected_at text not null,
  key text not null,
  label text not null,
  value real,
  dims text
);
create index if not exists watch_samples_sample on watch_samples(sample_id, key);
create index if not exists watch_samples_key on watch_samples(key, label, sample_id);

create table if not exists alerts (
  id integer primary key autoincrement,
  created_at text not null default (datetime('now')),
  kind text not null,
  resource text,
  message text not null,
  details text,
  acknowledged integer not null default 0,
  acknowledged_by text,
  triage text,
  triage_at text
);
create index if not exists alerts_open on alerts(acknowledged, id);

create table if not exists incidents (
  id integer primary key autoincrement,
  alert_id integer not null references alerts(id) on delete cascade,
  request_id text,
  status text not null default 'pending',
  cause text,
  confidence real,
  evidence text,
  episode_cost_usd real,
  monthly_run_rate_usd real,
  fixes text,
  raw_result text,
  created_at text not null default (datetime('now')),
  finished_at text,
  error text
);
create index if not exists incidents_alert on incidents(alert_id, id);
create index if not exists incidents_request on incidents(request_id);

create table if not exists prices (
  kind text not null,
  sku text not null,
  region text not null,
  engine text not null default '',
  hourly real,
  monthly real,
  fetched_at text not null default (datetime('now')),
  primary key (kind, sku, region, engine)
);

create table if not exists inventory_ec2 (
  instance_id text primary key,
  name text,
  instance_type text,
  state text,
  region text,
  az text,
  launch_time text,
  private_ip text,
  public_ip text,
  platform text,
  ssm_status text,
  ssm_platform text,
  ebs_gb real,
  volumes integer,
  cpu_30d real,
  cpu_days integer,
  probe_mem_pct real,
  probe_at text,
  monthly_usd real,
  open_recs integer not null default 0,
  findings integer not null default 0,
  first_seen text not null default (datetime('now')),
  last_seen text not null default (datetime('now')),
  gone integer not null default 0,
  snapshot text not null
);
create index if not exists inventory_ec2_state on inventory_ec2(gone, state);

create table if not exists inventory_rds (
  db_instance_identifier text primary key,
  class text,
  engine text,
  engine_version text,
  multi_az integer,
  storage_type text,
  storage_gb real,
  status text,
  region text,
  created text,
  cluster text,
  cpu_30d real,
  cpu_days integer,
  monthly_usd real,
  open_recs integer not null default 0,
  findings integer not null default 0,
  first_seen text not null default (datetime('now')),
  last_seen text not null default (datetime('now')),
  gone integer not null default 0,
  snapshot text not null
);

create table if not exists jev_calls (
  id integer primary key autoincrement,
  purpose text not null,
  state_hash text not null,
  questions text not null,
  answers text,
  model text,
  input_tokens integer,
  output_tokens integer,
  latency_ms integer,
  created_at text not null default (datetime('now')),
  error text
);
create index if not exists jev_calls_purpose on jev_calls(purpose, id);
create index if not exists jev_calls_created on jev_calls(created_at);

create table if not exists resource_roles (
  resource_id text primary key,
  role text not null,
  role_confidence real,
  protected_prob real,
  evidence text,
  state_hash text,
  updated_at text not null default (datetime('now'))
);

create table if not exists spend_daily (
  provider text not null,
  account_id text,
  day text not null,
  net_unblended real,
  unblended real,
  amortized real,
  usage_only real,
  fetched_at text not null default (datetime('now')),
  primary key (provider, day)
);

create table if not exists resolutions (
  id integer primary key autoincrement,
  recommendation_id integer not null references recommendations(id) on delete cascade,
  request_id text,
  status text not null default 'pending',
  gate text,
  gate_outcome text,
  context text,
  plan text,
  error text,
  created_at text not null default (datetime('now')),
  finished_at text
);
create index if not exists resolutions_rec on resolutions(recommendation_id, id);

create table if not exists rds_load_profiles (
  id integer primary key autoincrement,
  target_id text not null,
  kind text not null,
  region text,
  collected_at text not null default (datetime('now')),
  profile text not null,
  statements text,
  slow_log text,
  jev text,
  profile_hash text,
  error text
);
create index if not exists rds_load_profiles_target on rds_load_profiles(target_id, id);

create table if not exists inventory_elasticache (
  cache_cluster_id text primary key,
  node_type text,
  engine text,
  engine_version text,
  num_nodes integer,
  status text,
  region text,
  created text,
  replication_group text,
  monthly_usd real,
  open_recs integer not null default 0,
  findings integer not null default 0,
  first_seen text not null default (datetime('now')),
  last_seen text not null default (datetime('now')),
  gone integer not null default 0,
  snapshot text not null
);
`);
// recommendations and alerts carry the account they were made for (src/scope.ts stampRowAccounts); older rows get it on their next listing
for (const t of ["recommendations", "alerts"]) if (!(db.prepare(`pragma table_info(${t})`).all() as { name: string }[]).some((c) => c.name === "account_id")) { try { db.exec(`alter table ${t} add column account_id text`); } catch (e: any) { if (!/duplicate column/i.test(String(e?.message))) throw e; } }
// runs carry their provider: the AWS collection run (default) or a platform provider's rules pass (vercel); every "latest run" lookup names the provider it wants
if (!(db.prepare("pragma table_info(runs)").all() as { name: string }[]).some((c) => c.name === "provider")) { try { db.exec("alter table runs add column provider text not null default 'aws'"); } catch (e: any) { if (!/duplicate column/i.test(String(e?.message))) throw e; } }
// recommendations and alerts carry the provider they were made for, written with the row (the run's provider, the
// raiser's); rows from before the column existed are backfilled once from what only one provider writes: vercel_* rules
// and alert kinds are Vercel's, everything else was AWS's (the only other provider then)
for (const t of ["recommendations", "alerts"]) {
  const had = (db.prepare(`pragma table_info(${t})`).all() as { name: string }[]).some((c) => c.name === "provider");
  if (had) continue;
  addColumn(t, "provider", "text");
  db.prepare(`update ${t} set provider = case when ${t === "alerts" ? "kind" : "rule"} like 'vercel\\_%' escape '\\' then 'vercel' else 'aws' end where provider is null`).run();
}
rekeySpendDaily();

// agent_runs grew a kind (findings | incident) and an alert_id, and run_id became optional, when alert
// investigations arrived. SQLite cannot relax a NOT NULL, so databases from before that are rebuilt once.
migrateAgentRuns();
// Jev's alert triage added three columns to alerts; older databases get them here.
for (const [col, type] of [["acknowledged_by", "text"], ["triage", "text"], ["triage_at", "text"]]) addColumn("alerts", col, type);
// Tailored resolutions (src/resolve.ts) are a third kind of agent run, linked to a recommendation.
addColumn("agent_runs", "recommendation_id", "integer");
for (const [col, type] of [["prompt", "text"], ["score", "real"], ["grade", "text"], ["retry_of", "text"], ["retried_by", "text"]]) addColumn("agent_runs", col, type);
// what the request was, for its entry in the graph (src/graph_agent_runs.ts): the agent it ran as, the model, the flow that owns it and the metadata sent
for (const col of ["agent_name", "model", "link", "metadata"]) addColumn("agent_runs", col, "text");
addColumn("resolutions", "gate_outcome", "text");
// Step progress on a recommendation's plan and the day to look at it again (src/progress.ts).
addColumn("recommendations", "progress", "text");
// What an item waits on: another recommendation's id (src/related.ts).
addColumn("recommendations", "blocked_by", "integer");
// Notifications (src/notify.ts): the receipt on the alert, and the per-resource watch override (1 watch, 0 ignore, null auto).
addColumn("alerts", "notified_at", "text");
// Recommendation events posted to the chat (src/notify.ts): one row per event, `dedupe` keeps each from going twice,
// `result` is the receipt ("sent", "failed: …", "skipped: …"); null = not sent yet (quiet hours, or the bot was down).
db.exec(`create table if not exists notifications (
  id integer primary key autoincrement,
  subject text not null,
  subject_id integer not null,
  event text not null,
  dedupe text unique,
  content text not null,
  created_at text not null default (datetime('now')),
  sent_at text,
  result text
)`);
addColumn("alerts", "notify_result", "text");
for (const t of ["inventory_ec2", "inventory_rds", "inventory_elasticache"]) addColumn(t, "watch", "integer");
// probe 2.0 (src/probes.ts): which probe kind wrote the row; pre-2.0 rows carry the combined probe and count as "all"
addColumn("instance_metrics", "kind", "text not null default 'all'");
db.exec("create index if not exists instance_metrics_kind on instance_metrics(instance_id, kind, collected_at)");
addColumn("inventory_ec2", "pool_kind", "text");
addColumn("inventory_ec2", "pool", "text");

// Security posture (src/compliance.ts): the aws_compliance scan, apart from the cost runs so its thousand-odd alarms
// never reach the cost agent's brief or the run diff. A finding keeps the scan it was first seen in across scans.
db.exec(`create table if not exists compliance_scans (
  id integer primary key autoincrement,
  started_at text not null default (datetime('now')),
  finished_at text,
  status text not null default 'running',
  trigger text not null default 'manual',
  account_id text,
  benchmarks text,
  alarms integer not null default 0,
  new_alarms integer not null default 0,
  resolved integer not null default 0,
  errors integer not null default 0,
  counts text,
  error text,
  log text not null default ''
);
create table if not exists compliance_findings (
  id integer primary key autoincrement,
  scan_id integer not null references compliance_scans(id) on delete cascade,
  benchmark text not null,
  control_id text not null,
  control_title text,
  severity text,
  service text,
  resource text,
  reason text,
  account_id text,
  region text,
  fingerprint text not null,
  first_seen_scan integer not null,
  first_seen_at text not null
);
create index if not exists compliance_findings_scan on compliance_findings(scan_id, severity);
create index if not exists compliance_findings_fp on compliance_findings(fingerprint);
create index if not exists compliance_findings_resource on compliance_findings(resource);`);

// Member accounts (src/accounts.ts): the inventories and the executor's ledger remember which account a row belongs to.
for (const t of ["inventory_ec2", "inventory_rds", "inventory_elasticache", "inventory_ebs", "inventory_s3", "inventory_lambda", "log_groups"]) { try { addColumn(t, "account_id", "text"); } catch { /* table created by a module that has not loaded yet: it adds the column itself */ } }
// RDS identifiers and cache cluster ids are unique per account only: two members can each have a "prod-db" (src/logs.ts and
// src/lambda_inventory.ts do the same for log groups and functions).
rekeyByAccount("inventory_rds", "db_instance_identifier");
rekeyByAccount("inventory_elasticache", "cache_cluster_id");

export function addColumn(table: string, column: string, type: string) {
  const cols = db.pragma(`table_info(${table})`) as { name: string }[];
  if (cols.some((c) => c.name === column)) return;
  // Two processes on one file (the test runner) can both pass the check; the second alter is then a no-op.
  try { db.exec(`alter table ${table} add column ${column} ${type}`); }
  catch (e: any) { if (!/duplicate column/i.test(String(e?.message))) throw e; }
}

/**
 * Re-keys a table whose primary key is a name that is unique per account only (an RDS identifier, a log group, a
 * Lambda function) to (account_id, name), so the same name in two member accounts is two rows instead of the last
 * one written. `account_id` becomes `not null default ''`: the rows collected before the advisor kept account ids
 * are the primary account's (src/scope.ts reads '' that way), and an upsert on the pair always matches. Idempotent:
 * a table already keyed on the pair is left alone. The table is rebuilt in one transaction (no index or trigger is
 * defined on these tables; a column's type, not-null and default are carried over).
 */
export function rekeyByAccount(table: string, key: string): boolean {
  type Col = { name: string; type: string; notnull: number; dflt_value: string | null; pk: number };
  const cols = db.pragma(`table_info(${table})`) as Col[];
  if (!cols.length) return false;
  if (!cols.some((c) => c.name === "account_id")) addColumn(table, "account_id", "text");
  const now = db.pragma(`table_info(${table})`) as Col[];
  if (now.find((c) => c.name === "account_id")!.pk) return false;
  const def = (c: Col) => c.name === "account_id" ? "account_id text not null default ''"
    : c.name === key ? `${c.name} ${c.type || "text"} not null`
    // a default comes back as its expression text (0, '', datetime('now')); in parentheses it is valid again whatever it is
    : `${c.name} ${c.type}${c.notnull ? " not null" : ""}${c.dflt_value != null ? ` default (${c.dflt_value})` : ""}`.replace(/\s+/g, " ").trim();
  const names = now.map((c) => c.name);
  const tmp = `${table}__rekey`;
  db.exec(`drop table if exists ${tmp}`);
  db.transaction(() => {
    db.exec(`create table ${tmp} (${now.map(def).join(", ")}, primary key (account_id, ${key}))`);
    db.exec(`insert into ${tmp} (${names.join(", ")}) select ${names.map((n) => (n === "account_id" ? "coalesce(account_id, '')" : n)).join(", ")} from ${table}`);
    db.exec(`drop table ${table}`);
    db.exec(`alter table ${tmp} rename to ${table}`);
  })();
  return true;
}

/**
 * spend_daily was one row per day of the AWS payer's bill; it is keyed by (provider, day) now, so a second provider's
 * daily cost has its own rows. The rows from before are AWS's, under the account the credentials resolved to.
 */
function rekeySpendDaily() {
  const cols = db.pragma("table_info(spend_daily)") as { name: string }[];
  if (!cols.length || cols.some((c) => c.name === "provider")) return;
  const payer = (() => { try { const v = (db.prepare("select value from settings where key = 'aws_credentials_meta'").get() as { value: string } | undefined)?.value; return v ? JSON.parse(v).accountId ?? null : null; } catch { return null; } })();
  db.transaction(() => {
    db.exec(`create table spend_daily__rekey (provider text not null, account_id text, day text not null, net_unblended real, unblended real, amortized real, usage_only real,
      fetched_at text not null default (datetime('now')), primary key (provider, day))`);
    db.prepare("insert into spend_daily__rekey (provider, account_id, day, net_unblended, unblended, amortized, usage_only, fetched_at) select 'aws', ?, day, net_unblended, unblended, amortized, usage_only, fetched_at from spend_daily").run(payer);
    db.exec("drop table spend_daily");
    db.exec("alter table spend_daily__rekey rename to spend_daily");
  })();
}

function migrateAgentRuns() {
  const cols = (db.pragma("table_info(agent_runs)") as { name: string; notnull: number }[]);
  const runId = cols.find((c) => c.name === "run_id");
  if (cols.some((c) => c.name === "kind") && runId && !runId.notnull) return;
  db.transaction(() => {
    db.exec(`
      create table agent_runs_new (
        id integer primary key autoincrement,
        kind text not null default 'findings',
        run_id integer references runs(id) on delete cascade,
        alert_id integer references alerts(id) on delete cascade,
        request_id text unique,
        session_id text,
        events_token text,
        status text not null default 'pending',
        result text,
        error text,
        created_at text not null default (datetime('now')),
        finished_at text
      );
      insert into agent_runs_new(id, kind, run_id, request_id, session_id, events_token, status, result, error, created_at, finished_at)
        select id, 'findings', run_id, request_id, session_id, events_token, status, result, error, created_at, finished_at from agent_runs;
      drop table agent_runs;
      alter table agent_runs_new rename to agent_runs;`);
  })();
}

export function getSetting(key: string): string | null {
  const row = db.prepare("select value from settings where key = ?").get(key) as { value: string } | undefined;
  return row?.value ?? null;
}

export function setSetting(key: string, value: string) {
  db.prepare("insert into settings(key, value) values (?, ?) on conflict(key) do update set value = excluded.value").run(key, value);
}

export function getJsonSetting<T>(key: string, fallback: T): T {
  const v = getSetting(key);
  if (!v) return fallback;
  try { return JSON.parse(v) as T; } catch { return fallback; }
}

// Runtime settings saved from the Settings page live here as cfg:<key>; the config getters read them first.
registerSettingsResolver((key) => getSetting(`cfg:${key}`));
