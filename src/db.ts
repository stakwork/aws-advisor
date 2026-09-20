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
  day text primary key,
  net_unblended real,
  unblended real,
  amortized real,
  usage_only real,
  fetched_at text not null default (datetime('now'))
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

// agent_runs grew a kind (findings | incident) and an alert_id, and run_id became optional, when alert
// investigations arrived. SQLite cannot relax a NOT NULL, so databases from before that are rebuilt once.
migrateAgentRuns();
// Jev's alert triage added three columns to alerts; older databases get them here.
for (const [col, type] of [["acknowledged_by", "text"], ["triage", "text"], ["triage_at", "text"]]) addColumn("alerts", col, type);
// Tailored resolutions (src/resolve.ts) are a third kind of agent run, linked to a recommendation.
addColumn("agent_runs", "recommendation_id", "integer");
for (const [col, type] of [["prompt", "text"], ["score", "real"], ["grade", "text"], ["retry_of", "text"], ["retried_by", "text"]]) addColumn("agent_runs", col, type);
addColumn("resolutions", "gate_outcome", "text");
addColumn("inventory_ec2", "pool_kind", "text");
addColumn("inventory_ec2", "pool", "text");

function addColumn(table: string, column: string, type: string) {
  const cols = db.pragma(`table_info(${table})`) as { name: string }[];
  if (!cols.some((c) => c.name === column)) db.exec(`alter table ${table} add column ${column} ${type}`);
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
