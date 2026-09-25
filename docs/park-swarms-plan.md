# Plan: parking idle swarms (stop only, never terminate)

Status: plan, not built. Written 2026-09-25 against the executor shipped the same day
(`src/executor.ts`, README "Auto-actions"). A fourth track, S3 lifecycle rules from usage, is at the end.

## The idea

A customer swarm is one EC2 box (`sphinx-swarm-N`, `m6i.xlarge` mostly) running a stack of containers. When
nobody has used it for long enough the executor **stops the instance**; when someone needs it the executor
**starts it again**. Nothing is terminated and no volume is touched: the disks and the data stay exactly as they
are, the saving is the instance hours (an `m6i.xlarge` on demand is about 140 USD a month; the account has 64
running instances and 26 already stopped by hand). What makes it an agent's job rather than a person's is the
judgement call, made every hour for every swarm: *is anyone actually using this?*

## What "used" means, and where each signal comes from

The rule the user set: look at the containers' logs, the age of the containers against the last log line, and
whether what is logged is real usage rather than INFO heartbeat; and look at the resources and applications in
use. Signals, from cheapest to richest:

| signal | source | have it today? |
| --- | --- | --- |
| container up time, CPU %, memory | SSM probe (`docker stats`, `docker ps`), rolled up per day in `container_daily` (running share, avg and max CPU) | yes |
| network in/out per day and the 14-day baseline per instance | CloudWatch daily sums, `baselines` scope `instance` | yes |
| CPU per hour of day | `aws_ec2_instance_metric_cpu_utilization_hourly`, `baselines` `by_hour` | yes |
| Route 53 records that reach the box | `inventory_route53_link` | yes |
| whether the box is SSM-online, its state, when it last changed | inventory, `watch_samples` | yes |
| **last log line per container, lines per level in the last 24 h, last non-heartbeat line** | probe extension: `docker logs --since 24h --timestamps <c>` piped through a small classifier | **no: probe v1.3** |
| **established client connections on the published ports** (relay, tribes, proxy, jarvis, the web UI) | probe extension: `ss -Htn state established` counted per local port | **no: probe v1.3** |
| **last real request** on the front door | probe extension: the nginx / caddy access log tail, ignoring `/health`, `/ping`, the swarm checker's user agent | **no: probe v1.3** |
| **application-level use**: messages relayed, payments, tribe joins | relay / tribes container logs: lines matching the events the stack logs on real use, or the swarm's own admin API if it exposes counters | no; depends on what each container logs (to be catalogued on one live swarm first) |

### Probe v1.3 (the `AwsAdvisorProbe` SSM document)

One more section in the JSON the probe already emits, so nothing else in the pipeline changes shape:

```json
"activity": {
  "collected_at": "...",
  "containers": [
    { "name": "relay", "up_seconds": 864000, "log_lines_24h": 1440, "last_log_at": "...", "levels_24h": { "info": 1430, "warn": 8, "error": 2 },
      "last_signal_at": "...", "signal_lines_24h": 12 }
  ],
  "connections": { "443": 0, "3000": 2, "5002": 0 },
  "front_door": { "log": "/var/log/nginx/access.log", "last_request_at": "...", "requests_24h": 3, "health_checks_24h": 2880 }
}
```

- `levels_24h` is a count by level over the last 24 h (`grep -ciE '\b(warn|error)\b'`, the rest info).
- `signal_lines_24h` and `last_signal_at` count only lines that match the **signal patterns** for that container
  image: a small table in the advisor (image name pattern → regexes for "a human did something": a message
  relayed, a payment, a login, a tribe joined, an upload). The table is data, not code, edited from Settings, so
  a new container type is a row, not a release. Everything that does not match is heartbeat, however loud.
- The probe stays read-only and stays inside the 90 s SSM limit: `--tail 2000` per container, at most 20
  containers, `head -c` caps on every pipe. Log lines never leave the box: only counts and timestamps do
  (the probe's text reaches prompts later, so no free text from logs).
- Rolled into `container_daily` (`signal_lines`, `last_signal_at`) and a new `instance_activity` row per probe.

### The verdict: an idle score, then a decision

Computed by the daily review (`src/review.ts`, deterministic, no model call) per running instance whose role is
a customer swarm (Jev's `resource_roles`, or the `sphinx-swarm-*` name, or a tag `advisor:park=auto`):

| evidence | idle if |
| --- | --- |
| last signal line across all containers | older than `PARK_IDLE_DAYS` (default 7) |
| front door requests (non-health) in the window | 0 per day for the whole window |
| established connections on published ports at every probe in the window | 0, or only from the swarm checker / Hive addresses |
| network out per day | at or below the instance's own 14-day median low band, and below 50 MB/day |
| container CPU | every container under 1 % average with no bursts (`container_daily` max) |
| containers up time vs last log | every container has logged nothing but heartbeat since it started, or for the whole window |

All six must hold for `PARK_IDLE_DAYS` consecutive days, with at least `PARK_MIN_PROBES` probes in that time
(the score is explained line by line on the row, like the review's other findings). Any one signal alive keeps
the swarm running; a missing signal (the probe could not run, the log is not there) counts as **alive**, never as
idle: the failure mode must be "kept running", not "stopped by mistake".

Then the executor action `swarm_park` (same four verbs as the others):

- **plan**: each idle swarm becomes a proposal "stop sphinx-swarm-27 (esoteric): idle 9 days, last signal 2026-09-16
  (relay: message relayed), 0 requests, 0 connections, 12 MB/day out" with the estimate (list price per hour × 730),
  `rollback: start it again`. Pre-checks: not tagged `advisor:hands-off`, not `advisor:park=never`, no open
  incident or alarm on it, not a member of a pool or a cluster, **has an Elastic IP or a Route 53 record the
  start step can update** (a stop/start without an EIP changes the public IP and silently breaks the records that
  reach it), and not stopped or started by the executor within `PARK_COOLDOWN_HOURS` (48).
- **apply**: `ec2:StopInstances` (no `--force`, no hibernate); tag the instance `advisor:parked=<ISO time>` so
  the inventory, the Sphinx message and the wake path know it was the executor.
- **verify**: `DescribeInstances` state `stopped`.
- **revert** (= wake): `ec2:StartInstances`, wait for `running` and SSM online, then if the public IP changed and
  there is no EIP, update the Route 53 A records that reached the old IP (`route53:ChangeResourceRecordSets`,
  scoped to the hosted zone), then a probe to confirm the containers came back (`docker ps` count equals the
  count before parking, recorded in the row's facts). Remove the tag.

The Sphinx message on parking says what was idle, since when, and how to wake it. It is the one auto-action that
should be **announced before it happens**: a proposal for a swarm is posted to the chat when first made, and the
apply waits `PARK_GRACE_HOURS` (24) so anyone can say "keep it" (tag it, or reply in the recommendation's thread,
which the chat agent turns into `advisor:park=never`).

### Waking

Four ways in, cheapest first:

1. **Sphinx chat**: "wake swarm-27" in the advisor's chat thread; the chat agent gets a `wake_swarm` tool that calls
   `POST /api/actions/:id/revert` on the park row (the only write tool the agent ever gets, and it can only undo).
2. **The Auto-actions page**: Revert on the row.
3. **Schedule**: a swarm with a weekday pattern in its hour-of-day CPU baseline (the same `by_hour` the ACU action
   uses) gets a morning start before its first typical working hour and is only parked at the end of a workday
   after `PARK_IDLE_DAYS` of nothing.
4. **On demand from the front door** (later): keep a tiny parking page on a shared box behind the swarm's records
   while parked; a real visit hits `POST /api/swarms/:id/wake` and shows "starting, about two minutes". This is the
   only version that is transparent to the customer, and it is a bigger change (records repointed twice), so it is
   v2.

### Guard rails

- Stop only. `ec2:TerminateInstances`, `DeleteVolume` and `DeleteSnapshot` are not in the actuator policy at all.
- The policy's `StopInstances` / `StartInstances` carry a condition on `aws:ResourceTag/advisor:park` being
  `auto`, so only swarms someone tagged (or a one-time bulk tag from the Inventory page) are in scope; the
  tag-based `advisor:hands-off` Deny applies on top.
- One swarm per pass, `ACT_MAX_PER_PASS` still applies, and a swarm parked and woken twice in a week is left
  alone with a note ("flapping: somebody uses it irregularly").
- The saving verifier already measures actioned items against Cost Explorer; a park row gets the same treatment
  seven days after, so the Sphinx chat hears what the bill did.

### Order of work

1. Catalogue on one live swarm what each container logs on real use (an hour with `docker logs`), and write the
   signal-pattern table. This decides whether "signal lines" is a good proxy or whether the front door and
   connections carry the verdict.
2. Probe v1.3 with the `activity` section, roll-ups, and the activity shown on the EC2 drawer (so a person can see
   "last real use" before any automation exists). Ship this alone first: it is useful on its own and it is what
   the review will be judged on.
3. The review's idle score with its explanation, as an observation on the Overview for two weeks, no action.
   Compare it with what the team knows about each swarm; tune the thresholds.
4. `swarm_park` in dry run, with the announcement and the grace period.
5. Wake via chat and the page; then apply mode on the tagged swarms.
6. The morning schedule; the parking page.

## Fourth track: S3 lifecycle rules recommended from usage

The idea (added 2026-09-25): instead of the fixed "bucket without a lifecycle policy" finding, look at how each
bucket is actually used and propose the rule that fits it.

**Data.** Three sources, each one call to enable and cheap:

| source | gives | cost |
| --- | --- | --- |
| S3 Inventory (daily CSV per bucket) | every object's size, last-modified, storage class, version state | 0.0025 USD per million objects listed |
| CloudWatch request metrics on the bucket (`GetRequests`, `PutRequests`, `BytesDownloaded`), optionally per prefix filter | how often it is read and written, day by day | standard CloudWatch metric price per filter |
| S3 Storage Lens advanced activity metrics, or server access logs / CloudTrail data events | which objects and prefixes are read, and when | Storage Lens advanced: 0.20 USD per million objects a month; access logs: storage only |

Enabling S3 Inventory and request metrics on a bucket is itself a reversible, tier-`auto` executor action: the
executor turns them on for the buckets above 20 GB, waits for the first reports, and the recommendation comes a
week later.

**Analysis** (deterministic, in the daily review): from the inventory CSV, the bytes by age bucket (0-30, 30-90,
90-365, 365+ days) per bucket and per top-level prefix; from the request metrics, reads per day against those
bytes; from the activity metrics or the access log, the age of the objects that are actually read (the "access
recency curve"). The rule falls out of the curve:

- reads stop after N days with a clear knee → `Transition` to Standard-IA at N (30-day minimum, 128 KB minimum
  object size noted, retrieval price shown against the read rate so the rule cannot cost more than it saves);
- a tail that is never read → Glacier Instant Retrieval at 90 days, Deep Archive at 365 for anything not read
  in a year, with the restore time stated;
- no pattern, or reads spread across all ages → Intelligent-Tiering (no retrieval charge, small monitoring fee);
- versioned bucket → `NoncurrentVersionExpiration` / transition for noncurrent versions, from the share of bytes
  that are noncurrent;
- always → `AbortIncompleteMultipartUpload` after 7 days (the review can count the leftover parts from the
  inventory);
- prefixes that behave differently (logs/ vs uploads/) → one rule per prefix rather than one per bucket.

**Output.** A recommendation per bucket (tier `approve`: lifecycle transitions carry minimum-storage charges and
retrieval costs, so a human confirms), whose plan step is the exact `put-bucket-lifecycle-configuration` JSON, with
the saving computed from the bytes by age at the class prices already in `src/s3_inventory.ts`, and the exposure
panel listing what reads the bucket (CloudFront distributions, Lambda triggers, the instances whose logs mention
it). Applying it is a later executor action once the verifier has shown a few of them behaving.
