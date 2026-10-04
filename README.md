# Cloud Advisor (aws-advisor)

A cloud cost and security advisor that lives next to a sphinx-swarm; AWS is the first provider (the graph model is
provider-neutral, see `docs/cloud-ontology.md`). Names that live inside a provider account keep that provider's
prefix: the IAM user `aws-advisor-read`, the SSM documents `AwsAdvisorProbe-<kind>`, the setup script; a second
provider brings its own. Steampipe and Powerpipe collect the facts,
fixed rules draft recommendations, repo2graph's agent ranks and enriches them with evidence it gathers
itself, and a small web app is where the team reviews, decides and watches. The advisor reads, the agent
proposes, humans decide. The one exception is the [executor](#auto-actions-the-executor): a short catalog of
reversible micro-adjustments (a Serverless cluster's minimum capacity by hour of day, old snapshots to the
Archive tier) that run on a schedule under a separate actuator IAM role, ledgered, dry-run by default, never
through the agent.

## How it fits together

```
                 ┌──────────────── aws-advisor (this repo) ────────────────┐
  AWS account ──▶│ Steampipe (facts as SQL)  ──▶ collector ──▶ SQLite      │──▶ web UI (:9034)
                 │ Powerpipe (Thrifty checks)    rules        findings     │
                 │ watcher (cheap live checks)   changes      recs/alerts  │
                 │ MCP fact server (/mcp)  ◀─────────────┐                 │
                 └────────────────────────────────────────┼────────────────┘
                                   POST /repo/agent       │ aws_* tools
                                          ▼               │
                                   repo2graph (stakgraph-mcp) ── agent on Claude ── webhook back
```

1. **Collect.** A run confirms the Steampipe connection, executes the enabled AWS Thrifty benchmarks
   through Powerpipe, runs the custom queries in `src/queries.ts`, checks Aurora storage tiers against real
   I/O, and stores every alarm as a finding plus last-month cost metrics.
2. **Draft.** `src/rules.ts` turns the well-understood cases into recommendations with a saving estimate, a
   risk tier and a rationale, and reconciles them with earlier runs: open ones refresh, vanished ones resolve,
   rejected ones stay rejected.
3. **Compare.** The run is diffed against the previous one: findings that appeared or went away and cost
   lines that moved more than 20 % and 50 USD. Shown as "What changed" on the run page.
4. **Reason.** The batch, the drafts, the diff, last month's numbers and every past rejection with its reason
   go to repo2graph's agent, together with the advisor's MCP fact server so the agent can verify facts, look
   up real prices and read history before answering. It returns schema-shaped recommendations that are imported
   with source `agent`.
5. **Decide.** In the UI you approve, reject with a reason, snooze, mark pending (in progress) or mark done. Every decision is mirrored into
   repo2graph's Concept graph (one concept per recommendation under `aws/cost-advisor`, next to the operational
   patterns the prompts carry) and a rejection is also posted to its learnings store, so the agent consults past
   decisions natively on the next run.
6. **Watch.** Every 30 minutes a cheap watcher samples instance states, NAT traffic, Savings Plans and EBS
   totals and raises alerts on sudden change, shown at the top of Overview and on the Alerts page.
7. **Investigate.** A NAT traffic alert is handed to the agent as an incident: it gets the alert with its
   attribution, the VPC's flow-log status, the last day of samples and the instances involved, investigates
   with the MCP tools and comes back with a cause, confidence, the episode's cost, its run-rate and fixes that
   land as recommendations.

### What "Approve" does today

It records the decision (status, who, when) and moves the item to the approved list. Nothing is executed.
Approved recommendations are not (yet) read by the executor: its catalog is a separate list of standing
micro-adjustments (see [Auto-actions](#auto-actions-the-executor)), tiered like the playbooks: `auto`
(reversible: retention policies, tags, snapshots), `approve` (stop, resize, storage tier changes, deletions after
a snapshot), `report` (never automated).

### Pending: work in progress, step by step

Many fixes cannot be done in one sitting: a NAT investigation needs VPC flow logs enabled and a week of data
before the next step, a resize waits for a change window. The detail panel therefore has a step checklist on
whichever plan it shows (the tailored resolution's plan when there is one, else the playbook's generic steps),
with a "check again on" date. Ticking the first step of an open or snoozed item moves it to **pending**, its own
list in the status filter; the row says how far it got ("2 of 6 steps · check again 2026-09-30") and turns amber
once the follow-up day has come. "Mark pending" does the same without a tick, with the reason field holding what
you are waiting on. A pending item is left alone by later runs (like an approved one) and is never auto-resolved;
you mark it done when the saving is in place. The checklist remembers which plan it was ticked on
(`recommendations.progress`, `src/progress.ts`): running a new tailored resolution starts a fresh checklist rather
than inheriting ticks from the old plan. The search box takes an id (`#123` or `123`) and finds the row in any
status, so a recommendation from a link or an agent answer opens even when the list is on another filter.

The checklist also records **what happened** to each step: a tick means it worked, "failed?" opens a box for the
output or the reason (`progress.outcomes`, one per step). Those outcomes are what makes the plan interactive.
**Re-plan from here** (`POST /api/recommendations/:id/replan`, body `{ note? }`) asks the agent for a new tailored
plan with the previous plan, each step's outcome and your note in the brief (`src/resolve.ts buildFeedbackSection`):
what worked stays, what failed is replaced with steps that fix the cause shown in the output. The new resolution
shows the feedback it was written from. **Chat about this** (`src/chat.ts`, `GET|POST /api/recommendations/:id/messages`)
is a thread under the plan: each message you write becomes one agent request (task `chat`, `tasks/chat/`); the answer
arrives through the webhook (the thread polls every 5 s meanwhile). A thread talks in one repo2graph session: the
first message carries the full brief (the recommendation, the current plan, the step outcomes and, for a thread that
predates sessions, the last twelve messages), every later message is posted with the same `sessionId`, so repo2graph
replays the conversation with the agent's own tool calls and the brief carries only the new message plus the plan or
the outcomes when they changed. The prompt prefix is the same from turn to turn, so the model's prompt cache is hit
rather than paid for again. When repo2graph no longer has the session (`GET /api/sessions/:id` answers 404) or the
previous turn failed, the thread opens a new session with the full brief. The agent can hand back corrected steps with commands and verify
lines (`step_fixes`, shown as cards) and say the plan needs rewriting (`suggest_replan`, which offers the re-plan
button). Its replies are rendered as Markdown (`ui/src/components/markdown.tsx`: fenced code, lists, tables, links);
what you wrote is shown as typed, so a pasted output is never reflowed. Facts in the brief are read-only; the agent checks claims with the `aws_*` tools before answering.

**Run** on a step executes its check from the app (`src/step_runner.ts`,
`POST /api/recommendations/:id/steps/:index/run`), Steampipe first. The agent is asked to give each step a
`verify_sql`, one SELECT against the `aws_*` tables that shows whether the step worked, whenever a table covers the
check; the runner executes it through the advisor's own Steampipe connection, in a read-only transaction with the
cache switched off for that session, and the rows become the step's outcome ("Run · SQL"). When there is no SQL,
or a table does not cover the check (an Athena query's state, Logs Insights, listing a bucket), the step's command
runs through the aws CLI instead ("Run · CLI"), under a strict rule: every part of the command must be an `aws`
call whose operation reads (describe, get, list, lookup, search, batch-get, head, query, scan, the CloudWatch Logs
query calls; for `aws s3` only `ls`), optionally piped through a text filter (head, tail, grep, sort, uniq, wc, cut,
tr, awk, sed without -i, jq, column, nl), joined by `&&` or `;`. Anything a shell would interpret (substitution,
redirection, `||`, background jobs), any write verb, any `--profile` / `--endpoint-url`, any `file://` argument, and
the read calls that hand out credentials, secrets or objects (ecr get-login-password, sts assume-role, secretsmanager
get-secret-value, ssm get-parameter, s3api get-object, …) are refused and the step shows "copy to run" instead.
The CLI runs with the advisor's own credentials, whatever the mode, as environment variables for that one process,
with a 90 s limit. The image installs AWS CLI v2 for this; on a host without it the app says so at startup and on
every step (`GET /api/run/status`). The transcript becomes the step's outcome (worked or failed by exit code), so the re-plan and the
thread see real output, and every run is kept in `step_runs` (`GET /api/recommendations/:id/runs`). Nothing that
changes AWS ever runs from the app: that is the executor on the roadmap, under its own role.

**Chat** in the sidebar holds general threads with the agent, as many as the team opens (`/api/chat/threads`,
`src/chat.ts`; a thread without a name takes its first message as its title). The brief is deliberately small: a
few account numbers (spend last 7 days, month to date and projection, unacknowledged alerts, open recommendations
and their claimed saving), the index of the advisor's fact tools (bill, forecast, baselines, inventory, pools, RDS
load, NAT attribution, CloudTrail, the graph, Steampipe SQL, …); it is sent once, on the thread's first message,
and later messages continue the same session with the message alone. The agent pulls what the question needs with
those tools and says what it fetched, instead of being handed a dump it may not need. A recommendation's plan has
its own thread under that recommendation, where the brief is the plan and the outcomes.

The detail's "Affected resources" lists every resource the item touches as a link into its Inventory tab
(opened in a new tab): the resource column split up when the agent grouped several ids, each resolved
against the inventory for its name and kind (`src/affected.ts`, returned as `affected` by
`GET /api/recommendations/:id`). Ids and inventory names that appear only in the title or the rationale
("Right-size two boxes: web-1 and swarmAbc123x" with one id in the resource column) are listed apart as "also
named", because the rationale also names what the agent ruled out.

### Notifications in Sphinx

Alerts about resources you care about are posted into a Sphinx chat through a Sphinx bot (`src/notify.ts`).
The request is the one Hive and the swarm checker use: `POST <bot url>` with `{ action: "broadcast", bot_id,
bot_secret, chat_pubkey, chat_uuid, content }`. Settings > Notifications holds the bot endpoint, id, secret and
chat pubkey, the level to send from, the scope and the quiet hours, with a "send a test message" button.

- **Watched resources.** A resource is watched when marked so in its inventory detail ("watch" / "ignore" /
  "auto"), else by an `advisor:watch` tag, else automatically when it is a database, a Route 53 record reaches
  it, or Jev scores it protected (`GET|POST /api/inventory/:kind/:id/watch`). The detail says which rule applies.
  With `NOTIFY_SCOPE=watched`, alerts on other resources stay in the UI; account-level alerts (credentials,
  quota, spend and commitment steps) always qualify at their level.
- **Dispatch.** After every scheduled job (the watcher, the probe pass, the review, …) the dispatcher takes the
  alerts of the last two hours that carry no receipt, applies the rules (level, watched, quiet hours, already
  acknowledged by Jev's triage or a human) and posts the ones that pass, one request per alert with one retry.
  Each alert is sent once. `POST /api/notify/dispatch` runs it by hand; `GET /api/notify/status` says what is
  in force.
- **The message.** Level and the alert's text, the resource with its name and region, the Route 53 records that
  reach it, the open recommendations on it, and a link to the alert in the advisor. The link base is
  `NOTIFY_LINK_URL` when set (the address people actually open, e.g. the instance's private IP over the VPN),
  else `PUBLIC_URL`; the latter is also what repo2graph calls back to, so it stays the swarm-internal address.
- **Receipts.** Every considered alert gets `notified_at` and `notify_result` ("sent", "failed: …" or
  "skipped: <rule>"), shown on the Alerts page; "Send to Sphinx" on a row sends it now whatever the rules say
  (`POST /api/alerts/:id/notify`), and "Resend" repeats it.
- **Recommendation events.** With `NOTIFY_RECOMMENDATIONS=on` (the default) the chat also hears when a
  recommendation is approved, rejected or marked done (who and the reason), and when the saving verifier measures
  one (verdict, realised against estimated, days after the decision). Each event is a row in `notifications` with a
  dedupe key, so a decision saved twice or the same verdict on the next verification run goes out once; the
  receipt is on the row. Events are posted right away; in quiet hours they wait for the next after-job dispatch.
  "Send to Sphinx" in a recommendation's detail posts it now whatever the rules say
  (`POST /api/recommendations/:id/notify`); `GET /api/notifications[?recommendation=<id>]` lists events and
  receipts, `POST /api/notifications/:id/resend` repeats one.

### Resources are intertwined: conflicts, blockers, systems, exposure, history

- **Conflicts.** Two live items (open, pending, approved, snoozed) proposing different resource-changing actions
  on one resource cannot both be worth doing: "stop this instance" and "move it to Graviton". The list row says
  "conflicts with #N" and the detail lists the pair with "close as superseded by this one", which rejects the
  other with the reason `superseded by #id (action): title` on record, so the agent learns not to propose both.
  Report-only actions do not conflict. `src/related.ts`.
- **Distinct savings.** The list header and the Overview tile count one claim per resource, the largest, and say
  how much more is "claimed twice"; the raw sum is still returned as `total_saving`. Grouped items that name
  several resources count when any of them is not yet claimed by a larger item.
- **Blocked by.** An item can wait on another (`recommendations.blocked_by`; the NAT attribution waits on the flow
  logs item). The detail takes an id, refuses self and loops, and shows the blocker's status and follow-up day;
  the row says "blocked by #N" or "unblocked: #N is done" once the blocker is done. The blocker's detail lists
  what it blocks.
- **Systems, not members.** Instances of an autoscaled pool (Karpenter, EKS node group, ASG, Batch), instances of
  an RDS cluster and nodes of an ElastiCache replication group are one entry per (system, action) in the list,
  with the members listed and one decision for all of them (`mergeRecommendations` takes a system map from the
  inventory). A standalone resource is unchanged.
- **Before you act.** The detail shows, per affected resource, the Route 53 records that still reach it, the
  volumes attached, the open alerts on it and the pool or cluster it belongs to (`src/exposure.ts`). For a
  disruptive action (stop, terminate, resize, migrate, delete, storage change) records and alerts turn amber.
  The same records reach Jev's gate and the plan through the resource facts (`domains` in `resourceFacts`), and
  the plan prompt asks for a step or a blocker per record.
- **History.** Every inventory detail ends with the resource's timeline (`src/timeline.ts`,
  `GET /api/inventory/:kind/:id/timeline`): first and last seen, the controls that flagged it and in how many
  runs, recommendations and decisions with reasons, tailored resolutions, bill checks, alerts (folded per day)
  and incidents, probes. Each line links to the page that holds the rest.

### Security posture (aws_compliance)

A second, independent scan runs Turbot's [aws_compliance](https://hub.powerpipe.io/mods/turbot/aws_compliance) mod
through the same Powerpipe and Steampipe connection: AWS Foundational Security Best Practices by default, CIS v3.0.0
as an option (Security page checkboxes). It runs daily on `COMPLIANCE_CRON` (default `20 6 * * *`, about 30 seconds)
and keeps its own tables (`compliance_scans`, `compliance_findings`, `src/compliance.ts`), so its thousand-odd alarms
never reach the cost agent's brief, the cost run's diff or the "material" test. Each finding remembers the scan it was
first seen in, which is what "new" means on the page and in the chat.

Every alarm is listed on the **Security** page. A few become recommendations (rule `sec_<item>`, action_type
`security_fix`, no saving, tier approve; the executor never acts on them and the saving verification skips them):
- every alarm of a critical control, except the known noise (`CRITICAL_NOISE`)
- a short list of high controls (`CURATED`): account-wide ones always, security groups (ec2_18, ec2_19) and IMDSv1
  instances (ec2_8) only when the resource is reachable. Reachable comes from what the advisor knows and the scan
  does not: the running instances carrying the group, their public address, the ports the group opens to 0.0.0.0/0
  that something listens on (probe 1.8), and the Route 53 records that reach the box.

The recommendations reconcile with each scan (a finding that goes away resolves its open recommendation), are mirrored
into the graph (`AdvisorSecurityScan`, `SECURITY_FLAGGED` edges kept apart from the cost run's `FLAGGED`) and decided
like any other. New critical or high findings are posted to the Sphinx chat once per scan. The agent sees them through
the `security_findings` MCP tool: a cost change must not keep or widen an exposure (a public snapshot is deleted, not
archived). A control the read role may not evaluate is a control error in the scan log and in Settings › Permissions,
never a finding: the IAM, GuardDuty, Inspector and account-contact controls need reads the cost policy does not have
(the merged policy there lists them, or attach the AWS-managed `SecurityAudit` policy to the read role).

## Local run

Prerequisites: Node 22, the `steampipe` service running with the `aws` plugin installed, `powerpipe` on PATH.

```
cp .env.example .env            # set STEAMPIPE_DATABASE_URL from `steampipe service status --show-password`
npm install && npm --prefix ui install
(cd mod && powerpipe mod install)
npm --prefix ui run build       # builds the UI into ui/dist
npm start                       # http://localhost:9034
npm test                        # unit tests (probe output parser, SQL guard, credential writers)
```

For UI development with hot reload run `npm run dev` (backend) and `npm --prefix ui run dev` (UI on :5174,
proxied to the backend).

Then open **Settings > AWS credentials** and pick how the advisor authenticates: an **AWS profile** from your
`~/.aws/config` (the recommended setup, no key ever pasted into the app: see
[Onboarding](#onboarding-set-up-aws-access-in-10-minutes)), **Access keys** of a dedicated read-only IAM user
(optionally chained into a role), or the **Instance / default chain** (environment, EC2 instance profile,
container credentials; the swarm mode). The app writes a Steampipe connection named `advisor`
(`STEAMPIPE_CONNECTION`) in your Steampipe config directory with owner-only permissions (and, when a role is
assumed, a managed `[profile aws-advisor]` section in your AWS config file, see
[Three ways to authenticate](#three-ways-to-authenticate)), waits for Steampipe to load it, checks the same
identity through the AWS SDK (`sts:GetCallerIdentity`), and reports the account id. Nothing else stores the
credentials. Every query in the app is qualified with that schema and Powerpipe runs with the search path
pinned to it, so other Steampipe connections on the machine are never touched. Start a run from Overview or
Runs. The Steampipe service reads the AWS files of the user it runs as, so run it as the same user as the
advisor (or mount the same files into its container).

### The UI

| page | what it shows | actions |
| --- | --- | --- |
| Overview | per scope: one account's own overview (AWS: the cards below; Vercel: health, activity, exposure, billing, stores, attention), or for "all accounts" the table across them. AWS cards:  last full month invoice and coverage, open recommendations and their total, findings in the last run, open watcher alerts, top recommendations, on-demand spend by service, EC2 Other breakdown, commitment expiries | run now, acknowledge alerts |
| Runs | one row per collection with counts and status | start, open |
| Alerts | every watcher alert (open, acknowledged or all) with Jev's triage (kind, severity, expected probability, auto-acknowledged by Jev), expandable to its details (top receivers table for NAT alerts) and its incident: cause, confidence, episode cost, run-rate, evidence, fixes linking to their recommendations | investigate, poll result, retry, acknowledge, reopen (undo) |
| Run detail | live log, findings by control, what changed vs the previous run, agent runs for this collection with a live event stream | send findings to agent, watch, poll result |
| Findings | every alarm from the benchmarks and custom queries, filterable by control, searchable | |
| Inventory | tabs are the generic kinds (Compute, Databases, Caches, Functions, Load balancers, Volumes, Object storage, DNS, Deployments, Clusters, Filters, Tags), the provider's own word as the hint; the tabs shown follow the account the sidebar looks at (an AWS account has the AWS kinds, a Vercel team its Deployments; all accounts, every tab with a configured provider behind it). EC2 / RDS / ElastiCache / Lambda / EBS / S3 / Route 53 tabs: summary tiles (running, stopped, SSM online, SSM not managed, on-demand price of what runs, EBS GB), filters by state and SSM status, search, sortable table, sticky detail drawer with identity, network, storage and volumes, SSM, tags, utilisation with probe history, price, the domains that reach the resource, and links to the resource's findings and recommendations; gone resources on request. The EBS tab shows, next to AWS's own state (in-use means attached, even to a stopped instance), the state of the instance the volume is on, counts what sits on stopped instances, and for every volume on a probed instance how much of it is used and free (the probe credits each mount to its volume by the NVMe serial, or by device name on Xen). The Route 53 tab lists every record with what it leads to in this account (or that it is dangling, or outside AWS) | refresh now, probe (SSM-online Linux instances) |
| Recommendations | ranked list with saving, tier, confidence and source, searchable by text or `#id`; sticky detail panel with rationale, evidence, probe data and a step checklist with a follow-up day | approve, reject with reason, snooze, mark pending, mark done, reopen, tick steps, probe (idle instances) |
| Settings | organised around the configured accounts (`?tab=accounts&account=…&section=…`): the Accounts tab lists every account with its provider; opening one shows that provider's own sections, for AWS: Access (the one-command setup and the manual credentials), Permissions, Probes (the SSM documents, their scripts, scopes and crons), Benchmarks, Member accounts. Add account picks the provider; only AWS has an adapter today. Top-level tabs hold what is provider-neutral: Schedules (the non-probe crons with Run now), Auto-actions, Agent & Jev, Notifications, Other. The AWS Access section: AWS credentials (mode picker: access keys, AWS profile, instance / default chain, each with an optional role to assume; save and test checks Steampipe and the SDK side), permissions (what the credentials should be, the SSM probe document and its commands, per-capability check results, missing actions seen anywhere in the app with when and where, the IAM policy JSON that fixes them), benchmark toggles, agent configuration, Jev (enabled, calls and tokens today, last error), dev API token | save and test, remove, check permissions |

## Onboarding: set up AWS access in 10 minutes

### The one-command way

Settings > **Set up AWS access** is a four-step wizard: pick a path (**Laptop / server with a long-lived key**,
**EC2 host with an instance role**, or **Member account of the organisation** for a child, see
[Member accounts](#member-accounts)), keep or change the names, read the plan, copy one command:

```
curl -fsSL "http://localhost:9034/api/setup/script?path=laptop-key" -o aws-advisor-setup.sh && less aws-advisor-setup.sh && bash aws-advisor-setup.sh
```

`less` shows the script before it runs (`q` closes it and the script starts); the wizard also offers the piped
variant `curl -fsSL "..." | bash`, and `path=ec2-role&instanceRole=<role>&instanceId=i-...` for the EC2 host.
The wizard's last step polls the advisor until the script has saved the settings and the connection test
passed, then offers **Check permissions**.

- **Where it runs:** in *your* terminal, with *your* admin credentials for the account (`aws sts
  get-caller-identity` must answer as an admin; the wizard's "admin profile" field adds `--profile` to every
  admin call). The advisor never receives those credentials: the script only calls back with the profile name
  (laptop) or the role ARN (EC2). Needs `aws`, `curl` and, for readable summaries and the trust-policy merge,
  `python3`.
- **Dry run:** the **Dry run** toggle (`&dryRun=1`, or `bash aws-advisor-setup.sh --dry-run`) prints every
  command it would run, writes the policy / trust / SSM documents to a temp dir for inspection, and changes
  nothing: it makes no AWS call at all (every existence check is assumed to find nothing, the account id is a
  placeholder).
- **What it does**, laptop path, one numbered step each: detect the account; create the IAM user `aws-advisor`;
  create the role `aws-advisor-read` trusting the user; put [the policy](#the-policy) on the role; leave the
  user with the single inline policy `aws-advisor-assume` (`sts:AssumeRole` on the role; every other policy on
  the user is removed); create an access key only if the user has none and write it straight into
  `~/.aws/credentials` under `[aws-advisor-user]` with `aws configure set` (the secret is never printed; AWS
  allows two keys per user); write `[profile aws-advisor]` with `role_arn` / `source_profile` / `region`; verify
  `aws sts get-caller-identity --profile aws-advisor` answers as `assumed-role/aws-advisor-read`; create (or
  update) the four SSM probe documents `AwsAdvisorProbe-<kind>`; `PUT /api/settings/aws` with the profile and print the test
  result; `POST /api/permissions/check` and print the summary. The EC2 path instead creates the instance role
  with its instance profile when missing, attaches `AmazonSSMManagedInstanceCore` to it (the host is
  SSM-managed too), makes the read-only role trust it and gives it `aws-advisor-assume`; with an instance id it
  associates the instance profile (only if the instance has none) and raises the IMDS hop limit to 2 (`aws ec2
  modify-instance-metadata-options --http-put-response-hop-limit 2`, needed when the advisor runs in a
  container on the host); then it prints the chain-mode settings (mode Instance / default chain, the role ARN,
  credential source `Ec2InstanceMetadata`) and saves them when the advisor is reachable. Chain mode only works
  when the advisor runs on that instance.
- **Idempotent:** every step checks first (`get-user`, `get-role`, `list-access-keys`, `describe-document`...)
  and skips or updates: a rerun after a failure, or the EC2 path after the laptop path, changes only what is
  missing. Existing principals in the role's trust policy are kept (the new one is merged in).
- **Protected API:** with `API_TOKEN` set the command carries a one-hour `?token=` for the download and
  `ADVISOR_API_TOKEN=...` for the script's own calls back to the advisor; nothing is embedded in the script.

Endpoints: `GET /api/setup/plan?path=laptop-key|ec2-role&user&role&profile&region&instanceRole&instanceId&adminProfile&dryRun=1`
returns `{ steps: [{ title, detail }], command, piped, scriptUrl }`; `GET /api/setup/script?...` the script
(`text/x-shellscript`, attachment `aws-advisor-setup.sh`). Names must match `^[A-Za-z0-9_.-]+$`; the profile
must not be the app's own managed profile (`ADVISOR_AWS_PROFILE`). The generator is `src/setup_script.ts`.

### What the script does, by hand

The setup that works the same on a laptop today and on the swarm host later: a dedicated IAM user whose keys
can do nothing but assume a read-only role, a profile that assumes that role, and the advisor pointed at the
profile. No key is ever pasted into the app. Needs the AWS CLI with admin credentials for the account (any
profile; the commands below use your default) and the read-only policy from [The policy](#the-policy) saved as
`policy.json`. Every step shows the output to check.

```
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text) && echo $ACCOUNT_ID    # 12 digits
curl -s http://localhost:9034/api/permissions | jq .recommended_policy | sed "s/<account-id>/$ACCOUNT_ID/g" > policy.json
# (or copy the JSON from "The policy" below into policy.json and replace <account-id> by hand)
```

#### 1. The IAM user `aws-advisor` with long-lived keys

```
aws iam create-user --user-name aws-advisor
```

Expected: `"Arn": "arn:aws:iam::<ACCOUNT_ID>:user/aws-advisor"`. Give it the read-only policy for now (step 2
moves it to the role):

```
aws iam create-policy --policy-name aws-advisor-read --policy-document file://policy.json
aws iam attach-user-policy --user-name aws-advisor --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/aws-advisor-read
# not put-user-policy: an IAM user's inline policies are capped at 2,048 bytes in total, which the read policy
# exceeds and which leaves no room for the next action the advisor asks for; a managed policy allows 6,144 bytes
# and a user can carry ten of them. A role, as in the one-command setup, allows 10,240 bytes inline.
aws iam create-access-key --user-name aws-advisor
```

`attach-user-policy` prints nothing on success. `create-access-key` prints `AccessKeyId` (`AKIA...`) and
`SecretAccessKey` once; store the two values in `~/.aws/credentials` under `[aws-advisor-user]` and nowhere else
(not in the app, not in `.env`, not in a chat):

```
[aws-advisor-user]
aws_access_key_id = AKIA................
aws_secret_access_key = ........................................
```

```
chmod 600 ~/.aws/credentials
aws sts get-caller-identity --profile aws-advisor-user
```

Expected: `"Arn": "arn:aws:iam::<ACCOUNT_ID>:user/aws-advisor"`.

#### 2. The read-only role `aws-advisor-read`

Save this trust policy as `trust.json`. Principal (a) is the user from step 1; principal (b) is the swarm host's
instance role, for later. Leave (b) out until that role exists (IAM refuses a trust policy that names a
principal that does not exist yet) and add it with `aws iam update-assume-role-policy --role-name
aws-advisor-read --policy-document file://trust.json` when the swarm host is there.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "AdvisorUser", "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:user/aws-advisor" }, "Action": "sts:AssumeRole" },
    { "Sid": "AdvisorHost", "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/<SWARM_INSTANCE_ROLE>" }, "Action": "sts:AssumeRole" }
  ]
}
```

```
aws iam create-role --role-name aws-advisor-read --assume-role-policy-document file://trust.json --description "aws-advisor read-only"
```

Expected: `"Arn": "arn:aws:iam::<ACCOUNT_ID>:role/aws-advisor-read"`. Attach the read-only policy (it already
contains the SSM probe statements) to the role, remove the direct policy from the user, and leave the user with
exactly one permission: assuming this role.

```
aws iam put-role-policy --role-name aws-advisor-read --policy-name aws-advisor-read --policy-document file://policy.json
aws iam delete-user-policy --user-name aws-advisor --policy-name aws-advisor-read
aws iam put-user-policy --user-name aws-advisor --policy-name aws-advisor-assume --policy-document "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"sts:AssumeRole\",\"Resource\":\"arn:aws:iam::$ACCOUNT_ID:role/aws-advisor-read\"}]}"
aws iam list-user-policies --user-name aws-advisor
```

Expected: `"PolicyNames": ["aws-advisor-assume"]` and nothing else. Why: the keys in `~/.aws/credentials` are the
long-lived secret, and now they can read nothing on their own. Whoever gets hold of them still has to assume
the role, which shows up in CloudTrail, lasts an hour per session, and can be cut off in one command
(`aws iam update-assume-role-policy` without the user) without rotating anything. Check it:

```
aws ec2 describe-instances --profile aws-advisor-user --region us-east-1 --max-items 1
```

Expected: `An error occurred (UnauthorizedOperation)`: the keys alone can do nothing.

#### 3. A profile that assumes the role, and the advisor pointed at it

Add to `~/.aws/config`:

```
[profile aws-advisor]
role_arn = arn:aws:iam::<ACCOUNT_ID>:role/aws-advisor-read
source_profile = aws-advisor-user
region = us-east-1
```

```
aws sts get-caller-identity --profile aws-advisor
```

Expected: `"Arn": "arn:aws:sts::<ACCOUNT_ID>:assumed-role/aws-advisor-read/botocore-session-..."`: the CLI took
the keys from `aws-advisor-user`, assumed the role and answered as the role. Then in the advisor open
**Settings > AWS credentials**, choose the **AWS profile** tab, enter `aws-advisor`, leave the role field empty
(the profile already assumes it; the app's own managed profile is named `aws-advisor-managed`, see
`ADVISOR_AWS_PROFILE`, so the hand-written `aws-advisor` profile and the app never collide)
and press **Save and test**. Expected: "Steampipe: connected to account
<ACCOUNT_ID>" and "SDK: arn:aws:sts::<ACCOUNT_ID>:assumed-role/aws-advisor-read/...". The app wrote
`profile = "aws-advisor"` into its Steampipe connection file and nothing else; no key was pasted into the app
at any point and none is stored by it. The same role is what the swarm deployment assumes from the host's
instance profile (variant below), so nothing about the role, the policy or the app changes when the advisor
moves there: only the trust policy gains principal (b).

#### Variants

- **SSO profile instead of the IAM user** (a laptop with IAM Identity Center): `aws configure sso` (pick the
  account and a read-only permission set, name the profile e.g. `example-sso`), `aws sso login --profile
  example-sso`, then the same role through `source_profile = example-sso` in `[profile aws-advisor]` (and the
  permission set's role ARN as principal in `trust.json`), or skip the role and enter `example-sso` directly
  in the **AWS profile** tab. When the SSO session expires the test and the permission check say so and name
  the `aws sso login` command to run. Step 1 is not needed at all.
- **Swarm host** (an EC2 instance with an instance profile): add the instance role as principal (b) in
  `trust.json` and run `aws iam update-assume-role-policy`; in the advisor choose **Instance / default chain**,
  enter the role ARN and keep `Ec2InstanceMetadata` as the credential source. The app writes a managed
  `[profile aws-advisor-managed]` with `role_arn` + `credential_source = Ec2InstanceMetadata` into the AWS config file
  (`AWS_CONFIG_FILE`) and points the Steampipe connection at it; no secret exists on the host. `EcsContainer`
  is the same for a task role, `Environment` for `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` in the environment.

**Verify:** Settings > Permissions > **Check permissions**: the `Credentials (SDK identity)` row shows the
assumed-role ARN and everything is green (`ok`); a `missing` row names the action and the policy block at the
bottom is the fix.

## IAM permissions

Give the advisor its own IAM user or, better, an assumable role: never personal credentials. What is configured
in Settings is stored in one Steampipe connection file (plus a managed profile section when a role is assumed)
and reused by the SSM probe through the AWS SDK, so it should be an identity whose only job is this app. The
safety model, in five lines:

- The agent never holds AWS credentials: it only sees the read-only MCP tools the advisor serves.
- Every tool is read-only by construction (single `SELECT` statements in a `READ ONLY` transaction, price and
  metric lookups, the advisor's own database).
- The dispatch to repo2graph disables bash and pull requests, so the agent cannot reach anything else either.
- The credentials the advisor holds must be read-only, so a misuse of any of the above cannot destroy anything.
- The future executor that acts on approved items will run under a separate role; this identity never gains
  write permissions.

Missing permissions announce themselves: every benchmark, query, watcher sample, inventory refresh, probe and
MCP tool that is denied logs `Missing IAM permission <action>; add it to the advisor's policy (see Settings >
Permissions)` next to the original error, the action is recorded in the `permission_issues` table, and Settings >
Permissions shows the list with when and where it was seen plus one merged IAM policy JSON that fixes all of them.
"Check permissions" on that page runs one cheap probe per capability (`select 1 ... limit 1` on every table the
app uses, pinned to one region, plus the SSM calls through the SDK) and reports `ok`, `missing` (with the issue
and its statement), `error` (something other than a denial, such as expired credentials) or `skipped`.

### Three ways to authenticate

Settings > AWS credentials has three tabs. Each one configures Steampipe and the advisor's own SDK calls (the
SSM probe, the identity check) with the same identity, and each takes an optional role to assume on top.

1. **Instance profile plus an assumable read-only role: the swarm host.** The EC2 instance runs with an
   instance profile whose role has no permissions of its own except assuming `aws-advisor-read`; the advisor
   is in **Instance / default chain** mode with the role ARN. Trust policy of the read-only role, with the
   instance role as principal (add the user principal from the onboarding guide if a laptop also uses it):

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       { "Effect": "Allow", "Principal": { "AWS": "arn:aws:iam::<ACCOUNT_ID>:role/<SWARM_INSTANCE_ROLE>" }, "Action": "sts:AssumeRole" }
     ]
   }
   ```

   ```
   aws iam create-role --role-name aws-advisor-read --assume-role-policy-document file://trust.json --description "aws-advisor read-only"
   aws iam put-role-policy --role-name aws-advisor-read --policy-name aws-advisor-read --policy-document file://policy.json
   aws iam put-role-policy --role-name <SWARM_INSTANCE_ROLE> --policy-name aws-advisor-assume --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sts:AssumeRole","Resource":"arn:aws:iam::<ACCOUNT_ID>:role/aws-advisor-read"}]}'
   ```

   `policy.json` is [The policy](#the-policy) with `<account-id>` filled in. Nothing secret exists on the host;
   the instance metadata service hands out the base credentials and STS the role's.
2. **SSO profile on a laptop.** `aws configure sso`, `aws sso login --profile <name>`, then **AWS profile** with
   that name (optionally with the role ARN, so the SSO permission set only needs `sts:AssumeRole` on the role).
   The session expires after the permission set's duration; the test button and the permission check then say
   `run aws sso login --profile <name>`.
3. **Dedicated IAM user with long-lived keys**, optionally chained into the role: **Access keys** with the key
   and secret (and a session token for temporary keys), optionally the role ARN. The step-by-step version with
   the keys stored in `~/.aws/credentials` and never in the app is the [onboarding guide](#onboarding-set-up-aws-access-in-10-minutes).

What the app writes where (all files mode 0600; `<schema>` is `STEAMPIPE_CONNECTION`, default `advisor`;
`<managed>` is `ADVISOR_AWS_PROFILE`, default `aws-advisor-managed`):

| mode | `<schema>.spc` in `STEAMPIPE_CONFIG_DIR` | AWS config file (`AWS_CONFIG_FILE`, default `~/.aws/config`) | AWS credentials file (`AWS_SHARED_CREDENTIALS_FILE`, default `~/.aws/credentials`) |
| --- | --- | --- | --- |
| Access keys | `access_key`, `secret_key`, `session_token` | nothing | nothing |
| Access keys + role | `profile = "<managed>"` | `[profile <managed>]` with `role_arn`, `source_profile = <managed>-source`, and `[profile <managed>-source]` | `[<managed>-source]` with the key, secret and token |
| AWS profile | `profile = "<name>"` | nothing | nothing |
| AWS profile + role | `profile = "<managed>"` | `[profile <managed>]` with `role_arn`, `source_profile = <name>` | nothing |
| Instance / default chain | no credential fields | nothing | nothing |
| Instance / default chain + role | `profile = "<managed>"` | `[profile <managed>]` with `role_arn`, `credential_source = Ec2InstanceMetadata` (or `EcsContainer`, `Environment`) | nothing |

`regions` and `default_region` are always in the `.spc`. The managed sections are the only bytes the app ever
changes in the two AWS files: they sit between the marker lines `# >>> aws-advisor managed` and
`# <<< aws-advisor managed`, are rewritten in place on every save, removed on **Remove** or when the new mode
needs none, and everything outside the markers is left byte-for-byte as it was (a missing file is created with
only the section). Secrets never go into the config file. An example of the config file after saving
**Access keys + role**:

```
[default]
region = eu-west-1

# >>> aws-advisor managed
[profile aws-advisor]
role_arn = arn:aws:iam::123456789012:role/aws-advisor-read
role_session_name = aws-advisor
source_profile = aws-advisor-managed-source
region = us-east-1

[profile aws-advisor-managed-source]
region = us-east-1
# <<< aws-advisor managed
```

On the SDK side the advisor picks the matching provider (`src/aws_config.ts`): the static keys for plain
access keys, `fromIni` on the profile (the user's, or the managed one when a role is chained) for the profile
mode, the default Node provider chain for the chain mode, and STS `AssumeRole` on top of the keys or the chain
when a role is set. The permission check's first row, `Credentials (SDK identity)`, runs `sts:GetCallerIdentity`
through that provider and reports the mode and the ARN, or the remedy (`aws sso login --profile X`, "attach an
instance profile", "add the identity to the role's trust policy").

Environment: `ADVISOR_AWS_PROFILE` renames the managed profile (when several advisors share one home
directory), `AWS_CONFIG_FILE` and `AWS_SHARED_CREDENTIALS_FILE` move the two AWS files (the Steampipe service
and the advisor must see the same files: same user, or the same mounts). `STEAMPIPE_CONFIG_DIR` is where the
`.spc` goes.

### The policy

The complete minimal read-only policy the app needs (the same document is served by `GET /api/permissions` as
`recommended_policy`, with the account id filled in). It covers every table in `src/queries.ts`,
`src/inventory.ts`, `src/watcher.ts`, `src/investigate.ts`, the MCP tools and the AWS Thrifty benchmarks:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AdvisorReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "rds:Describe*", "rds:ListTagsForResource",
        "elasticache:Describe*", "elasticache:ListTagsForResource",
        "cloudwatch:GetMetricStatistics", "cloudwatch:GetMetricData", "cloudwatch:ListMetrics",
        "logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:ListTagsForResource", "logs:DescribeQueries", "logs:DescribeSubscriptionFilters", "logs:DescribeExportTasks", "logs:StartQuery", "logs:GetQueryResults", "logs:StopQuery",
        "cloudwatch:DescribeAlarms", "cloudwatch:ListTagsForResource",
        "kms:ListKeys", "kms:DescribeKey", "kms:ListAliases", "kms:ListResourceTags", "kms:GetKeyRotationStatus",
        "elasticfilesystem:DescribeFileSystems", "elasticfilesystem:DescribeLifecycleConfiguration", "elasticfilesystem:DescribeTags",
        "ce:GetCostAndUsage", "ce:GetCostAndUsageWithResources", "ce:GetSavingsPlansUtilization",
        "ce:GetSavingsPlansCoverage", "ce:GetReservationUtilization",
        "savingsplans:DescribeSavingsPlans",
        "pricing:GetProducts",
        "support:DescribeSeverityLevels",
        "ssm:DescribeInstanceInformation",
        "s3:ListAllMyBuckets", "s3:GetBucketLocation", "s3:GetLifecycleConfiguration", "s3:GetBucketTagging", "s3:GetBucketVersioning", "s3:GetBucketPolicyStatus",
        "lambda:ListFunctions", "lambda:GetFunction*", "lambda:GetPolicy", "lambda:ListTags",
        "ecr:DescribeRepositories", "ecr:DescribeImages", "ecr:ListImages", "ecr:GetLifecyclePolicy", "ecr:ListTagsForResource",
        "ecs:Describe*", "ecs:List*",
        "eks:Describe*", "eks:List*",
        "dynamodb:Describe*", "dynamodb:List*",
        "application-autoscaling:DescribeScalableTargets",
        "elasticloadbalancing:Describe*",
        "secretsmanager:ListSecrets", "secretsmanager:DescribeSecret",
        "cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus", "cloudtrail:ListTags", "cloudtrail:LookupEvents",
        "cloudfront:List*", "cloudfront:Get*",
        "route53:List*", "route53:Get*",
        "elasticbeanstalk:DescribeEnvironments", "elasticbeanstalk:DescribeConfigurationSettings", "elasticbeanstalk:DescribeEnvironmentResources", "elasticbeanstalk:ListTagsForResource", "elasticbeanstalk:DescribeApplicationVersions",
        "autoscaling:Describe*",
        "redshift:Describe*",
        "elasticmapreduce:List*", "elasticmapreduce:Describe*",
        "apigateway:GET",
        "tag:GetResources",
        "sts:GetCallerIdentity",
        "iam:ListAccountAliases"
      ],
      "Resource": "*"
    },
    {
      "Sid": "AdvisorSsmProbe",
      "Effect": "Allow",
      "Action": ["ssm:SendCommand"],
      "Resource": [
        "arn:aws:ssm:*:<account-id>:document/AwsAdvisorProbe*",
        "arn:aws:ec2:*:*:instance/*"
      ]
    },
    {
      "Sid": "AdvisorSsmProbeDocument",
      "Effect": "Allow",
      "Action": ["ssm:DescribeDocument", "ssm:GetDocument"],
      "Resource": "arn:aws:ssm:*:<account-id>:document/AwsAdvisorProbe*"
    },
    {
      "Sid": "AdvisorSsmProbeResults",
      "Effect": "Allow",
      "Action": ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"],
      "Resource": "*"
    }
  ]
}
```

`ce:*` is what Cost Explorer needs (`aws_cost_*` tables; resource-level history additionally needs the
preference enabled on the payer account), `pricing:GetProducts` the price list, `sts:GetCallerIdentity` and
`iam:ListAccountAliases` the `aws_account` table every run starts with. The wildcards (`ec2:Describe*`,
`ecs:List*`...) are all read-only families; nothing in the document can create, change or delete a resource.

### The SSM probe documents

`AWS-RunShellScript` runs whatever shell it is handed, so a policy that allows `ssm:SendCommand` on it lets the
credentials run *any* command on every instance, and IAM alone cannot make the probe read-only. The advisor
therefore runs its probes through its own SSM Command documents, one per probe (`src/probes.ts`):
`AwsAdvisorProbe-host`, `AwsAdvisorProbe-docker`, `AwsAdvisorProbe-apps` and `AwsAdvisorProbe-software` (the base
name is `PROBE_DOCUMENT`, default `AwsAdvisorProbe`), each embedding its fixed script, and the policy above grants
`ssm:SendCommand` on `arn:aws:ssm:*:<account-id>:document/AwsAdvisorProbe*` and `arn:aws:ec2:*:*:instance/*` only.
**Never grant the advisor `ssm:SendCommand` on `AWS-RunShellScript`** (or on `document/*`): with it a leaked key runs
arbitrary commands on the fleet. The setup script creates the four documents and updates them when a probe changes;
Settings › Probes shows each one's status (deployed and current, stale, missing) and the commands; by hand:

```
curl -s -H "x-api-token: $API_TOKEN" http://localhost:9034/api/probes/host/document > probe-host.json   # schemaVersion 2.2, one aws:runShellScript step, the script lines, the timeout
aws ssm create-document --name AwsAdvisorProbe-host --document-type Command --document-format JSON --content file://probe-host.json
# the same for docker, apps and software
```

The advisor sends a document by name with no `commands` parameter (the script is inside the document; the docker
one takes the use-signal patterns as its `signals` parameter); the policy also grants `ssm:GetCommandInvocation`,
`ssm:ListCommandInvocations`, `ssm:DescribeInstanceInformation` (the SSM inventory) and `ssm:DescribeDocument` /
`ssm:GetDocument` on the documents (the permission check verifies they exist and match, and Settings › Probes prints
the create command when one does not). SSM documents are regional: create them in every region with instances to
probe (`--region`). To limit which instances can be probed, add a condition on the instance ARN, e.g. `"Condition":
{"StringEquals": {"ssm:resourceTag/Environment": "staging"}}` on the `AdvisorSsmProbe` statement. A document's
description carries the probe kind, its version and a hash of the script, so after a probe changes (a new version, or
a script edited in Settings › Probes) the page says which documents are stale; rerun the setup script or update them:

```
curl -s -H "x-api-token: $API_TOKEN" http://localhost:9034/api/probes/host/document > probe-host.json
aws ssm update-document --name AwsAdvisorProbe-host --document-version '$LATEST' --document-format JSON --content file://probe-host.json
aws ssm update-document-default-version --name AwsAdvisorProbe-host --document-version "$(aws ssm describe-document --name AwsAdvisorProbe-host --query Document.LatestVersion --output text)"
```

A fleet that still has only the pre-2.0 combined document `AwsAdvisorProbe` keeps working: the host, docker and
apps probes fall back to it (once per process, with a warning) until their own documents exist; the software probe
has no fallback and waits for its document.

`PROBE_DOCUMENT=AWS-RunShellScript` exists only for a throwaway test with credentials that are deleted
afterwards: the permission check flags the setup as unsafe, and the recommended policy still names only the
`AwsAdvisorProbe*` documents, so nothing in this document ever grants the stock one.

### Shortcut

The AWS managed `ReadOnlyAccess` policy plus a small inline policy with the Cost Explorer (`ce:*` above),
`pricing:GetProducts` and the three SSM statements is an acceptable shortcut; it grants more than the advisor
uses, but nothing that writes.

### Creating the user with the AWS CLI

The quickest version, four commands with the policy above saved as `policy.json` (account id filled in), when
you just want keys to paste into the **Access keys** tab:

```
aws iam create-user --user-name aws-advisor
aws iam create-policy --policy-name aws-advisor-read --policy-document file://policy.json --query Policy.Arn --output text
aws iam attach-user-policy --user-name aws-advisor --policy-arn <the ARN printed above>
aws iam create-access-key --user-name aws-advisor          # paste AccessKeyId and SecretAccessKey into Settings
for k in host docker apps software; do curl -s -H "x-api-token: $API_TOKEN" http://localhost:9034/api/probes/$k/document > probe-$k.json; aws ssm create-document --name AwsAdvisorProbe-$k --document-type Command --document-format JSON --content file://probe-$k.json; done
```

Use a managed policy (`create-policy` + `attach-user-policy`), not `put-user-policy`: a user's inline policies
are limited to 2,048 bytes in total, the read policy is larger than that, and adding a later permission then
fails with `LimitExceeded`. Managed policies allow 6,144 bytes each, up to ten per user.

**Adding one permission later** (Settings > Permissions names the action; `cloudtrail:LookupEvents` was the
first one added after onboarding): create a small managed policy and attach it, or replace the read policy
with a new version of the recommended one from `GET /api/permissions` (`recommended_policy`):

```
aws iam create-policy --policy-name aws-advisor-cloudtrail \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"cloudtrail:LookupEvents","Resource":"*"}]}' \
  --query Policy.Arn --output text
aws iam attach-user-policy --user-name aws-advisor --policy-arn <the ARN printed above>
# or, to update the read policy in place (keeps five versions at most; delete an old one first if it refuses):
aws iam create-policy-version --policy-arn arn:aws:iam::<ACCOUNT_ID>:policy/aws-advisor-read \
  --policy-document file://policy.json --set-as-default
```

The recommended version, where the keys can only assume a role and the app never sees them, is the
[one-command setup](#the-one-command-way) (or its manual steps in the onboarding guide); the role-only version
for the swarm host is the same script's EC2 path, described in [Three ways to authenticate](#three-ways-to-authenticate).

Endpoints: `POST /api/permissions/check` (body `{ "instance_id": "i-..." }` optional; with it the real probe runs
once against that instance to prove `ssm:SendCommand` and `ssm:GetCommandInvocation`, since SendCommand has no
dry run) returns `{ checked_at, account_id, region, credentials_error?, results: [{ id, label, group, actions,
status: ok | missing | error | skipped, message?, issue? }], missing, policy }` where `policy` merges the
statements of everything missing; `GET /api/permissions` returns the recorded issues (`action`, `service`,
`contexts`, `first_seen`, `last_seen`, `count`, `last_message`), the merged `policy` for them, `checked_at` and
the last check, `recommended_policy` and `probe_document`; `GET /api/probe/document` the SSM document JSON. A
check that finds a capability `ok` clears earlier issues for its actions.

## repo2graph integration

The advisor never calls an LLM itself; reasoning is delegated to the swarm's repo2graph node
(image `ghcr.io/stakwork/stakgraph-mcp`, port 3355). Both directions go over HTTP:

- **Advisor → repo2graph.** `POST {REPO2GRAPH_URL}/repo/agent` with header `x-api-token: {REPO2GRAPH_TOKEN}`.
  The body carries the prompt, a cost-advisor system prompt, `ignoreRepoInfo`, the model, `toolsConfig` with
  bash and pull requests disabled, a JSON schema for the answer, `mcpServers` pointing back at
  `{PUBLIC_URL}/mcp`, a unique `sessionId` per dispatch, and `webhookUrl` = `{PUBLIC_URL}/api/agent-callback`.
  repo2graph answers immediately with `request_id`, `sessionId` and a one-hour `events_token`.
- **repo2graph → advisor.** Its agent connects to the advisor's MCP server during the run (tools appear to it
  as `aws_<tool>`), and when finished it POSTs the terminal result to the webhook (three attempts). If the
  webhook is missed, "Poll result" reads repo2graph's `/progress` record instead.
- **Live view.** "Watch" proxies repo2graph's `/events/:request_id` stream through the advisor so the browser
  never holds repo2graph credentials. The first event typically arrives after 30 to 90 seconds, when the agent
  makes its first tool call.
- **Session ids are unique per dispatch** because repo2graph aborts an in-flight run when a new request reuses
  its session id. The API refuses a second send for a run while one is pending unless `?force=1` is passed.
- **Learnings.** A rejection with a reason is posted to `POST /learnings` as
  `{ id: "aws-advisor:<sha1(fingerprint)>", rule, scopes: ["aws-cost-advisor"] }`; outcome in the `learnings`
  table.

### Approved / rejected decisions as Concepts

Every decision becomes a Concept in repo2graph, in one of two scopes (a third parent, the operational patterns,
is described below):

- **internal**: about one specific resource in this account (parent concept "AWS Cost Decisions"), named after the
  action and the resource, e.g. `terminate_stopped_instance example-node-1`.
- **generic**: reusable knowledge that transfers to any account (parent "AWS Cost Knowledge"), named after the
  workload role and the action, never a resource id, e.g. `blockchain_node rightsize_instance rule` with the rule
  "bitcoind nodes are idle on CPU by design; never treat them as right-size candidates".

When you decide, the detail panel asks whether the decision applies to this resource only or to all resources of
this kind; Jev reads the reason and pre-selects the likely scope with its confidence, and you can override it. The
agent prompt lists generic rules first, then internal decisions, and the stored scope is kept in the `concepts`
table (`scope`) and on the recommendation (`decision_scope`).

#### Operational patterns: Concepts only

The rules every agent run is told to respect (pool members are not individual candidates, new instances register
late with Systems Manager, autoscaling churn is normal, the advisor is the monitor for SSM-managed instances) live
only in the graph, as children of a third parent, **AWS Operational Patterns**. `OPERATIONAL_PATTERN_SEEDS` in
`src/concepts.ts` is the seed: at startup and before any dispatch the advisor creates each pattern it finds missing
from both the graph and its `concepts` table (scope `pattern`, status `seeded`) and never rewrites one. After that
the graph owns the text: edit a pattern's description in repo2graph and the agents read the new wording at the next
dispatch; delete it and the rule is retired (the advisor does not recreate a pattern its table already records).
`systemPromptFor(kind)` appends the block "Operational patterns to respect (facts, not guesses)" with one `[id] rule`
line per pattern to the editable system prompt of every kind (findings, incident, resolution, observe), so a plan's
`concepts_used` can cite a pattern by id. The Knowledge page lists them first, with the same click-for-the-record.

#### Mechanics

Every decision on a recommendation (approve, reject, snooze, done, reopen, and a resolved item that once carried a
decision) is also mirrored into repo2graph's Concept graph by `src/concepts.ts`, under the namespace
`aws/cost-advisor` (`CONCEPT_NAMESPACE`): one parent concept, "AWS Cost Decisions", and one child concept per
recommendation, named `<action_type> <resource name>`, whose description carries the current decision and reason
and whose documentation holds the rationale, evidence and guidance for future runs. The child is deleted and
recreated on each decision so the description and its embedding stay current; the deterministic slug means the id
never changes. SQLite stays the source of truth (table `concepts` records the concept id, status and last sync
error per fingerprint); the export is one-way and fire-and-forget, so the UI never waits on it. At dispatch time
the advisor lists the concepts into the prompt ("Team decisions on record") and tells the agent to `learn_concept`
one when it needs the full record before proposing something similar.

Where the two values come from:

| | inside a swarm | on your laptop against a local swarm | production swarm from outside |
| --- | --- | --- | --- |
| ✎ `REPO2GRAPH_URL` | `http://repo2graph.sphinx:3355` | `http://localhost:3355` | `https://repo2graph.<swarm host>` |
| `REPO2GRAPH_TOKEN` | boltwall's `stakwork_secret`, injected by the swarm | the `BOLTWALL_API_SECRET` value in `sphinx-swarm/.env` | the boltwall node's `stakwork_secret` in that swarm's `vol/stack/config.yaml` |

`PUBLIC_URL` must be an address repo2graph's container can reach: `http://host.docker.internal:9034` when the
advisor runs on the Docker host, `http://advisor.sphinx:9034` once it is a swarm node.

### Running repo2graph locally to match production

The swarm's graph-mindset preset is the documented local stack and includes repo2graph:

```
cd sphinx-swarm
cp .env.example .env            # GRAPH_MINDSET_ONLY=true is already set; add ANTHROPIC_API_KEY or use AGENT_API_KEY here
cargo build --bin stack && ./target/debug/stack     # swarm UI on :8888, login admin / password
```

Things learned the hard way:

- The swarm never starts pre-existing *exited* containers; remove stale `*.sphinx` containers from an old run
  first (named volumes survive).
- On Apple Silicon the swarm pulls repo2graph as `linux/x86_64` but, before the fix in `src/dock.rs`
  (`create_container` now pins the platform for images in its `m1_not_supported` list), Docker could pick a
  locally cached arm64 variant, which lacks the x64-only native tokenizer module and crash-loops.
- If you keep an old Neo4j volume, its password no longer matches a freshly generated stack config; reset it
  (start Neo4j on that volume with auth disabled, `ALTER USER neo4j SET PASSWORD`) or delete the volume.
- `AGENT_API_KEY` forwards an Anthropic key per request so a local repo2graph needs no key of its own. In the
  swarm, leave it empty; repo2graph has its own key.

## MCP fact server

The backend serves an MCP server (Streamable HTTP, stateless) at `POST /mcp`, protected by `MCP_TOKEN` as a
bearer token (unset = open, like `API_TOKEN`). All tools are read-only:

| tool | what it does |
| --- | --- |
| `steampipe_query` | one `SELECT`/`WITH` statement against this app's Steampipe schema; bare `aws_*` names are qualified, runs in a read-only transaction with a 60 s timeout, 200-row cap |
| `cloudwatch_metric` | hourly series and summary of one metric (namespace, metric, exact dimensions, statistic, days, region) |
| `price_lookup` | on-demand hourly and monthly price of an EC2 type, RDS class or ElastiCache node type in a region |
| `rds_load` | the load profile of an RDS or Aurora database (cluster or instance id): 14 days of I/O and capacity, the bursts and their cadence, the buffer cache picture, the top statements from Performance Insights, the slow statements from the log tail, and Jev's classification; `refresh` collects it again now |
| `resource_cost_history` | daily cost of one resource id over up to 14 days (needs resource-level data enabled on the payer account; the error says so otherwise) |
| `recommendation_history` | earlier recommendations and decisions for a resource or rule |
| `findings_for_resource` | findings that mention a resource, and which earlier runs saw it |
| `instance_inventory` | the EC2 inventory snapshot (name, type, state, SSM status, 30-day CPU, probe memory, EBS GB, list price, open recs, findings), filterable by state / SSM status / search, 200-row cap |
| `load_balancer_inventory` | the load balancer snapshot: every ALB, NLB, gateway and classic balancer with listeners, target groups and targets resolved to instances or functions with their health, the Beanstalk environment, ASGs and ECS services attached, 30 days of traffic, the fixed list price and the Route 53 records reaching it; `instance_id` = the balancers in front of one instance |
| `domain_inventory` | the Route 53 snapshot: every record with where it leads in this account (`linked` with the resources reached, `unmatched` for AWS names the account does not have, `external`, `none`), filterable by search, zone, state or type; or one resource's domains by kind and id |
| `instance_probe` | runs the SSM probe below and returns the parsed JSON |
| `instance_apps` | what runs on an instance (the apps, the OS set aside, with first/last seen and appear/disappear events, and where its log agents ship), where a program runs across the fleet, or every program running anywhere |
| `status_checks` | the free EC2 status checks of every running instance (system, instance, attached EBS), the events AWS has scheduled for the boxes, and the recent status changes |
| `graph_log_groups` | every log group with the system it was attributed to and how, the instances seen shipping to it, and the unattributed ones with their closest candidates |
| `nat_attribution` | instances in a NAT gateway's VPC ranked by NetworkIn/NetworkOut over the last 1 to 24 hours (what the watcher attaches to a NAT alert as `top_receivers`) |
| `alert_context` | one watcher alert with its parsed details, the watcher samples for the same resource over the last N hours, and the incidents already investigated for it |
| `graph_query` | one read-only Cypher statement against the Neo4j mirror (see [Graph mirror](#graph-mirror)): must start with `MATCH`, `OPTIONAL MATCH`, `WITH` or `CALL {`, no write clause, no `apoc`/`dbms` procedure, read transaction, 5 s timeout, 200-row cap; says so when the mirror is not configured |

## Scheduler and watcher

Two clocks, on purpose. Cost Explorer refreshes a few times a day at daily granularity and inventory findings
change on a scale of days, so the full run is daily; sudden waste (a NAT spike, a fleet that doubled) needs
minutes, so a watcher that costs almost nothing runs every half hour; and the agent runs on change, not on a
clock, so the model bill follows real activity.

Every firing is logged as `[cron] <job> fired ("<expression>")`, and every job says why it did nothing when it
did nothing: no AWS credentials yet, a run already in progress, the previous sample still collecting, the spend
fetch younger than six hours, no repo2graph URL for the observation. The probe pass explains its selection
(`23 candidate(s) of 62 running: left out 30 outside scope "idle", 5 probed within 55 min, 3 not SSM online`)
and groups its failures by cause; the watcher says for each NAT alert whether it went to the agent, and if not,
whether the policy or Jev's triage held it back. The collection run writes the agent-dispatch decision into its
own log. `docker logs advisor.sphinx` is therefore the answer to "did it run, and why not". Every cron row on the
Settings page has a **Run now** button that runs the same job immediately, with the same checks, and shows the
outcome under the row.

- `RUN_CRON` (default `0 6 * * *`, `off` to disable) starts a full run when nothing is running and credentials
  exist.
- `WATCH_CRON` (default `*/30 * * * *`, `off` to disable) samples with live Steampipe queries only, no
  Powerpipe and no Cost Explorer: running instances by type, every instance's state, NAT gateway bytes in and
  out over the last hour, active Savings Plans, total EBS GB. Samples go to `watch_samples`; an instance that
  changes state, appears or disappears, or a NAT gateway above 2x its previous six samples and above 5 GB/hour,
  creates an `alerts` row. Instances that belong to an autoscaling pool (Karpenter node pool, EKS node group or ASG tag) never alert individually: their launches and terminations are folded into one `node_churn` summary alert per pool per day, updated in place. `POST /api/watch` takes a sample by hand.
- `PROBE_CRON` (default `30 5 * * *`, `off` to disable) runs the SSM probe automatically, but only where it can
  change a decision: running, SSM-online instances whose 30-day CPU is under `PROBE_IDLE_CPU` (default 20 %) or
  that carry an open idle-instance recommendation, skipping any probed more recently than `PROBE_MIN_INTERVAL_HOURS` (default 20; 1 with an hourly cron, 24 with a daily one; a five-minute margin is built in so the next pass is never skipped), at most `PROBE_MAX`
  (default 25) per pass, three at a time. `PROBE_SCOPE=all` widens the pass to every SSM-online running instance
  (cap raised to 100), so the Inventory carries memory, disk and process data for the whole fleet. It runs half an hour before the daily collection so the idle-instance
  rule sees fresh memory and process data. Samples older than 30 days are pruned. `POST /api/probe-pass` runs it
  by hand and `GET /api/probe-pass/targets` previews the candidates.
- `AGENT_AUTO_DISPATCH`: `changes` (default) hands a scheduled run to the agent only when change detection
  found something material (a first run always counts), `always` after every run, `never` only on the button.

## Who changed an instance's state

An instance is called gone only when the pass could see its account: the watcher records each instance's account
with its sample and, when a previous sample's account returns no instance at all this time (a parent switch, a
member not registered yet, a role that stopped resolving), leaves its instances as they were and logs how many it
could not see (`canCallGone` in `src/watcher.ts`). The inventory marks rows gone the same way, only in the accounts
the refresh returned rows for (`markGone` in `src/inventory.ts`). An instance seen again closes the "is gone" alert
it got (acknowledged by "watcher (seen again)"): the earlier pass could not see it, it did not leave.

Every `instance_state` alert is explained as it is raised (`src/alert_cause.ts`): who started, stopped, launched
or terminated the instance, how and from where. Three sources, cheapest first: the advisor's own ledger (an
executor row on the instance in the window: office hours, parking, a wake, Revert, the Stop / Start buttons),
EC2's own state reason (the only witness for an OS shutdown, a Spot interruption or an AWS scheduled event), and
CloudTrail `LookupEvents` by the instance id between the previous watcher sample and the alert (the person or
role and session, the channel such as the console, the CLI, Terraform, an SDK, Auto Scaling or a Lambda, and the
source IP). CloudTrail delivers 5 to 15 minutes late, so an alert usually starts `pending`; the watcher and a
ten-minute timer look again until the event arrives or two hours pass. The verdict is stored on `alerts.cause`,
added once to the message as `· Why: …` (so the Sphinx message, Jev's triage, the investigation and the graph
carry it), shown under Details on the Alerts page, and mirrored to the alert's graph node with a `CAUSED_BY` edge
to the ledger row when the advisor did it. An alert already sent to Sphinx before its cause was known gets the
"Why:" as a short follow-up. Needs `ec2:DescribeInstances` and `cloudtrail:LookupEvents`, both already in the
read policy.

## Alert-triggered investigations

A watcher alert says *that* something happened; the investigation says *why* and *what it costs*. The
pieces, in `src/investigate.ts`:

1. **Trigger.** `ALERT_INVESTIGATE=auto` (the default) investigates every new `nat_traffic` alert as soon as
   the watcher has attributed it, when `REPO2GRAPH_URL` is set; `instance_state` alerts are never
   auto-investigated (they are cheap to read and mostly expected). `manual` only starts one from the
   Investigate button or `POST /api/alerts/:id/investigate`; `off` refuses both. The watcher fires and forgets:
   a failed dispatch is logged and marked on the incident, the sample is never delayed by it.
2. **Prompt.** `investigateAlert(alertId)` inserts an `incidents` row and builds a focused prompt: the alert
   (kind, message, details including `top_receivers`), the gateway's VPC, subnet and region, the VPC's flow
   logs (queried from `aws_vpc_flow_log` for the VPC and each of its subnets) and its VPC endpoints, the last
   24 h of `watch_samples` for that gateway, a cost grounding line (NAT data processing is 0.045 USD/GB in
   us-east-1, so the excess over the baseline is priced for the hour and as a monthly run-rate), the instances
   involved from `inventory_ec2` with type, launch time, tags, EKS cluster and nodegroup label and list price,
   any earlier incident on the same resource and the incident recommendations already on file. An alert that
   predates attribution is attributed on the spot and its details updated.
3. **Dispatch.** The same `postAgentRequest` helper the findings batch uses (`src/agent.ts`): same model and
   tool config, the advisor's MCP server (with the two tools above), a unique session id, `agentName`
   `aws-incident-investigator`, and the webhook. The `agent_runs` row records `kind = 'incident'` and the
   alert id; the findings flow records `kind = 'findings'` and the run id. The answer must match this schema:

   ```
   { cause, confidence (0..1), evidence: string[], episode_cost_usd, monthly_run_rate_usd,
     fixes: [{ title, action_type, resource, resource_name?, est_monthly_saving, tier, confidence, rationale }] }
   ```

   `action_type` is one of `enable_flow_logs`, `add_vpc_endpoint`, `add_pull_through_cache`, `move_workload`,
   `reschedule_job`, `rightsize_instance`, `stop_instance`, `other`; `tier` is `auto | approve | report`.
4. **Result.** `POST /api/agent-callback` (or "Poll result") reaches `handleAgentResult`, which routes on the
   agent run's kind: an incident is completed by `completeIncident`, which stores cause, confidence, evidence,
   costs, fixes and the raw result on the incident and imports every fix through `upsertRecommendations` with
   source `agent`, rule `incident:<action_type>` and evidence carrying `{ incident_id, alert_id }`, then writes
   each fix's recommendation id back onto the incident so the UI can link them. The system prompt tells the
   agent that attribution is instance-level (no pods, no destinations without flow logs) and that the advisor
   never enables flow logs itself.
5. **Flow logs, deterministically.** Independently of the agent, `src/flowlogs.ts` emits an
   `enable_flow_logs` recommendation (tier `approve`, no saving estimate, fingerprinted by VPC so it never
   duplicates) for every VPC that owns a NAT gateway with a `nat_traffic` alert in the last 7 days and has no
   flow log on the VPC or any of its subnets. The rationale explains that without flow logs a spike can only be
   attributed to instances, not destinations, and that a 5-minute-aggregation flow log to CloudWatch Logs on
   such a VPC costs on the order of a few USD per month. It runs from the watcher when a NAT alert fires (a
   partial upsert that leaves the other rules alone) and from every collection run (where it reconciles like
   any other rule: once the VPC gets a flow log, or the alerts age out, the item resolves).

Endpoints: `POST /api/alerts/:id/investigate` (202 with `{ incidentId, requestId }`; 409 while an earlier
investigation of the same alert is pending unless `?force=1`; 400 when the agent is not configured or
`ALERT_INVESTIGATE=off`), `GET /api/alerts/:id/incident` (the latest incident with parsed evidence, fixes and
the recommendations they became), `GET /api/incidents`. `GET /api/alerts?status=open|acknowledged|all` rows
carry `incident_id`, `incident_status` and, once completed, the cause, confidence, costs and fixes; `&kind=<kind>`
keeps one kind (nat_traffic, instance_state, disk_full, …) and the answer's `kinds` counts every kind in scope, which
is the kind dropdown on the Alerts page (a kind under a row's badge is clickable too).

Each investigation is one agent run, so it costs model time: the watcher only investigates NAT alerts, one per
alert, and the same gateway does not alert again while an earlier alert is unacknowledged.

## Typed decisions with Jev

Three places in the advisor used to rely on a regex or on nothing at all: whether a watcher alert deserves
anyone's time, what an instance is actually for, and whether a fix the agent proposed could destroy something.
With `TYPESAFE_API_KEY` set, [TypeSafe](https://docs.typesafe.ai)'s Jev answers those as typed questions
(`src/jev.ts`, npm `@typesafe-ai/sdk`, `POST /v1/systemone`, model `JEV_MODEL`, default `jev-latest`): the
state is a small object of summarised facts, the questions are atomic, and every answer is a probability, a
choice with probabilities or a score on a rubric, so a fixed policy can act on it. Jev never loosens a tier and
never triggers an action: it acknowledges, lowers confidence, tightens tiers and annotates; the agent and the
humans still decide. Without the key every use below is a no-op and the advisor behaves exactly as before.

1. **Alert triage** (`src/triage.ts`, purpose `alert_triage`). Right after the watcher creates a `nat_traffic`
   or `instance_state` alert (`node_churn` is known-expected and skipped), and before the auto-investigation
   decision, Jev gets the alert with its details, the top receivers enriched from `inventory_ec2` (name, type,
   launch age, pool and tags), the last 24 h of `watch_samples` as min/avg/max/last plus the hour-of-day of the
   last six, the resource's earlier alerts and incidents, and the VPC's endpoints. Questions: `expected` (noul:
   routine behaviour rather than waste), `kind` (choice: `cold_start_pulls`, `backup_or_sync`,
   `runaway_workload`, `external_abuse`, `capacity_change`, `unknown`) and `severity` (score: Noise / Worth a
   look this week / Should be looked at today / Costing real money right now). The answers are stored on the
   alert (`alerts.triage`, `triage_at`). Policy: `expected >= 0.85` and `severity <= 1` acknowledges the alert
   automatically (`acknowledged_by = 'jev'`, "Auto-acknowledged: <kind> (<prob>)" appended to the message,
   Undo on the Alerts page reopens it); `expected <= 0.4` or `severity >= 2` makes it eligible for the agent
   (the existing `ALERT_INVESTIGATE` logic still applies, so only NAT alerts are dispatched); anything in
   between stays open and is not investigated automatically. The Alerts page and the Overview card show kind,
   severity label and expected probability.
2. **Resource roles** (`src/roles.ts`, purpose `resource_role`). For the EC2 instances a rules batch looks at
   (stopped and idle) and for every RDS instance, one batched call per run (up to 40 resources per call,
   questions namespaced `r0_role`, `r0_protected`...) asks `role` (choice: `blockchain_node`, `database`,
   `cache_or_queue`, `web_or_api`, `batch_or_worker`, `ci_or_build`, `bastion_or_vpn`, `dev_or_test`,
   `k8s_node`, `unknown`) and `protected` (noul: the name, tags or description say it is deliberately kept)
   from the name, tags, type, platform, launch age, the latest probe's top processes and the attached volume
   sizes. Answers are cached in `resource_roles` for 7 days or until name/tags/type change (a state hash).
   `src/rules.ts` uses them: `protected >= 0.7` makes the item tier `report` (the old "do not delete" regex is
   the fallback when Jev is off or has no answer); a `blockchain_node` or `cache_or_queue` with confidence
   `>= 0.7` lowers the idle-instance confidence to 0.2 and says why; `dev_or_test` keeps tier `approve` but the
   rationale suggests a scheduler that parks it out of hours. The Inventory drawers (EC2 and RDS) and the
   Recommendations detail show the role and the protected probability.
3. **Tier check** (`src/tiercheck.ts`, purpose `tier_check`). Every recommendation imported from the agent
   (the findings batch in `src/agent.ts`, an incident's fixes in `src/investigate.ts`) is checked in batches of
   40: `irreversible` (noul: could destroy data or an address that cannot be recovered) and `service_impact`
   (score: No user-visible effect / Brief or degraded / Outage possible). `irreversible >= 0.6` or
   `service_impact >= 1.5` means at least `approve`; `irreversible >= 0.85` means `report`. A tier can only get
   stricter, never looser; the check is recorded in the recommendation's evidence under `jev` and shown in the
   detail panel.

Mechanics: 10 s timeout, one retry on 429/5xx (the SDK's retry policy), never throws into a caller (a failure
returns null, is recorded, and is logged at most once per purpose per minute, after which the existing
behaviour applies: the alert stays open and goes to the agent if it would have before, the rules use their
regex, the agent's tier is imported as proposed). Every call lands in `jev_calls` (purpose, state hash,
questions, answers, model, tokens, latency, error); `GET /api/jev/calls?limit=50&purpose=` reads them for
auditing and Settings shows whether Jev is enabled, today's calls and tokens and the last error. Batched
questions name the key they refer to ("Consider only the resource under resources.r3"): without that Jev
answers the batch as a whole and every resource gets the same answer.

## SSM probes

Four fixed, versioned, read-only shell scripts (`src/probes.ts`), each in its own SSM document and on its own
schedule, so the cheap hourly readings and the heavy daily ones never share a cadence:

| probe | document | collects | default schedule | setting |
|---|---|---|---|---|
| host | `AwsAdvisorProbe-host` | memory, swap, load, CPUs, uptime, disks (with the EBS volume behind each mount), top processes by CPU and memory; the disk, memory and load alerts, the daily roll-ups and the charts read it; the pass also refreshes the RDS load profiles | `PROBE_CRON` (daily; hourly `5 * * * *` fills the charts) | Schedules › Probe: host |
| docker | `AwsAdvisorProbe-docker` | the containers (state, CPU, memory, network) and the [activity section](#activity-is-anyone-using-this-box): container logs and use signals, connections, the front door, logins, traffic; the usage profiles and the swarm costs read it | `PROBE_DOCKER_CRON` | Schedules › Probe: containers and activity |
| apps | `AwsAdvisorProbe-apps` | [what runs](#what-runs-on-the-box-probe-16) (process groups), [what listens](#exposed-ports-and-who-serves-them-probe-18) and where the log agents ship; an opened internet-facing port raises `port_exposed`, and the graph's reachability verdicts are rebuilt for the box | `PROBE_APPS_CRON` | Schedules › Probe: programs and ports |
| software | `AwsAdvisorProbe-software` | the OS and kernel, every installed package with its version and its source package (dpkg, rpm or apk; the advisories name the source, `openssh`, not the binary, `openssh-server`), the version of well-known programs read from the binary (`ssh -V`, `nginx -v`, `openssl version`, …), the images behind the running containers with their digests; stored in `instance_os`, `instance_packages`, `instance_binaries`, `instance_images` with first and last seen and a change log (`src/software_inventory.ts`); the inventory a CVE is matched against | `PROBE_SOFTWARE_CRON` (daily) | Schedules › Probe: installed software |

Host, docker and apps share the scope (`PROBE_SCOPE`: idle candidates, or every box) and the minimum interval
between probes of one box (`PROBE_MIN_INTERVAL_HOURS`); the software probe has its own (`PROBE_SOFTWARE_SCOPE`,
every box by default, since a vulnerability has to be found everywhere, and `PROBE_SOFTWARE_INTERVAL_HOURS`). Every
script prints exactly one JSON object on its last line carrying `probe` (`aws-advisor/<kind>/<version>`) and `kind`;
each row is stored in `instance_metrics` with its kind, and an instance is read back as one merged view (each section
from its kind's newest row; a pre-2.0 combined row counts for host, docker and apps). **Settings › Probes** lists the
probes with what each collects, its document and whether the deployed one matches, its schedule and scope, when it
last ran and on how many boxes, "Run pass now", and the script itself: an edit is saved as a setting (refused when it
stops looking like a read-only probe), embedded in the document and takes effect when the document is redeployed;
the status column says when that is due. `GET /api/probes`, `PUT/DELETE /api/probes/:kind/script`,
`GET /api/probes/:kind/document`, `POST /api/probes/:kind/pass`; `POST /api/instances/:id/probe?kind=` runs one
probe on one box (without `kind`, every probe in turn); `GET /api/instances/:id/software`, `GET /api/software`,
`GET /api/software/where?name=` read the software inventory.

A probe is sent
to one instance that `aws_ssm_managed_instance` reports as online Linux, using the same
identity Steampipe uses (the saved keys, the profile or the default chain, with the role when one is set; see
[Three ways to authenticate](#three-ways-to-authenticate)). It prints one JSON object (memory total and used,
disk usage per mount, 1/5/15 load, top five processes by CPU and by memory, the containers, from 1.4 the
[activity section](#activity-is-anyone-using-this-box), and from 1.6 the
[process list and the log shipping](#what-runs-on-the-box-probe-16)); the app polls the invocation,
validates the output and stores it in `instance_metrics`. SSM hands back only the first 24,000 characters of a
command's output, so from 1.7 a probe whose object is large (a box with many processes and containers) prints it
gzip-compressed and base64-encoded on one marked line and the app decodes it; a smaller one still prints plain JSON. The idle-instance rule uses the latest probe to raise
or lower its confidence and to mention memory and load in the rationale. The credentials need
`ssm:SendCommand` and `ssm:GetCommandInvocation`; missing permission, an unmanaged instance or a timeout come
back as a clear error code (`permission`, `not_managed`, `no_credentials`, `timeout`, `failed`, `bad_output`). A
`permission` error names the missing action, carries its IAM statement (`issue`) and is recorded for Settings >
Permissions.

### Activity: is anyone using this box?

CPU, memory and disk say whether a box is *busy*, not whether anyone *uses* it: a swarm with no customers still
runs its containers, logs its heartbeats and answers its health checks. Probe 1.4 adds an `activity` section
that reads the signals a person would look at before deciding a box is idle, and reduces each to counts and
timestamps so nothing from the logs leaves the instance except the last three lines of each container (capped at
160 printable ASCII characters, shown in the drawer as untrusted text and never put in a prompt):

| signal | how the probe reads it | what it says |
| --- | --- | --- |
| per running container (up to 20): log lines in the last 24 h, the last line's time, error and warning counts | `docker logs --since 24h --tail 2000 --timestamps` | a container that logged nothing but heartbeat since it started is not serving anyone |
| **use signals** per container: lines that look like a human did something, matched against named patterns (`login`, `auth`, `payment`, `message`, `join`, `upload`, `write_request`, `websocket`, `subscribe` by default), minus health checks, pings, metrics and stack traces; the count per pattern and up to five recent distinct matched lines | the patterns are the SSM document's `signals` parameter (probe 1.5), which the advisor fills from **Settings › Probe pass › Use-signal patterns** (`PROBE_SIGNALS`, `name=regex` entries joined by `;;`, POSIX ERE, `src/signals.ts`) on every probe, so revising or adding a pattern is a setting, not a new document; a document from before 1.5 has no parameter and the probe falls back to its built-in list, saying so once in the log. Which patterns *count* is decided per image, see [Tuning the use signals](#tuning-the-use-signals) | `signal_lines` and `last_signal_at` are the "last real use" of that container |
| restarts since the container started | `docker inspect .RestartCount` | a restart loop (≥ 10) is flagged: a crashing worker, not a busy one |
| per container network bytes since it started | `docker stats .NetIO` (`net_rx_bytes` / `net_tx_bytes` on the container row) | the difference between probes is that container's traffic; rolled up as `net_bytes_day` |
| established TCP flows: external (public peers), internal (RFC 1918 peers other than docker bridges), ssh, by destination port, the busiest peer→port pairs, and which container answers on each published port | `/proc/net/nf_conntrack` first (it sees the DNAT'd flows into containers that the host's own sockets do not), else `conntrack -L`, else `ss`; `docker ps` for the port map | an external client connected right now is the strongest "in use" there is, and the drawer says who, to what: `203.0.113.5 → :443 (proxy)` |
| the front door: requests in 24 h, health checks counted apart, the last non-health request | the log of the first proxy container (image `nginx`, `caddy`, `traefik`, `haproxy`, `*proxy*`, `*ingress*`), else the tail of `/var/log/nginx/access.log` and friends, whose `25/Sep/2026:10:00:00 +0000` date the advisor parses on arrival (`parseClfDate`) | a swarm nobody visits has thousands of health checks and zero requests |
| logins: users on the box now, the last login and who | `who`, `last --time-format iso` | somebody working on the box is use too |
| host interface counters since boot | `/proc/net/dev`, loopback and docker bridges excluded | the drawer shows the difference from the previous probe ("12 MB in the 58 min since the previous probe"), the roll-up the bytes per day; the raw counter is never shown |

The section takes about three seconds on a box with a handful of containers and never fails the probe: a
missing tool or file becomes a null. The probe's own machinery (the `ssm-document-worker` that runs the document, its
shell and the tools the script pipes through) is always running at the moment the probe looks and is left out of
"busiest process" and the top-CPU lists (`realProcesses` in `src/ssm.ts`). `useSummary` (`src/ssm.ts`) reduces it to one line, **last real use** and
what the evidence was (the newest of: a use signal line, a front-door request, a login, an external connection
at probe time), which the drawer shows first and `summarizeProbe` carries as `last_use_at` for the rules. The
history keeps it: `instance_activity` (one row per probe, 30 days), the activity columns on `container_samples`
and `container_daily` (`log_lines_avg`, `signal_lines_avg`, `errors_avg`, `restarts_max`, `last_log_at`,
`last_signal_at`, `net_bytes_day`) and on `instance_daily` (`external_connections_avg/max`, `ssh_sessions_max`,
`requests_24h_avg`, `signal_lines_24h_avg`, `last_use_at`, `last_use_kind`, `net_bytes_day`, 400 days).
`GET /api/instances/:id/history` returns them with an `activity` summary over the window (days with external
connections, with requests, with signals; the newest use). After upgrading, update the SSM document as described
under [Containers and long-lived history](#containers-and-long-lived-history); instances keep answering with 1.3
output until then, and everything above simply stays empty for them.

#### Tuning the use signals

The patterns are generic and a container's log decides what they mean: boltwall writes an `authorization` line
for every macaroon check and a health checker's `POST` matches `write_request`, so a box nobody uses can show
hundreds of "use signals". The fix is not a probe script per instance but a **rule per image**
(`src/signal_rules.ts`, table `signal_rules`): for images whose name contains a pattern (the image without its
tag, `sphinxlightning/sphinx-boltwall`), a kind is `noise` (never counts) or `signal`. Rules apply to every
instance running that image, at the moment a probe is stored (`container_signals` in `src/ssm.ts`): the
container's `signal_lines_24h` becomes the count after the rules, a container whose every matched kind is noise
has no last use, and the drawer's "last real use" line and the roll-ups follow.

- **In the drawer** every container shows one chip per matched kind with its count (`auth 200`, `write_request
  18`) and a "lines" toggle with the sample lines that matched, so you can see what the pattern caught. Click a
  chip to rule that kind noise for that image (with a reason), click again to lift the rule.
- **Ask the agent to review the signals** opens a chat thread: the agent reads the samples with the
  `activity_signals` tool, says per container what is a person and what is machine chatter, and records
  proposals with `propose_signal_rule`. Proposals change nothing until you press **Confirm** on them in the
  drawer (or Reject); a confirmed rule is never overridden by a proposal. This is the one write tool the agent
  has, and it can only propose.
- `GET /api/signal-rules`, `PUT /api/signal-rules` `{ image_pattern, kind, verdict, note }` (confirmed),
  `POST /api/signal-rules/:id/confirm`, `DELETE /api/signal-rules/:id`, `POST /api/instances/:id/signals/review`.

The raw per-kind counts stay on `container_samples.signal_kinds`, so a rule added later can be judged against
the last thirty days.

### What runs on the box (probe 1.6)

The probe lists every user-space process (`ps -eo pid,ppid,user,pcpu,rss,etimes,comm,args`, kernel threads left
out) grouped by program and user: how many, CPU now, resident memory, the oldest one's age and the program with
its first words, 80 groups at most, biggest first. Interpreters are grouped by what they run (`python3 worker.py`,
`node server.js`, `java app.jar`), not by the interpreter. `src/instance_apps.ts` then sets the operating system
aside (systemd and its units, sshd, cron, the package managers, the shells and the probe's own utilities, the SSM
worker…), marks the platform pieces `infra` (containerd, dockerd, kubelet, the CloudWatch and SSM agents,
Fluent Bit, Datadog, node_exporter, Postfix…) and keeps the rest as `app`. Each program on each box is a row in
`instance_apps` with first and last seen and how many probes saw it; the graph has the same as
`(:AdvisorResource)-[:RUNS]->(:AdvisorApp)`.

**Monitoring.** The first probe of a box records its apps without comment. From the second on, a program not
seen before is an `appeared` event, one that was there and is not any more is `disappeared` (when it had been
seen on two probes or had run an hour, so a cron job seen once is not news), and one back after leaving is
`returned`. An `app` that had run for a day and vanishes raises an `app_gone` alert (warning, one open per box
and program) with the instance, the program, when it was last seen and how long it had run. The events live in
`instance_app_events` (180 days).

**Reading it.** The instance drawer on the Inventory page shows "Runs" (apps, then infra; "include what left"
adds the ones that are gone), the app events and "Ships logs to". `GET /api/instances/:id/apps` is the same;
`GET /api/apps` lists every program running anywhere with how many boxes run it (`?kind=app|infra`) or, with
`?name=`, where one program runs; `GET /api/apps/events` lists the events. The agent has `instance_apps`.
Instances probed before 1.6 have no process list until they are probed again.

The probe also reports where the box's log agents ship (`log_shipping`, see
[Log attribution](#graph-mirror-and-the-knowledge-graph)): the log group names found in the CloudWatch agent,
awslogs, Fluent Bit and Fluentd configs, in `/etc/docker/daemon.json` and on each running container's `awslogs`
log driver. Config files are read, never changed, and templated group names are skipped.

### Exposed ports and who serves them (probe 1.8)

The probe lists every port the box answers on: the listening sockets from `ss -Hlntup` (protocol, port, bind
address, the owning program and pid) and the ports the containers publish from `docker ps` (host port, container,
the port inside it), 80 of each at most. A host socket and the container behind it (docker-proxy on the host)
merge into one row that names both. Each row's **scope** says which interfaces it listens on (`all`, `loopback`,
one `address`) and `src/instance_apps.ts` matches the row to the app inventory (the container's name, or the
program by its name: `node` finds `node server.js`) and to the ingress rules of the box's security groups, read
from Steampipe on every inventory refresh (`aws_vpc_security_group_rule`, table `sg_ingress`). The result is the
port's **exposure**: `internet` (a rule lets 0.0.0.0/0 in and the box has a public IPv4 address, or ::/0 and it has
an IPv6 address), `network` (other addresses or a prefix list, or a world rule on a box with no public address),
`group` (other security groups only), `closed` (no rule lets it in: shown as "blocked by security group") or `local`
(loopback only). An IPv6-only rule on a box without an IPv6 address lets nothing in; the inventory records each
box's IPv6 addresses (`network.ipv6` in the snapshot) for that. Every port also carries the rules that let it in
(`allowed_by`: group name, ports, source, the rule's description) and a `reason` sentence, and a world rule that is
all traffic or wider than 1,000 ports is flagged `broad` (a banner on the box names the ports public only because of
it). The subnet's **network ACL** is checked as well (`aws_vpc_network_acl`, table `nacls`, refreshed with the
inventory; the subnet's own ACL, else the VPC's default): for every security group rule with a CIDR source, the
lowest-numbered matching entry decides, a narrow deny before a world allow is an exception (a blocklist does not
close a port), a world deny with narrower allows before it narrows the port to those networks, and because ACLs
are stateless the replies need an outbound entry to the client's ephemeral ports (40000, 55000 and 62000 are
sampled: Linux and Windows/macOS ranges). A port the groups let in but the ACL stops is `closed` with `blocked_by:
"network_acl"` ("blocked by network ACL" and the deciding rule in the UI); one where only some clients' replies get
out carries a `nacl_note`. The other direction is listed too: `unused_rules` are the rules that let nothing reach a listening port (a
hole without a reason, a leftover, or an IPv6 rule on an IPv4-only box). Rows live in
`instance_ports` with first and last seen; a port that appears or goes is a `port_opened` / `port_closed` event in
the app events under its owner's name, and a port open to the internet raises a `port_exposed` alert (warning)
when first seen, once while it stays open. The EC2 detail's "What runs" tab lists them under **Listens on**, the
`instance_apps` tool carries them (and `port: 443` answers where a port is open across the fleet), `GET
/api/ports` lists the fleet's open ports, and the graph holds `(:AdvisorCompute)-[:EXPOSES]->(:AdvisorEndpoint {kind: port})`
with `(:AdvisorApp)-[:SERVES]->(:AdvisorEndpoint)`. Update the SSM document to 1.8 (Settings › Permissions prints the
command) so the probe sends the section.

### Security groups and the Ports tab

The EC2 detail has a **Ports** tab (after Usage): every listening port in a table with what serves it, the interfaces it
binds, its reach (open to the internet, reachable from the network, from other groups, blocked by security group,
blocked by network ACL, this box only) and why, naming the rule with a link to its group; the rules that open nothing
on the box are listed under it. The Inventory has a **Security groups** tab (`src/security_groups.ts`, read with the
inventory: `aws_vpc_security_group`, `aws_vpc` for whether each VPC has IPv6, `aws_ec2_network_interface` for who
wears each group): every group with its VPC, its rules, the instances and other interfaces (databases, load
balancers, Lambdas, endpoints) using it and its flags (a broad rule, listening ports it opens to the internet, a
dormant IPv6 rule, unattached), the troubled ones first; a row opens the rules with what listens behind each.
`GET /api/security-groups`, `GET /api/security-groups/:id`.

An IPv6 rule cannot open anything in a VPC without an IPv6 block, so such ports read as blocked whatever the
instance snapshot says. The same rule is flagged, though, when it is dangerous the day IPv6 is turned on: all traffic
or a range wider than 1,000 ports from `::/0`, or a port the group does not open to `0.0.0.0/0` as well. Each such
group gets one recommendation (rule `sg_dormant_ipv6`, `security_fix`, tier approve, no saving) naming the rules,
the listening ports they would open and the revoke command; it is refreshed with every inventory and resolved when
the rule is gone.

### Clusters and the workloads inside them

The inventory reads every EKS and ECS cluster (`src/cluster_inventory.ts`, Inventory › Clusters). ECS comes from
Steampipe: clusters, services, task definitions, running tasks and container instances. EKS needs the Kubernetes API:
the advisor signs an EKS bearer token the way `aws eks get-token` does (a presigned `sts:GetCallerIdentity` carrying
the cluster name, `src/k8s_client.ts`) and lists Deployments, StatefulSets, DaemonSets, Jobs, CronJobs, Services,
Ingresses, NetworkPolicies and pods, read-only, over TLS pinned to the cluster's CA. The cluster has to know the
advisor's IAM identity: the Clusters tab shows each cluster's access status (readable, identity not mapped, mapped
but may not list, endpoint not reachable) and, for one it cannot read, the commands that grant read access, either
an access entry with the `AmazonEKSViewPolicy` or an `aws-auth` mapping bound to the `view` ClusterRole. A private-only
endpoint is reachable from inside the VPC only, where the swarm's advisor runs.

Every workload is one row with its containers and images, replicas desired and ready, the nodes its pods run on (by
owner reference through the ReplicaSet, or by labels), the Services that select it, the Ingresses that route to those
Services and the NetworkPolicies whose podSelector matches it. The graph (`src/graph_clusters.ts`) draws
`AdvisorCluster` nodes (with the control plane as an `api` endpoint and its public CIDRs as `REACHABLE_FROM` sources,
`requires_auth` true), one `AdvisorDeployment` per workload `RUNS_IN` its cluster, `BUILT_FROM` one `AdvisorImage` per
container image, `SCHEDULED_ON` its nodes, `EXPOSES` a `service_endpoint` per Service port and a `url` per Ingress host
and path, and `GUARDED_BY` the NetworkPolicies as `AdvisorFilter {kind: network_policy}` with their rules. An Ingress
or a LoadBalancer Service names the balancer AWS created for it; when that balancer is in the inventory its listener
`FORWARDS_TO` the endpoint and the listener's internet verdict is copied onto it, so "which workload runs the
vulnerable image and can the internet reach it" is one query inside a cluster too. Node groups are `PART_OF` their
cluster. `GET /api/inventory/clusters`, `GET /api/inventory/clusters/:arn/workloads`, `POST /api/inventory/clusters/refresh`.

### The network layer and reachability verdicts in the graph

The inventory also reads, every refresh, the network objects behind reachability (`src/network_inventory.ts`):
subnets, route tables, internet, NAT and egress-only gateways, VPC peerings and endpoints, Elastic IPs, every network
interface with its addresses and groups, and the security groups' egress rules (the ingress rules, VPCs, groups and
network ACLs were already read). RDS instances and ElastiCache clusters now carry their security groups in the
snapshot. The graph (`src/graph_network.ts`, rebuilt after every inventory and resource mirror) draws them as
`AdvisorNetwork` (VPC), `AdvisorSegment` (subnet, `public` when its route table sends the default route to an
internet gateway), `AdvisorRouteTable` with `ROUTES` edges, `AdvisorGateway`, `AdvisorInterface` (`ATTACHED_TO` its
instance, balancer, function or gateway, `WEARS` its groups, `IN_SEGMENT`), `AdvisorPublicIp`, and `AdvisorFilter`
(security groups and network ACLs) with one `AdvisorFilterRule` per rule or ACL entry and a `FROM` edge to the
`AdvisorSource` it admits (`internet`, `cidr:<range>`, `prefix:<id>`) or to the group it references. Resources wear
their groups directly too (`GUARDED_BY`).

On top of it the verdicts, so no agent query re-implements security group and ACL logic: every `AdvisorEndpoint` gets
`REACHABLE_FROM` edges to the sources that can reach it (with the rule and the ACL entry it passed in `through`),
`ALLOWED_BY` edges to the rules that let each source in, and `BLOCKED_BY` edges to what stops a source a rule would
otherwise admit (a network ACL entry, the ACL's implicit deny, or the groups themselves when no rule matches), plus
`exposure`, `reach_reason` and `reach_computed_at` on the endpoint. They are computed by the same code the Ports tab
uses (`reachOf`, `naclVerdict`) for instance ports (groups, public address, subnet ACL), balancer listeners (groups
and scheme; a balancer without groups admits what its scheme allows) and RDS endpoints (groups and
`publicly_accessible`), and refreshed per instance after each probe. The question "is this vulnerable sshd
reachable" is then one query: the box `EXPOSES` port 22 (its `process` says sshd), and the endpoint either
`REACHABLE_FROM` the internet or `BLOCKED_BY` something that says why.

The **Network** page shows the layer as the graph holds it (`GET /api/graph/network`, `/api/graph/network/:vpc`,
`/api/graph/filter/:id`, `POST /api/graph/network/sync` to rebuild): what is reachable from the internet and the rule
that lets it in, what a rule admits but something else blocks, every network with its segments, routes, gateways and
peers, and every filter with its rules and what wears it.

### Vulnerabilities: the installed software against the advisories

The software probe's inventory is matched against published advisories (`src/software_vulns.ts`), never against a
hand-written list, and the result is judged by reachability, the way the rest of the graph is:

- **Sources.** [OSV](https://osv.dev) for Ubuntu, Debian, Alpine, Rocky Linux and AlmaLinux: the batch API is asked
  about each distinct (distribution release, source package, exact version) the fleet has, under OSV's
  release-qualified ecosystems (`Ubuntu:24.04:LTS`, `Debian:12`, `Alpine:v3.19`). Amazon Linux is not in OSV, so
  AL2 and AL2023 use the core repository's `updateinfo.xml.gz` on `cdn.amazonlinux.com` (the feed `dnf updateinfo`
  reads; public, about 1.5 MB per release and architecture, re-read when its timestamp changes), matched by binary
  package with rpm's own version order (`src/alas_feed.ts`). RHEL, CentOS, Fedora and SUSE are reported as not
  matchable, with the reason, on the Security page.
- **Scores.** Ubuntu's and Debian's advisories carry no CVSS; the CVE they fix is read from OSV and lends its score
  and attack vector (`severity_from`). Amazon's `Important`/`Critical` words are kept and the CVEs add the score.
  Ubuntu and Debian publish both per-CVE records and the USN/DSA bundles that fixed several; when the per-CVE records
  exist the bundles are left out, so one hole is one row.
- **The verdict.** Each match is judged by what the affected program listens on (the apps probe's ports and their
  exposure through security groups and network ACLs): `critical` when the internet can reach it, `exposed` when the
  network or another group can, `mitigated` when it listens but is blocked, `local_only` when only loopback can or
  the attack needs local access, `affected` when it is installed with no listening program of its own (a library,
  the kernel, a tool). A package is tied to its program by name (`openssh` → `sshd`, `postgresql` → `postgres`, …).
- **Where it shows.** Security page › Vulnerabilities (grouped by advisory, worst verdict first, each box underneath
  with its version, the fixed version, the port and its exposure; "Match now" runs a scan); Inventory › EC2 › a box ›
  Software tab (its OS and kernel, the advisories matched against it with the verdict, every package with its source,
  searchable, the programs by version flag, the container images it runs, recent version changes, "Probe software now"). `GET
  /api/security/vulnerabilities`, `/api/security/vulnerabilities/:id`, `/api/instances/:id/vulnerabilities`,
  `POST /api/security/vulnerabilities/scan`. In the graph: `AdvisorPackage` nodes `INSTALLED_ON` the box,
  `KnVulnerability` nodes with `AFFECTS` edges and the `VULNERABLE_TO` verdict from the box (`docs/ontology.md` §1b),
  so "which boxes run a vulnerable sshd the internet can reach" is one query.
- **Cadence and cost.** `VULN_CRON` (default `40 4 * * *`, after the software probe) asks only about versions not
  asked about in the last 6 hours and reads only advisories not stored or changed since; the first scan of a fleet
  reads a few hundred advisories (about half a minute). Everything is cached in SQLite.

### Testing the probe

Prerequisites are on two sides. The instance needs the SSM agent online: the Inventory page's SSM column (or
`select instance_id, ping_status from <schema>.aws_ssm_managed_instance`) tells you which ones qualify; in the
example account most running instances do. The identity configured in Settings needs `ssm:SendCommand` on the
`AwsAdvisorProbe` document (which must exist in the instance's region) and on the target instances, plus `ssm:GetCommandInvocation`; without them the
probe returns `permission` naming the missing action and nothing else happens.

Three ways to run one:

1. **Inventory page**: open an instance, press Probe in the drawer. The result and the history appear under
   Utilisation.
2. **Recommendations page**: idle-instance items have a Probe button in the detail panel; the next collection
   run uses the result to adjust that rule's confidence and rationale.
3. **API**, for any instance id:

   ```
   curl -X POST localhost:9034/api/instances/i-0123456789abcdef0/probe     # runs the probe (10 to 20 s)
   curl localhost:9034/api/instances/i-0123456789abcdef0/metrics           # every stored probe for it
   ```

   The agent can do the same through the `aws_instance_probe` MCP tool when it wants to confirm an instance is
   idle.

A good result has memory total and used, one entry per mounted filesystem, the three load averages and the five
busiest processes by CPU and by memory. The script is fixed and read-only, so probing a production instance is
safe. Probes also run on the `PROBE_CRON` schedule (hourly by default) for the instances `PROBE_SCOPE` selects.

### Pools: Batch, Karpenter, EKS and autoscaling groups

An instance that a controller launches and terminates is a *pool member*, and the advisor reasons about the pool,
never about the member. `src/pools.ts` classifies every EC2 instance from its tags, deterministically:

| pool kind | tags | what it means |
|---|---|---|
| `batch` | `AWSBatchServiceTag`, or an ASG named `AWSBatch-<compute environment>-asg-…` | an AWS Batch worker: exists only while a job runs; idle CPU between jobs, a short life and a late SSM registration are all expected |
| `karpenter` | `karpenter.sh/nodepool` | Karpenter adds and removes the node with demand |
| `eks` | `eks:nodegroup-name` and variants | an EKS managed node group scales it |
| `asg` | `aws:autoscaling:groupName` | a plain Auto Scaling group replaces it |

The result is stored on `inventory_ec2` (`pool_kind`, `pool`) and in the snapshot with a one-line note, shown as a
badge on the Inventory page and in the detail's Identity group, and it reaches every decision maker:

- the **probe pass** skips Batch workers and any instance younger than fifteen minutes (Run Command is not ready yet
  even when the inventory already shows the agent Online);
- the **idle-instance rule** never proposes to stop or right-size a Batch worker, and the **Graviton rule** points at
  the compute environment's instance types and arm64 job images instead of the instance;
- **Jev** sees the pool in the role state, so a Batch worker is classified as `batch_or_worker` with the reason attached;
- the **agent prompts** (findings, incident, resolution, observe) carry the same operational patterns, read from
  the graph at dispatch (Concepts under "AWS Operational Patterns"): pool members are not individual candidates,
  new instances register late, autoscaling churn is normal; the `instance_inventory` MCP
  tool returns `pool_kind` and `pool`, and incident facts list the pool with its note;
- the **watcher** already summarises pool churn per day instead of alerting per instance.

### Containers and long-lived history

Probe version 1.2 adds a Docker section when the `docker` binary is present and the socket answers: a `docker`
object (`available`, `running`, `total`) and one `containers` entry per container (name, image, state, up time,
CPU %, memory bytes and memory % from `docker stats --no-stream`). Instances without Docker report
`available: false` and nothing else changes. The section only appears once the SSM document in AWS carries the
new script, so after upgrading run

```
aws ssm update-document --name AwsAdvisorProbe --document-version '$LATEST' \
  --content "$(curl -s http://localhost:9034/api/probe/document)"
```

(the setup script does this on a fresh install). The advisor keeps the data at three grains
(`src/history.ts`):

| table | one row per | kept |
|---|---|---|
| `instance_metrics` | probe (the full JSON) | 30 days |
| `container_samples` | container per probe (name, image, state, CPU %, memory) | 30 days |
| `instance_daily` | instance per day (samples, memory / disk / load average and max, containers running) | 400 days |
| `container_daily` | container per instance per day (running share, CPU and memory average and max; from probe 1.4 log lines, use signals, errors, restarts, last log and last signal, bytes moved) | 400 days |
| `instance_activity` | probe (probe 1.4: connections, front-door requests, logins, signal lines, counters) | 30 days |

The roll-ups are rebuilt for the last 31 days, today included, at the end of every probe pass, so a late probe still lands in the
right day; `POST /api/history/rollup?days=` rebuilds further back on demand. The EC2 drawer's utilisation charts
read the raw probes for the 24h / 48h / 7d windows and the daily tables for 30d / 90d (line = daily average, faint
line = daily max), and list the containers seen in the window with their running share and their average and
peak CPU and memory (`GET /api/instances/:id/history?days=`). Before the first roll-up the containers table
falls back to the latest probe. Container images also feed Jev's resource-role guess.


### RDS load profiles

Every probe pass also profiles every database in the inventory (`src/rds_load.ts`): each Aurora cluster once, each
standalone RDS instance by id, skipping any profiled within `PROBE_MIN_INTERVAL_HOURS`. A profile is fourteen days of
CloudWatch at five-minute resolution (I/O per day and what it costs on Standard storage, volume size, CPU,
connections, buffer cache hit ratio) plus three days of the Serverless v2 ACU curve at one minute, reduced to the
numbers that decide: the floor and the ceiling, the share of time at each, the bursts (count per day, length,
cadence: hourly, daily or irregular), the buffer cache at the average capacity and at the cap and whether the
database fits in it. Where Performance Insights is on, the top statements by load over seven days come with it;
the tail of the newest engine log gives the slow statements (Postgres `duration:` lines, MySQL slow-log blocks) and
the temp-file and checkpoint counts, with a note on the parameter to set when the log has none. Jev then classifies
the whole picture (purpose `rds_load`): the shape, what drives the I/O (cache-starved reads, writes, scans,
checkpoints), whether the capacity ceiling throttles it, whether the pattern is structural, and the first lever
(I/O-Optimized storage, a higher minimum capacity, a higher maximum, a query fix, an application cache, nothing).
The hourly pass re-asks Jev only when the profile's coarse hash changes or the answer is a day old.

The profile is what an RDS recommendation is judged against: `resourceFacts` in `src/resolve.ts` finds a cluster by
its id (the writer's inventory row plus the members) and carries the profile summary into the Jev gate and the
agent's prompt, the Aurora storage-tier rule cites it in its rationale and raises its confidence when Jev finds the
pattern structural, the MCP tool `rds_load` returns it, and the Inventory RDS detail and the recommendation detail
show it with a Refresh button (`GET /api/inventory/rds/:id/load`, `POST …/load/refresh`). It needs
`cloudwatch:GetMetricData`, `rds:DescribeDBClusters`, `rds:DescribeDBLogFiles`, `rds:DownloadDBLogFilePortion` and,
for the statements, `pi:DescribeDimensionKeys`; all in the recommended policy.

### The effect of a decision on the bill

Every actioned recommendation (approved, or marked done) is verified against Cost Explorer from seven days after
the decision (`VERIFY_CRON`, `src/verify.ts`): the daily cost of the lines the action moves (`costScopeFor` in
`src/verify_math.ts`), the median of the fourteen days before against the median of the days after (the decision
day and the next are mixed and skipped), scaled to a month and compared with the estimate. The daily series is
stored with the verdict, so the recommendation detail shows the bill's shape around the decision: the scope's cost
per day as bars, the decision day marked, the two medians as dashed lines and the whole bill as a thin line on its
own scale, with a Check now button for an early read (`GET /api/verifications/:id/impact`). The Overview's
"Impact of your decisions" card lists every actioned recommendation and every auto-action with what it claimed and
what the bill did.
Where the scope is account-wide (Aurora lines, EBS volumes, NAT bytes: resource-level cost data is off by default)
the chart says so; another change on the same lines moves it too.

## Inventory

The Inventory page is meant to replace the console for "what do we run, and which of it can we actually manage".
`src/inventory.ts` snapshots three kinds of resource with a handful of schema-qualified Steampipe queries (Lambda, load
balancers, EBS, S3 and Route 53 have modules of their own, below):

- **EC2** (`inventory_ec2`): id, Name tag and all tags, type, state, region and AZ, launch time, private and public IP
  and DNS, platform, architecture, AMI, key pair, instance profile, VPC and subnet, security groups, root device;
  joined with `aws_ssm_managed_instance` (ping status, platform name and version, agent version and whether it is
  current, last ping, IAM role; null when the instance is not registered with Systems Manager), attached EBS volumes
  from `aws_ebs_volume` attachments (list and total GB), the 30-day average of the daily maximum CPU and the number of
  days of data from `aws_ec2_instance_metric_cpu_utilization_daily`, the latest SSM probe from `instance_metrics`
  (memory used %, load, busiest process), the on-demand list price of the type, and how many open recommendations
  and alarm findings of the last run mention the instance.
- **RDS** (`inventory_rds`): identifier, class, engine and version, Multi-AZ, storage type and GB, status, region,
  created, cluster, endpoint, 30-day CPU from `aws_rds_db_instance_metric_cpu_utilization_daily`, list price (instance
  hours only; Aurora I/O-Optimized picks the matching rate, `db.serverless` has none), recs and findings counts.
- **ElastiCache** (`inventory_elasticache`): cluster id, node type, engine and version, node count, status, region,
  created, replication group, list price (node price x nodes), recs and findings counts.

The EC2 detail opens under its row in four tabs, every fact once: a header (name, state, SSM, pool, type, region,
the watch and auto-park switches), a glance strip (list price, 30-day CPU, memory, fullest disk, last real use,
quiet hours a week, storage), then **Overview** (identity, network, storage, Systems Manager, role, tags), **Usage**
(the hour-of-week profile with the signals that tripped each busy hour, the activity block, the typical values,
the charts, the probes), **What runs** (processes, apps, one containers table with now and 30 days), **Logs** (the
groups the box ships to, by agent or container, with retention, size and ingestion from the logs refresh:
`GET /api/instances/:id/logs`) and **Links & history** (DNS records, balancers in front, recommendations, findings,
the graph, the timeline).

Each row keeps the denormalised columns used for filtering and sorting plus a `snapshot` JSON with everything, and
`first_seen` / `last_seen`. A resource the refresh no longer sees keeps its `last_seen` and gets `gone = 1`, so
terminated instances remain visible as history ("include gone" on the page). The refresh runs at the end of every
collection run and after every watcher sample (it is a few cheap queries; the SSM status is therefore never older
than `WATCH_CRON`), and by hand with `POST /api/inventory/refresh` or the "Refresh now" button. The Route 53 links
(below) ride along with the run and the button only: they read every zone's records and one URL config per Lambda function.

Prices come from the same pricing SQL the MCP `price_lookup` tool uses (`src/prices.ts`) and are cached in the
`prices` table by kind, SKU, region and engine (Linux / Windows for EC2, engine plus Multi-AZ or I/O-Optimized for
RDS, engine for ElastiCache); a refresh only asks the price list for SKUs missing or older than seven days. The
monthly figure is hourly x 730, the list price, not the invoice: reservations and Savings Plans are not applied.

Endpoints: `GET /api/inventory/summary` (running / stopped, SSM online / lost / not managed, monthly on-demand price of
running instances, EBS GB, and the RDS and ElastiCache equivalents), `GET /api/inventory/ec2?state=&ssm=&q=&sort=&gone=`
(`ssm` = `online`, `lost`, `unmanaged` or `managed`; `sort` a column name, `-` prefix for descending),
`GET /api/inventory/ec2/:id` (full snapshot plus that instance's findings, recommendations and probe history),
`GET /api/inventory/rds` and `GET /api/inventory/elasticache` (`q`, `sort`, `gone`), `POST /api/inventory/refresh`.
The agent gets the same data through the `instance_inventory` MCP tool.

### Lambda

The Inventory page has a Lambda tab (`src/lambda_inventory.ts`, `GET /api/inventory/lambda`, refreshed with the
rest of the inventory): every function with its runtime, memory, architecture and timeout, 30 days of
invocations, average duration and errors from CloudWatch, the GB-seconds that follow, and the monthly cost at
list (GB-seconds at the architecture's rate plus requests). The detail shows the arithmetic, what the bill
applies on top (the Compute Savings Plan discount and the free tier), and what the function would cost on
arm64. The knowledge graph's `lambda:<name>` systems read the same table. The account's 30-day GB-seconds from
the metrics match Cost Explorer's usage line within a percent.

### EBS volumes

The EBS tab (`src/ebs_inventory.ts`, `GET /api/inventory/ebs?q&sort&gone`, refreshed with the inventory) lists
every volume with its type, size, provisioned IOPS and throughput, state, the instance and device it is attached
to, and the price at list (`ebsMonthlyCost`: GB-month by type, plus provisioned IOPS above the gp3 baseline of
3,000 and throughput above 125 MiB/s, or the io1/io2 IOPS rate). Against that it puts 30 days of the volume's
own read and write ops from the daily CloudWatch tables: the average IOPS is the month's total divided by its
seconds, the peak the busiest single sample (the table's `maximum` scaled by its sample period). The detail
shows the share of the provisioned IOPS actually used and flags gp3/io volumes provisioned above 3,000 IOPS
whose 30-day peak stays under 30 % of it. Unattached volumes and gp2 volumes (gp3 is cheaper and faster) are
counted in the tiles.

### S3 buckets

The S3 tab (`src/s3_inventory.ts`, `GET /api/inventory/s3?q&sort&gone`, `POST /api/inventory/s3/refresh`,
refreshed daily after CloudTrail in `LOGS_CRON` because it is slow) lists every bucket with its region,
versioning, lifecycle rule count, and the storage held per class from the `BucketSizeBytes` CloudWatch metric
(published once a day per bucket and class; one `ListMetrics` per region finds which classes each bucket has and one `GetMetricData` call fetches them all, so the pass takes seconds; the newest point of the last three days is used) plus the object
count, priced at the list GB-month of each class (`S3_CLASS_PRICE`: Standard 0.023, IA 0.0125, Glacier
Instant 0.004, Deep Archive 0.00099 and the rest). The detail shows the class split and what moving the Standard
part to IA would save. Every hydrated column of `aws_s3_bucket` is a separate S3 call with its own permission,
so a denied one (`s3:GetBucketVersioning`, `s3:GetBucketPolicyStatus`, `s3:GetLifecycleConfiguration`) drops
that column and the refresh continues, reporting the missing action; the affected fields show as unknown rather
than as zero.

### Load balancers

The Load balancers tab (`src/elb_inventory.ts`, `GET /api/inventory/elb?q&sort&gone&kind&scheme`, refreshed with the
rest of the inventory, after EC2 so targets resolve against the rows just written) lists every ALB, NLB, gateway and
classic load balancer with what it fronts and what reaches it:

- **Targets, resolved.** Each target group with its targets: an `instance` target by id, an `ip` target matched to
  the instance that owns the private address, a `lambda` target by function ARN, each with its health and the
  reason when unhealthy. A classic balancer's registered instances are shown as one group. The row links every
  instance, and an instance's own detail lists the balancers in front of it ("Behind", `load_balancers` on
  `GET /api/inventory/ec2/:id`).
- **Owners.** The Elastic Beanstalk environment that made the balancer (from its `elasticbeanstalk:environment-name`
  tag: Beanstalk owns it, change it through the environment), the autoscaling groups attached to its target groups
  or, for a classic balancer, to its name, and the ECS services that register into it.
- **Listeners** (port, protocol, certificates, default action), scheme, state, VPC, zones, security groups, tags.
- **Traffic, 30 days**, from CloudWatch in one `GetMetricData` per region: requests and processed GB for an ALB,
  peak active flows and GB for an NLB, GB for a gateway balancer, requests for a classic one. A balancer with no
  datapoint publishes nothing, which is what an unused one looks like.
- **Price**: the fixed hourly list price × 730 (16.43 USD for an ALB or NLB, 18.25 classic, 9.13 gateway); the
  LCU-hours (ALB, NLB) or per-GB (classic) part scales with traffic and is left out, and the detail says so.
- **Domains**: the Route 53 records that lead to the balancer, from the Route 53 links below.

The agent reads the same table through the `load_balancer_inventory` MCP tool (with `instance_id`: the balancers in
front of one instance), and the graph carries every balancer as an `AdvisorLoadBalancer` (id = ARN) that `EXPOSES` one
`AdvisorEndpoint {kind: listener}` per listener, each with a `FORWARDS_TO {target_group, health}` edge to the instance port
endpoints behind it (or a function's invoke endpoint for a Lambda target).
Rows keep `first_seen` / `last_seen` and `gone` like the other tabs.

### Usage profiles

When is a box used, and when is nobody there? `src/usage_profile.ts` folds the last 28 days into the 168 hours of
the week for every running standalone instance (pool members belong to their controller) and for every
autoscaling group behind a load balancer (subject `asg:<name>`), and asks, per hour and per week, whether
anything happened:

- **CloudWatch**, every hour the instance ran: the hour's maximum CPU under 10 % and the bytes in and out under
  5 MB; for a group, its average CPU and, when an ALB fronts it, the requests that hour.
- **The shipped logs**: one Logs Insights query per box over the CloudWatch log groups it ships to (probe 1.6
  `log_shipping`), over the last `USAGE_LOG_DAYS` (7), counting the use-signal lines per hour with the same
  patterns the probe uses, the kinds ruled noise for the shipping container's image left out. Log evidence for
  every hour of that week, not only the hours a probe ran in; a use-signal line makes the hour busy. Costs the
  scan, about 0.005 USD per GB; 0 turns it off.
- **The probes** that fell in the hour (`instance_activity`, `container_samples`): no established external
  connection, no use-signal line, no front-door request and no login in the last hour, nobody logged in, no
  container above 5 % CPU. The use signals already pass the per-image noise rules, so a heartbeat log is not use;
  whether *any* log line was written is kept (`logs`) and shown, but does not by itself make an hour busy.

An hour of the week is **quiet** when every week we saw it was quiet (at least three), **busy** when any week
was, **unknown** otherwise. Quiet hours in a row make a window; a window keeps an hour of margin on each side
(people work late, boxes take a minute to come back), so a four-hour run is a two-hour stop. A window's
confidence is the weeks behind it and how much of it the probes covered: CloudWatch alone says "not busy" and
tops out at 0.6, the probes say "not used", and only both together reach 1. A group's members come and go, so a
group is measured as a group, never through a member: its CPU by `AutoScalingGroupName`, and its balancer's
request count is the use evidence that lifts its confidence (a group with no balancer stays at 0.6). The group
profile is shown on its balancer's detail in the Load balancers tab. From the busy hours the profile
says, per busy hour, which signal tripped it (network over 5 MB/h, CPU over 10 %, balancer requests, a probe
signal), in the summary and in the cell's tooltip, so a box that is "busy" only because something ships 2 GB an hour
is read for what it is. It derives the smallest `advisor:schedule` value (UTC) that keeps the box up whenever it was ever used, one window a
day over the days that have any use, a day with none off; a box used around the clock gets none, a box never used
is a parking case, not a schedule.

The EC2 detail shows the profile as a heat grid (green quiet, amber busy, grey unknown) with the windows, the
busiest hour and the suggested tag, and a "profile now" button. The daily logs job computes them
(`GET /api/usage`, `POST /api/usage/run`, `GET /api/instances/:id/usage`, `POST /api/instances/:id/usage/refresh`),
files a tier-approve `usage_schedule` recommendation when the confidence reaches 0.85 and the schedule leaves the box
off 20 h a week or more (approving it puts the tag on, see [Auto-actions](#auto-actions-the-executor); a box tagged
`AdvisorAutoPark=ON` needs none, the office-hours action reads its schedule directly), and
writes the result on the graph: `usage_quiet_hours_week`, `usage_confidence`, `usage_schedule`,
`usage_off_hours_week`, `usage_est_usd_month`, `usage_quiet_windows` and `usage_summary` on the instance's
`AdvisorResource` or the group's `AdvisorNodePool`. The Beanstalk capacity action reads the group profiles to
lower a group's minimum for the quiet hours and raise it back before the busy ones.

#### The usage review: Jev decides the window

The profile is arithmetic and cannot weigh what a person would: that the external connections at every probe
are relay peers and the swarm checker, that one 39 % hour four weeks ago was a deploy, that 86 % memory on a
swarm box is Docker holding what it was given, that the role makes the box protected. So once a day, after the
profiles, `src/usage_review.ts` hands Jev (purpose `usage_review`) every EC2 profile with its context: the quiet
windows and what tripped the busy hours, the latest activity with the peers behind the connections, the last two
weeks of daily roll-ups, the containers with their logs and use signals, the role, the tags, the executor rows
and the team's decisions on the box, plus a set of candidate windows (the profile's own, a wider one with an
extra hour of margin, a weekdays-only one, and keep running). Jev picks one and answers two typed questions:
are the quiet windows real non-use rather than a measurement gap, and is what made the busy hours busy machine
chatter rather than people. The verdict (`confirm`, `adjust` or `keep_running`, with the window, the confidence
and a reason) is stored in `usage_reviews`, shown on the profile as "Agent's decision", and mirrored to the graph
(`usage_review_*` on the node). A pick Jev is unsure of, or one whose quiet windows it doubts, becomes
keep_running.

**The executor follows the review.** For a box tagged `AdvisorAutoPark=ON` the office-hours action takes Jev's
window when the verdict is confirm or adjust, leaves the box running on keep_running, waits when there is no
review yet, and falls back to the profile's own window only when Jev is not configured. Memory is never a usage
signal anywhere in this chain.

**The agent, for the boxes Jev is not sure about.** When Jev's pick is under 0.75, or its answer on whether the
quiet windows are real sits between 0.3 and 0.7, the box goes to a real agent run (task `usage`, `tasks/usage/`,
`src/usage_agent.ts`): the same brief plus the candidate windows and Jev's doubt, and the tools to go and look
(`instance_apps`, `activity_signals`, `instance_history`, `cloudwatch_metric`, `instance_probe`, `log_groups`,
`domain_inventory`, `load_balancer_inventory`, `recommendation_history`, `auto_actions`, `graph_query`). It answers
with explicit windows: for an instance `safe_off_windows` (days, start and end hour in UTC, whether it is
certain, and why), for a group `downsize_windows` in the same shape plus `group_min_size` and `group_max_size`
(fewer machines that still do the job in the busy hours, judged by CPU and requests per member), its confidence,
the reasoning, evidence with numbers and, per busy stretch, the cause and whether that was people. Only certain
windows count, and only those at least `USAGE_MIN_OFF_HOURS` (4) long: a box off for twenty minutes saves nothing
and costs a restart; the agent may set `min_off_hours` to a better number for one box when the evidence supports
it (a slow boot, a DNS TTL). The windows become an off schedule ("off weekdays 01-06 UTC | off weekends 00-24 UTC";
see below), the answer is graded by the task's rubric, stored in `usage_investigations`, shown on the profile, and
becomes the box's decision (model `agent:…` in `usage_reviews`) so the executor follows it: the office-hours action
stops the box in those windows, and the Beanstalk capacity action runs the group at its floor in them and moves
the configured minimum and maximum to the agent's bounds (inside the tag's band). An
answer below the rubric's bar keeps the box running and says so. The daily pass sends at most
`USAGE_AGENT_MAX_PER_DAY` (5) boxes, the least recently investigated first, none twice within a week, under the
agent quota; "investigate with the agent" on a profile sends that box now (`POST /api/instances/:id/usage/investigate`,
`POST /api/usage/investigate` for every unsure box).

On demand: **Recompute usage + ask Jev** on the EC2 tab runs the profiles and Jev's typed review for every box
(no Claude agent run), and **Send unsure boxes to the agent** dispatches one Claude agent run per unsure box
(`POST /api/usage/investigate`); "Recompute usage + ask Jev" runs the profiles and the review for every box
(`POST /api/usage/recompute`); "ask the agent" on one profile asks for that box (`POST /api/instances/:id/usage/review`);
`POST /api/usage/review` reviews all without recomputing.

### Route 53: domains linked to resources

The Route 53 tab (`src/route53_inventory.ts`, `GET /api/inventory/route53?q&sort&gone&zone&link&type`,
`GET /api/inventory/route53/zones`, `POST /api/inventory/route53/refresh`; refreshed at the end of every
collection run and by the Refresh button, not by the half-hourly watcher) lists every hosted zone and every
record in it, and follows each record to what serves it inside this account:

- an **alias or CNAME** to a load balancer (`aws_ec2_application_load_balancer`, `..._network_...`, `..._classic_...`)
  links the balancer *and the instances behind it* (target groups' instance and IP targets, the classic balancer's
  instance list); to a CloudFront distribution, the distribution and its origins, resolved one hop further (an S3
  bucket, a balancer and its instances); to an RDS instance or Aurora cluster endpoint, an ElastiCache node,
  configuration or replication-group endpoint, an EC2 public or private DNS name, a Lambda function URL, an API
  Gateway custom domain, an S3 website endpoint (the bucket in the host, or the record's own name for the plain
  `s3-website-<region>.amazonaws.com` alias), or another record in the account's zones (an apex alias to `www`,
  a CNAME chain), which is followed in turn;
- an **A / AAAA address** is matched against Elastic IPs (to their instance, or through the network interface to a
  NAT gateway or a balancer), instance public and private addresses, and every network interface's addresses
  (an RDS, ElastiCache, Lambda, container or VPC endpoint interface is named by its description). An address
  nothing here holds is checked against AWS's published EC2 ranges (`ip-ranges.amazonaws.com`, fetched once a
  day and kept in `settings`): inside them it is **unmatched**, a terminated instance's or a released Elastic
  IP's address that the record still serves, with the region; outside them it is external;
- an alias to an **Elastic Beanstalk** environment's CNAME (`aws_elastic_beanstalk_environment`, needs
  `elasticbeanstalk:DescribeEnvironments`) links the environment and follows its endpoint to the balancer and
  instances behind it;
- **NS, SOA, MX, TXT, CAA** and the other records that name no resource are classified for what they are: zone
  delegation, mail (SES inbound, or the provider), SPF, DMARC, ACM certificate validation, SES DKIM and
  verification, ACME challenges, ownership verification.

Record names come back from Route 53 with octal escapes (`\052` for `*`); they are decoded, so a wildcard
shows as `*.example.com`. Each record gets a `link_state`: **linked** (a resource here, with `links` listing them, hop 1 the direct target,
hop 2 what it fronts), **unmatched** (an AWS-hosted name this account does not have, `*.elb.amazonaws.com`,
`*.cloudfront.net`, an S3 website bucket that does not exist...: deleted, so a dangling record that an S3 or ELB
name lets a stranger claim, or a resource in another account, which the advisor cannot see), **external**
(outside AWS, with well-known providers named: Cloudflare, Netlify, Vercel, Heroku, Google, Shopify...), or
**none**. The tiles count them; the filters pick a zone or a state; the detail shows the values, routing policy
(weight, failover, geolocation, latency, set identifier), health check and the chain of resources, each linked to
its inventory row. The other way round, every EC2, RDS, ElastiCache, Lambda and S3 detail has a **Domains** group
with the records that reach it, directly or via a balancer or distribution (`GET /api/inventory/route53/resource/:kind/:id`;
the list endpoints carry `domains` per row). The agent gets the same through the `domain_inventory` MCP tool.

Zones are priced at list: 0.50 USD a month each for the first 25, 0.10 after, plus 0.40 USD per million queries
from 30 days of the `DNSQueries` metric (us-east-1; alias queries to AWS resources are free, so the figure is a
ceiling). The index is built from the inventory tables already refreshed (EC2, RDS, S3, Lambda) plus a dozen
Steampipe lookups (`aws_vpc_eip`, `aws_ec2_network_interface`, the balancer and target group tables,
`aws_cloudfront_distribution`, `aws_rds_db_cluster`, `aws_elasticache_cluster` and `_replication_group`,
`aws_lambda_function` URL configs, `aws_api_gateway_domain_name` and `_v2_`); each lookup fails on its own, so a
missing permission drops one kind of link and reports the action, never the refresh. The resolver is pure
(`resolveRecord`, `makeResolver`) and `src/__tests__/route53.test.ts` walks every kind of target.

### Playbooks and the Graviton rule

A finding such as "X is not using Graviton processor" says what is wrong, not what to do. `src/playbooks.ts` is the
catalog of what to do: one playbook per control that raises alarms here (every AWS Thrifty control seen in this
account, the four CloudWatch / Route 53 / API Gateway ones the benchmarks can raise, the advisor's own `query.*`
controls, and the two rules without a control behind them, `rule.aurora_storage_tier` and `rule.enable_flow_logs`).
Each carries `meaning` (what the alarm actually says), `act_when`, `ignore_when`, numbered `steps` with the real
commands, `saving` (the formula in words), a `tier` (`auto` reversible, `approve` needs a human, `report` never
automate) and an `effort` (`low`, `medium`, `high`). They are written the way a senior engineer would brief a
colleague: the Graviton one says Lambda is a one-line architecture switch unless a dependency ships x86-only native
code, RDS is a class change to the g-suffixed family with a restart in the maintenance window, and EC2 is a rebuild
from an arm64 AMI where every binary and image needs an ARM build, with Kubernetes pools handled at the node group /
Karpenter level and hand-built boxes by launching a replacement next to the old one. The reservation playbooks note
that RDS and ElastiCache reservations are owned by the member account and show up in the `query.commitments` list.

- `GET /api/playbooks?run_id` → `{ run_id, count, playbooks: [{ ...playbook, findings }] }` with the number of
  alarms each control raised in the run (default the last completed one); `GET /api/playbooks/:controlId` one playbook.
- `GET /api/findings` carries `playbook: { control_id, title, tier, effort } | null` on every entry of `controls`.
- UI: on the Findings page every control in the filter and every row has a "How to act" affordance (the control's
  title or the info icon) that opens a sticky panel with the playbook; a Playbooks section at the bottom lists every
  playbook with its tier, effort and the finding count of the run. The Recommendations detail shows the playbook's
  steps under "How to do it" when the recommendation names its playbook (`evidence.playbook`) or its rule maps to one.

**The Graviton rule** (`graviton_migration` in `src/rules.ts`) turns the three Thrifty graviton alarms into
recommendations with a real saving. `src/graviton.ts` holds the ARM type map (EC2 m5/m6i/m7i/m4 → m7g, c5/c6i/c7i →
c7g, r5/r6i/r7i → r7g, t3/t3a/t2 → t4g, i3 → i4g, x1 → x2gd, same size suffix; RDS db.m5/m6i → db.m7g,
db.r5/r6i → db.r7g, db.t3 → db.t4g; unknown or already-Graviton families give null) and the saving math
`(current hourly − ARM hourly) × 730`. `src/graviton_facts.ts` gathers the facts once per run: the instance type,
platform, state and tags (Steampipe, inventory as fallback), both SKUs' on-demand prices through the shared 7-day
price cache (`ensurePrices`, engine and Multi-AZ / I/O-Optimized label for RDS), the Lambda functions' `architectures`
from `aws_lambda_function` and their cost from `aws_cost_by_resource_daily` (one query for the whole service, since
each Cost Explorer request costs 0.01 USD; 14 days scaled to 30). The collector passes them to `buildRecommendations`
as `ctx.graviton` and logs every skip: a type with no ARM twin (g4dn, m8i), a stopped instance (nothing to save until
it runs), a price the list does not know. EC2 is tiered by the resource's role (`resource_roles`; the graviton
instances are added to the run's Jev classification batch): `k8s_node`, or EKS / Karpenter tags, → `approve` with a
node group / NodePool and multi-arch image rationale; `web_or_api`, `batch_or_worker`, `dev_or_test`,
`cache_or_queue`, `bastion_or_vpn` → `approve` with the AMI rebuild caveat; `blockchain_node`, `database`,
`ci_or_build`, `unknown` or no role → `report` ("needs an ARM build audit"); protected (Jev or the name regex) →
`report`. RDS is `approve` with the class prices; Lambda is `approve` with 20 % of the function's monthly cost, or a
null saving with the reason when resource-level cost data is not available. The fingerprint is
`graviton_migration:<resource>`, every rationale ends with the playbook's steps in one sentence and the evidence carries
`{ playbook, current_sku, target_sku, prices }`.

### The adapter boundary and the account scope

Everything provider-specific sits behind `src/adapters/` (`types.ts` is the contract, `index.ts` the registry, `aws/`
the one adapter today). An adapter owns its credentials and accounts, its collection, its storage (the SQLite tables it
fills, listed on the adapter) and emits the generic model: resource nodes from its storage and the graph layers it
writes; the mirror core, the rules, the executor and the pages read the generic shape. `GET /api/providers` lists the
adapters (configured or not, with their Settings sections) and the providers the advisor knows but cannot collect from
yet. The sidebar's "Looking at" picks the account scope: every read carries `?account=<id>` and the inventories,
clusters, cost findings, security findings, recommendations, alerts, changes, runs, network and the Overview narrow
to it (rows stored before the inventory recorded account ids belong to the primary account; recommendations and alerts
are attributed through the resource they name, the details a rules pass wrote or the run that proposed them, and
stamped with the account once). Under one AWS account the Overview shows that account's recommendations, alerts,
inventory and findings count, and its own months from Cost Explorer's per-account view (`spend_by_account_monthly`,
unblended, refreshed with the daily spend); the daily spend, the service breakdown and the invoice figures stay the
payer's consolidated bill and are labelled "whole organisation" when members are registered. The daily review, the
open alerts list and the Impact card (`GET /api/review`, `/alerts`, `/verifications`) narrow the same way; the morning
observation is the agent's read of the whole fleet. Overview › Accounts is the view across accounts
(`GET /api/accounts/overview`): under one account it lists that provider's family (an AWS parent with its members),
under "all accounts" every provider.


### Vercel

The second adapter (`src/adapters/vercel/`). Settings › Accounts › Add account › Vercel takes a read-scope token and,
for a team, the team id; the token is tested against the API, saved as a runtime secret (`VERCEL_TOKEN`,
`VERCEL_TEAM_ID`) and never shown again. Every 30 minutes (`VERCEL_CRON`) the adapter reads the projects with their
framework and Node version, the latest deployments, the domains, the names of environment variables (never values)
and the firewall state, and mirrors them: a project is an `AdvisorDeployment`, each URL it serves an `AdvisorEndpoint`
reachable from the internet with `requires_auth` taken from the project's deployment protection (Vercel login,
password or trusted IPs, per target), the runtime an `AdvisorPackage`. The account's Projects section shows all of it;
`GET /api/vercel/projects`, `GET /api/vercel/stores?kind=`, `POST /api/vercel/refresh`, `POST`/`DELETE /api/accounts/vercel`.
Usage is read from `/v2/usage` per type and day (requests with cache hits, bandwidth, function invocations by
outcome and GB-hours, builds, blob, cron, data cache, log volume) with Vercel's per-project breakdown: the team's
Overview shows the last week and month, a daily series and a per-project table, and flags error rates, throttles,
timeouts, failed builds and a cold edge cache; the project nodes carry `usage_*_7d`.
Billing is read from Vercel's invoices (`GET /v1/invoices`: totals, status, the groups and line items, with the
marketplace stores such as Neon billed through them) and from the team's subscription (plan, seats and their price,
the current period): the Overview for the team shows the last invoice, the average of the last three, the
subscription and the current period; the accounts table shows the last paid invoice as the team's spend.
This month for a Vercel team (`GET /api/vercel/bill`, `ui/src/components/vercelBill.tsx`) is the bill page the
sidebar opens when it looks at the team: the subscription and where the period stands (day n of 30), the estimate
for the period (subscription plus what infrastructure usage cost on the last three invoices, since Vercel has no
cost-to-date endpoint), the metered usage since the period started with a daily series and the per-project split,
every invoice with its groups and line items (click a row), and the team's own unit prices (amount over quantity on
the last paid invoice). Each project in Inventory › Deployments opens a detail panel (`GET /api/vercel/projects/:id`,
`VercelProjectDetail` in `ui/src/components/vercel.tsx`) with the depth an instance gets: repository, latest
deployment, protection, firewall and Secure Compute, the URLs it serves and the stores it uses, its last 30
deployments, domains, env variable names (never values), and its own usage (requests, invocations, errors,
bandwidth, builds for 7 and 30 days with a daily series; read per project from `/v2/usage?projectId=`, so exact
where the team-wide split is whole percent).
The stores get the same depth. Each store row under Databases, Caches and Object storage carries what the store
object says: a Neon database's compute hours this billing period as Neon reports them to Vercel, its project id at
Neon and whether Neon Auth is on; a Redis store's high availability and storage type; a Blob store's size, object
count, access and whether its token expired; for all of them the plan with its price lines and quotas ("$0.106 per
CU-hour", "30 MB"), the partner's status, the secret names it injects (never values), and the projects on it with
the variables each gets. Clicking a store opens its detail (`GET /api/vercel/stores/:id`) with those, the blob
store's daily requests from Vercel's per-store breakdown, and what the store costs at its plan's listed rates at
this period's pace. The Overview adds the stores in numbers (blob GB and objects, database compute hours, the cost
at their plans), the team's people (members, owners, how many without MFA) and its log drains (where logs go, which
projects they cover); a member without MFA, a project no drain covers, an expired blob token, a store over quota or a
production database on a free plan land in the attention list. Project detail shows what the project costs at the
team's listed rates for its last 30 days of metered usage, before the plan's included allocation, and which drains
keep its logs.

Vercel's prices are pricing knowledge in the graph, the same shapes AWS fills from its pricing API
(`src/adapters/vercel/pricing.ts`, the layer "vercel pricing knowledge and systems", `GET /api/vercel/rates`, the
"Your rates" card on This month). The team object lists every metered item with its price in cents per unit; the
advisor stores them in dollars with the unit the item is priced per and writes one `KnSystemType {kind: usage,
source: team_billing}` each (function invocations, GB-hours, edge requests, data transfer, build minutes, blob, log
volume, ...), one `KnSystemType {kind: plan}` for the Pro plan (seat price, base fee, included usage), one type per
price line of each marketplace plan a store is on plus a plan type carrying the quotas as `included`
(`source: marketplace_plan`), and one `KnSystemType {source: invoice}` per line the last paid invoice charged
(amount over quantity: the observed price next to the listed one). `KnPricingOverlay {kind: plan}` nodes for the
team's subscription and for each store's plan COVER those types. Every project is a `KnSystem {kind: deployment}`
and every store a `KnSystem` of its kind, MEMBER_OF from the resource, RUNS_ON the usage types with the quantity
and the cost at list: the project's `monthly_list_usd` is its last 30 days priced at the team's rates, the store's is
its marketplace usage (Neon compute hours) or blob size at the plan's rate; the resource nodes carry the same number
as `monthly_usd`, so "what does this project cost" is one hop for the agent, on Vercel as on AWS.

The agent is told all of this. The MCP fact server's instructions name every account the advisor is pointed at
(the AWS account as the default for the aws_* tools, the Vercel team for `vercel_projects`, `vercel_stores`,
`vercel_bill`, the vercel.* Steampipe tables and the graph tools with the team id as `account`); the graph schema
summary that `graph_query` carries describes the Vercel shapes (the project as an `AdvisorDeployment` with its
protection, usage and cost, its URL endpoints with `requires_auth`, the stores it `USES`, the log drains it
`SHIPS_LOGS_TO`) and the pricing knowledge (`KnSystemType` by source, `KnPricingOverlay` plans, `KnSystem` per
project and store priced line by line); `graph_systems` and `graph_log_groups` take an `account`. The general chat
brief names the Vercel team in a few numbers next to the AWS account whenever a token is saved, and the chat
prompt says the graph holds every provider in one model.

Log drains are the team's log layer, in the shape CloudWatch groups have: one `KnLogGroup {native_type:
log_drain}` per drain with the host it delivers to (never the URL with its token), sources, environments,
sampling, the team's metered log volume split evenly across its enabled drains and priced at the team's
`logDrainsVolume` rate; `SHIPS_LOGS_TO` from every project system the drain covers, from the team account when it
covers them all, and from the project resource itself. There is nothing to attribute: a drain names its projects.
Knowledge › Logs shows the drains when the sidebar looks at the team, and a project no drain covers is in the
Overview's attention list.

What the partners behind the marketplace stores know is read with their own keys (Settings › Accounts › Vercel ›
Partners; `NEON_API_KEY`, `REDIS_CLOUD_API_KEY` + `REDIS_CLOUD_SECRET_KEY`, runtime secrets tested against the
partner's API before they are saved, `src/adapters/vercel/partners.ts`). With a Neon key each Neon store carries
what Neon says about its project (the store's `external_id`): storage, branches and which are protected, the
compute endpoints with their autoscaling range, state, suspend timeout and last activity, the databases, the
consumption this period (compute and active hours, data written and transferred), the history retention and the IP
allow list. With Redis Cloud keys each Redis store (matched by name on the account, Pro and Essentials
subscriptions alike) carries memory used against its limit, persistence, replication, eviction, throughput, the
Redis version, the public endpoint, TLS and the source IPs allowed to connect. The numbers land flat on the store
node (`pg_version`, `storage_gb`, `branches`, `compute_min_cu`, `suspend_timeout_s`, `memory_used_pct`,
`persistence`, `source_ips`, ...), the partner's own compute hours override the ones Vercel relays (kept as
`compute_hours_relayed`), and the store's network endpoints become `AdvisorEndpoint {kind: service_endpoint}`
nodes `REACHABLE_FROM` the internet with `requires_auth` and `restricted_to` (the IP allow list or source IPs), the
same shape a port on a box has. The attention list gains Redis memory above 80% of its limit, a public Redis
endpoint open to any source IP, a production cache without persistence, a Neon compute that never suspends, a
production Neon with no IP allow list, and a project with more than ten branches. Passwords and connection URIs
never leave the fold: the snapshots keep hosts and names only.

What the advisor notices about the team is a finding, and the actionable ones are recommendations, the same way
AWS findings and rules work (`src/adapters/vercel/rules.ts`). Every collection ends with a rules pass: a run row
with `provider: vercel` and the team as its account, one finding per control and resource (`vercel.control.*`:
a failed production deployment, preview URLs open to anyone, an unverified domain, the firewall off, a member
without MFA, a project no log drain covers, an unconnected store, a store over quota or unhealthy at the partner,
an expired blob token, a free plan in production, function errors, throttles and timeouts, failing builds, a cold
edge cache, and with the partner keys a Neon compute that never suspends, a Neon database without an IP allow
list, many branches, Redis memory near its limit, a Redis endpoint open to any address, a production cache without
persistence), and a recommendation in the shared table for the ones a person can act on, with the tier (approve
or report, never auto: there is no Vercel actuator), the confidence, the rationale and the evidence, and a saving
where one can be estimated (idle Neon compute hours at the plan's CU-hour rate). The fingerprint is rule and
resource, so a decision survives the next pass, and a finding that goes away resolves its recommendation. Runs,
Findings and Recommendations open under the Vercel scope (capability `findings`; the Runs list and the default
run follow the account the sidebar looks at), the Overview's attention list is the latest pass, the resolution
thread and the playbooks work as on AWS (there are no hand-written seeds for Vercel: each control names the
Vercel, Neon or Redis Cloud documentation pages it is about in `CONTROL_REFERENCES`, and the agent writes the
playbook from those pages alone, published on its own confidence since there is no reference to grade against), and the
graph records it all: `AdvisorRun {native_type: rules_pass}`, `AdvisorControl -[:FLAGGED]-> project | store`,
`AdvisorRecommendation -[:TARGETS]->` the project or store under the team's account, `DECIDED_AS` when a person
decides. The AWS rules' reconcile leaves `vercel_*` rules alone and the Vercel pass reconciles its own.

The general view ("all accounts" in the sidebar, `GET /api/accounts/general`, the Overview's top strip) sums the
month across providers where it means the same thing (the AWS forecast, the Vercel period estimate, the stores at
their plans), counts open recommendations and claimed savings per provider, alarms, alerts and security findings
across accounts, and lists what needs attention with the account each item is about: the latest AWS run's alarm
controls, unacknowledged alerts, and the Vercel team's findings. "Open" on a line scopes the sidebar to that
account and opens the page.

IAM users are in the inventory (Inventory › Identities, `src/iam_inventory.ts`, `GET /api/inventory/iam`): per
user, console access, MFA, groups and policy names, whether a policy is administrative (AdministratorAccess or an
inline Allow * on *), the access keys with status, age and last use (the key id masked to its last four
characters), the last sign-in or call, and the account the user belongs to. The summary counts console users
without MFA, administrators, active keys and keys older than 90 days, and users unused for 90 days. In the graph
each is an `AdvisorIdentity {kind: user}` with the ontology's `human`, `mfa`, `admin`, `credentials`,
`credential_age_days` and `last_used_at`. Under the Vercel scope the same tab lists the team's members with role and
MFA.

Accounts are nodes with their hierarchy. Every account the advisor is pointed at is an `AdvisorAccount` with its
name, how it is reached (in words, never a secret), whether it is enabled and may be acted in, its last credential
test and its role: `management` for an AWS parent other accounts are members of, `member` for a child, `standalone`
otherwise. A member is `PART_OF` its parent, and every resource, run, pass and scan is `IN_ACCOUNT` of the account it
was collected from, so a member's instances hang off the member and not off the parent, and "what runs in this
account" and "what runs in the organisation" are one hop apart.

Changes and alerts follow for the team too. Every collection ends with a snapshot of what matters (projects with
their production deployment, protection, firewall, runtime, domains and env variable names; stores with plan,
status and projects; members with role and MFA; log drains; the subscription) diffed against the previous one
(`src/adapters/vercel/changes.ts`, `GET /api/vercel/changes?days=`): each difference is a row with its before and
after, in words ("production deployment READY at …", "deployment protection (sso) changed from off to all
except custom domains", "3 env variables added to hive: …", "alice enabled MFA"), and the Changes page shows them
under the Vercel scope the way CloudTrail is shown for AWS. The rules pass raises an alert for every alarm or
warning finding that was not there in the previous pass (kind `vercel_<control>`, the finding's severity as the
alert's level, the fingerprint in its details) and closes the alert when the finding goes away (acknowledged by
the system with the reason), so the Alerts page and the Sphinx notifier carry Vercel the way they carry the
watcher's alerts; info findings never page, and the very first pass records the backlog without paging it.
Capabilities `changes` and `alerts` gate the two pages.

Nothing in a playbook is hand-written. `src/playbooks.ts` is a table of official sources per control (the
provider's documentation pages; for a Thrifty control the benchmark mod's own text is the primary source and the
list may be empty), the Vercel controls list theirs in `src/adapters/vercel/rules.ts`, and every playbook is
written by the agent from those sources, cited step by step, judged by Jev for tier and effort, and published on
the agent's own confidence. A control whose playbook is unwritten or held shows none, with the reason, rather
than prose someone typed; the seed catalogue and its coverage check are gone.

Saving the token also writes the Steampipe connection `vercel` (plugin `turbot/vercel`, `steampipe plugin install
vercel` once per host) into `<STEAMPIPE_CONFIG_DIR>/vercel.spc`, owned by the advisor and removed with the account, so
the agent's `steampipe_query` tool and ad-hoc SQL can read `vercel.vercel_project`, `vercel_deployment`,
`vercel_domain`, `vercel_dns_record`, `vercel_team`, `vercel_user` next to the AWS tables. Collection itself stays on
the REST client, which reads what the plugin does not expose: deployment protection, the env variable names and the
firewall.

### Playbooks from sources

The playbooks (what a finding means, when to act, when not to, the steps, the saving) are written by the agent from
named sources, never by hand (`src/playbook_gen.ts`, `src/sources.ts`, `tasks/playbook/`):

- **Sources.** The installed benchmark mods' own control definitions and documents, parsed from the `.pp` files
  under `POWERPIPE_MOD_DIR/.powerpipe/mods` (Thrifty: title, description and the check's SQL plus the service's doc
  page; Compliance: title, description and, for CIS and Foundational Security, a Remediation document per control),
  and the provider pages those documents reference (docs.aws.amazon.com and a short allow-list, read as text, re-read
  weekly). Every source is hashed; `GET /api/playbooks/:id/sources` shows them.
- **Generation.** A batch of four controls per agent run with their sources in the prompt and a strict schema: each
  step cites the source it came from. Jev then judges the tier the way it judges recommendations (could the steps
  destroy data, what would users notice; stricter only) and the effort; the agent's confidence decides publication
  (0.5 or more), a held one says why, and a person can mark one reviewed (pins it) or disputed (unpublishes).
- **The catalogue** in `src/playbooks.ts` lists each control's official sources and nothing else: there is no
  hand-written playbook text anywhere; the "How to act" panel shows the generated playbook with its citations or
  says none is in force.
- **When.** `PLAYBOOK_CRON` weekly (default Monday 07:00) rebuilds what a changed source or age made due and writes
  the ones controls flagged in the latest run still lack, a few per run under the agent quota; Findings › Playbooks
  has Generate now. `GET /api/playbooks/due`, `/api/playbooks/jobs`, `POST /api/playbooks/generate`,
  `PUT /api/playbooks/:id/review`. In the graph: `KnPlaybook` with provenance and `CITES` edges to `KnSource`
  (`docs/ontology.md` §1c).

### Tailored resolutions

A playbook is generic; a resolution is the playbook applied to one recommendation on one resource, with the graph,
Jev and the agent. `POST /api/recommendations/:id/resolve` (`src/resolve.ts`) runs the credential gate, then:

1. **Context pack.** The playbook for the recommendation's origin control (`evidence.playbook`, else the rule's
   control), the resource's inventory snapshot (type, state, tags, volumes, role from `resource_roles`, the latest
   probe's top processes), the decision concepts from repo2graph (`listDecisionConcepts`) filtered to those whose
   name or description mentions the resource id or name plus the generic rules whose name starts with the resource's
   role, and the resource's history in the advisor (earlier recommendations with their decision reasons, incidents
   whose fixes named it, its other alarms in the last run).
2. **Jev gate** (purpose `resolution_gate`, only with `TYPESAFE_API_KEY`): `applies` (probability the playbook
   applies), `blocker` (`none`, `third_party_binary_without_arm_build`, `stateful_data_migration`,
   `protected_or_owner_says_keep`, `retiring_soon`, `unknown`) and `effort` (an hour / a day / a week or more).
   The gate outcome (`gate_outcome`, also in the gate JSON) is `blocked` (closed as `not_applicable`, no agent call)
   only when Jev names a specific blocker (not `none`, not `unknown`) with confidence ≥ 0.7, or when `applies` ≤ 0.15
   and the blocker answer (anything but `unknown`) has confidence ≥ 0.7; `applies` when `applies` ≥ 0.5 without a
   confident blocker; `unsure` otherwise (a low `applies` with `none`/`unknown` or a shaky blocker goes to the agent,
   which can gather the facts Jev lacked). The reason is worded plainly ("Jev is unsure (applies 29 %, no confident
   blocker), asking the agent", "Closed: Jev is confident (82 %) the blocker is …", "Jev thinks it applies (91 %)")
   and says how many team decisions or rules were in the context pack, or that none are on record yet.
3. **Agent.** Otherwise the pack goes to repo2graph through `postAgentRequest` (kind `resolution`, the MCP fact tools,
   40 turns) with a schema `{ applies, summary, blockers[], plan: [{ step, command?, verify }], risk, est_monthly_saving,
   needs_from_human[], concepts_used[] }`; the webhook (or a poll of the agent run) completes it.

Rows live in `resolutions` (recommendation id, request id, status `pending | completed | failed | not_applicable`, the
gate, the context pack, the plan, error, timestamps); `agent_runs` gained `recommendation_id`. `GET
/api/recommendations/:id/resolution` returns the latest one with graph links for the concepts used; the POST answers
202 (409 while one is pending unless `?force=1`, 404 for an unknown recommendation). Without `REPO2GRAPH_URL` the gate
still runs and the resolution is stored as `failed` with a message saying the static playbook applies. UI: the
Recommendations detail has a **Resolve** button and a "Tailored resolution" block (gate answers with their
confidences, blockers, the numbered plan with commands in code blocks and verify lines, what it needs from a human,
the concepts used as links), with the static playbook below it as the fallback.

## Graph mirror and the knowledge graph

Two layers in the same Neo4j. The **mirror** is a one-way projection of the advisor's tables (resources,
recommendations, runs, alerts, incidents, controls, playbooks; `Advisor*` labels). The **knowledge graph**
(`src/graph_knowledge.ts`, `Kn*` labels, rebuilt with every sync) is the shape the design note asks for:

- **General area**, true in any account: `KnSystemType` nodes for every instance SKU in the price cache and
  every pricebook rule, with the list price, its unit and source; `KnArchetype` nodes (the workload roles Jev
  assigns, with their descriptions). The operational rules the prompts carry are not `Kn*` nodes but Concepts
  under "AWS Operational Patterns" (see [Operational patterns: Concepts only](#operational-patterns-concepts-only)).
- **Our side**, a schematic: `KnSystem` nodes, one per autoscaled pool, RDS cluster, ElastiCache replication
  group or NAT gateway, and one per standalone instance, cluster or node (`systemsFromInventory`); each linked
  `IS_A` to its archetype (from Jev's role, or from the pool kind), `RUNS_ON` to the types it uses with the
  count, the hours and the cost at list, and reached from its members through `MEMBER_OF`. Stopped instances
  are not members. `KnPricingOverlay` nodes (the Savings Plan with its implied discount from the bill
  reconstruction, active RDS and ElastiCache reservations) `COVERS` the types they apply to, so a system carries
  both a list price and what covers it.
- **Traffic on the edges**: each NAT gateway system `TRANSFERS_TO` the internet with GB/day, price per GB,
  USD/month and the measurement source (the 14-day baseline); the account `TRANSFERS_TO` the region for cross-AZ
  bytes (from the bill); `KnLogGroup` nodes carry ingestion and storage cost, and `SHIPS_LOGS_TO` edges attach
  them to the system whose name, pool or member id appears in the group's name, else to the account.
- **Outcomes**: a verified recommendation carries `verdict`, `realised_usd_month` and `realised_ratio`.

Read it back: `GET /api/graph/systems?kind=`, `GET /api/graph/system/:id` (id such as `pool:<name>`,
`ec2:<instance id>`, `rds:<cluster>`, `cache:<group>`, `nat:<id>`, or a name), `GET /api/graph/bill`, and the
Knowledge page (Systems card, click a system for its types, overlays, members, edges and decisions). The
agent has the same through `graph_systems`, `graph_system` and `graph_bill`, next to the raw `graph_query`.

**Log attribution** (`src/log_attribution.ts`) works from evidence, strongest first:

1. **What the instance says it ships.** Probe 1.6 reads the log agent configs on the box (the CloudWatch agent's
   JSON and TOML, the old `awslogs.conf`, Fluent Bit and Fluentd configs, `/etc/docker/daemon.json` and each
   running container's `awslogs` log driver) and reports every `log_group_name` it finds, templated names
   skipped. The graph draws `(:AdvisorResource)-[:SHIPS_LOGS_TO {via, source, observed_at}]->(:KnLogGroup)`
   from it, and the group belongs to the instance's system (`observed: cloudwatch-agent on i-…`). When members of
   two systems ship to the same group it stays unattributed and says so (`observed on several systems`).
2. **The AWS naming conventions**: `/aws/lambda/<function>`, `/aws/rds/cluster|instance/<name>`,
   `/aws/eks/<cluster>/cluster`, `/aws/elasticbeanstalk/<environment>/…`.
3. **The group's own tags** (`logs:ListTagsForResource`, fetched with the daily log refresh and kept in
   `log_groups.tags`): a cluster or environment tag, or any tag whose value is exactly a system's name, pool,
   alias or member id (`tag service=orion-api`). Ownership tags (`Environment`, `Owner`, `Team`, `Project`,
   `CostCenter`…) never count, even when their value happens to match. Two tags naming two systems is a tie.
4. The cluster and environment names the members' tags carry, found in the group's path.
5. A **token match** between the path and the systems' names, pools, member ids and aliases (the members' Name
   tags), where a compute system beats a database or cache on a tie and a tie between compute systems stays
   unattributed.
6. **Jev** (`src/log_attribution_jev.ts`, purpose `log_group_owner`), for what the rules left unowned: in
   batches of 8, each group's name and path, tags and what the rules found, against the account's systems
   (the rule candidates first, then the compute systems, then the rest, 50 at most, plus `none`). A pick at
   60 % or better becomes the owner (`jev: pool:web at 82% (rules: no match)`); a weaker one stays on the node
   as `jev_choice` / `jev_confidence` so the page can say what Jev leaned to. Answers are cached in
   `log_group_jev` until the group's name, tags or the set of systems change, or 30 days pass, so the mirror's
   frequent refreshes do not re-ask.

EKS clusters are systems of their own (`eks:<cluster>`, pools `PART_OF` them) and so are the Lambda functions,
so their log groups have somewhere to attach. Every `KnLogGroup` carries `attributed_by` (the rule, in words) and,
when nothing claimed it, `candidates`: the closest systems with their score, so the team can name or tag the group.
Every group an instance was seen shipping to gets a node whatever its size; otherwise the 300 biggest do.
`GET /api/graph/logs`, the `graph_log_groups` tool and the Knowledge page's "Log groups · who writes them" card
list the attribution: counts per rule, the instances seen shipping to each group, and the unattributed groups
first with their candidates and monthly cost.

**Quantities from our own history** (`src/quantities.ts`, `GET /api/bill/quantities?from&to`, a card on the
Bill page): instance hours per type from the watcher's running counts (each sample stands for the time to the
next one, capped at an hour, so hours the watcher did not see count as nothing), EBS GB-months from its attached
total, NAT GB from its hourly gateway bytes, log GB from the metered ingestion, beside Cost Explorer's quantity
and cost for the same complete days. The card shows the sampled figure, the same scaled to full coverage, and
Cost Explorer's; on the first complete day the scaled instance hours and EBS GB-months land within a few percent
of Cost Explorer's, which is the evidence that a reconstruction from the graph alone is within reach once the
watcher runs uninterrupted.

**Lambda** functions are systems too (`lambda:<name>`, from the account's function list), priced from 30 days
of CloudWatch invocations and duration: GB-seconds (duration × memory) at the architecture's rate plus requests,
scaled to a month; the account's 30-day GB-seconds from the metrics match Cost Explorer's usage line within a
percent. The graph carries the list price; the bill's Lambda line is lower because the Compute Savings Plan and
the free tier apply to it.

**The bill from the graph** (`graphBill`, on the Bill page under the reconstruction) prices the current fleet
for a month at list from `RUNS_ON`, adds EBS, the transfer edges and the log groups, and shows last full
month's on-demand value beside each category the mapping covers. First build, 2026-09-20: 65 systems, 98 system
types, 4 overlays, 128 traffic and log edges; the graph explains about 15.6k USD of a month at list, and the
gaps are the ones expected at v1: fleet change during the month (August ran more compute than runs today),
lines the graph does not hold yet (Lambda, S3, support), and log groups whose names match no system, which fall
to the account. Closing those is the graph's own eval, the same way the reconstruction is the pricebook's.

### Schema

The graph follows the provider-neutral model of `docs/cloud-ontology.md`; `docs/ontology.md` lists what the AWS
adapter writes today, label by label. In short: labels are prefixed `Advisor` (records of things that exist: resources,
endpoints, recommendations, actions, alerts) or `Kn` (knowledge rebuilt from them: systems, types, archetypes, log
groups, playbooks); the Neo4j is shared with stakgraph and repo2graph, nothing without those prefixes is ever created,
changed or deleted, and the only foreign label used is `Concept`, matched by id, never created. Every node carries
`provider`, `account_id`, `native_type` (the provider's word: `ec2_instance`, `rds_instance`, `s3_bucket`), `native_id`
and `updated_at`.

```
(:AdvisorAccount {id, kind: account})
   ▲ IN_ACCOUNT
(:AdvisorResource + one of :AdvisorCompute | :AdvisorDatabase | :AdvisorCache | :AdvisorLoadBalancer | :AdvisorFunction
                   | :AdvisorStorage | :AdvisorDeployment | :AdvisorDnsZone | :AdvisorDnsRecord
   {id, name, state: running|stopped|pending|terminated|available|degraded|unknown, native_state, region, monthly_usd,
    role, role_confidence, protected_prob, gone, first_seen, last_seen, + the label's own properties})
   ├─[:HAS_ROLE]────▶ (:KnArchetype {id, name, description})       the judged workload role; systems reach the same node with IS_A
   ├─[:IN_POOL]─────▶ (:AdvisorNodePool {id, name, kind: asg|karpenter|node_group|batch})   usage profile and capacity pattern live here
   ├─[:OBSERVED_BY {since, last_at, status, detail}]─▶ (:AdvisorTelemetry {kind: api|metrics|probe, native})
   │                                                          what the advisor can see of it; no probe edge = cannot look inside
   ├─[:EXPOSES {gone}]─▶ (:AdvisorEndpoint {id, kind: port|listener|service_endpoint|url, protocol, port, hostname, bind, scope, exposure})
   │        ◀─[:SERVES]── (:AdvisorApp {id, name, kind: app|infra})        the program behind a port
   │        ─[:FORWARDS_TO {target_group, health}]─▶ (:AdvisorEndpoint)    a balancer listener to the ports it fronts
   ├─[:RUNS {user, count, cpu_pct, rss_bytes, command, first_seen, last_seen, gone}]─▶ (:AdvisorApp)
   ├─[:STORES_ON {device}]─▶ (:AdvisorStorage {kind: block})               a volume attached to an instance
   ├─[:SHIPS_LOGS_TO {via, source, observed_at}]─▶ (:KnLogGroup)           what the box's own log agent config writes to
   ├─[:MEMBER_OF]───▶ (:KnSystem)                                         the system it is part of (knowledge layer)
   ◀─[:TARGETS]──── (:AdvisorRecommendation {id, title, action, native_action, tier, status, source, rule, est_monthly_saving,
   │                  confidence, decided_by, decided_at, decision_scope, verdict, realised_usd_month})
   │                  ├─[:TARGETS]──────▶ (:AdvisorResourceRef {id, guessed_type})   a resource with no node yet (a VPC, a table, a new instance)
   │                  ├─[:DECIDED_AS]───▶ (:Concept)                   the team's decision or rule in repo2graph (MATCH only)
   │                  ├─[:PROPOSED_IN]──▶ (:AdvisorRun {id, started_at, finished_at, status, trigger, findings_count, recommendations_count})
   │                  └─[:FROM_INCIDENT]▶ (:AdvisorIncident {id, status, cause, confidence, episode_cost_usd, monthly_run_rate_usd})
   │                                        └─[:INVESTIGATES]▶ (:AdvisorAlert {id, kind, level, message, cause, cause_actor_kind, ...})
   ◀─[:ABOUT]────────────────────────────────────────────────────┘        ─[:CAUSED_BY]─▶ (:AdvisorAction) when the advisor did it
   ◀─[:FLAGGED {run_id, reason}]── (:AdvisorControl {id, title, framework, category}) ─[:HAS_PLAYBOOK]─▶ (:KnPlaybook {control_id, title, meaning, steps, tier, effort})
   ◀─[:SECURITY_FLAGGED {scan_id, reason, severity, first_seen_at}]── (:AdvisorControl)      the latest security scan's alarms
   ◀─[:TARGETS]──── (:AdvisorAction {id, kind, status, mode, trigger, title, reason, rollback, est_usd_month, result, error, ...})
                      ├─[:CARRIES_OUT]▶ (:AdvisorRecommendation)           when the change executes an approved recommendation
                      ├─[:LAUNCHED]───▶ (:AdvisorResourceRef)              the instance a relaunch created
                      └─[:TOUCHED_IN {event, outcome, at, trigger, detail}]▶ (:AdvisorPass {...})   the executor's activity log
(:AdvisorDnsRecord)-[:IN_ZONE]->(:AdvisorDnsZone); (:AdvisorDnsRecord)-[:POINTS_TO {hop, via}]->(resource | :AdvisorResourceRef)
(:AdvisorDeployment {platform: beanstalk})-[:RUNS_ON_POOL]->(:AdvisorNodePool), -[:BACKED_BY]->(:AdvisorLoadBalancer)
```

Everything the advisor plans, does or decides is in the graph, always: the ledger is mirrored on every pass, apply,
read-back and revert (proposals included, so a future agent sees what was planned and why it was left alone), and a
recommendation the executor closes fires the same Concept sync and re-mirror as a decision from the page.

Findings are not mirrored one node per row (thousands per run); instead the latest completed run's alarm findings
whose resource is in the inventory become `FLAGGED` edges from the control to the resource, one per control and
resource, and earlier runs' edges are dropped. Resource references are matched as the id itself or the last segment
of an ARN (`arn:...:instance/i-abc` → `i-abc`, `arn:aws:s3:::name` → `name`); anything else becomes an
`AdvisorResourceRef` with a `guessed_type` read off the id's shape. Playbooks come from `src/playbooks.ts`. Unique
constraints on each label's id are created if missing, and the v1 labels (`AdvisorRole`, `AdvisorPort`,
`AdvisorPlaybook`, `KnService`) are removed once per process. After deploying the v2 mirror run
`POST /api/graph/sync?wipe=1` once, so nodes written by the old mirror lose their old property names too.

### Configuration

| variable | default | meaning |
| --- | --- | --- |
| ✎ `NEO4J_URI` | unset = mirror off | `bolt://neo4j.sphinx:7687` inside the swarm, `bolt://localhost:7687` against a local swarm |
| `NEO4J_USER` | `neo4j` | |
| `NEO4J_PASSWORD` | | the Neo4j node's password in the swarm's `vol/stack/config.yaml` |
| `NEO4J_DATABASE` | unset = the server's default | only for multi-database servers |

### Hooks (all fire-and-forget)

| when | what is mirrored |
| --- | --- |
| end of a collection run (`src/collector.ts`, completed or failed) | the run node, then `mirrorResources`, then every recommendation (`mirrorRecommendations`); the latest completed run's alarms become the `FLAGGED` edges |
| after the watcher's inventory refresh (`src/watcher.ts`) | `mirrorResources` (role, pool, state, price, SSM status, gone) |
| after the watcher created or auto-acknowledged alerts | `mirrorAlertsAndIncidents` |
| a decision or batch decision (`src/routes/browse.ts`), alert ack / reopen (`src/routes/api.ts`) | `mirrorRecommendations([ids])` / `mirrorAlertsAndIncidents` |
| `completeIncident` (`src/investigate.ts`, any outcome) | `mirrorAlertsAndIncidents`, then the fixes' recommendations (`FROM_INCIDENT`) |
| a concept sync wrote its row (`src/concepts.ts`) | `mirrorRecommendations([id])`, so the `DECIDED_AS` edge appears once repo2graph has the Concept |
| a probe stored what runs on a box (`src/ssm.ts`, probe 1.6) | `mirrorApps([instance])`: the `RUNS` edges to `AdvisorApp` |
| the watcher read the EC2 status checks (`src/status_checks.ts`, every cycle and 20 s after server start) | `mirrorStatusChecks`: the three statuses and the scheduled-event count on each `AdvisorResource` |
| end of a collection run, end of a probe pass, the daily logs refresh (manual too), and 15 s after server start | `mirrorKnowledge` (`mirrorKnowledgeInBackground`): the whole `Kn` layer, systems, types, overlays, traffic and log attribution, rebuilt from the database; overlapping triggers are coalesced into one more pass, so the `Kn` labels are always there without a manual resync |
| an executor pass, apply, verify or revert (`src/executor.ts`) | `mirrorActions([ids])` for the rows touched; a recommendation the executor marks done also gets `syncDecisionConcept` + `mirrorRecommendations([id])` |

Endpoints (`src/routes/graph.ts`): `GET /api/graph` → `{ configured, uri (host only), connected, server, error, stats: { nodes,
relationships, total_nodes, total_relationships }, account_id }`; `POST /api/graph/sync[?wipe=1]` → the counts of
`mirrorAll` (`resources`, `recommendations`, `runs`, `flagged`, `controls`, `playbooks`, `alerts`, `incidents`, `actions`), `wiped`,
`took_ms` and the fresh `stats`; `GET /api/graph/resource/:id` → the resource node with its role, pool, recommendations
(each with its Concept when decided), alerts (latest 25), incidents, flagged controls and `counts`.

UI: the Knowledge page has a **Graph mirror** card (connected or not, node and relationship counts by label and
type, **Resync now**, three copyable Cypher examples: one resource with everything about it, every recommendation
decided as a Concept, resources by role); the Inventory EC2 drawer has a **Graph** line with how many
recommendations, alerts, incidents and controls are linked to the instance and a copyable Cypher for it.

### The `graph_query` tool

The agent gets the same graph through MCP: one read-only Cypher statement, guarded (`guardReadCypher`: must start with
`MATCH`, `OPTIONAL MATCH`, `WITH` or `CALL {`, no `CREATE`/`MERGE`/`SET`/`DELETE`/`DETACH`/`REMOVE`/`DROP`/`LOAD`/`FOREACH`,
no `apoc.*`, `dbms.*` or `gds.*` procedure, a single statement; string literals and comments are stripped before the
check so a title containing "DELETE" is fine), run in a read transaction with a 5-second timeout and a 200-row cap. The
tool's description carries the schema above and tells the agent that `Concept` nodes hold the team's decisions and
rules. Without `NEO4J_URI` the tool answers with a clear "not configured" message and points at the SQLite-backed tools.
Examples:

```
MATCH (r:AdvisorResource {id: 'i-0123456789abcdef0'}) OPTIONAL MATCH (r)-[e]-(x) OPTIONAL MATCH (x)-[d:DECIDED_AS]->(c:Concept) RETURN r, e, x, d, c
MATCH (rec:AdvisorRecommendation)-[:DECIDED_AS]->(c:Concept) RETURN rec.status, rec.title, c.name, c.description ORDER BY rec.decided_at DESC
MATCH (r:AdvisorResource)-[:HAS_ROLE]->(role) WHERE r.gone = false RETURN role.name, count(r), round(sum(coalesce(r.monthly_usd, 0))) ORDER BY 3 DESC
```

Tests: `src/__tests__/graph_mirror.test.ts` covers the Cypher guard and the row-to-node mapping without a network, plus a
live test (`mirrorAll`, `graphStats`, the `DECIDED_AS` edge to an existing Concept, resync idempotence, `wipeMirror`) that
runs only when `NEO4J_URI` is set, with its own account id `TEST-000000000000`, and removes everything it created.

## Spend, alerts and paginated lists
Routes live in `src/routes/browse.ts`, mounted on `/api` before `src/routes/api.ts`, so
the paths below supersede the older unpaginated ones with the same path; everything else in `api.ts` is untouched.

## Spend (Cost Explorer, daily)

- Table `spend_daily` (`day`, `net_unblended`, `unblended`, `amortized`, `usage_only` = amortized cost of the
  Usage / SavingsPlanCoveredUsage / DiscountedUsage record types, `fetched_at`), filled by `refreshSpend()` in
  `src/spend.ts` from `aws_cost_by_record_type_daily`: one Cost Explorer call covering the last 45 days or back
  to the first of the previous month, whichever is earlier. Every call is billed, so a refresh is skipped when
  the last one is younger than 6 hours (unless forced) and while the credential gate is closed.
- Triggered at the end of every collection run (after the inventory refresh, logged in the run) and by the
  `SPEND_CRON` schedule (default `15 */6 * * *`, `off` disables it; `config.spendCron`).
- `GET /api/spend` (`?metric=net_unblended|unblended|amortized|usage_only`, default net unblended):
  `{ metric, as_of, today: { day, usd | null }, last_7_days: { from, to, usd, days }, month_to_date: { from, to, usd,
  days, projected_month_end, projection_basis: { days, daily_avg } }, previous_month: { from, to, usd, days, complete },
  fetched_at, series: [{ day, net_unblended, unblended, amortized, usage_only, fetched_at }], last_fetch,
  min_interval_hours, days }`. "Today" is null until Cost Explorer reports the day (it lags about a day); the
  7-day window ends on the last complete day with data (yesterday at the latest); the projection is the daily
  average of the month's complete days times the days in the month; the previous month says whether every day
  is covered.
- `POST /api/spend/refresh?force=1` runs the fetch (without `force` the 6-hour rule applies) and returns
  `{ refreshed, days, fetched_at | skipped | error, summary }`.
- Overview: a spend row at the top (today, last 7 days, month to date with the projection, previous month), the
  as-of date and a 45-day bar sparkline (plain divs) with a Refresh button.

## Disk alerts

Every probe's mounts are judged at once (`src/disk_alerts.ts`): a mount at `DISK_WARN_PCT` (80 %, a runtime
setting) opens a `disk_high` warning, at `DISK_ALARM_PCT` (90 %) a `disk_full` alarm, one open alert per instance
and mount with the free GB in the message. The alert closes by itself (acknowledged by the system) when the level
falls five points under its threshold, so a disk hovering at the line does not flap; an escalation replaces the
warning with an alarm. The latest probe of every running instance is judged again at startup and after every
probe pass, so a disk that filled while the advisor was down alerts immediately. This is the level today; the
daily review's `disk_fill` is the trend, days until full at the current rate. The agents are told this (the
operational pattern "The advisor is the monitor for SSM-managed instances", a Concept appended to every system
prompt at dispatch): the advisor is the monitor for SSM-managed
instances, so they must not recommend the CloudWatch agent, CloudWatch alarms or external monitoring for disk,
memory, load or reboots; a gap in the advisor's coverage goes under `needs_from_human`, not into a recommendation.

## Host alerts from the probes

The same pass judges memory, swap, load and reboots (`src/host_alerts.ts`): `memory_high` at `MEM_WARN_PCT`
(85 %) and `memory_full` at `MEM_ALARM_PCT` (95 %) of used memory with available subtracted; `swap_in_use` at
`SWAP_WARN_PCT` (25 %) of the swap space; `load_high` when the 15-minute load average per vCPU reaches
`LOAD_PER_CORE` (1.5), a sustained saturation rather than a spike; `reboot` when a probe's uptime is lower than
the previous probe's, with the reboot time worked back from the uptime. Hysteresis and system acknowledgement as
for disks. All thresholds are runtime settings under Probe pass.

## Status checks: system, instance and attached EBS

`src/status_checks.ts` reads, on the watcher's cadence (`WATCH_CRON`, every 30 minutes by default) and 20 seconds
after server start, the built-in EC2 status checks of every running instance, per account and region
(`DescribeInstanceStatus`; free, on every instance): the **system** check (the hardware and network under the
box), the **instance** check (the OS is reachable) and the **attached-EBS** check (volumes complete I/O), each
`ok | impaired | insufficient-data | initializing | not-applicable`, plus the events AWS has scheduled for the box
(retirement, reboot, maintenance) with their dates.

Every reading goes to `instance_status`; every change of a status is a row in `instance_status_events` (180 days).
One alert, an alarm, one open per instance, closed by the system when the checks pass again:
`status_check_failed`, whose message says which check fails and what that means (a system failure is AWS-side and a
stop/start moves the box; an instance failure is the OS, and a reboot usually clears it) and lists the scheduled
events. Insufficient data neither raises nor closes.

Read it on the Inventory drawer ("Status checks" line with the three statuses, the scheduled events and the status
changes), `GET /api/status-checks?only=impaired|events|all`, `POST /api/status-checks/refresh`, and the agent's
`status_checks` tool. The graph carries the statuses on the `AdvisorResource`. The read-only policy's `ec2:Describe*`
already covers the call.

The application-level status checks EC2 added in August 2026 (AWS probes an HTTP port and path on the box every
60 seconds) are deliberately not used: they bill 0.01 USD per hour for a managed network interface per subnet and
security group combination, which on this fleet, where many boxes sit in a security group of their own, would be
hundreds of dollars a month. The probe's front-door reading (requests in the last 24 hours, the last real request)
gives a free, slower answer to the same question.

## Lambda errors, commitments, RDS and ElastiCache

- **Lambda error rate** (`lambda_errors`, warning): with every inventory refresh, a function with at least 100
  invocations in 30 days whose failed share reaches `LAMBDA_ERROR_PCT` (5 %) alerts, and closes at half that;
  failed invocations are billed like the rest.
- **Commitments** (`src/commitments.ts`, with the spend refresh every six hours; `GET /api/commitments`,
  `POST /api/commitments/refresh`): the Savings Plan's 30-day utilisation, unused commitment and net savings
  from Cost Explorer's `GetSavingsPlansUtilization`, and every reservation's utilisation from
  `GetReservationUtilization` asked per service (without a SERVICE filter only EC2 reservations answer), joined
  to the reservations by instance type. Two alerts: `commitment_underused` (warning) under
  `COMMITMENT_MIN_UTIL_PCT` (80 %) over 30 days, and `commitment_expiring` (alarm) at 60 days from expiry. The
  Overview's Commitments card shows utilisation and days left. Both Cost Explorer calls need
  `ce:GetSavingsPlansUtilization` and `ce:GetReservationUtilization` (covered by `ce:*` in the policy).
- **RDS**: connections (average and peak), read and write IOPS and the 30-day minimum of freeable memory join
  the CPU figure in the inventory and the drawer; `rds_memory_low` (warning) when freeable memory fell under
  half a gigabyte.
- **ElastiCache**: engine CPU, peak memory usage, evictions and peak connections over 30 days in the inventory
  and the drawer; `cache_memory_high` (warning) at 90 % of the node's memory, where keys start being evicted.

## Alerts, alarm first, paginated

- `GET /api/alerts?status=open|acknowledged|all&page=1&page_size=10&day=YYYY-MM-DD` →
  `{ total, page, page_size, status, day, counts: { alarm, warning, info }, alerts }`. `page_size` defaults to 10,
  max 50; `day` filters to one local server date; `?all=1` still means `status=all`. Rows keep every field of the
  old route (`incident_*` columns, parsed `triage`) plus `level` and `day`.
- Order: today's alerts before older days; within a day alarms, then warnings, then info; newest first. The level
  rule lives in `src/alert_level.ts` and `ui/src/alertLevel.ts` re-exports it, so the API and the badges agree.
- Overview: the alerts card shows the first 5 with the counts by level in its header; "Show all (N)" expands to
  the paginated list (10 per page) in place. Alerts page: 10 per page, `?status=&page=` in the URL, counts by level.

## Findings and recommendations, paginated and deduplicated

- `GET /api/findings?run_id&control_id&status&q&page&page_size` (default 50, max 200) →
  `{ total, page, page_size, run_id, controls, findings }`. Within the run one row per `fingerprint` and one per
  (`control_id`, `resource`), the first by id; the control counts are computed the same way.
- `GET /api/recommendations?status=open|...|all&q&page&page_size` (default 50, max 200) →
  `{ total, page, page_size, status, total_saving, recommendations }`. Rows with the same (`resource`, `action_type`)
  in the same status are one entry: the highest `est_monthly_saving` is primary, the others are listed in
  `merged: [{ id, source, rule, est_monthly_saving, confidence }]`, `sources` (`["rules", "agent"]`) and
  `merged_ids` (all ids, primary first). Sorted by saving desc, nulls last. `q` matches title, resource and name;
  `#123` or `123` is an id, matched exactly and across every status (the row's own `status` says which).
- `POST /api/recommendations/:id/decision` body `{ status, reason?, by?, scope?: "internal" | "generic" }`
  (default internal): same rules as before (a reason is required to reject), stores `decision_scope` next to the
  other decision columns and mirrors the decision into repo2graph's concepts (generic ones under "AWS Cost
  Knowledge" with role-based names, see `src/concepts.ts`).
- `GET /api/recommendations/:id` also returns `affected` (resources and mentioned), `exposure` (domains, volumes,
  open alerts, pool, cluster per resource, and `disruptive`), `conflicts` and `blocker` / `blocks`. The list rows
  carry `system`, `conflicts` and `blocker`; the list answer carries `total_saving_distinct` and `overlap_usd`.
- `POST /api/recommendations/:id/blocked-by` body `{ id: number | null }` → the row with `blocker` and `blocks`;
  400 on self or a loop, 404 when the blocker does not exist.
- `POST /api/recommendations/:id/progress` body `{ plan: "resolution:<id>" | "playbook:<control id>", total, done: number[], follow_up?: "YYYY-MM-DD" }`
  stores the step checklist (the whole list every time) and the follow-up day; the first tick on an open or
  snoozed item sets `status = pending`. `status` accepts `pending` in the decision routes too. → the row.
- `POST /api/recommendations/decision-batch` body `{ ids, status, reason?, by?, scope? }` applies one decision
  to every id (up to 100) → `{ updated, missing, recommendations }`. The UI uses it for merged entries.
- `GET /api/recommendations/:id/scope-suggestion?reason=` → `{ suggestion: { scope, confidence } | null }`,
  Jev's view of whether the reason is reusable knowledge; null when Jev is off or there is no reason.
- UI: Findings and Recommendations pages have prev/next, "page X of Y · N total"; a merged recommendation row says
  "also proposed by <source>", the detail panel lists the merged ids and Approve/Reject act on all of them; the
  detail panel has "This decision applies to" (this resource only / all resources of this kind), pre-selected from
  Jev's suggestion 600 ms after the reason stops changing, and decided items show their stored scope.

## Environment

| variable | default | meaning |
| --- | --- | --- |
| `SPEND_CRON` | `15 */6 * * *` | when the daily spend is refreshed from Cost Explorer (one call; skipped if the last fetch is under 6 hours old); `off` disables it |

## Tests

`src/__tests__/browse.test.ts`: spend summary math on fixture rows (today null vs present, the 7-day window, the
month-to-date projection, the previous month, an empty table, the `spend_daily` table in a scratch database),
alert ordering and level counts by day, paging bounds, findings dedupe, recommendation merge and sort.
`src/__tests__/playbooks.test.ts`: every control seen in the account has a complete playbook, the Graviton type map
(a dozen types, unknown and already-ARM → null), the graviton rule's tiering by role and its saving math on fixture
prices. `src/__tests__/resolve.test.ts`: the resolution context assembly on a seeded scratch database (resource facts,
concept filtering, history, the Jev state and the agent prompt), the gate decision policy and the plan parser; no network.


### What the advisor looks like in CloudTrail

- `ssm:SendCommand` about 60 times an hour with `PROBE_CRON` hourly and `PROBE_SCOPE=all` (one per SSM-online
  running instance), each followed by two or three `ssm:GetCommandInvocation` polls. Every call names the probe
  document, so the trail shows exactly what ran. Drop the cadence or scope, or exclude the advisor's role from
  CloudTrail Insights, if the rate alert is noise.
- `ce:GetCostAndUsageWithResources` is denied until resource-level data is enabled under Cost Explorer >
  Preferences on the payer account. The advisor remembers a refusal for 24 hours so an investigation does not
  repeat the denied call.
- Everything else is Describe/List/Get reads from the collection run, the watcher (every 30 minutes) and Cost
  Explorer (a few calls per refresh, every 6 hours).

## Agent prompts

The system prompt for each kind of agent request (findings batch, incident investigation, tailored resolution)
is editable under Settings > Agent prompts. The code ships a default (`SYSTEM` in `src/agent.ts`,
`INCIDENT_SYSTEM` in `src/investigate.ts`, `RESOLUTION_SYSTEM` in `src/resolve.ts`); a saved override lives in
the `settings` table as `prompt:<kind>` and wins until reset. At dispatch the advisor appends the operational
patterns (Concepts under "AWS Operational Patterns", read from the graph) to the prompt and sends the data after
it, so what you edit is the persona; the operational rules are edited in the graph. `GET /api/prompts`, `PUT /api/prompts/:kind { text }`,
`DELETE /api/prompts/:kind`.

## Baselines: what is typical

Before the advisor can judge a value it needs to know what is normal for this system, not a fixed threshold.
`src/baselines.ts` computes, daily (`BASELINE_CRON`, 06:40) and on demand (Knowledge page, `POST
/api/baselines/refresh`), a robust baseline per scope and metric and stores it in `baselines`:

| scope | metrics | source | window |
|---|---|---|---|
| NAT gateway | bytes per hour (total, in, out) | CloudWatch hourly sums | 14 days |
| EC2 instance | CPU % (average and maximum per hour) | CloudWatch hourly | 14 days |
| EC2 instance | memory %, root disk %, load as % of cores, running containers | the hourly probes | 30 days |
| EC2 instance | network in and out, GB per day | CloudWatch daily sums | 14 days |
| service | net spend per day | Cost Explorer daily | 60 days |

Each baseline holds the median, the MAD (a spread a spike cannot move), p95, max, the number of days seen, and,
once seven days of history exist, a median per hour of day and per day of week (`src/baseline_math.ts`).
Scoring a new value against it gives the expected value for that hour, the ratio to it, a robust z-score from
the expected value, and a level: `normal`, `high` (twice the expected, or three spreads away) or `extreme`
(both, and above p95).

Where it is used today:

- the **watcher** judges NAT traffic against the gateway's hour-of-day baseline once it has seven days: an
  alert needs an `extreme` score and more than 5 GB in the hour, and its message says what is typical for that
  hour and the p95; the six-sample average remains the fallback for a gateway without a baseline;
- the **EC2 drawer** shows a "Typical" line (median and p95 per metric, days of history, whether an hourly
  profile exists) under Utilisation;
- the **Knowledge page** lists every baseline per scope kind with a refresh button.

`GET /api/baselines?scope_kind=nat|instance|service&scope_id=` returns them. Next: the same scoring for CPU,
memory and spend per service in the watcher, the p95 band on the instance charts, and change-point detection
over the daily roll-ups.

The network baselines also raise `network_step` (warning): an instance whose last two complete days moved at
least twice its own 14-day median and three spreads above it, with at least 5 GB/day, in either direction. A
bandwidth or data-transfer line that grows on the bill then has a named instance and a day behind it.

## What the findings batch sends

The prompt for the findings batch is a summary plus the diff, not a dump (`buildPrompt` in `src/agent.ts`):
per control a count and three examples; the rule drafts as a table per rule (count, claimed saving, the three
biggest items) plus the fifteen largest drafts overall; the rejected decisions; the month's cost context; and
the full "what changed since the previous run". Everything else the agent pulls on demand:
`open_recommendations` (any draft with its full rationale and evidence, by rule, resource, ids or minimum
saving), `findings_for_resource`, `recommendation_history`, `review_findings`. Before this the prompt carried
every draft with its rationale, about 66k tokens for 300 drafts and roughly half of the run's cost; it is now
under 8k tokens for the same run.

## Realised savings: verifying an approval against the bill

Approving a recommendation is a claim; seven days later the bill can confirm it. `src/verify.ts` runs daily
(`VERIFY_CRON`, 07:30, a runtime setting) over every approved recommendation up to thirty days after its
decision, pulls the daily cost of the Cost Explorer lines the action moves (`costScopeFor` in
`src/verify_math.ts`: Aurora storage and I/O lines for a storage-tier change, EBS GB-months for a termination
or a volume deletion, the instance type's `BoxUsage` hours for a right-size or a Graviton move, NAT bytes for a
cache or an endpoint, and so on), and compares the median of the 14 days before the decision with the median
of the days after it, skipping the decision day and the next. The difference, scaled to a month, against the
claimed saving gives the verdict: `realised` (60 % or more of the estimate), `partial`, `none`, `increase`;
`too_early` until seven complete days exist; `not_verifiable` for actions that move no cost line (a flow log,
a reservation). Where the inventory can see it, the row also says whether the action was applied (an instance
gone or stopped, a type changed). The scope is account-wide for the line, since resource-level cost data is not
enabled, and the row says so.

Results are stored per recommendation per day (`verifications`), shown on the recommendation's detail
("Realised") and summed on the Overview next to the top recommendations (claimed vs realised, how many still
waiting). `GET /api/verifications`, `GET /api/verifications/:id`, `POST /api/verifications/run?force=1&id=`
(force gives an early read before the seven days). Next: attach the verdict to the decision in the graph.

**Auto-actions are measured the same way.** The executor's applied changes are grouped by kind and resource
(`actionDecisions`: every applied ledger row of `swarm_park` on one instance is one change, its decision day the
first application) and read against the cost lines their kind moves (`actionCostScope`: instance hours for
parking and office hours, snapshot storage for archiving, ECR storage for its lifecycle, ACU-hours for the
Serverless minimum, and so on), with the same medians and verdicts; the latest per change is kept in
`action_verifications`. A change that carries out an approved recommendation is measured on that recommendation,
not twice; kinds that only write a tag or a setting (consent switches, schedule tags, S3 request metrics, a
hibernation relaunch) are not listed. The impact card marks these rows "auto" and links them to the ledger, the
totals say how much of the realised saving came from auto-actions, and each AdvisorAction node in the graph
carries its `bill_verdict` and `realised_usd_month`.

## Tasks: the agent's work as files

Each kind of agent run is a folder under `tasks/` in the Harvey LAB shape: `system.md` (the instruction),
`schema.json` (the deliverable) and `task.json` (the tools it is meant to use, `max_turns`, a `rubric`, and a
`retry` policy). `src/tasks.ts` loads them at startup; the instruction becomes the code default of that prompt
kind (an override saved from Settings still wins), and every dispatch takes its schema and turn limit from the
task. `src/rubric.ts` grades an answer with the task's rubric, a small declarative language: `required`,
`numbers`, `range`, `enum`, `min_items`, `max_items`, `max_sentences`, `unique`, `no_destructive_auto`,
`covers` (a share of the facts in the brief must be mentioned) and `flag_consistent`, over dotted paths that fan
out across arrays (`fixes[].resource`). Every completed run is scored and the score stored on `agent_runs`;
the UI stays quiet about it unless the answer fell under the bar, in which case the failed checks are named
next to the run and on the morning note (`belowBar`). When the score falls below the task's threshold the same brief goes back once with the
failed checks appended under "Your previous answer failed these checks", under the agent quota, and the
retry's answer replaces the first on the observation, incident or resolution it belongs to. Adding a situation
is adding a folder; every run has a score; a weak answer gets one concrete second chance.

## The morning observation: the agent's read of the day

Every morning after the review (`OBSERVE_CRON`, 07:15, only when repo2graph is configured) and on demand
(Overview card, `POST /api/observe/run`), the agent gets a brief (`GET /api/observe/brief` shows today's):
spend against its baselines, the review's observations, the alerts still open from the last day, the pools with
their churn, decisions of the last day, and the latest run's changes. It answers in a fixed shape (summary,
changes with cause and evidence, attention items with urgency, proposals with tier) after verifying with the
read-only tools, and the answer is graded by a deterministic rubric (`src/observe_grade.ts`): every change cites
numbers, the review's and the alerts' resources are covered, no destructive proposal at tier auto, every proposal
names its resource, confidence in range, a summary of three sentences, a consistent nothing-to-report flag. The
result, the brief and the score are stored in `observations`; the Overview shows the note, and the grade only
when it failed.

This is the first task of the runner design (a brief, a schema, a rubric, a score per run). The first live
observation scored 8 of 8 and corrected the review: what the review flagged as an RDS spend step was a one-day
reservation purchase fee, while the real drift underneath was Aurora I/O on a cluster whose approved storage
change had not been applied. The review's spend-step rule now uses the median of the recent days for that reason.

The agent's tools grew with it (`/mcp`): `baseline` (what is typical, and a value scored against it),
`instance_history` (a month of daily memory, disk, load and containers per instance), `review_findings`, `bill`
(the month priced from our own knowledge, per service and per line) and `pools`.

## CloudWatch Logs and CloudTrail

Two more sources, collected daily before the review (`LOGS_CRON`, 06:50) and on demand:

- **CloudWatch Logs as a cost line** (`src/logs.ts`, `GET /api/logs`, `POST /api/logs/refresh`, agent tool
  `log_groups`): every log group with retention, stored bytes and class (`log_groups`), the account's ingestion
  per day and, for the groups above 200 MB stored (at most 80), ingestion per day over 14 days from the AWS/Logs
  `IncomingBytes` metric (`log_ingest_daily`, plus a `loggroup` baseline per group). Cost is derived at the list
  rates: 0.50 USD/GB ingested, 0.03 USD/GB-month stored. The review raises a warning alert when a group's last
  three days run above its 14-day median (`log_step`) and notes groups over 5 GB with no retention. The brief
  carries the top ingesters. In the graph design this is the "ships logs to" edge with its rate and price.
- **CloudTrail write events as the change feed** (`src/trail.ts`, `GET /api/trail?hours=`, `POST
  /api/trail/refresh`, agent tool `cloudtrail_changes`): non read-only events of the last 26 hours through the
  SDK's `LookupEvents` with a real time window (Steampipe's `aws_cloudtrail_lookup_event` does not push the
  window down and pages through the whole 90-day trail, at 2 requests per second, for any query), stored by
  event id (`trail_events`, 90 days). The API returns 50 events per page at 2 pages a second, and this account
  writes about 20,000 events a day, so the daily job takes three to four minutes; it stops at 900 pages. Almost
  all of that is machine heartbeat the trail files as writes: SSM agents checking in, log streams being opened,
  Batch and EKS running their tasks, instance roles registering push endpoints. Those are stored with `noise = 1`
  (`isNoise`: a fixed list of event names, and any principal that is an AWS service, an instance id, a Batch or
  autoscaling controller or a botocore session) and only counted; the summary and the brief show the rest, about
  170 events a day here: people, deployment roles, lifecycle managers, CloudFormation. This needs
  **`cloudtrail:LookupEvents`**, in the recommended policy; until it is granted the job records the missing
  action under Settings > Permissions and the brief says the feed is not available. The observing agent is told
  to look here first for the cause of a cost move: who changed what, when.

What the collection costs in AWS API charges: nearly nothing. EC2, RDS, ElastiCache, SSM, Pricing, IAM and
CloudTrail `LookupEvents` calls are free; CloudWatch `GetMetricStatistics` is free within the first million
requests a month; the Cost Explorer API is the one metered call at 0.01 USD per request, and the advisor makes a
few dozen a day (the spend refresh, the run, the baselines, the review, a reconstruction), about 3 USD a month.
The `CloudTrail InsightsEvents` line on the bill is CloudTrail Insights, a feature of the account, not the advisor.

## The daily review: what the statistics say

Collecting statistics is only worth it if something reads them back. `src/review.ts` runs every morning after
the baselines (`REVIEW_CRON`, 07:00) and on demand (Overview card, `POST /api/review/run`), looks at the last
30 days of roll-ups, the baselines and the last complete days of spend, and turns what they show into
recommendations and alerts with the numbers attached (`src/review_math.ts`, pure and tested):

| observation | evidence | result |
|---|---|---|
| sustained idle | at least 5 days of probes with memory under 40 % (peak under 60 %), load under 25 % of cores, CPU p95 under 20 % | recommendation `review_idle` (right-size, saving ≈ half the list price); report-only for pool members, protected or naturally idle roles; Batch workers skipped |
| memory pressure | memory over 85 % on average for 5+ days | warning alert |
| disk filling | a least-squares line through the root disk usage reaches 90 % (100 % for a disk already past 90 %) within 60 days, climbing at least 0.01 points a day (fit r² ≥ 0.5) | recommendation `review_disk_fill`; alarm when under 14 days |
| idle container | ran 90 %+ of the window at under 0.3 % CPU | observation on the Overview |
| spend step | a service's last 3 complete days average more than 3 spreads and 30 % above its 60-day median, at least 20 USD/day | warning alert with the monthly excess |
| bucket without lifecycle | a bucket with at least 20 GB in Standard and no lifecycle rule | observation `s3_no_lifecycle` with the IA saving |
| over-provisioned IOPS | an in-use gp3/io1/io2 volume above 3,000 provisioned IOPS whose 30-day peak stays under 30 % of it (5+ days of metrics) | observation `ebs_overprovisioned_iops` with the monthly IOPS charge |

Every observation is stored per day in `review_findings` (90 days) and listed on the Overview with a link to the
instance. Review recommendations are refreshed by the review itself and never resolved by the collection run.
Next: pool growth over weeks, and the same observations offered to the agent as facts.

## This month: the bill, forecast from what is running now

The page called This month (`ui/src/pages/Bill.tsx`, `GET /api/forecast`, `POST /api/forecast/run`) answers the
question the previous month cannot: what will this month cost, and why. `src/forecast.ts` runs after every spend
refresh (six-hourly) and stores one row per day in `forecasts`, so the projection has a history; the arithmetic
is pure and tested in `src/forecast_math.ts`.

- **Spent so far** is what Cost Explorer has for the month's complete days (the same three queries the price
  check uses, so every usage line is already classified and priced).
- **The remaining days** are priced three ways, and every service says which. *What runs now*: the EC2 fleet,
  RDS instances, ElastiCache nodes, EBS volumes, S3 buckets and Lambda functions as the inventory holds them at
  this moment, at our prices. The Savings Plan fee is fixed and, at its implied discount, covers a known amount
  of on-demand compute per hour; only compute above that is paid on demand. Reservations are the lower of two
  estimates: what the month's own billed share says is left to pay (this catches reservations the list misses)
  and the reservation list against the inventory (this catches ones bought late in the month). *Run rate*: the
  usage-based lines (transfer, NAT, CloudWatch, requests, snapshots, spot) at their month-to-date daily average;
  for the first week of a month that average is blended with the newest reconciled month's daily rate (which
  weighs seven days minus the days elapsed), because Cost Explorer's first days are incomplete and carry what AWS
  posts on the 1st. *Fixed*: the Savings Plan fee, the reservations' monthly fees (the `HeavyUsage` lines, posted
  once on the 1st for the whole month, never multiplied by the days left) and support. Where last month's price
  check found the bill's on-demand value for EC2, RDS or ElastiCache off our list price, the inventory leg is
  scaled by that ratio before the Savings Plan's cover is taken off it. AWS posts support on the 1st as a
  placeholder and trues it up at month end, so the forecast asks the Support API which plan the account is on
  (`src/support_plan.ts`, `support:DescribeSeverityLevels`: Basic fails with a subscription error, the severity
  codes tell Developer, Business and Enterprise apart) and applies that plan's formula to the forecast charges;
  a cancelled plan adds nothing beyond what was posted, and while the plan is unknown last month's support charge
  is the floor. The plan is cached as the account fact
  `fact:support_plan`, refreshed with every forecast, and the agent sees it in the `forecast` MCP tool.
- **On track for** is the sum, against last month's bill, with the services that moved by more than 20 USD and
  the resources that launched or disappeared this month (with their list price), so a moved forecast has names
  behind it. **Locked in** is the part already committed for the whole month.

The Overview card shows spent so far, on track for, locked in and the three biggest movers. When a Batch pool
scales up, the compute leg moves with it while the workers run; the Savings Plan's spare capacity absorbs the
first few dollars an hour of that.

### Price check: the previous month rebuilt from our own prices


The Bill page (`/bill`, `GET /api/bill?month=`, `POST /api/bill/reconcile?month=`) prices a month's usage from the
advisor's own knowledge and compares it, line by line and per service, with what Cost Explorer says was billed.
It is the eval of the pricing side of the graph: a priced line that disagrees is a wrong price, an unpriced line
is a system type the knowledge does not hold yet.

- **Where the prices come from.** `src/pricebook.ts` holds the list prices for the usage types Cost Explorer
  bills (NAT bytes and hours, EBS and snapshot GB-months, transfer, CloudWatch ingestion and storage, S3 classes,
  Aurora storage and I/O, Lambda, SQS, ELB, EKS, ECR, public IPv4, endpoints, and so on), each with its unit and a
  source note, dated. This is the seed of the "system types with list pricing" branch of the general area of the
  graph. Instance hours (EC2 `BoxUsage`, RDS `InstanceUsage`, ElastiCache `NodeUsage`) come from the price cache
  filled by the Pricing API, with the engine taken from the inventory (Cost Explorer abbreviates RDS classes,
  `db.r7g.xl`; the parser expands them).
- **Account overlays**, kept out of the pricebook: the Savings Plan commitment (`aws_savingsplans_savings_plan`,
  hourly × hours in the month) and its implied discount (fee over the on-demand value it covered), reservations
  (shown at amortized cost, their discount not modelled yet), Business Support (published tiers on the modelled
  charges), tax as billed.
- **What is compared.** Per line: our unit price × Cost Explorer's quantity against the line's on-demand value
  (uncovered part as billed, the Savings-Plan-covered part scaled back by the implied discount). Per service:
  modelled vs on-demand value, pass within 10 % or "named" when the residual is an unpriced line. Net identity:
  modelled net = the uncovered part of every line at our price (as billed where unpriced) + the Savings Plan fee
  + modelled support + billed tax.
- **The eval** (five criteria, all shown on the page): total within 5 %; every service within 10 % or named;
  Savings Plan fee matches the commitment; at least 90 % of usage value priced by a rule; every priced line names
  its rule. First run on a real account: within 0.4 % of the bill, 99.7 % of usage value priced, 5 of 5.
- **What v0 does not do.** The usage quantities are Cost Explorer's; only the prices are ours. Reconstructing
  the quantities from the inventory history (instance hours, GB-months, NAT bytes from the watcher) is the next
  step, and the one that makes the eval independent of Cost Explorer.

Results are stored in `reconciliations` (one JSON per month) and summarised on the Overview.

## Auto-actions: the executor

The brief behind it: an agent that watches the numbers and makes the small adjustments a person would never
bother making all day: turn things down when nothing needs them, turn them back up before something does,
move what is cold to cold storage. The dollar amount is beside the point; the point is that it happens every
hour without anyone remembering. `src/executor.ts` is that loop, the Auto-actions page is its ledger, and
`src/actions/*` is the catalog: one module per adjustment, each with the same four verbs.

- **plan** reads the facts with the advisor's ordinary read credentials and proposes changes, each with its
  before, its after, the numbers that justify it, an estimate at list price and how to undo it.
- **apply** makes one change under the actuator role.
- **verify** reads the change back with the read credentials.
- **revert** undoes it (the Revert button on the row).

**Modes** (Settings › Auto-actions, `ACT_MODE`): `off` runs nothing; `dry_run` (the default) records every
proposal in the ledger and touches nothing; `apply` applies the proposals up to the per-pass cap
(`ACT_MAX_PER_PASS`). In `dry_run` you can still press **Apply** on one row: a human decision, made under the same
role. The pass runs on `ACT_CRON` (hourly at :45, so a change is in place before the hour it is for), from
**Run pass now** on the page and from Run now on the Settings row; **Preview plan** shows what a pass would
propose without recording it. Every applied, failed or reverted row is posted to Sphinx (quiet hours respected)
with what changed, why, the estimate, how to undo and a link to the row.

**A role narrower than the policy.** The page prints the full policy, but the role may carry less. The executor
checks what the role can actually do per action (`ACTUATOR_NEEDS` in `src/permissions.ts`: the calls apply and
revert make), through `iam:SimulatePrincipalPolicy` from the read identity when it has that permission (it is in the
read policy; cached ten minutes) and, whatever the case, from denied applies (a denial is remembered per IAM
action until the role allows it again). The simulation runs against a wildcard resource, so a statement scoped to
specific ARNs (one environment, one bucket) comes back as an implicit deny: that counts as **unproven**, not as
missing. Only an explicit Deny or a real AccessDenied learned from an apply blocks a kind. A kind the role cannot
apply shows "by hand: role lacks …" instead of Apply, the pass leaves its rows for a person with a note, and the
API refuses them; the same for Revert. Where a kind spans resource families (the consent tag on an instance or
on an environment) each row is judged on its own family's calls.

**Deleting rows.** Any row can be deleted from its expanded detail on the page (`POST /api/actions/delete` with
`ids`): its executor events and its chat thread go with it, and its node leaves the graph. A row that never
changed anything (proposed, failed, refused, stale) goes on one click; a row that changed AWS (applied, verified,
reverted) is the record of that change, so the page asks twice and the API needs `force: true`. The change itself
stays on AWS either way.

**The activity log.** The ledger says what each proposal became; the log says what the actuator did, in order.
`src/executor_log.ts` records every pass, scheduled or manual, including the ones that did nothing because the
mode was off or the executor was paused, with its counts, its module notes and every line it printed (what each
action looked at, what it proposed, what waited on the cap, the grace period or Jev), and every apply, read-back
and revert on a row with its outcome and who triggered it (`schedule`, `manual`, the chat). Auto-actions › Activity
shows it, collapsed by default: click a pass for its changes and its lines; an entry outside a pass is an Apply,
Check or Revert someone made by hand. `GET /actions/log` returns it, `GET /actions/:id` carries the row's own
history as `events`, and the log keeps 90 days. Every pass is mirrored into the graph as an `AdvisorPass` node with
a `TOUCHED_IN` edge from each row it applied, read back or reverted.

**The actuator role.** `ACT_ROLE_ARN` is the only identity that ever changes AWS. The executor assumes it from the
read credentials for the change itself and for nothing else; the read role never gains a write action. The page
shows the permissions policy to put on it (`actuatorPolicy` in `src/permissions.ts`: `rds:ModifyDBCluster`,
`ec2:ModifySnapshotTier`, `ec2:RestoreSnapshotTier`, the describes those need, `ec2:CreateTags`/`DeleteTags` for the
`advisor:schedule` key alone, and a **Deny on anything tagged `advisor:hands-off`**) and the trust policy naming the
advisor's read identity. It carries no Route 53 write: the right to re-point an instance's A records after a start is
part of that instance's Auto-park grant (below). Without a role the executor is
dry-run only and "acts as" on the page says so. Every plan also skips a hands-off tag itself, and a change
that failed three times in a day is refused until the next day.

#### Elastic Beanstalk environments

Beanstalk owns the Auto Scaling group behind an environment: its CloudFormation stack tracks MinSize and MaxSize, so
a size set on the group directly is overwritten by the next configuration change or platform update, and the
environment's own trigger scales the group back to what its configuration says. The capacity action therefore
changes the environment's option settings (`aws:autoscaling:asg`) through `UpdateEnvironment`, and the read policy
carries the describes that need (`DescribeConfigurationSettings`, `DescribeEnvironmentResources`,
`ListTagsForResource`, `autoscaling:Describe*`).

Who does the CloudFormation and Auto Scaling work depends on the environment. With an **operations role** attached,
Beanstalk assumes that role for the update and the actuator needs `elasticbeanstalk:UpdateEnvironment` alone, which
is what `actuatorPolicy` grants (on environments tagged `advisor:scale` only). Without one, Beanstalk uses the
caller's permissions, and the actuator would need `cloudformation:UpdateStack`, `autoscaling:UpdateAutoScalingGroup`
and the rest of what the update makes. Attach a role once per environment instead of widening the actuator:

```sh
aws iam create-role --role-name aws-elasticbeanstalk-operations-role --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"elasticbeanstalk.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
aws iam attach-role-policy --role-name aws-elasticbeanstalk-operations-role --policy-arn arn:aws:iam::aws:policy/AWSElasticBeanstalkManagedUpdatesCustomerRolePolicy
aws elasticbeanstalk associate-environment-operations-role --environment-name <env> --operations-role arn:aws:iam::<ACCOUNT_ID>:role/aws-elasticbeanstalk-operations-role
```

`describe-environments` shows the role as `OperationsRole`; the pass notes name every tagged environment without one.

**Older environments.** The managed-updates policy allows what a stack update makes (re-tagging the balancer's
security group, modifying the target group, even describing the listeners) only on resources that carry Beanstalk's
own tags (`elasticbeanstalk:environment-id` and the like). Environments created before Beanstalk stamped those, or
whose resources were rebuilt outside the normal path, do not have them, so the first update under the operations role
fails on exactly those resources and leaves the CloudFormation stack in `UPDATE_ROLLBACK_FAILED`. The pass checks the
tags on every tagged environment with an operations role and says so in its notes before proposing anything. The
remedy is the Beanstalk-scoped admin policy on the operations role: the role is assumed by the Beanstalk service
alone (its trust policy), never by the advisor, so it carries what a person clicking in the console carried before:

```sh
aws iam attach-role-policy --role-name aws-elasticbeanstalk-operations-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess-AWSElasticBeanstalk
```

A stack already left in rollback is cleared once by a person (the rollback runs with their own rights), after which
updates go through the operations role again:

```sh
aws cloudformation continue-update-rollback --stack-name awseb-<env id>-stack
aws cloudformation wait stack-rollback-complete --stack-name awseb-<env id>-stack
```

**The application bundle.** A configuration update (a MinSize change included) re-stages the running application
version: Beanstalk copies its source bundle into its own bucket (`elasticbeanstalk-<region>-<account>`, under
`resources/environments/<env id>/_runtime/_versions/`), and with an operations role attached it does so **as the
operations role**. The managed policies on that role cover only the `elasticbeanstalk-*` buckets, which is enough
for versions uploaded through the console or the EB CLI. A version your CI uploaded to its own bucket is not
covered: the update fails with "Failed to deploy configuration … You don't have permission to copy an Amazon S3
object", MinSize stays where it was, the row's read-back fails and the pass does not mistake the old minimum for a
hand-set. Before the operations role, updates ran with the caller's rights, which is why this surfaces the day the
role is attached. Give the operations role read on the bundle bucket (only Beanstalk can assume it):

```sh
aws iam put-role-policy --role-name aws-elasticbeanstalk-operations-role --policy-name ReadAppBundles --policy-document '{
  "Version": "2012-10-17",
  "Statement": [{ "Effect": "Allow",
    "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectAcl", "s3:GetBucketLocation", "s3:ListBucket"],
    "Resource": ["arn:aws:s3:::<bundle bucket>", "arn:aws:s3:::<bundle bucket>/*"] }]
}'
```

A bundle bucket encrypted with a customer-managed KMS key also needs `kms:Decrypt` on that key for the role, and a
bucket policy that names its readers must name the role. The actuator itself needs no S3 rights for this.
The capacity pass and the pressure check check this before proposing: they read where the running version's
bundle lives (`DescribeApplicationVersions`) and, outside `elasticbeanstalk-*`, ask IAM whether the operations role
may read it (`iam:SimulatePrincipalPolicy`, cached an hour). A denial holds every MinSize and MaxSize change for the
environment and the pass notes carry the command above with the bucket filled in; a check that could not run is a
note only.

Tag writes are the one thing the operations role does not cover: Beanstalk applies `UpdateTagsForResource` as an
environment update under the caller's own rights, so the consent tags on an environment are written by a person
(the **run as me** box on the switch and on the ledger, with temporary credentials used once).

##### The learned week

With a band on the environment the pass sizes MinSize per hour of the week instead of by hand
(`src/capacity_pattern.ts`). Every hourly pass sizes each of the last 28 days' hours from what the group did in
it (`src/capacity_signals.ts`), folds the result into the 168 hours of the week and takes, per hour, the p95
across the weeks seen (the maximum while there are fewer than three). The trigger's desired capacity (replayed
from the scaling activities) is not the measure: it can never fall below the MinSize in force, so a group held at
6 would learn 6 forever. Instead each hour gets one estimate per signal and the largest wins:

| Signal | Source | Members the hour needed |
|---|---|---|
| CPU | `AWS/EC2` CPUUtilization by the group | members × CPU ÷ `ACT_EB_TARGET_CPU` (60 %) |
| Memory | CloudWatch agent `mem_used_percent` (by the group, else by its members), else the probes | members × (memory − idle footprint) ÷ (`ACT_EB_TARGET_MEM` (75 %) − idle footprint); the footprint is the group's p5; within 10 points of the target the hour keeps its members |
| Requests | the environment's ALB `RequestCount` | requests ÷ the most one member served in a healthy hour |
| Network in / out | `AWS/EC2` NetworkIn / NetworkOut by the group | bytes ÷ 60 % of the instance type's baseline bandwidth (`DescribeInstanceTypes`), else the most one member moved in a healthy hour |
| Disk | CloudWatch agent `disk_used_percent`, else the probes | a member disk at `ACT_EB_HIGH_DISK` (85 %) or more: keeps the members it ran |
| Latency / 5xx | ALB `TargetResponseTime`, `HTTPCode_Target_5XX_Count` | over twice the healthy median, or 5xx ≥ 1 % of requests: keeps the members it ran |

A healthy hour has CPU and memory under target and normal latency and 5xx; per-member rates need 24 of them.
The busiest healthy hour is proof, so no hour needs more members than ran it well and the group is never assumed
to serve more per member than it has served well (as quiet hours run leaner the
proven rate rises by itself). An hour with no signal falls back to the capacity the trigger ran. Without the
CloudWatch agent or probes on the members, memory and disk do not size anything, and the pass notes say so. A single hour lower than both its neighbours is lifted to the lower one (a one-hour dip saves nothing and costs
two environment updates). The
timeline shows which signal set each hour (`capacity_binding` in the graph). A **pressure event** (the group pinned at its ceiling with
high CPU, or memory at `ACT_EB_HIGH_MEM` (90 %) when the agent reports it, recorded by the pressure check) lifts that hour and the one before it to the capacity that ran plus
one. The band clamps everything: never below the bare minimum, never above the ceiling. Once the pattern is
confident (two weeks, four fifths of the hours covered) the pass fifteen minutes before each hour sets MinSize
to the learned value when it differs, so capacity is warm before the hour that needs it and back at the bare
minimum in the hours that never did; the windowed schedule and the idle-floor trim step aside while the pattern
is in force (the ceiling raise still runs). A MinSize set by hand holds for a day before the pattern resumes.
The pattern lives in `capacity_patterns`, the events in `capacity_pressure_events`, and both are mirrored to the
graph on the group's `AdvisorNodePool` node (`capacity_learned_min`, `capacity_floor`, `capacity_ceiling`,
`capacity_summary`, `capacity_binding`, `capacity_signals`, `PRESSURED_AT` edges to `AdvisorPressureEvent`); Jev's group review reads the same record,
and the Concept "The learned hourly minimum of a Beanstalk group" holds the rule.
The tag is the band the executor may move within: `advisor:scale=2-8` means the floor never goes under 2 and the
ceiling never over 8, whatever the usage says.

#### Consent switches: `AdvisorAutoPark` and `AdvisorAutoScale`

One label per resource says whether the advisor may take it down, and the page flips it (`src/consent.ts`):

- **`AdvisorAutoPark=ON`** on an instance: the executor may stop and start it when the evidence says so. Idle
  parking (stopped after `ACT_PARK_IDLE_DAYS` quiet days, woken on demand) and the usage schedule (stopped in the
  confident quiet windows of its [usage profile](#usage-profiles), started before the busy ones) both read it, and
  neither needs a further approval: the tag is the consent. A box without an Elastic IP is accepted: the stop
  records the A records that name its address and the start points them at the new one. The **Stop** and
  **Start** buttons on the EC2 detail work only on a box that carries it (`POST /api/inventory/ec2/:id/power`),
  as manual office-hours rows on the ledger. `OFF` means the executor never stops or starts the box, whatever
  else it is tagged. The older `advisor:park=auto` and `advisor:schedule` tags keep working as they did.
- **`AdvisorAutoScale=ON`** on an Elastic Beanstalk environment: the capacity action may move the group's
  MinSize and MaxSize, floor 1 and the ceiling where it is unless **`AdvisorScaleBand=<floor>-<ceiling>`** widens
  it (`advisor:scale=<band>` is the older spelling). Beanstalk propagates the tag to its group and its balancer,
  so the environment is the one place to tag; the switch sits on the balancer's detail in the inventory, with the
  band's two fields under it: the **bare minimum** (MinSize never goes below it) and the **ceiling** (MaxSize
  never goes above it), written as `AdvisorScaleBand` through the same ledgered row (`POST
  /api/inventory/beanstalk/:env/band`, empty both to remove). Between them the executor sizes the group from its
  [learned week](#the-learned-week) and answers pressure at the ceiling at once.

The switch writes the tag through the actuator role as a `consent_tag` row (Revert puts the previous value back),
and the IAM policy lets the role write these keys and no other. The stop, start and scaling grants carry the same
tag conditions (`aws:ResourceTag/AdvisorAutoPark = ON`, `aws:ResourceTag/AdvisorAutoScale = ON`), so the consent
is enforced on the role, not only in the code: a bug in the page cannot stop an untagged box.

**The catalog today**

| action | what it does | when it leaves things alone |
| --- | --- | --- |
| Serverless v2 minimum by hour of day (`src/actions/acu_window.ts`) | From the load profile's capacity per UTC hour over fourteen days (`by_hour` in `rds_load_profiles`, p95 per hour), sets an Aurora Serverless v2 cluster's minimum to the floor (`ACT_ACU_FLOOR`, 0.5) before two quiet hours and back to the minimum the owner configured before a working hour or the daily burst. Moves only within [floor, owner's minimum]; an owner's own change to the minimum becomes the new band; the maximum is never touched. Estimate: the band × quiet hours × 0.12 USD/ACU-hour. | no profile or one older than 30 h; fewer than four quiet hours a day; bursts every hour; the cluster busy right now; the owner's minimum already at the floor; `advisor:hands-off`; cluster not `available` |
| gp3 IOPS trimmed to the 30-day peak (`src/actions/ebs_iops_trim.ts`) | gp3 volumes above the free 3,000 IOPS whose 30-day peak stays under 30 % of what is provisioned (the review's `ebs_overprovisioned_iops`): `ModifyVolume` to twice the peak rounded up to 500, never under 3,000, online. Estimate: the IOPS removed × 0.005 USD/month. EBS allows one modification per volume per six hours, so a recent modification waits and the revert says so. Throughput is left alone (no metrics yet). | fewer than 5 days of metrics, peak above 30 %, a modification in flight or under 6 h old, `advisor:hands-off`, not gp3 any more |
| Log groups with no retention get one (`src/actions/log_retention.ts`) | every group with no retention policy and at least 100 MB stored: `PutRetentionPolicy` with `ACT_LOG_RETENTION_DAYS` (90, snapped to a value CloudWatch accepts). An existing retention is never lowered. Estimate: the stored GB beyond that many days of ingestion × 0.03 USD. The one action that is not fully reversible: lifting the policy keeps what is left, the events already purged are gone, hence the long default. | groups under 100 MB (unless approved), a retention already set, `advisor:hands-off` |
| S3 request metrics where they would change a lifecycle decision (`src/actions/s3_request_metrics.ts`) | buckets at or above `ACT_S3_MIN_GB` (20) with no entire-bucket metrics configuration whose stored [usage analysis](#s3-lifecycle-rules-from-usage) fell back to Intelligent-Tiering for want of read data, and where the cold Standard bytes (older than 30 days) could save at least twice the metrics price under a sharper class (Standard to Glacier Instant Retrieval, about 0.019 USD/GB-month, so roughly 530 GB and up): `PutBucketMetricsConfiguration`, so CloudWatch publishes GetRequests, PutRequests and BytesDownloaded. Costs about 5 USD per bucket per month in CloudWatch metrics (the row says so, with the cold GB and the saving ceiling; no saving is claimed). Reversible in one call. | buckets under the threshold, a configuration already there, no analysis stored yet, a whole-bucket expiration at 30 days or less (nothing gets old enough to move), a transition rule already on the bucket, under 1 GB cold, or a saving ceiling below twice the metrics price; each with its reason in the pass notes |
| EBS snapshots to the Archive tier (`src/actions/snapshot_archive.ts`) | Every completed snapshot the account owns, per region, through the SDK: older than `ACT_SNAPSHOT_MIN_AGE_DAYS` (90), standard tier, not behind an AMI, not AWS Backup's or DLM's, and either the newest remaining standard snapshot of a volume that no longer exists (the chain drains one per pass, newest first, because an archived snapshot becomes a full copy) or the only snapshot of a live volume. `ModifySnapshotTier`; the read-back is `DescribeSnapshotTierStatus`, so the row stays `applied` until the archival completes. Estimate: size × (0.05 − 0.0125) USD/GB-month, a ceiling. Revert is a permanent `RestoreSnapshotTier` (24 to 72 hours). | younger snapshots, AMI-backed, Backup/DLM-managed, `advisor:hands-off`, an older sibling of a gone volume, one of several snapshots of a live volume |
| Aurora storage type, once approved (`src/actions/aurora_storage.ts`) | An approved recommendation of `aurora_set_storage_iopt` or `aurora_set_storage_standard` (any tier: the approval is the decision) becomes `ModifyDBCluster` with the storage type, applied immediately, online, no failover. The newest approval per cluster wins; every approved recommendation for the cluster is marked done once the change is read back. Estimate: the recommendation's own figure. | no approved recommendation; cluster not `available`; already on that storage; a switch to I/O-Optimized less than 30 days after the last (`IOOptimizedNextAllowedModificationTime`); `advisor:hands-off` |
| S3 lifecycle rules, once approved (`src/actions/s3_lifecycle.ts`) | An approved `review_s3_lifecycle` recommendation (the [usage analysis](#s3-lifecycle-rules-from-usage) files one per bucket with the exact rule JSON in its evidence): `PutBucketLifecycleConfiguration` with the rules merged into the ones already there (same id replaces, the rest kept). Revert restores the previous configuration exactly; objects a transition already moved stay in their class. | no approved recommendation; every rule already on the bucket; `advisor:hands-off` |
| gp2 volumes moved to gp3 (`src/actions/ebs_gp3_migrate.ts`) | every gp2 volume in the inventory: `ModifyVolume` to gp3 with IOPS at three per GiB when that is above the 3,000 baseline and 250 MiB/s from 170 GiB, so the volume performs at least as it did. Online, reversible (back to gp2), one modification per volume per six hours. Estimate: 0.02 USD/GB-month minus the extra IOPS and throughput. | a modification in flight or under 6 h old; a target that would not be cheaper; `advisor:hands-off` |
| ECR repositories without a lifecycle policy get one (`src/actions/ecr_lifecycle.ts`) | every repository with no policy whose untagged images reach 1 GB or twenty: `PutLifecyclePolicy` with one rule, untagged images older than `ACT_ECR_UNTAGGED_DAYS` (30) expire. Tagged images are never touched; an existing policy, whatever it says, is left alone. Estimate: the bytes already past the threshold × 0.10 USD/GB-month. Removing the policy stops the expiry; images it deleted do not come back. | a policy already there; under 1 GB and fewer than twenty untagged; `advisor:hands-off` |
| Idle swarms parked (`src/actions/swarm_park.ts`) | `docs/park-swarms-plan.md` built: a running instance tagged `advisor:park=auto` whose probe roll-ups show no use for `ACT_PARK_IDLE_DAYS` (7) consecutive days (no external connection, no front-door request, no use-signal line in any container log, under 50 MB/day out, every container under 1 % CPU, with a probe there every day) is stopped with `StopInstances` and tagged `advisor:parked`. Never terminated; volumes, data and the Elastic IP stay. The proposal is announced in the Sphinx chat when first made and the pass waits `ACT_PARK_GRACE_HOURS` (24) before stopping (Apply on the page does not wait). Revert, or "wake &lt;name&gt;" in the chat (`wake_swarm`, the one write tool the chat has), starts it again. Swarm-named instances that would qualify but are not tagged are listed in the pass notes. The actuator policy allows `StopInstances`/`StartInstances` only on instances carrying the tag. `AdvisorAutoPark=ON` is the same consent, and with it a box without an Elastic IP is parked too: the stop records the A records naming its address and the wake points them at the new one. Estimate: the instance's list price. | not tagged `advisor:park=auto`; any signal alive or missing (a missing probe counts as alive); no Elastic IP; a pool member; an open alert on it; parked or woken in the last 48 h; woken twice in a week (flapping) |
| gp3 throughput trimmed to the 30-day peak (`src/actions/ebs_throughput_trim.ts`) | gp3 volumes above the free 125 MiB/s whose 30-day peak (VolumeReadBytes + VolumeWriteBytes per five minutes, read by the plan through GetMetricData) stays under 30 % of what is provisioned: `ModifyVolume` to twice the peak rounded up to 25 MiB/s, never under 125, never above 1,000, never above a quarter of the volume's IOPS (the gp3 ratio limit), online. Estimate: the MiB/s removed × 0.04 USD/month. One modification per volume per six hours, so a recent modification waits and the revert says so. | fewer than 5 days of metrics, peak at or above 30 %, a modification in flight or under 6 h old, an open IOPS trim on the same volume (it goes first), `advisor:hands-off`, not gp3 any more |
| EFS file systems without a lifecycle policy get one (`src/actions/efs_lifecycle.ts`) | every available file system with no lifecycle policy and at least 1 GiB in Standard: `PutLifecycleConfiguration` with TransitionToIA after `ACT_EFS_IA_DAYS` (30, snapped to 1/7/14/30/60/90/180/270/365) and TransitionToPrimaryStorageClass AFTER_1_ACCESS, so a file read once comes back to Standard and never pays IA access twice. Estimate: a ceiling, half the Standard GB × (0.30 − 0.016) USD; how much is cold is unknown until the policy runs. Revert puts an empty configuration back; files already in IA stay there until read. | a policy already there (whatever it says), under 1 GiB in Standard, state not available, `advisor:hands-off` |
| Stale alarms on gone resources deleted (`src/actions/alarm_cleanup.ts`) | Metric alarms in INSUFFICIENT_DATA for `ACT_ALARM_STALE_DAYS` (30) whose InstanceId, VolumeId, NatGatewayId, DBInstanceIdentifier, DBClusterIdentifier (a describe call no longer returns it) or FunctionName (the Lambda inventory marks it gone) names a resource that no longer exists: `DeleteAlarms`, with the full `PutMetricAlarm` definition saved on the row so Revert recreates it as it was (state history excepted). Estimate: 0.10 USD/alarm-month, 0.30 for a period under 60 s. At most 50 per pass. | younger alarms; resources that still exist or could not be checked (a failed describe never counts as gone); dimensions the executor cannot check (load balancers, custom namespaces); composite alarms; `advisor:hands-off` |
| Log retention shortened where nobody queries (`src/actions/log_retention_tune.ts`) | Only groups whose current retention is exactly what a verified `log_retention` row set. Every pass records the Logs Insights query history (`DescribeQueries` keeps only recent queries, so it accumulates in `log_query_history`) and the date recording began. Once that history covers `ACT_LOG_QUIET_DAYS` (90), a group nobody queried in the window and with no subscription filter drops to `ACT_LOG_QUIET_RETENTION_DAYS` (30, snapped). Estimate: stored GB beyond that many days of ingestion × 0.03 USD. Events past the new retention are purged, which the row says; revert puts the old retention back for what is left. | a retention a person set or changed after the executor set it, history shorter than the quiet window (the note says how many days to go), a query in the window, a subscription filter on the group, `advisor:hands-off` |
| Unattached Elastic IPs released, once approved (`src/actions/eip_release.ts`) | An approved `release_eip` recommendation (the eip_unattached rule, one per allocated address with no association): `ReleaseAddress`, after the proposal is announced in the Sphinx chat and the pass has waited `ACT_DELETE_GRACE_HOURS` (24). Still unattached when the pass looks, or nothing happens. Estimate: 3.65 USD/month per address. Revert is AWS's recovery path, `AllocateAddress` with the same address, which works while nobody else has been allocated it; after that the address is gone and the revert says so. | associated now (instance, interface); `advisor:hands-off`; already released (the recommendation is marked done) |
| EBS snapshots deleted, once approved (`src/actions/snapshot_delete.ts`) | An approved `delete_snapshot` recommendation (the old_snapshot rule): `DeleteSnapshot`, after the proposal is announced in the Sphinx chat and the pass has waited `ACT_DELETE_GRACE_HOURS` (24). Estimate: size × 0.05 USD/GB-month standard, × 0.0125 archived, a ceiling. No revert: a deleted snapshot cannot be recovered, and the row and the Sphinx message say so. | behind an AMI; managed by AWS Backup or DLM; `advisor:hands-off`; not completed; an archive by snapshot_archive proposed or in flight; already deleted (the recommendation is marked done) |
| Gateway endpoints for S3 and DynamoDB, once approved (`src/actions/vpc_gateway_endpoint.ts`) | An approved `add_vpc_endpoint` fix from the NAT investigator (resource a VPC, NAT gateway or instance id; S3 unless the fix only names DynamoDB, both when it names both): `CreateVpcEndpoint` of type Gateway on the route tables that send 0.0.0.0/0 through a NAT gateway (every route table of the VPC when none does, and the row says so), tagged `advisor:created`. Free: no hourly or per-GB charge; existing connections are not interrupted. Estimate: the recommendation's own figure. Revert deletes the endpoint and traffic goes back through the NAT. | no approved recommendation; the VPC already has a gateway endpoint for the service (the recommendation is closed as done by hand); VPC tagged `advisor:hands-off`; resource not a VPC, NAT or instance id; the VPC has no route table |
| Unused KMS keys scheduled for deletion, once approved (`src/actions/kms_key_retire.ts`) | Customer-managed keys older than 90 days that nothing the advisor sees encrypts (EBS volumes and snapshots, RDS instances and clusters, log groups) and that CloudTrail shows no cryptographic call against in 90 days (LookupEvents by key ARN; DescribeKey and tag reads do not count) get a tier-approve `kms_key_unused` recommendation. Approving it is the decision: `ScheduleKeyDeletion` with `ACT_KMS_PENDING_DAYS` (30), announced in Sphinx and held `ACT_DELETE_GRACE_HOURS` (24) first; Revert is `CancelKeyDeletion` then `EnableKey`, intact until the period ends. Estimate: 1 USD per key-month. 25 CloudTrail lookups per pass. | AWS-managed, disabled, multi-region or young keys; anything referencing the key; any real CloudTrail event; `advisor:hands-off`; CloudTrail unreadable (usage unknown = used); no approved recommendation |
| Idle load balancers deleted, once approved (`src/actions/idle_load_balancer.ts`) | ALBs, NLBs and gateway load balancers older than 30 days whose CloudWatch metrics (RequestCount and ProcessedBytes; ActiveFlowCount and ProcessedBytes; ProcessedBytes) all summed to zero over 30 days and with no healthy target get a tier-approve `elb_idle` recommendation. Approving it is the decision: `DeleteLoadBalancer`, announced and held `ACT_DELETE_GRACE_HOURS` first, with the listeners, target groups and attributes saved on the row (target groups are not deleted). No automatic revert. Estimate: 0.0225 USD/h (16.43/month) for ALB and NLB, 0.0125 USD/h for GWLB. | classic ELBs (not covered); a missing metric (unknown = traffic); any healthy target or unreadable target health; deletion protection on; `advisor:hands-off`; not idle any more at apply time; no approved recommendation |
| DynamoDB capacity mode from the 30-day load, once approved (`src/actions/dynamodb_capacity_mode.ts`) | Every table (100 per pass, per region) priced both ways from 30 days of CloudWatch consumed and provisioned units at list (RCU 0.00013 and WCU 0.00065 USD/h; on-demand 0.125 USD per million reads, 0.625 per million writes). Where the other mode is at least 20 % and 5 USD/month cheaper a tier-approve recommendation is filed (rule `dynamodb_capacity_mode`); once approved, `UpdateTable` switches the mode, online. Going to provisioned, table and index units are set to the busiest hour plus 30 %. Estimate: the recommendation's own difference. Revert switches back with the previous units. | fewer than 14 days of metrics (a table's age stands in when it has none); saving under 20 % or 5 USD; table not ACTIVE; a global table; application auto scaling on (or unreadable) when going to on-demand; a switch to on-demand in the last 24 h (AWS allows one per day); `advisor:hands-off` |
| T-family credit specification from the 30-day credit usage, once approved (`src/actions/cpu_credit_spec.ts`) | Running t2/t3/t3a/t4g instances: from 30 days of CPUSurplusCreditsCharged, CPUCreditBalance and CPUUtilization. Unlimited → standard is recommended where surplus credits cost at least 5 USD and a tenth of the instance's month while the CPU averages under the size's baseline (the bursts are occasional; standard throttles them instead of billing). Standard → unlimited where the credit balance hit zero on three or more days (the instance was throttled; the recommendation carries the cost, no saving claimed). A tier-approve recommendation (rule `cpu_credit_spec`) per instance; once approved, one `ModifyInstanceCreditSpecification`, online, no restart. Estimate: the surplus charge per month (→ standard) or none (→ unlimited). Revert sets it back. | fewer than 14 days of metrics; surplus under the thresholds or CPU above the baseline; balance zero on fewer than 3 days; pool members; `advisor:hands-off` |
| Office-hours schedules for tagged instances and databases (`src/actions/schedule_hours.ts`) | An EC2 instance, RDS instance or Aurora cluster tagged `advisor:schedule` (e.g. `weekdays 08-20 Europe/Madrid`; several windows joined by ` \| `, or off windows `off daily 01-06 UTC \| off weekends 00-24 UTC` naming the hours to be stopped, the form the usage agent decides in) runs only in that window: at :45 the pass decides for the top of the coming hour, `StopInstances`/`StopDBInstance`/`StopDBCluster` when it is running outside the window, the matching start when it is stopped inside it. The tag is the consent: no grace, no announcement; the actuator policy allows the calls only on tagged resources. A stopped RDS instance is started by AWS after seven days; the next scheduled stop takes it down again. Revert is the opposite call, and a box a person woke by hand is left running until the window closes. A box without an Elastic IP gets a new public address on start: the stop row records the A records in the account's zones that name the old address (`dns_records`), the start waits up to 150 s for the new address and points them at it (`route53:ChangeResourceRecordSets`, UPSERT of A records only, the routing kept), and the row and its read-back say which names moved or, if the address never came, that DNS was not updated. Estimate: the inventory's monthly price × the share of the week outside the window. | no `advisor:schedule` tag; a tag the parser rejects (the note says why); `advisor:hands-off`; EC2 pool members; states other than running/stopped (pending, stopping, modifying wait); RDS read replicas or instances with replicas; Multi-AZ SQL Server; RDS instances inside a cluster (tag the cluster); a cluster whose members are not all available; a resource the executor stopped and someone started by hand in the last 12 h |
| Incomplete multipart uploads aborted on every bucket (`src/actions/s3_multipart_abort.ts`) | Every bucket in the inventory (100 largest per pass) without an enabled whole-bucket abort rule: `PutBucketLifecycleConfiguration` adding `aws-advisor-abort-incomplete-multipart` (abort after `ACT_MULTIPART_DAYS`, 7) merged with the existing rules, which are kept as they are. The same rule id the usage analysis proposes, so that part of the lifecycle recommendation becomes moot once this has run. Parts of an abandoned upload bill as Standard and never appear in a listing; completed objects are never touched. No estimate is claimed: the analysis counts the uploads but not their bytes. Revert restores the previous configuration; a bucket that had none keeps the rule Disabled. | a whole-bucket abort rule already enabled (a prefixed or disabled one does not count); `advisor:hands-off`; buckets past the 100-per-pass cap wait |
| Usage schedules tagged on instances, once approved (`src/actions/usage_schedule.ts`) | An approved `usage_schedule` recommendation (the [usage profile](#usage-profiles) files one for a running standalone instance whose quiet hours are confident, at least 0.85, and add up to 20 h a week or more): one `CreateTags` of `advisor:schedule=<window>` on the instance, e.g. `weekdays 07-19 UTC`, the smallest window that keeps the box up whenever it was ever used plus an hour each side. From then on the office-hours action above stops it outside the window, starts it before the window opens and re-points its DNS records. Revert removes the tag. The actuator policy lets the role write and delete this one tag key on instances and no other. | no approved recommendation; `advisor:hands-off`; pool members; a box not running; a box already tagged `advisor:schedule` by someone (never overwritten; a tag equal to the recommendation marks it done) |
| Consent switches flipped from the page (`src/actions/consent_tag.ts`) | `AdvisorAutoPark` on an instance (`CreateTags`) or `AdvisorAutoScale` or `AdvisorScaleBand` on an environment (`UpdateTagsForResource`, which IAM checks as `elasticbeanstalk:AddTags` / `RemoveTags`; Beanstalk then applies the change as an environment update under the caller's own rights, operations role or not, so with a narrow actuator the row fails on read-back and offers **run as me**, which every ledger row offers: the person pastes temporary credentials of their own (ASIA… with a session token; long-lived keys are refused) and the advisor makes that one call with them, in memory, attributed to their identity on the row as `person:<arn>`, credentials forgotten on return; `POST /api/actions/:id/as-person`. A person authorises one change that way without widening the actuator), from the switch on the Inventory page, applied at once and ledgered. Never planned by the pass. Revert puts the previous value back or removes the tag. | everything: a switch is a person's decision; `advisor:hands-off` refuses it |
| Lambda memory right-sized from the REPORT lines, once approved (`src/actions/lambda_memory.ts`) | Functions with `ACT_LAMBDA_MIN_INVOCATIONS` (1,000) or more invocations in 14 days (40 per pass): one Logs Insights query on `/aws/lambda/&lt;name&gt;` over the REPORT lines gives the peak and average memory used, the p95 and average duration and the count. Where the peak stays under half of the configured memory and 100+ reports back it, a tier-approve `lambda_memory` recommendation is filed: target = peak + 50 % headroom rounded up to 64 MB, never under 128, at least one step below the current setting, worth at least 1 USD/month in GB-seconds. Approval-tier because CPU scales with memory, so a lower setting can lengthen the duration. Once approved, `UpdateFunctionConfiguration`, online; Revert puts the old memory back. Estimate: the GB-second difference at the observed average duration and invocation rate. | fewer than 100 REPORT lines; peak over 50 % of configured; already at 128 MB; saving under 1 USD; no log group; function not Active; memory changed since the window; `advisor:hands-off`; no approved recommendation |
| Elastic Beanstalk ceiling raise under pressure now (`src/actions/beanstalk_pressure.ts`) | On its own cadence (`ACT_PRESSURE_CRON`, every ten minutes): an environment tagged `AdvisorAutoScale=ON` with an `AdvisorScaleBand` whose group is at its MaxSize, every member in service, with the average CPU of the last ten minutes at or above `ACT_EB_HIGH_CPU`, or the members' memory at or above `ACT_EB_HIGH_MEM` (CloudWatch agent `mem_used_percent`, when installed), gets MaxSize + 1 up to the band's ceiling, one `UpdateEnvironment`, applied in the same pass (urgent: Jev's opinion is recorded as advice, not waited on). One raise per environment per thirty minutes. Every pressure seen is a pressure event for the learned week, raise or not; at the ceiling already the pass notes say to raise the band. | no band, the trigger still has room, members still launching, CPU and memory under their lines, the environment not Ready |
| Elastic Beanstalk capacity bounds from the group's 14-day usage (`src/actions/beanstalk_scale.ts`) | An environment tagged `advisor:scale=<floor>-<ceiling>` (e.g. `2-8`; `auto` = floor 1, the ceiling stays) has its configured `aws:autoscaling:asg` MinSize/MaxSize moved one step at a time, through `UpdateEnvironment` so the change survives deployments (a size set on the group directly is overwritten by the next configuration change, and Beanstalk's own trigger scales the group back). From 14 days of the group's hourly average CPU (`CPUUtilization` by `AutoScalingGroupName`) and its scaling activities, whose causes ("changing the desired capacity from 2 to 3") let the pass replay the desired capacity hour by hour: the floor comes down by one when the group sat at its minimum for 90 % of the window with the p95 hourly CPU under `ACT_EB_LOW_CPU` (30 %), so one instance fewer stays under twice that; the ceiling goes up by one when the group spent `ACT_EB_PRESSURE_HOURS` (3) or more hours pinned at its maximum with the CPU at or above `ACT_EB_HIGH_CPU` (70 %), which adds cost and the row says so. Pressure wins over an idle floor. A third move follows the group's day: when the [usage profile](#usage-profiles) of the group (`asg:<name>`, its CPU and its balancer's requests) has confident quiet windows adding up to 20 h a week or more, the pass before two quiet hours sets MinSize to the tag's floor and the pass before a working hour puts the configured minimum back (the same dance as the Serverless v2 minimum; a minimum the owner changes by hand becomes the new baseline, kept under `act:eb:<environment id>`), and the idle-floor trim is skipped while that schedule is in force. The environment updates for a minute or two, no instance is replaced; the group scales in to a new floor when Beanstalk's scale-in alarm next fires (the row says whether it is in ALARM already). Revert puts the previous bound back. The actuator policy allows `UpdateEnvironment` only on a tagged environment; with an operations role on the environment that is all it needs, without one Beanstalk uses the caller's rights and the pass notes say so (see [Elastic Beanstalk](#elastic-beanstalk-environments)). Estimate: one member's list price for a floor cut. | no `advisor:scale` tag, or one that does not parse; `advisor:hands-off`; a single-instance environment; status other than Ready; fewer than 7 days of metrics; the live group's bounds differ from the configuration (edited directly); health not Ok while a floor cut is due; a step made in the last 24 h; the floor or ceiling of the tag reached |

**The kill switch.** "Pause auto-actions" stops the executor from planning or applying anything until someone
resumes it: the Pause button on the Auto-actions page (with a reason), `POST /api/actions/pause` `{ reason, until? }`
(an ISO date or a number of hours, after which it resumes by itself) and, in the chat, the `pause_auto_actions` and
`resume_auto_actions` tools ("pause auto-actions, the IOPS trim looks wrong"). While paused the page shows who paused
it, since when and why; passes record "paused by …; nothing planned or applied" and Apply is refused, but **Revert
keeps working**: undoing a change is what a pause exists for. Pausing and resuming are posted to Sphinx immediately,
quiet hours or not.

**Where the agent comes in.** The pass itself stays deterministic: every module reads facts and applies its own
rules, and no model decides what to change. The agent and Jev come in three places around it, each asked once per
distinct thing so a pass that repeats itself costs nothing.

**A second opinion.** Before a pass applies anything, Jev (`src/proposal_check.ts`, purpose `proposal_check`) sees
every new proposal with the record around its resource (its role, open alerts, what the team approved or rejected on
it, other changes in flight) and answers three typed questions: could it destroy something that cannot be recovered,
what would users notice, does it contradict what the team decided. The verdict lands on the row (`check_json`, the
"Jev ok" / "held by Jev" badge, a `Jev:` line in the Sphinx message). `ACT_JEV_CHECK`: `hold` (default) makes the
pass leave a proposal Jev objects to for a person, `advise` only records, `off` skips it. Apply on the page proceeds
anyway (that is the human decision) and the objection stays on the row's result. Jev is asked once per distinct
change: a proposal refreshed pass after pass keeps its first verdict, and a new row for the same change within 30
days reuses it ("same change as #id"). Without a TypeSafe key the rows go unchecked and the pass says so.

**The narrated pass.** After a pass, the agent writes the short version (`src/pass_report.ts`, task
`tasks/pass_report/`): what the pass did, what happens at the next one and when, what waits on an approval or a
grace period (with row ids), what was left alone grouped by reason, and anything that looks wrong. It gets the
complete record, every row touched with its status and Jev verdict, every module's notes and the errors, and may use
the read-only fact tools only to explain a skip. The agent is asked once per distinct outcome: `ACT_NARRATE=changes`
(default) digests the pass and skips one whose outcome matches the last narrated pass, `always` narrates every pass,
`off` never. The answer is graded (row ids must exist, no change may be claimed in a pass that applied nothing, the
message stays under 900 characters and cites numbers when there were proposals); a note under the bar is kept on the
page marked "held back" and not posted. Otherwise its `sphinx` text goes to the chat (quiet hours respected, older
unsent notes superseded) and the Auto-actions page shows it under "Last narrated pass" with its grade and a Resend
button (`GET /api/actions/pass-reports`, `POST /api/actions/pass-reports/:id/resend`).

**Ask about a row.** Every ledger row has an Ask button that opens a thread with the agent on that row: why the
executor proposed it, what happens if it is applied, what the revert does. The agent gets the row as recorded
(reason, before and after, the facts it decided on, the undo, what became of it, Jev's second opinion when there is
one), what else the advisor knows about the resource (inventory facts, recommendations and the team's decisions on
them, open alerts, the other rows on it) and the fact tools, including `auto_actions`, the ledger itself with the
executor's mode and pause state. One thread per row, kept for as long as the row; `GET`/`POST
/api/actions/:id/messages`. The thread is for understanding, not deciding: Apply and Revert stay buttons a person
presses.

**Approved recommendations as the go-ahead.** An approved recommendation of tier `auto` on a resource (a log
group without retention, an over-provisioned volume) is picked up by the matching action whatever its own
thresholds say (`approvedFor` in `src/executor.ts`): the row cites "approved as #id by whom", and once the change
is read back the recommendation is marked done by the executor, with the decision posted to Sphinx like any other.

**The ledger** (`actions`, `GET /api/actions?status=&kind=&page=&page_size=`, 25 a page, `?id=` lands on the page holding that row): `proposed` (waiting for an apply pass or a click),
`applied` (the call succeeded, read-back pending), `verified`, `failed`, `refused` (no role, or failing
repeatedly), `reverted`, `stale` (the latest pass no longer proposes it: the hour moved on). An open proposal with
the same dedupe key is refreshed, not duplicated: the row keeps its id and its proposal date, and the page shows the
date it was proposed with the last pass that saw it underneath. A proposal that went stale and comes back revives
its newest stale row (same id, same date, `revived_at` set) instead of inserting another; the grace period then
restarts from the revival, since the announcement people saw may be days old. `GET /api/actions/status` returns mode, role, who the executor
acts as, the policy and the trust policy; `POST /api/actions/run`, `GET /api/actions/preview`,
`POST /api/actions/:id/apply|verify|revert`.

What the first dry run said in this account: the hub cluster already sits at the 0.5 ACU floor and hits its 2 ACU
ceiling in every hour's p95 (a different problem, the profiler's), and of 24 snapshots twelve are already archived,
four sit behind AMIs, six are young and two are siblings on a live volume: nothing to do today, which is the
correct answer and the ledger says so. Since 2026-09-26 the executor also carries out what a person approved
(Aurora storage type, S3 lifecycle rules), moves gp2 volumes to gp3, puts a lifecycle policy on ECR repositories
and parks idle swarms that were opted in with a tag. On 2026-09-27 twelve more actions joined, in three shapes:

- **Standing, reversible, no approval**: gp3 throughput trimmed to the 30-day peak, EFS lifecycle policies,
  stale alarms on gone resources deleted (definition kept for Revert), log retention shortened where nobody
  queries (only retentions the executor itself set).
- **Approval-driven**: the executor carries out an approved recommendation. Some recommendations come from the
  rules (release an Elastic IP, delete a snapshot) or the NAT investigator (a gateway endpoint); the others are
  filed by the action's own plan from what it measures, tier approve, and picked up once a person approves
  them: unused KMS keys (`kms_key_unused`), idle load balancers (`elb_idle`), DynamoDB capacity mode
  (`dynamodb_capacity_mode`), T-family credit specification (`cpu_credit_spec`). The irreversible ones (EIP
  release, snapshot and load balancer deletion, KMS retirement) are announced in Sphinx when proposed and held
  `ACT_DELETE_GRACE_HOURS` (24) before they happen; a KMS key is only ever scheduled, never deleted outright,
  and comes back with Revert inside `ACT_KMS_PENDING_DAYS`.
- **Opt-in by tag**: office hours. `advisor:schedule = "<days> <HH>-<HH> [IANA tz]"` on an EC2 instance, RDS
  instance or Aurora cluster, where days is `daily`, `weekdays`, `weekends`, a range like `mon-fri` or a list
  like `mon,tue,wed`; whole hours on a 24-hour clock, `22-06` is an overnight window; the time zone defaults
  to UTC. The actuator policy allows the stop and start calls only on tagged resources.

Later the same day: incomplete multipart uploads aborted on every bucket as a standing action, Lambda memory
right-sizing from the REPORT lines (approval-tier), and the kill switch below. Still to come: a wake-on-visit
parking page, and "wake <name>" in the chat covering scheduled boxes as well as parked swarms.

#### Auto-park grants: stop and start one instance at a time

The actuator role may stop and start an EC2 instance only when a person granted that one instance
(`src/autopark_grant.ts`). Switching **Auto-park** on is done with your own credentials (**Run as me** on the row the
switch proposes): it writes `AdvisorAutoPark=ON` and adds the instance to a customer-managed policy attached to the
actuator role, `/aws-advisor/AdvisorAutoParkInstances` (created and attached on the first grant): `ec2:StartInstances`
and `ec2:StopInstances` on exactly those instances, one ARN each with the region as `*`, and per instance a
`route53:ChangeResourceRecordSets` statement on the hosted zones of the A records that lead to it (the records naming
its public and private addresses, and those the Route 53 inventory links to it), limited by condition to UPSERT of A
records with exactly those names: what a start without an Elastic IP re-points, and what the hibernation relaunch
moves. The row's reason lists the names; the grant check on the row reads as "not granted" when the records changed
since, and **Grant it** writes the grant again. A box with A records and no Auto-park grant is not relaunched for
hibernation (the skip reason says so). A managed policy, because a
role's inline policies share 10,240 characters and the actuator policy, pasted inline, uses about 9,000 of them; the
managed one has 6,144 of its own, about 100 instances, and a grant that would not fit is refused with a message. Each
change is a new default version (AWS keeps five; the oldest is deleted first). Switching it off removes the
instance; with none left the policy is detached and deleted. Revert on either row puts both the tag and the grant
back. Your credentials need `ec2:CreateTags` and `iam:GetPolicy`, `GetPolicyVersion`, `ListPolicyVersions`,
`CreatePolicy`, `CreatePolicyVersion`, `DeletePolicyVersion`, `DeletePolicy`, `AttachRolePolicy`, `DetachRolePolicy`
(the Run-as-me panel previews them).

The actuator has no IAM write right and may write neither `AdvisorAutoPark` nor `advisor:hibernate`, and no
statement opens a stop or a start by a tag it can write itself (the tag-conditioned statements for `AdvisorAutoPark`,
`advisor:schedule` and `advisor:park` are gone; the `advisor:parked` marker it may still write opens nothing), so it
can never grant itself an instance. The row under the switch says whether the instance is granted, read with
`iam:SimulatePrincipalPolicy` on the role (`GET /api/inventory/ec2/:id/autopark-grant`); a box tagged ON from before
grants existed shows "not granted" with a **Grant it** link. Everything that stops or starts (idle parking, office
hours on instances, the Stop/Start buttons, the doorman's wake) needs the grant, and a refusal says so. Office hours
on RDS keep their `advisor:schedule` condition. The hibernation choice (`advisor:hibernate`) is a Run-as-me row too.

#### Wake profiles and the doorman

**The DNS flip on sleep.** With `DOORMAN_PUBLIC_IP` set (Settings > Auto-actions: the swarm host's public address,
where its Traefik forwards the sleeping domains to the doorman) every stop of a box whose wake profile says *DNS
flip* (idle parking, office hours, the Stop button) first UPSERTs the profile's domains (by name: what they point
at now is read from Route 53, since the inventory may predate the last start) and any A record naming the box's
address to that address, under the instance's Auto-park grant, then stops the box, so the change propagates while
the box still answers (the doorman proxies to it meanwhile). The row records it (`dns_parked`, and `dns_records` as
flipped). Visitors then get the waiting page and a visit can wake the box; the start's UPSERT points the records
back at the box's new address. A
box with an Elastic IP, no wake profile or another front door is left alone, and the row says why. The swarm host
needs a certificate for the domain (Traefik's resolver, DNS-01 or a wildcard), since the record arrives there only
once the box sleeps.

**Traefik routes to the doorman.** After the flip the domain resolves to the swarm host, and its Traefik has to send
it to the doorman. Traefik's docker provider reads labels fixed at container start, so the advisor serves the routes
and Traefik polls them (`src/traefik_dynamic.ts`): add to the swarm's Traefik command

```
--providers.http.endpoint=http://<advisor container>:9034/traefik/dynamic.json
--providers.http.pollInterval=10s
```

The document carries one HTTP router per wake-profile domain and port the profile does not ignore, on the
swarm's entrypoint for that port (`web`, `websecure`, `port<N>`), TLS on: with the certificates Traefik's file
provider loads (the production swarm's wildcard for the zone), or from the ACME resolver named in
`TRAEFIK_CERT_RESOLVER` (Settings > Auto-actions; a Route 53 DNS challenge issues for the name before any traffic
arrives), all to the doorman service at `DOORMAN_URL` (same page; empty = the advisor container's host name and
`DOORMAN_PORT`). It is served
to private addresses only, without a token, and holds nothing but names and ports. Profiles whose front door is not
the DNS flip are left out. An entrypoint Traefik does not have is logged by Traefik and the router ignored: the ports
in the profile should be ones the swarm host listens on.

A parked instance can be woken by its own traffic. Its **wake profile** (`src/wake_profiles.ts`, the instance's
**On-demand** tab, `GET/PUT/DELETE /api/wake-profiles/:id`) names the domains it answers for, what happens on each
port while it sleeps (`page`: the waiting page for browsers and a hold for API and WebSocket calls; `hold`;
`redirect`; `ignore`, the only choice for UDP), how to tell it is ready (an HTTP(S) status or a TCP connect on the
private address), the sleep mode, the minimum awake time, the hold time, instances to start first, commands for
after the wake and before the sleep, the wake filter (host match, ignored paths, scanner user agents, wakes per day)
and the page's title and text. A new profile is suggested from the A records naming the box and its listening ports.
Saving changes nothing in AWS; every save is mirrored onto the instance's AdvisorResource node (`wake_enabled`,
`wake_domains`, `wake_profile`).

The **doorman** (`src/doorman.ts`) listens on `DOORMAN_PORT` (9035; `0` turns it off), plain HTTP, meant to sit
behind the swarm's Traefik. A request is matched to a profile by its Host header: while the box is not ready a
browser gets the waiting page (503 with Retry-After; it polls `/__wake/status` and reloads when the box answers),
other requests and WebSocket upgrades are held up to the hold time, and a visit that passes the filter wakes the box
when the profile's **Wake on traffic** switch is on. Once the ready check passes, requests are reverse-proxied to
the private address. A wake is the Inventory's Start (`manualPower`: a ledger row, DNS re-pointed when there is no
Elastic IP, only on a box tagged `AdvisorAutoPark=ON`), dependencies first, recorded in `wake_events` with how long
it took to be ready (the page's "usually about" figure).

**Trying it by hand.** `http://<advisor host>:9035/__wake/test/<instance-id>` serves the waiting page for that
instance with a **Start it now** button, whatever the switch says; it is answered only to private addresses and
never for a profile's own host, so it cannot be reached through Traefik. Publish the port next to 9034 (`-p
9035:9035`) and open it over the VPN; the On-demand tab links to it. To see the host-routed path without DNS:
`curl -H 'Host: <domain>' -H 'Accept: text/html' -A Mozilla/5.0 http://<advisor host>:9035/`.

#### Hibernation when parking

Every stop the executor makes (idle parking, office hours, the Stop button) goes through `stopOrHibernate`
(`src/hibernation.ts`): an instance launched with hibernation on is hibernated, so it comes back in about a minute
with its memory and containers as they were; any other instance is stopped as before. If EC2 refuses the
hibernation (the guest agent not ready, the root volume too small for the RAM) the stop falls back to a plain one
and the ledger row says so. Under the Auto-park switch a note says which it is: **Hibernation ready**, or **Cold
start** with the reason it cannot be migrated (an EKS or Auto Scaling member, Spot, too much RAM, an unsupported
type: the same `skipReason` the relaunch uses) or with three answers: Migrate (with downtime), Migrate live, Keep
stop/start. Each is the `advisor:hibernate` tag (`stop`, `live`, `no`) written as a ledgered consent row
(`POST /api/inventory/ec2/:id/hibernation`, Revert puts it back; the actuator may write that one key on any
instance, statement `ActuatorHibernateChoiceTag`); `stop` and `live` hand the box to the relaunch action
(announced, after its grace period), `no` keeps cold starts, stops the suggestion, and on a box already launched for
hibernation makes parking use a plain stop. `GET /api/inventory/ec2/:id/hibernation` reads the state from EC2
(cached ten minutes).

## Member accounts

One parent, the children it reaches through a role. The credentials in Settings are the parent (in an
Organization, usually the management or payer account). For each child, create two roles that trust the
parent's read identity (Settings › Member accounts prints the trust policy with that ARN filled in):

- `aws-advisor-read`, with the same read policy as the parent's (Settings › Permissions).
- `aws-advisor-act`, with the actuator policy (Auto-actions page), only if the executor may change that account;
  without it the child is dry-run only.

The child side is one script too: Settings › Set up AWS access › **Member account of the organisation** renders
it with the parent's read identity filled in; run it in a terminal with the *child's* admin credentials. It
creates the child's read role trusting that identity (or merges the trust into an existing role, keeping other
principals), applies the read policy, creates the probe documents and registers the child with the advisor,
which tests the assumption from the parent. Both sides of a cross-account assumption are needed: the child's
trust policy, and the parent's read policy statement `AdvisorAssumeMembers` (`sts:AssumeRole` on
`arn:aws:iam::*:role/aws-advisor-read`), which the parent's setup script applies on a rerun if it predates it.
The actuator role stays a manual step for now.

**Production: the advisor on an EC2 host in a member account.** The host has no key; its instance profile is the
base identity, and the chain is instance role (in the host's account) → the parent's read role (in the parent) →
each member's read role, the host's own account included. Two scripts, one per account:
1. In the host's account, **EC2 host in a member account** (`ec2-host`, run with that account's admin credentials):
   creates the instance role and profile, attaches the SSM core policy, and lets the role assume the parent's read
   role and nothing else.
2. In the parent, **EC2 host with an instance role** with "Host instance role in another account" set to that
   instance role's ARN (`ec2-role&hostRoleArn=`): the parent's read role trusts the host's instance role across
   accounts (merged into an existing trust policy), the policy and documents are refreshed; nothing is created for
   the host there.
On the host, Settings › AWS credentials › Instance / default chain with the parent's read role as the role to
assume and credential source Ec2InstanceMetadata (the parent-side script prints exactly that); the members
registered under Member accounts, including the host's own account, are reached through their read roles from
there. Hop limit 2 on the instance's IMDS when the advisor runs in a container.

Settings › Member accounts also lists the organisation's accounts as the parent sees them
(`organizations:ListAccounts`, in the recommended policy; the management account only), with which are the
parent, registered members, or not registered yet, and a "Set up as member" link into the wizard for each.

When the credentials start resolving to a different account than the one the advisor was collecting (a new
parent), nothing is deleted on its own: the change is recorded and Settings › Access shows what is still stored
about the previous account with three explicit ways out: make the previous account a member of the new parent
(its rows already carry its account id, so they become the member's), keep the data, or purge it, which removes
every row and graph node attributed to that account after typing its id again (`GET/DELETE /api/settings/aws/change`,
`POST /api/settings/aws/purge`). Recording the change also stamps the rows collected before the advisor kept
account ids with the previous parent (the only account collected then), so the scope rule, which reads an empty
account as the parent's, does not hand them to the new parent.

Settings › Accounts › Data wipes on request (`src/purge.ts`): one account (an AWS account, the current one
included, or a Vercel team: its tables, the rows attributed to it, its runs and its graph nodes) or everything.
The full wipe empties every collected table and the collection state in `settings`, deletes every Advisor* and Kn*
node in the graph and mirrors the playbooks straight back; it keeps the configuration (credentials metadata,
registered accounts, runtime settings), the public reference data (price lists, Amazon Linux advisories), the
generated playbooks with their sources and, with the switch on (the default), the Concepts and learnings. The
Concepts in repo2graph's graph are never deleted. Each wipe shows what goes first, is confirmed by typing the
account id or WIPE, and is refused while a run is collecting (`GET /api/settings/data/preview`,
`POST /api/settings/data/wipe`). For a production install that collected before accounts were scoped, wipe
everything with the Concepts kept and start a run. The inventory summary the tabs count from is scoped the same way as the lists
(`scopedStmt` in `src/scope.ts` adds the account clause to each summary query; the Route 53 rows carry their zone's
account too), so the parent's tabs count the parent's resources only. The other pages scope the same way: Findings and Security
by the rows' account id (the Security header says the account's share of the scan's findings; a scan spans the
organisation), Recommendations and Alerts by an `account_id` each row gets once, from the resource it names
through the inventories, from the details a platform pass wrote, or from the run that proposed it (what cannot be
attributed reads as the primary account's), Network and Knowledge by the graph's account, Changes by a CloudTrail
read per account (the parent with its own credentials, each member through its read role, every event stamped),
Logs by the groups' account, the vulnerability card by the instances' account. This month stays the payer's whole bill, since Cost Explorer and the forecast are
organisation-wide; under one account's scope it shows that account's own months from Cost Explorer's per-account
view. A collection run reads every account in one pass, so the Runs list does not scope.

Otherwise add the child (id, name, the two ARNs, optional regions) in Settings › Member accounts by hand. Saving rewrites the
Steampipe connection: the app's schema becomes an aggregator over the parent and one connection per child
(through a managed AWS profile chaining the child role onto the parent's identity), so every query, inventory,
finding and rule spans all accounts as is, with `account_id` on the rows. The executor reads a child's resources
with its read role, acts under that child's actuator role only, and stamps every ledger row with the account
(`src/accounts.ts`; `GET/POST /api/accounts`, `POST /api/accounts/:id/test`, `GET /api/accounts/bill`). The Bill
page shows the payer's cost per linked account.

Names that are unique per account only (RDS identifiers, cache cluster ids, Lambda functions, log groups) are keyed on
(account, name) in the inventories (`rekeyByAccount` in `src/db.ts` rebuilds a table keyed on the name alone on
startup, once), so two children with a `prod-db` are two rows; the lookups that start from a recommendation, an
action row or an instance prefer the row of that account (`accountRank` in `src/scope.ts`) and fall back to any.
The actuator capability check runs per account: each child's actuator role is simulated from that child's read role
and a denial learnt from a failed apply is remembered for that child's role only (`actuatorCapabilities(accountId)`,
`GET /api/actions/status` returns `accounts` with each member's capabilities, "re-check the role" re-simulates them
all). Settings › Permissions has an account picker: a child is checked through its own Steampipe connection
(`<schema>_<account id>`) and its read role, the parent through `<schema>_p`, and each account keeps its own last
result (`POST /api/permissions/check` with `account_id`, `GET /api/permissions?account=`). Every executor action
plans per account; the SSM probes and the RDS load profiles run under the account the instance or database lives in.
**A credential save restarts the Steampipe service.** The connection watcher reloads a changed `.spc`, but the AWS
config file next to it (the managed profile with the role to assume) is not watched and the plugin keeps the session it
opened, so a new role kept answering as the old identity until the container was restarted. `PUT /api/settings/aws`
now runs `steampipe service restart` when the service is local (`STEAMPIPE_RELOAD=auto`, the default: the database URL
points at localhost; `on` forces it, `off` never), a few seconds during which queries wait, and reports the outcome as
`steampipe_reload`; the connection test that follows retries through the restart. With a remote service, the response
says to restart it yourself.

**What an account's month is made of.** The spend refresh also reads Cost Explorer per linked account and service for
the last three months (`aws_cost_usage`, `LINKED_ACCOUNT` × `SERVICE`, `spend_by_account_service_monthly`); "By account"
on the This month page opens a row into its services (`GET /api/accounts/bill` returns them as `services`), which is how
the parent's own few hundred dollars are explained next to a child's bill.

**The Domains tab and the network layer scope like the rest.** Route 53 zones and records carry the account of the zone
(Steampipe's column), so Inventory › Domains narrows to the scope; the links to resources are unchanged. Every node of the
graph's network layer (`src/graph_network.ts`) carries the account its VPC lives in: VPCs, subnets and security groups from
their own inventory column, route tables, interfaces, ACLs and their rules through their VPC, an address through its
interface or box, an instance port through its instance. Network and Knowledge therefore show one account's layer under
its scope instead of everything stamped with the primary account.

**Which account the credentials resolve to is read from the parent's connection only.** The connection test and the
credential gate select `account_id` from `aws_account`; over the aggregator that is one row per account in no fixed
order, and a run once recorded a member as the parent. Both read `<schema>_p` once members exist (`parentSchema` in
`src/steampipe.ts`), the connection that carries the parent's own credentials.

**Cost Explorer is read from the parent's connection only.** The aggregator runs every query once per connection,
and a member's role sees its own spend through Cost Explorer too, so a sum over `aws_cost_*` through the aggregator
counts every member twice (the parent's organisation view already has a row per linked account). The query layer
therefore routes every `aws_cost_*` table to the parent's own connection (`<schema>_p`) whenever members are
registered (`routeBillingTables` in `src/steampipe.ts`, applied to the app's SQL and to the agent's `steampipe_query`),
and the Thrifty `cost_explorer` benchmark runs with that connection as its search path. Savings Plans and reserved
instances stay on the aggregator: they are owned per account and each connection lists only its own.
Buckets stay keyed on the name alone (bucket names are global). Two name-keyed side tables are deliberately shared
across accounts: the log group ingest history and baselines (keyed by group name) and Jev's log-group attribution
cache; a colliding group name shares those with its namesake.

## Cost per swarm

Each swarm is one EC2 box running a customer's stack, so the box's bill is the customer's. `src/swarm_costs.ts`
writes one row per swarm per day (`swarm_cost_daily`): instance hours while it runs, its volumes whether it runs or
not, the public IPv4 address (0.005 USD/h, attached or not) and the standard-tier snapshots of its volumes, all at
list price from the inventory. The Swarms page (`GET /api/swarms/costs?month=`) shows the month-to-date figure per
swarm (the mean of the month's daily totals), last use and idle days from the probe roll-ups, whether the executor
parked it, and a **nudge** flag for boxes that run, that nobody has used for `ACT_PARK_IDLE_DAYS`, and that are not
being parked: the customers to ask. The chat has it as `swarm_costs`; the figures also land on the instance's
`AdvisorResource` node in the graph (`cost_month_usd`, `idle_days`, `parked`, `nudge`). Refreshed daily with the
review (`REVIEW_CRON`) and from the page.

## Tag hygiene

Inventory › Tags lists every resource that lacks the required tags (`TAG_KEYS_REQUIRED`, `owner,env` by default;
`Environment`, `stage`, `team` and the like count as aliases) across EC2, EBS, RDS, S3, Lambda, DynamoDB, load
balancers, log groups and ECR, with the value the advisor would suggest from the name and the tags already there and
the CLI to set it. It also names the EC2 instances that could opt into the executor once tagged: swarm-named boxes
without `advisor:park` and dev, staging or test boxes without `advisor:schedule`. One report-tier recommendation per
kind (`tag_hygiene`) carries the list; the chat reads it through `tag_hygiene`. The advisor never writes a tag:
naming an owner is a person's call. Refreshed daily with the logs job (`src/tag_hygiene.ts`).

## S3 lifecycle rules from usage

The Thrifty finding says a bucket has no lifecycle policy; it cannot say which one it should have. `src/s3_usage.ts`
looks at how each bucket at or above `ACT_S3_MIN_GB` is used and proposes the rules that fit, after the daily S3
inventory (`LOGS_CRON`, fifteen buckets a pass, each re-analysed after six days) and on demand (Inventory › S3 ›
Usage and lifecycle › Analyse, `POST /api/inventory/s3/:name/usage/refresh`, the agent's `s3_usage` tool).
Read-only: a sampled listing (up to ten pages of a thousand keys, flat, so the top-level prefixes fall out of the
keys; scaled to the bucket's size when truncated) gives the bytes by age (0-30, 30-90, 90-365, 365+ days) and by
storage class and the share of bytes in objects under 128 KB; `ListMultipartUploads` the incomplete uploads;
`ListObjectVersions` (five pages) the noncurrent versions when versioning is on; the lifecycle rules already there;
and, once the executor has put request metrics on the bucket, the GET and PUT requests and bytes downloaded per
day over fourteen days. It needs `s3:ListBucket`, `s3:ListBucketVersions`, `s3:ListBucketMultipartUploads` and
`s3:GetMetricsConfiguration`, in the recommended policy.

`proposeLifecycle` (pure, tested) turns that into rules, each with its reason and its estimate at the class prices:

| observation | rule |
| --- | --- |
| incomplete multipart uploads | `AbortIncompleteMultipartUpload` after 7 days (their parts are billed and never listed) |
| versioning with a gigabyte or more of noncurrent versions | `NoncurrentVersionExpiration` at 90 days |
| a gigabyte or more of Standard older than 30 days, reads known and near zero (under 10 GET/day or one per thousand objects) | transition to Glacier Instant Retrieval at 90 days (millisecond access, a sixth of the price, 90-day minimum, retrieval per GB) |
| the same, read more than that | transition to Standard-IA at 30 days (half the price, 0.01 USD/GB per read) |
| the same, reads unknown (no request metrics yet) | transition to Intelligent-Tiering at 0 days (moves what is untouched for 30 days by itself, no retrieval charge, 0.0025 USD per thousand objects); the reason says request metrics would let the next analysis pick a sharper class |

When 80 % or more of the old bytes sit under one top-level prefix the transition is scoped to it. Over half the
bytes in objects under 128 KB adds a note: an IA class bills those as 128 KB each, Intelligent-Tiering does not.
A rule already on the bucket is respected (an existing transition means no new one; an existing abort or
noncurrent rule likewise) and listed. The result is a recommendation per bucket (`review_s3_lifecycle`, tier
`approve`, playbook "bucket without a lifecycle policy") whose evidence carries the rules, the usage summary and
the `put-bucket-lifecycle-configuration` JSON, with the existing enabled rules named so the merge is explicit;
the S3 drawer shows the same with a copy button. Applying it is a later executor action, once the verifier has
shown a few of these behaving: transitions carry minimum-storage and retrieval charges, so a person confirms.

## Security posture

What a compromise of the advisor, of the repo2graph agent, or of a machine on the same network can and cannot do,
after the 2026-09-19 review (`src/__tests__/security.test.ts` pins the guards):

- **One write path to AWS, under its own role.** On the read credentials the only mutating SDK call is
  `SendCommand` on the probe document, whose name comes from the environment and never from a request or the
  agent; the script is a constant and instance ids are regex-checked. `PROBE_DOCUMENT=AWS-RunShellScript` is
  refused at startup. Approving a recommendation only updates a row; nothing reads `approved` or `tier = auto` to
  act. The [executor](#auto-actions-the-executor) changes AWS only by assuming `ACT_ROLE_ARN` for the call itself,
  from a fixed catalog (`ModifyDBCluster` scaling configuration, `ModifySnapshotTier`, `RestoreSnapshotTier`),
  with a tag-based Deny in the role's policy and a ledger row per change; the agent has no tool that reaches it.
- **Three shared secrets, all mandatory when `PUBLIC_URL` is not localhost**: `API_TOKEN` (API and UI),
  `MCP_TOKEN` (the fact server the agent calls back into) and `CALLBACK_SECRET` (the webhook). The advisor sends
  the last two to repo2graph itself, so setting them is a `.env` change and a restart. Comparisons are constant
  time; a webhook result is accepted once per dispatch, so a replay or a forged second answer changes nothing.
  The webhook router is mounted before every authenticated router (`src/routes/callback.ts`): a router-level
  `use(authMiddleware)` answers 401 to any `/api` path passing through it, which silently blocked every callback
  once `API_TOKEN` was set until this was fixed; `POST /api/agent-runs/:id/poll` remains the fallback.
- **The agent stays inside the advisor's connection.** `steampipe_query` runs in a read-only transaction with
  `search_path` pinned to the advisor schema, refuses any other connection by name (`aws_parent.…`, `aws.…`, the
  aggregator, Steampipe's internal schemas) and the Postgres admin functions (`pg_sleep`, `pg_terminate_backend`,
  `pg_read_file`, …). Other connections on the same Steampipe service hold credentials the advisor was never
  given; they are simply unreachable from the tools.
- **Agent output is validated before import**: action type from the known list, tier one of the three, confidence
  clamped, text capped; items without a title or resource are dropped. Incident fixes and resolution plans were
  already coerced. Nothing the agent returns is rendered as HTML.
- **An approved item keeps the text it was approved with.** A later run or agent answer for the same resource
  and action no longer rewrites the title, tier or saving of an approved row.
- **Untrusted text still reaches the prompts** (tag values, finding reasons, process and container names from
  probes). With web search off by default the agent has no channel out except its answer, which is validated;
  the remaining risk is a misleading recommendation, which a human reads before anything happens.
- `data/` is created `0700`; credential files are `0600`; no secret is written to the database or the log.

- **Quotas** (`src/quota.ts`, Settings > Quotas): agent runs per hour and per day (findings batches,
  investigations, resolutions and observations together; default 6 and 20) and SSM probes per hour (default
  150), checked at the two choke points every dispatch and every probe go through. Failed probe attempts count,
  so a loop cannot spend through a quota by failing. A hit refuses the call with the time until it frees up and
  opens one `quota` alarm. `GET /api/quotas` shows the counters.

Not done, worth doing before the executor: an allowlist of AWS profiles selectable from Settings; reading the
setup token from a file instead of the command line; a decision hash stored at approval time and checked before
execution.

## Environment variables

Two kinds. **Bootstrap** settings come from the environment only: the app needs them before its database
exists, or they gate what a person may change from a browser (port, paths, the Steampipe connection, the three
shared secrets, the public URL, the probe document). **Runtime** settings (the agent, Jev, the graph mirror,
every schedule, the probe pass) are edited on the Settings page: a saved value wins over the environment, the
environment is only the seed a deployment provides, and the default applies when neither is set. Reset on the
page returns a setting to its environment value or the default. Everything has a working default for a laptop.
What each one is for (✎ = also editable in Settings):

| variable | needed when | default |
| --- | --- | --- |
| `PORT` | you want another port | `9034` |
| `API_TOKEN` | **required unless `PUBLIC_URL` is localhost**; gates the API and the UI. The app shell itself is public (static JS); without a session it shows a sign-in box that takes the token and the browser then keeps a 30-day session (`/?token=<API_TOKEN>` does the same) | unset = open, refused when `PUBLIC_URL` is not local |
| `MCP_TOKEN` | **required unless `PUBLIC_URL` is localhost**; gates `/mcp`. The advisor passes it to repo2graph with every dispatch, nothing else to configure | unset = open, refused when `PUBLIC_URL` is not local |
| `CALLBACK_SECRET` | **required unless `PUBLIC_URL` is localhost**; repo2graph echoes it as `?key=` on the webhook; a result is accepted once per dispatch | unset = open, refused when `PUBLIC_URL` is not local |
| `BIND_ADDR` | listen on one interface only (`127.0.0.1` on a laptop without a swarm) | unset = all interfaces |
| ✎ `AGENT_WEB_SEARCH` | the agent may use web search (off: prices and facts come from the MCP tools; a search query is an exfiltration channel for anything a hostile tag or probe line injects into the prompt) | off |
| `ALLOW_OPEN_ENDPOINTS` | start with the three secrets unset although `PUBLIC_URL` is not local (isolated machine only) | off |
| `STEAMPIPE_DATABASE_URL` | always locally; `steampipe service status --show-password` prints it | local service without password |
| `STEAMPIPE_CONFIG_DIR` | Steampipe's config lives elsewhere (containers) | `~/.steampipe/config` |
| `STEAMPIPE_CONNECTION` | you want the managed connection named differently | `advisor` |
| `ADVISOR_AWS_PROFILE` | the managed AWS profile the app writes when a role is assumed should have another name (several advisors in one home directory) | `aws-advisor-managed` |
| `AWS_CONFIG_FILE`, `AWS_SHARED_CREDENTIALS_FILE` | the AWS config / credentials files live elsewhere (containers); the Steampipe service must see the same files | `~/.aws/config`, `~/.aws/credentials` |
| `POWERPIPE_BIN`, `POWERPIPE_MOD_DIR` | non-standard Powerpipe location or mod path | `powerpipe`, `./mod` |
| `REPO2GRAPH_URL`, `REPO2GRAPH_TOKEN` | you want agent ranking at all; see the table above | unset = rules only |
| `PUBLIC_URL` | repo2graph runs in a container and must reach the webhook and `/mcp` | `http://localhost:PORT` |
| ✎ `AGENT_MODEL` | a different model for the agent, in repo2graph's `provider/model` form | `anthropic/claude-opus-5` |
| ✎ `AGENT_API_KEY` | local testing without giving the swarm a key | unset |
| ✎ `RUN_CRON`, `WATCH_CRON`, `PROBE_CRON`, `SPEND_CRON`, `BASELINE_CRON`, `REVIEW_CRON`, `OBSERVE_CRON`, `LOGS_CRON` | a different rhythm, or `off` | daily 06:00, every 30 min, hourly at :05, daily 06:40, daily 07:00, daily 07:15, daily 06:50 |
| ✎ `PROBE_MAX`, `PROBE_IDLE_CPU` | a bigger or narrower automatic probe pass | 25 instances, under 20 % CPU |
| ✎ `ACT_MODE`, `ACT_ROLE_ARN`, `ACT_CRON`, `ACT_PRESSURE_CRON`, `ACT_ACU_FLOOR`, `ACT_MAX_PER_PASS`, `ACT_SNAPSHOT_MIN_AGE_DAYS`, `ACT_LOG_RETENTION_DAYS`, `ACT_S3_MIN_GB`, `ACT_EB_LOW_CPU`, `ACT_EB_HIGH_CPU`, `ACT_EB_PRESSURE_HOURS`, `ACT_EB_TARGET_CPU`, `ACT_EB_TARGET_MEM`, `ACT_EB_HIGH_MEM`, `ACT_EB_HIGH_DISK` | the executor: `off` / `dry_run` / `apply`, the actuator role it assumes for changes, its rhythm, the Beanstalk pressure check's rhythm (every ten minutes), the lowest Serverless v2 minimum it may set, the cap per pass, the snapshot age, the retention put on log groups without one, the bucket size from which request metrics are enabled and the lifecycle analysis runs | `dry_run`, unset (dry runs only), hourly at :45, 0.5 ACU, 10, 90 days, 90 days, 20 GB |
| ✎ `USAGE_LOG_DAYS`, `USAGE_MIN_OFF_HOURS`, `USAGE_AGENT_MAX_PER_DAY` | how many days of the shipped CloudWatch logs the usage profile scans for use signals (0 = off), the shortest stop worth making, and how many unsure boxes a day go to the agent (0 = never) | 7, 4, 5 |
| ✎ `PROBE_SIGNALS` | other or more use-signal patterns for the probe (`name=regex;;name=regex`) | the nine built-in patterns |
| `PROBE_DOCUMENT` | the probe document has another name (see [The SSM probe document](#the-ssm-probe-document)); `AWS-RunShellScript` is refused outside the test suite | `AwsAdvisorProbe` |
| ✎ `AGENT_AUTO_DISPATCH` | you want every scheduled run sent (`always`) or none (`never`) | `changes` |
| ✎ `ALERT_INVESTIGATE` | NAT alerts should be investigated only on request (`manual`) or never (`off`) | `auto` |
| ✎ `SPHINX_BOT_URL` | the swarm's bot endpoint alerts are broadcast to (the one Hive and the swarm checker use); empty = notifications off | unset |
| ✎ `SPHINX_BOT_ID`, `SPHINX_BOT_SECRET`, `SPHINX_CHAT_PUBKEY` | the bot and the chat it posts into; the secret is masked on the Settings page and never logged | unset |
| ✎ `NOTIFY_LEVEL` | `alarm` = alarms only, `warning` = alarms and warnings, `off` | `alarm` |
| ✎ `NOTIFY_SCOPE` | `watched` = alerts on watched resources and account-level alerts; `all` = every alert at the level | `watched` |
| ✎ `NOTIFY_QUIET_HOURS` | `HH-HH` local time during which warnings wait for the next dispatch; alarms still go | unset |
| `CONCEPT_NAMESPACE` | decisions should land in another Concept namespace in repo2graph | `aws/cost-advisor` |
| ✎ `TYPESAFE_API_KEY`, `JEV_MODEL` | you want Jev's alert triage, resource roles and tier checks (see [Typed decisions with Jev](#typed-decisions-with-jev)) | unset = no-op, `jev-latest` |
| `DATA_DIR` | the SQLite database should live elsewhere (a named volume in the swarm) | `./data` |
| `NEO4J_URI`, `NEO4J_USER`, `NEO4J_PASSWORD`, `NEO4J_DATABASE` | you want the one-way [graph mirror](#graph-mirror) of resources, recommendations, decisions, alerts, incidents and rules in the swarm's Neo4j | unset = off, `neo4j`, unset, the server default |

## API

- `GET /health`, `GET /busy` public; the swarm's fast updater respects `/busy`.
- `GET /api/settings/runtime`, `PUT /api/settings/runtime` (`{ key, value }`, `value: null` resets; validated per kind: cron, url, enum, number, bool), `POST /api/settings/runtime/:cronKey/run` (runs that job now, as the cron would; answers with what it did or why it did nothing)
- `GET /api/settings` (`aws` carries the credential mode meta: `mode`, `label`, masked key or `profile`, `roleArn`, `credentialSource`, `temporary`, `accountId`), `PUT /api/settings/aws` (`{ mode: keys | profile | chain, accessKey, secretKey, sessionToken?, profile, credentialSource?, roleArn?, regions, defaultRegion }`; profile names must match `^[A-Za-z0-9_.-]+$`, role ARNs `^arn:aws:iam::\d{12}:role/.+$`; answers `{ saved, test, sdk }`), `POST /api/settings/aws/test` (Steampipe and SDK identity), `DELETE /api/settings/aws`, `PUT /api/settings/benchmarks`
- `GET /api/runs`, `POST /api/runs`, `GET /api/runs/:id`, `GET /api/runs/:id/stream` (SSE), `GET /api/runs/:id/changes`, `POST /api/runs/:id/agent`
- `GET /api/agent-runs/:requestId`, `POST /api/agent-runs/:requestId/poll`, `GET /api/agent-runs/:requestId/events` (SSE proxy), `POST /api/agent-callback` (repo2graph's webhook)
- `GET /api/findings?run_id&control_id&status&q`, `GET /api/playbooks?run_id`, `GET /api/playbooks/:controlId`
- `GET /api/recommendations?status`, `GET /api/recommendations/:id`, `POST /api/recommendations/:id/decision`, `POST /api/recommendations/:id/progress`, `POST /api/recommendations/:id/blocked-by`, `POST /api/recommendations/:id/resolve`, `GET /api/recommendations/:id/resolution`
- `GET /api/overview`, `GET /api/alerts?status=open|acknowledged|all` (rows carry `triage`, `acknowledged_by`), `POST /api/alerts/:id/ack`, `POST /api/alerts/:id/reopen` (undo an acknowledgement, Jev's or a person's), `POST|GET /api/watch`, `GET /api/learnings`
- `GET /api/jev/calls?limit&purpose` (Jev audit trail); `GET /api/inventory/ec2/:id` and `GET /api/recommendations/:id` carry the resource's `role` / `resource_role`
- `POST /api/alerts/:id/investigate`, `GET /api/alerts/:id/incident`, `GET /api/incidents`, `GET /api/nat/:id/attribution?hours&limit`
- `POST /api/instances/:id/probe`, `GET /api/instances/:id/metrics`, `GET /api/instances/:id/timeseries?hours=`, `GET /api/instances/:id/history?days=`, `POST /api/history/rollup?days=`, `GET /api/probe/document` (the SSM document for `aws ssm create-document`)
- `GET /api/permissions` (issues, merged policy, last check, recommended policy), `POST /api/permissions/check` (`{ instance_id? }`)
- `GET /api/setup/plan?path&user&role&profile&region&instanceRole&instanceId&adminProfile&dryRun` (the wizard's steps and the one-liner), `GET /api/setup/script?...` (the setup script, `text/x-shellscript`)
- `GET /api/inventory/summary`, `GET /api/inventory/ec2?state&ssm&q&sort&gone`, `GET /api/inventory/ec2/:id`, `GET /api/inventory/rds`, `GET /api/inventory/elasticache`, `GET /api/inventory/lambda`, `GET /api/inventory/ebs?q&sort&gone`, `GET /api/inventory/s3?q&sort&gone`, `GET /api/inventory/route53?q&sort&gone&zone&link&type`, `GET /api/inventory/route53/zones`, `GET /api/inventory/route53/resource/:kind/:id`, `GET /api/inventory/:kind/:id/timeline`, `GET|POST /api/inventory/:kind/:id/watch`, `POST /api/inventory/refresh`, `POST /api/inventory/s3/refresh`, `POST /api/inventory/route53/refresh`
- `GET /api/logs?limit=`, `POST /api/logs/refresh`, `GET /api/trail?hours=`, `POST /api/trail/refresh` (see [CloudWatch Logs and CloudTrail](#cloudwatch-logs-and-cloudtrail))
- `GET /api/observe`, `GET /api/observe/brief`, `POST /api/observe/run?force=1` (see [The morning observation](#the-morning-observation-the-agents-read-of-the-day))
- `GET /api/review`, `POST /api/review/run` (see [The daily review](#the-daily-review-what-the-statistics-say))
- `GET /api/baselines?scope_kind&scope_id`, `POST /api/baselines/refresh` (see [Baselines](#baselines-what-is-typical))
- `GET /api/accounts/general` (the month, open items and attention across every account), `GET /api/runs?account=` and `GET /api/findings?account=` (a platform account's rules passes and their findings)
- `GET /api/vercel/stores/:id` (one store in full with its usage and cost at plan), `GET /api/vercel/rates` (the team's listed metered rates, the marketplace plans' lines, the invoice-observed unit prices)
- `GET /api/forecast` (this month's forecast, its history and the last price check), `POST /api/forecast/run`; `GET /api/bill?month=YYYY-MM`, `POST /api/bill/reconcile?month=` (the price check, see [This month](#this-month-the-bill-forecast-from-what-is-running-now))
- `GET /api/graph/systems?kind=`, `GET /api/graph/system/:id`, `GET /api/graph/bill`, `POST /api/graph/knowledge` (see [the knowledge graph](#graph-mirror-and-the-knowledge-graph))
- `GET /api/graph`, `POST /api/graph/sync?wipe=1`, `GET /api/graph/resource/:id` (the Neo4j mirror, see [Graph mirror](#graph-mirror))
- `POST /mcp` the MCP fact server

## Data

SQLite (`DATA_DIR/advisor.db`): `settings`, `runs`, `findings`, `metrics`, `recommendations`, `agent_runs`
(`kind` findings or incident, linked to a run or an alert), `run_changes`, `watch_samples`, `alerts`,
`incidents` (alert id, request id, status pending | completed | failed, cause, confidence, evidence, episode
and run-rate cost, fixes with their recommendation ids, raw result, error), `learnings`, `instance_metrics`,
`inventory_ec2`, `inventory_rds`, `inventory_elasticache`, `inventory_route53_zone`, `inventory_route53_record` and `inventory_route53_link` (one row per resource a record leads to, with the hop), `prices`, `concepts`, `permission_issues` (one row per
missing IAM action: service, the contexts it was seen in, first and last seen, count, last message; cleared for an
action once a check proves it granted), `jev_calls` (every Jev call: purpose, state hash, questions, answers, model,
tokens, latency, error), `resolutions` (tailored resolutions per recommendation, see above) and `resource_roles` (Jev's role, confidence and protected probability per resource, with the
state hash the answer was given for), `container_samples`, `instance_daily` and `container_daily` (see
[Containers and long-lived history](#containers-and-long-lived-history)). `alerts` carries `triage`, `triage_at` and `acknowledged_by` (`jev` or `ui`). A database from before
investigations is migrated once at startup (`agent_runs` is rebuilt with the new columns). Powerpipe can attach the same file
as a data source for a recommendations dashboard. Neo4j is not a store: the agent gets history through the MCP
tools and its own learnings, and the [graph mirror](#graph-mirror) is a one-way projection of these tables that the
advisor never reads back.

## Layout

- `src/` backend (Express 5, better-sqlite3, pg). `routes/api.ts` is the API surface; `steampipe.ts` owns the
  connection file and the credential meta, `aws_config.ts` the credential modes (the `.spc` and managed AWS
  profile writers, validation, the SDK provider selection); `collector.ts` runs a
  collection; `rules.ts` drafts recommendations, `flowlogs.ts` the flow-logs one; `changes.ts`, `watcher.ts`,
  `scheduler.ts`; `agent.ts`, `investigate.ts`, `concepts.ts` and `learnings.ts` talk to repo2graph; `mcp.ts` is
  the fact server; `graph_mirror.ts` the one-way Neo4j mirror and `routes/graph.ts` its endpoints; `ssm.ts` the probe; `permissions.ts` recognises denied AWS calls and builds the fixing policy,
  `permission_check.ts` runs the per-capability check, `setup_script.ts` renders the one-command setup script and its plan; `jev.ts` is the TypeSafe client, `triage.ts`, `roles.ts`
  and `tiercheck.ts` its three uses.
- `ui/` React 19 + Vite + Tailwind 4, the same stack as repo2graph's pages. Built output is served by the
  backend from `ui/dist`.
- `mod/` Powerpipe mod: the AWS Thrifty dependency plus custom queries and dashboards.
- `data/` SQLite database (gitignored).

## Deployment: the image and the swarm

The advisor ships as one image, `ghcr.io/stakwork/aws-advisor`, built the way stakgraph-mcp's is
(`.github/workflows/publish.yml`: a native build per architecture on a published release, then a multi-arch
manifest tagged with the release name and `latest`). The image holds the app with its built UI, a Steampipe
service with the AWS plugin, and Powerpipe with the Thrifty mod, all fetched at build time so a container
starts without network access to Turbot. Steampipe refuses to run as root, so everything runs as the
`advisor` user; the entrypoint starts the service on 9193 and then the app. About 1.3 GB.

The entrypoint starts the Steampipe service once and then watches it: every 30 seconds, if port 9193 stops
answering (a plugin panic, memory pressure), it starts the service again and logs `[steampipe] service
restarted` to the container's output. The app reports the gap as "Steampipe service is not running" instead of
a bare connection refusal. `docker logs advisor.sphinx` shows the restarts; the service's own log is at
`/home/advisor/.steampipe/logs/` inside the container.

```
docker build -t aws-advisor .
docker run -d -p 9034:9034 -v aws-advisor-data:/data \
  -e API_TOKEN=$(openssl rand -hex 32) -e MCP_TOKEN=$(openssl rand -hex 32) -e CALLBACK_SECRET=$(openssl rand -hex 32) \
  -e PUBLIC_URL=http://host.docker.internal:9034 ghcr.io/stakwork/aws-advisor:latest
```

One volume, `/data`, holds everything that must survive a recreation: the SQLite database (`/data/advisor`),
the Steampipe connection the app writes (`/data/steampipe/config`) and the AWS config and credentials files
(`/data/aws`, linked to the advisor user's `~/.aws`). Credentials are entered in Settings as on a laptop, or
come from the host's instance role in chain mode. `DATA_DIR`, `STEAMPIPE_CONFIG_DIR`, `AWS_CONFIG_FILE`,
`AWS_SHARED_CREDENTIALS_FILE` and `STEAMPIPE_DATABASE_URL` are preset in the image; every other variable in
[Environment variables](#environment-variables) applies. The UI is built with `npm install` rather than `npm
ci` in the image because the lockfile is written on macOS and `ci` skips the optional native packages
(lightningcss, tailwind) of another platform.

**In sphinx-swarm** the image is part of the graph-mindset stack when the swarm's `.env` has `DEVOPS=1`
(`src/images/advisor.rs`, added in `graph_mindset_imgs`): node `advisor` on port 9034, linked to repo2graph
(the agent; boltwall's `stakwork_secret` becomes `REPO2GRAPH_TOKEN`) and neo4j (the mirror), with `PUBLIC_URL`
set to its own container address so the agent's callbacks and tool calls stay on the swarm network. It is
private, like neo4j: no Traefik route and no public hostname, because the UI lists the account's instances,
probes, costs and decisions. Reach it on the host's private IP at port 9034 (over the VPN or a tunnel), and
sign in with the `API_TOKEN` the swarm generated for the node (in the stack's config.yaml). The swarm
generates `API_TOKEN`, `MCP_TOKEN` and `CALLBACK_SECRET` when the stack is created, and links the node to
repo2graph, boltwall and neo4j. Everything else, the agent's model and key, the TypeSafe key, every schedule
and threshold, is set on the advisor's Settings page and stored in its database; the swarm's `.env` seeds
nothing. Without a key of its own the advisor's agent runs on repo2graph's key. It passes no AWS credentials: the
advisor is configured read-only from its Settings page, exactly as documented above, and `advisor` is on the
stack's auto-update list.

## Roadmap

1. Executor: done for five standing adjustments (Serverless v2 minimum by hour, snapshots to Archive, gp3 IOPS
   trim, log retention, S3 request metrics) with the actuator role, dry run, read-back, revert, the tag-based deny
   and approved `auto` recommendations as the go-ahead. Next in the same shape: gp3 throughput (needs throughput
   metrics in the EBS inventory), applying the S3 lifecycle recommendations, parking stopped swarms
   (`docs/park-swarms-plan.md`).
2. Seven-day realized-saving verification from Cost Explorer.
3. sphinx-swarm images as above.
4. Cross-link the [graph mirror](#graph-mirror) with the code graph (which repository deploys to which instance).
