# aws-advisor

An AWS cost advisor that lives next to a sphinx-swarm. Steampipe and Powerpipe collect the facts,
fixed rules draft recommendations, repo2graph's agent ranks and enriches them with evidence it gathers
itself, and a small web app is where the team reviews, decides and watches. Nothing in this repository
changes anything in AWS: the advisor reads, the agent proposes, humans decide. An executor that acts on
approved items is on the roadmap and will run under its own IAM role, never through the agent.

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
   repo2graph's Concept graph (one concept per recommendation under `aws/cost-advisor`) and a rejection is also
   posted to its learnings store, so the agent consults past decisions natively on the next run.
6. **Watch.** Every 30 minutes a cheap watcher samples instance states, NAT traffic, Savings Plans and EBS
   totals and raises alerts on sudden change, shown at the top of Overview and on the Alerts page.
7. **Investigate.** A NAT traffic alert is handed to the agent as an incident: it gets the alert with its
   attribution, the VPC's flow-log status, the last day of samples and the instances involved, investigates
   with the MCP tools and comes back with a cause, confidence, the episode's cost, its run-rate and fixes that
   land as recommendations.

### What "Approve" does today

It records the decision (status, who, when) and moves the item to the approved list. Nothing is executed.
Approved items are the queue the future executor will read from, restricted to a catalog of tiered actions:
`auto` (reversible: retention policies, tags, snapshots), `approve` (stop, resize, storage tier changes,
deletions after a snapshot), `report` (never automated).

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
is a thread under the plan: each message you write becomes one agent request (task `chat`, `tasks/chat/`) whose brief
is the recommendation, the current plan, the step outcomes and the last twelve messages; the answer arrives through
the webhook (the thread polls every 5 s meanwhile). The agent can hand back corrected steps with commands and verify
lines (`step_fixes`, shown as cards) and say the plan needs rewriting (`suggest_replan`, which offers the re-plan
button). Facts in the brief are read-only; the agent checks claims with the `aws_*` tools before answering.

The detail's "Affected resources" lists every resource the item touches as a link into its Inventory tab
(opened in a new tab): the resource column split up when the agent grouped several ids, each resolved
against the inventory for its name and kind (`src/affected.ts`, returned as `affected` by
`GET /api/recommendations/:id`). Ids and inventory names that appear only in the title or the rationale
("Right-size two boxes: Hive and swarmPExsmg" with one id in the resource column) are listed apart as "also
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
  reach it, the open recommendations on it, and a link to the alert in the advisor (`PUBLIC_URL`).
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
| Overview | last full month invoice and coverage, open recommendations and their total, findings in the last run, open watcher alerts, top recommendations, on-demand spend by service, EC2 Other breakdown, commitment expiries | run now, acknowledge alerts |
| Runs | one row per collection with counts and status | start, open |
| Alerts | every watcher alert (open, acknowledged or all) with Jev's triage (kind, severity, expected probability, auto-acknowledged by Jev), expandable to its details (top receivers table for NAT alerts) and its incident: cause, confidence, episode cost, run-rate, evidence, fixes linking to their recommendations | investigate, poll result, retry, acknowledge, reopen (undo) |
| Run detail | live log, findings by control, what changed vs the previous run, agent runs for this collection with a live event stream | send findings to agent, watch, poll result |
| Findings | every alarm from the benchmarks and custom queries, filterable by control, searchable | |
| Inventory | EC2 / RDS / ElastiCache / Lambda / EBS / S3 / Route 53 tabs: summary tiles (running, stopped, SSM online, SSM not managed, on-demand price of what runs, EBS GB), filters by state and SSM status, search, sortable table, sticky detail drawer with identity, network, storage and volumes, SSM, tags, utilisation with probe history, price, the domains that reach the resource, and links to the resource's findings and recommendations; gone resources on request. The Route 53 tab lists every record with what it leads to in this account (or that it is dangling, or outside AWS) | refresh now, probe (SSM-online Linux instances) |
| Recommendations | ranked list with saving, tier, confidence and source, searchable by text or `#id`; sticky detail panel with rationale, evidence, probe data and a step checklist with a follow-up day | approve, reject with reason, snooze, mark pending, mark done, reopen, tick steps, probe (idle instances) |
| Settings | AWS credentials (mode picker: access keys, AWS profile, instance / default chain, each with an optional role to assume; save and test checks Steampipe and the SDK side), permissions (what the credentials should be, the SSM probe document and its commands, per-capability check results, missing actions seen anywhere in the app with when and where, the IAM policy JSON that fixes them), benchmark toggles, agent configuration, Jev (enabled, calls and tokens today, last error), dev API token | save and test, remove, check permissions |

## Onboarding: set up AWS access in 10 minutes

### The one-command way

Settings > **Set up AWS access** is a four-step wizard: pick a path (**Laptop / server with a long-lived key**
or **EC2 host with an instance role**), keep or change the names, read the plan, copy one command:

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
  update) the SSM probe document `AwsAdvisorProbe`; `PUT /api/settings/aws` with the profile and print the test
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
        "logs:DescribeLogGroups", "logs:DescribeLogStreams", "logs:ListTagsForResource",
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
        "elasticbeanstalk:DescribeEnvironments",
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
        "arn:aws:ssm:*:<account-id>:document/AwsAdvisorProbe",
        "arn:aws:ec2:*:*:instance/*"
      ]
    },
    {
      "Sid": "AdvisorSsmProbeDocument",
      "Effect": "Allow",
      "Action": ["ssm:DescribeDocument", "ssm:GetDocument"],
      "Resource": "arn:aws:ssm:*:<account-id>:document/AwsAdvisorProbe"
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

### The SSM probe document

`AWS-RunShellScript` runs whatever shell it is handed, so a policy that allows `ssm:SendCommand` on it lets the
credentials run *any* command on every instance, and IAM alone cannot make the probe read-only. The advisor
therefore runs the probe through its own SSM Command document, `AwsAdvisorProbe` (`PROBE_DOCUMENT`, the
default), which embeds the fixed probe script, and the policy above grants `ssm:SendCommand` on
`arn:aws:ssm:*:<account-id>:document/AwsAdvisorProbe` and `arn:aws:ec2:*:*:instance/*` only. **Never grant the
advisor `ssm:SendCommand` on `AWS-RunShellScript`** (or on `document/*`): with it a leaked key runs arbitrary
commands on the fleet. The setup script creates the document and updates it when the probe changes; by hand:

```
curl -s http://localhost:9034/api/probe/document > probe-document.json   # schemaVersion 2.2, one aws:runShellScript step, the PROBE_SCRIPT lines, 60 s timeout
aws ssm create-document --name AwsAdvisorProbe --document-type Command --document-format JSON --content file://probe-document.json
```

The advisor sends that document with no `commands` parameter (the script is inside the document); the policy
also grants `ssm:GetCommandInvocation`, `ssm:ListCommandInvocations`, `ssm:DescribeInstanceInformation` (the SSM
inventory) and `ssm:DescribeDocument` / `ssm:GetDocument` on the document (the permission check verifies it
exists and is readable, and prints the create command when it does not). SSM documents are regional: create it
in every region with instances to probe (`--region`). To limit which instances can be probed, add a condition
on the instance ARN, e.g. `"Condition": {"StringEquals": {"ssm:resourceTag/Environment": "staging"}}` on the
`AdvisorSsmProbe` statement. When `PROBE_VERSION` in `src/ssm.ts` changes, rerun the setup script or update
the document:

```
curl -s http://localhost:9034/api/probe/document > probe-document.json
aws ssm update-document --name AwsAdvisorProbe --document-version '$LATEST' --document-format JSON --content file://probe-document.json
aws ssm update-document-default-version --name AwsAdvisorProbe --document-version "$(aws ssm describe-document --name AwsAdvisorProbe --query Document.LatestVersion --output text)"
```

`PROBE_DOCUMENT=AWS-RunShellScript` exists only for a throwaway test with credentials that are deleted
afterwards: the advisor then passes the script as the `commands` parameter, the permission check flags the
setup as unsafe, and the recommended policy still names only `AwsAdvisorProbe`, so nothing in this document
ever grants the stock one.

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
aws ssm create-document --name AwsAdvisorProbe --document-type Command --document-format JSON --content file://probe-document.json
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

Every decision becomes a Concept in repo2graph, in one of two scopes:

- **internal**: about one specific resource in this account (parent concept "AWS Cost Decisions"), named after the
  action and the resource, e.g. `terminate_stopped_instance example-node-1`.
- **generic**: reusable knowledge that transfers to any account (parent "AWS Cost Knowledge"), named after the
  workload role and the action, never a resource id, e.g. `blockchain_node rightsize_instance rule` with the rule
  "bitcoind nodes are idle on CPU by design; never treat them as right-size candidates".

When you decide, the detail panel asks whether the decision applies to this resource only or to all resources of
this kind; Jev reads the reason and pre-selects the likely scope with its confidence, and you can override it. The
agent prompt lists generic rules first, then internal decisions, and the stored scope is kept in the `concepts`
table (`scope`) and on the recommendation (`decision_scope`).

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
| `domain_inventory` | the Route 53 snapshot: every record with where it leads in this account (`linked` with the resources reached, `unmatched` for AWS names the account does not have, `external`, `none`), filterable by search, zone, state or type; or one resource's domains by kind and id |
| `instance_probe` | runs the SSM probe below and returns the parsed JSON |
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
carry `incident_id`, `incident_status` and, once completed, the cause, confidence, costs and fixes.

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

## SSM probe

A fixed, versioned shell script (`PROBE_SCRIPT` in `src/ssm.ts`, read-only: `/proc`, `df`, `ps`) is sent through
the SSM document named by `PROBE_DOCUMENT` (`AwsAdvisorProbe`, the custom document that embeds the script and
the only one the policy ever grants; the setup script creates it; see [The SSM probe document](#the-ssm-probe-document))
to one instance that `aws_ssm_managed_instance` reports as online Linux, using the same
identity Steampipe uses (the saved keys, the profile or the default chain, with the role when one is set; see
[Three ways to authenticate](#three-ways-to-authenticate)). It prints one JSON object (memory total and used,
disk usage per mount, 1/5/15 load, top five processes by CPU and by memory); the app polls the invocation,
validates the output and stores it in `instance_metrics`. The idle-instance rule uses the latest probe to raise
or lower its confidence and to mention memory and load in the rationale. The credentials need
`ssm:SendCommand` and `ssm:GetCommandInvocation`; missing permission, an unmanaged instance or a timeout come
back as a clear error code (`permission`, `not_managed`, `no_credentials`, `timeout`, `failed`, `bad_output`). A
`permission` error names the missing action, carries its IAM statement (`issue`) and is recorded for Settings >
Permissions.

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
- the **agent prompts** (findings, incident, resolution) carry the same operational patterns: pool members are not
  individual candidates, new instances register late, autoscaling churn is normal; the `instance_inventory` MCP
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
| `container_daily` | container per instance per day (running share, CPU and memory average and max) | 400 days |

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
"Impact of your decisions" card lists every actioned recommendation with what it claimed and what the bill did.
Where the scope is account-wide (Aurora lines, EBS volumes, NAT bytes: resource-level cost data is off by default)
the chart says so; another change on the same lines moves it too.

## Inventory

The Inventory page is meant to replace the console for "what do we run, and which of it can we actually manage".
`src/inventory.ts` snapshots three kinds of resource with a handful of schema-qualified Steampipe queries:

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
  assigns, with their descriptions); `KnPattern` nodes (the operational rules the prompts carry).
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

**Log attribution** (`src/log_attribution.ts`) works from evidence, in order: the AWS naming conventions
(`/aws/lambda/<function>`, `/aws/rds/cluster|instance/<name>`, `/aws/eks/<cluster>/cluster`,
`/aws/elasticbeanstalk/<environment>/…`), the cluster and environment names the members' tags carry, then a
token match between the group's path and the systems' names, pools, member ids and aliases (the members' Name
tags), where a compute system beats a database or cache on a tie and a tie between compute systems stays
unattributed. EKS clusters are systems of their own (`eks:<cluster>`, pools `PART_OF` them) and so are the
Lambda functions the latest run flagged (`lambda:<name>`), so their log groups have somewhere to attach. Each
`SHIPS_LOGS_TO` edge records how it was attributed. 97 of 123 groups attach to a system on this account; the
rest stay on the account node.

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

All labels are prefixed `Advisor` (the Neo4j is shared with stakgraph and repo2graph; nothing without the prefix is
ever created, changed or deleted), every node carries `account_id` and `updated_at`, and the only foreign label used is
`Concept`, matched by id, never created:

```
(:AdvisorAccount {id})
   ▲ IN_ACCOUNT
(:AdvisorResource {id, kind: ec2|rds|elasticache, name, type, state, region, role, role_confidence, protected_prob,
                   monthly_usd, cpu_30d, ssm_status, gone, first_seen, last_seen})
   ├─[:HAS_ROLE]──▶ (:AdvisorRole {name})                one node per Jev role name
   ├─[:IN_POOL]───▶ (:AdvisorNodePool {name})            Karpenter pool / EKS node group / ASG (EC2 only)
   ◀─[:TARGETS]──── (:AdvisorRecommendation {id, fingerprint, title, action_type, tier, status, source, rule,
   │                  est_monthly_saving, confidence, decided_by, decided_at, decision_scope, created_at})
   │                  ├─[:TARGETS]──────▶ (:AdvisorResourceRef {id})   when the resource is not in the inventory (a VPC, a bucket, a Lambda)
   │                  ├─[:DECIDED_AS]───▶ (:Concept)                   the team's decision or rule in repo2graph (MATCH only)
   │                  ├─[:PROPOSED_IN]──▶ (:AdvisorRun {id, started_at, finished_at, status, trigger, findings_count, recommendations_count})
   │                  └─[:FROM_INCIDENT]▶ (:AdvisorIncident {id, status, cause, confidence, episode_cost_usd, monthly_run_rate_usd, created_at})
   │                                        └─[:INVESTIGATES]▶ (:AdvisorAlert {id, kind, level, message, created_at, acknowledged, acknowledged_by})
   ◀─[:ABOUT]────────────────────────────────────────────────────┘        (alerts point at an AdvisorResource or an AdvisorResourceRef)
   ◀─[:FLAGGED {run_id, reason}]── (:AdvisorControl {id, title}) ─[:HAS_PLAYBOOK]─▶ (:AdvisorPlaybook {control_id, title, tier, effort})
```

Findings are not mirrored one node per row (thousands per run); instead the latest completed run's alarm findings
whose resource is in the inventory become `FLAGGED` edges from the control to the resource, one per control and
resource, and earlier runs' edges are dropped. Resource references are matched as the id itself or the last segment
of an ARN (`arn:...:instance/i-abc` → `i-abc`); anything else becomes an `AdvisorResourceRef`. Playbooks come from
`src/playbooks.ts`. Unique constraints on each label's id (name for roles and pools) are created if missing.

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

Endpoints (`src/routes/graph.ts`): `GET /api/graph` → `{ configured, uri (host only), connected, server, error, stats: { nodes,
relationships, total_nodes, total_relationships }, account_id }`; `POST /api/graph/sync[?wipe=1]` → the counts of
`mirrorAll` (`resources`, `recommendations`, `runs`, `flagged`, `controls`, `playbooks`, `alerts`, `incidents`), `wiped`,
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
daily review's `disk_fill` is the trend, days until full at the current rate.

## Host alerts from the probes

The same pass judges memory, swap, load and reboots (`src/host_alerts.ts`): `memory_high` at `MEM_WARN_PCT`
(85 %) and `memory_full` at `MEM_ALARM_PCT` (95 %) of used memory with available subtracted; `swap_in_use` at
`SWAP_WARN_PCT` (25 %) of the swap space; `load_high` when the 15-minute load average per vCPU reaches
`LOAD_PER_CORE` (1.5), a sustained saturation rather than a spike; `reboot` when a probe's uptime is lower than
the previous probe's, with the reboot time worked back from the uptime. Hysteresis and system acknowledgement as
for disks. All thresholds are runtime settings under Probe pass.

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
the `settings` table as `prompt:<kind>` and wins until reset. The advisor appends the data after the prompt, so
what you edit is the persona and the rules. `GET /api/prompts`, `PUT /api/prompts/:kind { text }`,
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
| disk filling | a least-squares line through the root disk usage reaches 90 % within 60 days (fit r² ≥ 0.5) | recommendation `review_disk_fill`; alarm when under 14 days |
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
  usage-based lines (transfer, NAT, CloudWatch, requests, snapshots, spot) at their month-to-date daily average.
  *Fixed*: the Savings Plan fee, the reservations' amortized cost and support. AWS posts support on the 1st as a
  placeholder and trues it up at month end, so the forecast asks the Support API which plan the account is on
  (`src/support_plan.ts`, `support:DescribeSeverityLevels`: Basic fails with a subscription error, the severity
  codes tell Developer, Business and Enterprise apart) and applies that plan's formula to the forecast charges;
  a cancelled plan adds nothing beyond what was posted. The plan is cached as the account fact
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

## Security posture

What a compromise of the advisor, of the repo2graph agent, or of a machine on the same network can and cannot do,
after the 2026-09-19 review (`src/__tests__/security.test.ts` pins the guards):

- **No write path to AWS.** The only mutating SDK call is `SendCommand` on the probe document, whose name comes
  from the environment and never from a request or the agent; the script is a constant and instance ids are
  regex-checked. `PROBE_DOCUMENT=AWS-RunShellScript` is refused at startup. Approving a recommendation only
  updates a row; nothing reads `approved` or `tier = auto` to act. The executor, when it exists, gets its own role.
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

1. Executor with an actuator IAM role: tiered actions, pre-check, dry run, post-check, rollback note, tag-based
   deny. Tier one first.
2. Seven-day realized-saving verification from Cost Explorer.
3. sphinx-swarm images as above.
4. Cross-link the [graph mirror](#graph-mirror) with the code graph (which repository deploys to which instance).
