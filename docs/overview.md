# Cloud Advisor: overview

A short, non-technical description of what this project is, what runs and when. The README is the full reference;
this page is the one to hand to someone new. Keep it in step with the code: when a job, its default schedule or a
user-facing feature changes, update this file in the same change.

*Last updated: 2026-10-09*

## What it is

Cloud Advisor (repo `aws-advisor`) watches our cloud accounts for wasted money and security risk. It reads the
accounts with read-only access. Fixed rules draft recommendations, and an AI agent (repo2graph on Claude) checks and
ranks them. People approve or reject them in a private web app.

**The advisor reads, the agent proposes, humans decide.** The one exception is a small set of reversible adjustments
that can run on their own. That is off by default (dry run), uses a separate locked-down role, records every change,
and can be undone with one click.

AWS is the main provider and covers several accounts (the management account and its member accounts). Vercel and
GitHub are being added on the same model.

## Where it runs

- It ships as a single Docker image (`ghcr.io/stakwork/aws-advisor`). That image holds the app, its UI, and
  Steampipe/Powerpipe (open-source tools that turn cloud APIs into SQL plus standard cost and compliance checks).
- It is deployed inside a sphinx-swarm as part of the graph stack (when `DEVOPS=1`). It sits next to repo2graph
  (the agent) and Neo4j (the knowledge graph).
- It is private: there's no public route. You reach it over the VPN on port 9034 and sign in with a token.
- Its data lives in a local SQLite database. Everything important (resources, decisions, actions, alerts) is also
  mirrored into the Neo4j graph, so the agent and other tools can query it.

## What runs and when

Default schedules use the container's clock (normally UTC). Every schedule can be changed or turned off in
Settings, and each job has a **Run now** button there. Every job writes a log line when it fires and explains why
when it does nothing (no credentials, already running, and so on).

### The morning cycle

| Time | Job | What happens |
|---|---|---|
| 04:10 | Software probe | Lists installed packages, OS and container images on each server (via AWS SSM) |
| 04:40 | Vulnerability match | Checks that software against public advisories (OSV, Amazon Linux) and flags known CVEs |
| 05:30–05:40 | Host, container and port probes | Memory, disk, processes, containers, logins, open ports and whether they're exposed to the internet |
| 06:00 | **Collection run** | Standard cost checks plus custom queries; rules draft recommendations with a saving estimate and risk level. The run is compared with yesterday's, and the agent gets it only if something material changed |
| 06:20 | Security scan | AWS Foundational Security Best Practices benchmark, producing security findings |
| 06:40 | Baselines | Learns what "normal" looks like for each resource (see below) |
| 06:50 | Logs and CloudTrail | Log groups, who changed what, AWS notifications, S3 usage, usage profiles, tag hygiene |
| 07:00 | Daily review | Turns the statistics into recommendations and alerts (see below) |
| 07:15 | Morning observation | The agent writes its summary of the day |
| 07:30 | Saving verification | Checks approved fixes against the actual bill, starting 7 days after the decision. This feeds the "Impact" chart |
| Mondays 07:00 | Playbooks | The agent rewrites fix guides from official sources (see below) |

### Throughout the day

| How often | Job | What happens |
|---|---|---|
| Every 10 minutes | Alert causes | Finds out in CloudTrail who or what triggered an alert |
| Every 10 minutes | Pressure check | If a Beanstalk app is maxed out and its CPU is high, raises its ceiling by one, within agreed limits |
| Every 30 minutes | Watcher | Samples instance states, NAT traffic, Savings Plans, EBS and EC2 health checks; raises an alert on sudden change |
| Every 30 minutes | Vercel collection | Projects, deployments, domains, environment variable names, firewall |
| Hourly at :45 | Auto-actions pass | Proposes, and in apply mode makes, small changes ahead of the coming hour |
| Every 6 hours | Spend refresh | Bill, commitments and month-end forecast from Cost Explorer |
| Every 6 hours | GitHub collection | Members, access, credentials, installed apps, Copilot seats, billing |

## The three jobs that make the data useful

### Baselines: learning what "normal" looks like

A fixed threshold like "alert above 80% CPU" is wrong for half our machines. Some are always busy, some are always
quiet, and some only spike at night. So every morning the advisor learns, for each resource, what is typical **for
that resource at that hour of that weekday**.

| What | Measure | History used |
|---|---|---|
| NAT gateways (internet egress) | Traffic per hour | 14 days |
| Each server | CPU | 14 days |
| Each server | Memory, disk, load, number of containers (from our probes) | 30 days |
| Each server | Network in and out per day | 14 days |
| Each AWS service | Spend per day | 60 days |

For each of these it stores the median, a measure of spread that one spike can't distort, and the 95th percentile.
Once it has a week of data, it also stores a typical value for each hour of the day and each day of the week.

A new reading is scored against its own baseline as normal, high or extreme. This keeps alerts quiet when a
resource is doing what it always does, and makes them fire when it isn't. Two examples:

- A NAT gateway alerts only when traffic is extreme **for that hour** and also above 5 GB.
- A server whose daily network traffic suddenly doubles above its own norm (at least 5 GB a day) raises a warning.
  A jump in the data-transfer line on the bill then points to a specific machine and a specific day.

### Daily review: turning the statistics into recommendations

Collecting numbers only helps if something reads them back. Right after the baselines, the review looks at the last
30 days and produces concrete items, each with the evidence attached:

| What it notices | Rule (simplified) | Result |
|---|---|---|
| Machine sitting idle | At least 5 days with low memory, low load and low CPU | Recommendation to downsize, saving about half the machine's cost. Report-only for machines idle by design or part of an autoscaling group |
| Memory pressure | Memory above 85% for 5 or more days | Warning |
| Disk filling up | The usage trend reaches 90% within 60 days | Recommendation, and an alarm if the disk is less than 14 days from full |
| Idle container | A container near 0% CPU for 90% of the period | Note on the Overview |
| Spend jump | A service's last 3 days are clearly above its 60-day norm, by at least 30% and $20 a day | Warning with the projected extra cost for the month |
| S3 bucket without lifecycle rules | At least 20 GB in the most expensive storage tier and no rule to move it | Note with the saving from moving it |
| Over-provisioned disk performance | A disk is paying for performance (IOPS) it never uses | Note with the monthly cost of the unused performance |

This is the step that turns "we have data" into "here is what to do and what it's worth."

### Playbooks: how-to guides written from official sources

When a check flags something like "this server isn't using the cheaper Graviton processors," that says what's wrong,
not how to fix it. A playbook is the how-to guide for one check. It covers:

- what the alert means
- when to act on it and when to ignore it
- the steps
- the saving
- a risk level: safe to automate, needs approval, or report only

How playbooks are produced:

- **Sources:** only official material. That means the definitions from the standard checks and the AWS
  documentation pages they point to. **Nobody writes playbook text by hand.**
- **Writing:** the AI agent writes each playbook, and every step must cite the source it came from.
- **Review:**
  - A second model checks the risk level ("could these steps destroy data?") and can only make it stricter.
  - Playbooks the agent isn't confident about are held back, with the reason shown.
  - A person can mark a playbook as reviewed, which locks it, or as disputed, which takes it down.
- **Weekly refresh:** sources are re-read each Monday. Playbooks whose source changed, or that are getting old, are
  rewritten. Checks that fired recently but have no playbook yet get one. This happens a few at a time to keep AI
  costs down.

Fix guidance therefore stays current with AWS's own documentation, can be traced back to a source, and doesn't
depend on someone remembering to update a wiki.

## The graph: why it matters

Most cost and security tools give you lists: a list of servers, a list of findings, a list of users. The hard
questions sit **between** the lists. Is this vulnerable package actually reachable from the internet? Who could
switch this database off? What else breaks if we stop this machine? Have we already decided against this?

The advisor answers these by keeping everything it knows in one connected graph (Neo4j). Every resource, person,
permission, open port, installed package, alert, recommendation, decision and auto-action is a node, and the facts
that connect them are edges. It is shared with repo2graph, so the infrastructure sits next to the code graph and
the team's recorded decisions.

### Questions it answers directly

| Question | How the graph answers it |
|---|---|
| Which vulnerabilities actually matter? | A CVE is linked to the server that has the affected package, to the port that software listens on, and to whether that port is reachable from the internet. "Critical" means exploitable from outside, not just installed somewhere |
| Who can touch production? | People are linked to their AWS users, Identity Center assignments and Vercel accounts (GitHub is being added), and then to the roles they can assume and the servers they can open a shell on. One question gives everything a person can reach, directly or indirectly, and what they actually changed in the last 90 days |
| What is exposed, and why? | Each endpoint carries a verdict: reachable from the internet, from the network, or blocked, with the exact firewall rule that allows or blocks it |
| What breaks if we change this? | A server is linked to its pool or cluster, its disks, the DNS records that still point at it, its containers and apps, and its open alerts. These are checked before anyone acts |
| Where does the money go? | Systems are linked to the machine types they run on with hours and list price, to the discounts that cover them, to the traffic they send and the logs they write. From the graph alone the advisor can rebuild a large part of the monthly bill, and closing the gap is ongoing |
| What did we already decide? | Every recommendation, approval, rejection (with its reason) and auto-action is in the graph, linked to the resources it touched. The agent reads this before proposing anything, so it doesn't repeat a rejected idea |

### Why this is a lasting advantage

- **The AI reasons over facts, not guesses.** The agent queries the graph (read-only) to check what it claims
  before it recommends anything. Hard verdicts like "reachable from the internet" or "vulnerable" are computed once
  by the advisor and stored as edges, so the agent never has to work out firewall logic itself.
- **One model for every provider.** AWS, Vercel and local machines (GitHub next) are described in the same terms
  (compute, network, identity, cost). A question like "who can deploy to production" works across all of them,
  and a new provider plugs into the same questions.
- **It remembers.** Decisions, what was done and what happened afterwards (including whether the saving showed up
  on the bill) all build up over time. That memory is what turns a scanner into an advisor that learns how this
  team works.

## What people see and do

- **Overview:** this month against last month, the forecast, alerts and spend for each account.
- **Recommendations:** approve, reject with a reason, snooze, or work through step-by-step plans. You can also chat
  with the agent about a recommendation or ask it to re-plan. Rejections are remembered so the agent doesn't propose
  them again.
- **Inventory, Security and Access:** every resource and how they connect, vulnerabilities, exposed ports, and who
  can get into what (people, roles, SSO, Vercel and AWS links).
- **Notifications:** alerts and every auto-action are posted to a Sphinx chat, with quiet hours respected.

## Auto-actions and why they're safe

- About 30 reversible adjustments are available. Examples:
  - Scaling a database's minimum capacity by hour of day
  - Moving old snapshots to cheaper archive storage
  - Shortening log retention
  - S3 lifecycle rules
  - Parking idle swarms
  - Scaling Beanstalk apps within agreed limits
- **Dry run by default.** Changes are only recorded until someone switches to apply mode or presses Apply on a
  single row.
- **Only one identity can change anything:** a separate actuator role with narrow permissions. The read access is
  AWS's ViewOnlyAccess policy plus a few extra read permissions, and it can never write.
- **Opt-in by tag, with a hard opt-out.** Stopping and starting machines requires a consent tag on that resource
  and a grant for each instance. Anything tagged `advisor:hands-off` is blocked by an explicit Deny.
- Every change has a before and after, a reason, a cost estimate and a Revert button. It is read back to confirm it
  worked and kept in a ledger for 90 days. There is a kill switch.

## Status

- **Built:**
  - AWS cost advisor and agent
  - Alerts and Sphinx notifications
  - Auto-actions executor
  - Security scan and vulnerability matching
  - Multi-account support (management account plus member accounts)
  - Identity and access mapping
  - Knowledge graph mirror
- **In progress:**
  - The GitHub organisation adapter.
  - The Vercel adapter is built but hasn't been tested against a live account.
- **Open:** the graph namespace clashes with Jarvis's tenant namespace.
- **Planned:** wake-on-traffic, which puts unused machines to sleep and wakes them when a request arrives.
