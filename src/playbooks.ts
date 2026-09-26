/**
 * Playbooks: what a finding means and how to act on it. One entry per control that raises alarms in this
 * app (every AWS Thrifty control seen so far plus the advisor's own `query.*` controls and the two rules that
 * have no control behind them), written the way a senior engineer would brief a colleague: what the alarm
 * actually says, when it is worth acting, when to leave it alone, the concrete steps, how the saving is
 * computed, the risk tier the action belongs to and the effort it takes. The catalog is static; the
 * resolution flow in src/resolve.ts tailors it to one resource with the graph, Jev and the agent.
 */

export type PlaybookTier = "auto" | "approve" | "report";
export type PlaybookEffort = "low" | "medium" | "high";

export interface Playbook {
  control_id: string;
  title: string;
  /** What the alarm actually says, in one or two sentences. */
  meaning: string;
  /** When it is worth acting on. */
  act_when: string;
  /** When to leave it alone (and why). */
  ignore_when: string;
  /** Concrete steps, in order. */
  steps: string[];
  /** The saving formula, in words. */
  saving: string;
  /** auto = reversible and safe to automate; approve = needs a human; report = never automate. */
  tier: PlaybookTier;
  effort: PlaybookEffort;
  references?: string[];
}

const T = "aws_thrifty.control.";

const GRAVITON_EC2_STEPS = [
  "List what runs on the box: `ssh` in (or run the advisor's SSM probe) and note every binary, container image and package that is not from the distro repos.",
  "Check each one has an arm64 build: `docker manifest inspect <image>` must list linux/arm64; vendor binaries need an aarch64 download; Python/Node native modules need arm64 wheels or a compiler on the box.",
  "Pick the target type from the same size in the Graviton family (m6i.xlarge -> m7g.xlarge, t3.medium -> t4g.medium, r5 -> r7g, c5/c6i -> c7g) and confirm the price with the advisor's price lookup.",
  "Build an arm64 AMI: launch a t4g from the arm64 edition of your base image (Amazon Linux 2023 / Ubuntu arm64), run the same provisioning, snapshot it. A snapshot of the x86 root volume does not boot on Graviton.",
  "Kubernetes: instead of touching instances, add an arm64 node group or a Karpenter NodePool with `kubernetes.io/arch: arm64` and make every workload image multi-arch (`docker buildx --platform linux/amd64,linux/arm64`); let the scheduler drain the x86 nodes.",
  "Hand-built boxes: launch the replacement from the arm64 AMI in the same subnet and security groups, move the data volume (EBS is architecture-neutral), re-point the DNS or Elastic IP, keep the old instance stopped for a week, then terminate.",
  "Verify: CPU and latency on the new instance at the same load, then check the next invoice line for the instance family.",
];

export const PLAYBOOKS: Record<string, Playbook> = {
  // ---- Graviton --------------------------------------------------------------------------------------------
  [`${T}ec2_instance_with_graviton`]: {
    control_id: `${T}ec2_instance_with_graviton`,
    title: "EC2 instance is not on Graviton",
    meaning: "The instance runs an x86 type (Intel or AMD). Graviton is AWS's ARM CPU: the same size in the g-suffixed family (m7g, c7g, r7g, t4g) costs roughly 10-20% less per hour and usually performs as well or better, but every binary on the box must have an ARM build.",
    act_when: "The instance runs software you build yourself or well-known open source with arm64 packages (nginx, postgres, redis, node, python, go, java, docker images with linux/arm64 manifests), it will live for months more, and it is not a Windows box.",
    ignore_when: "The workload is a third-party binary with no ARM build (some blockchain daemons, proprietary agents, old JVM builds), the instance is due to be retired or replaced soon, it is stopped (nothing to save until it runs), or it is a GPU/accelerated type (g4dn, p3) with no Graviton counterpart.",
    steps: GRAVITON_EC2_STEPS,
    saving: "(on-demand hourly price of the current type - hourly price of the same size in the Graviton family) x 730 hours; zero while the instance is stopped.",
    tier: "approve",
    effort: "high",
    references: ["https://aws.amazon.com/ec2/graviton/", "https://github.com/aws/aws-graviton-getting-started"],
  },
  [`${T}lambda_function_with_graviton`]: {
    control_id: `${T}lambda_function_with_graviton`,
    title: "Lambda function is not on arm64",
    meaning: "The function's architecture is x86_64. Lambda on arm64 (Graviton) bills about 20% less per GB-second and often runs faster; for most functions it is a one-line change.",
    act_when: "The runtime is Python, Node.js, Ruby, Java, .NET or a Go/Rust binary you build, and the function's dependencies are pure (no compiled extensions) or have arm64 wheels/binaries. Functions with real monthly cost first; a function that runs a hundred times a month saves cents.",
    ignore_when: "A layer or dependency ships x86-only native code (some ML wheels, ImageMagick/ffmpeg builds, old Sharp/canvas versions), the deployment package is a container image with no arm64 manifest, or the function is about to be deleted.",
    steps: [
      "Look at the function's runtime and layers: `aws lambda get-function-configuration --function-name <name>` (Architectures, Runtime, Layers).",
      "Pure Python/Node code: change the architecture to arm64 in the console, SAM (`Architectures: [arm64]`), CDK (`architecture: Architecture.ARM_64`) or Terraform (`architectures = [\"arm64\"]`) and redeploy.",
      "Native dependencies: rebuild the package on arm64 (`pip install --platform manylinux2014_aarch64 --only-binary=:all:`, or build in an arm64 container); container images need `--platform linux/arm64` and an arm64 base image.",
      "Layers must be arm64-compatible too: AWS-provided layers have arm64 variants with a different ARN.",
      "Deploy behind an alias, run the test event or a canary invoke, compare duration and errors in CloudWatch for a day, then shift 100%.",
      "Verify the saving on the Lambda line of the next invoice (the price per GB-second drops, and a faster function bills fewer milliseconds).",
    ],
    saving: "About 20% of the function's last-month Lambda cost (compute and requests), from aws_cost_by_resource_daily when resource-level cost data is enabled; unknown otherwise.",
    tier: "approve",
    effort: "low",
    references: ["https://docs.aws.amazon.com/lambda/latest/dg/foundation-arch.html"],
  },
  [`${T}rds_db_instance_with_graviton`]: {
    control_id: `${T}rds_db_instance_with_graviton`,
    title: "RDS instance is not on a Graviton class",
    meaning: "The DB instance class is x86 (db.m5, db.r5, db.t3, db.m6i, db.r6i). The g-suffixed classes (db.m7g, db.r7g, db.t4g) run the same engine version on Graviton for roughly 10-20% less; the engine does not care about the CPU.",
    act_when: "The engine version supports the Graviton class (PostgreSQL 12+, MySQL 8+, MariaDB 10.4+, Aurora on r6g/r7g), the instance will live for months, and you can afford the restart the class change implies.",
    ignore_when: "Oracle or SQL Server (licensing and no Graviton classes for most editions), a reserved instance covers the current class until it expires, or the instance is due to be retired.",
    steps: [
      "Confirm the engine version is supported on the target class: `aws rds describe-orderable-db-instance-options --engine <engine> --engine-version <v> --db-instance-class db.r7g.large`.",
      "Pick the same size in the Graviton family (db.r5.large -> db.r7g.large, db.t3.medium -> db.t4g.medium, db.m6i.xlarge -> db.m7g.xlarge).",
      "Check active reservations: an RI on the current class keeps billing after the move (the advisor's commitments query lists them; reservations are owned by the member account).",
      "Modify the class in the maintenance window: `aws rds modify-db-instance --db-instance-identifier <id> --db-instance-class db.r7g.large` (add `--apply-immediately` only if the downtime is acceptable now). Multi-AZ fails over with about a minute of unavailability; Single-AZ restarts, usually 5-15 minutes.",
      "Aurora: modify the writer last, or add a Graviton reader, fail over to it, then modify the old writer.",
      "Watch CPU, connections and p99 latency for a day; roll back with the same command if anything regresses.",
    ],
    saving: "(hourly price of the current class - hourly price of the same size Graviton class, same engine and Multi-AZ/I/O-Optimized setting) x 730 hours.",
    tier: "approve",
    effort: "medium",
    references: ["https://aws.amazon.com/rds/instance-types/"],
  },

  // ---- EC2 -------------------------------------------------------------------------------------------------
  [`${T}ec2_instance_older_generation`]: {
    control_id: `${T}ec2_instance_older_generation`,
    title: "EC2 instance on a previous-generation type",
    meaning: "The instance runs t2, m3, m4 or similar. Newer generations of the same size cost the same or less and are faster (m4.xlarge is 0.20 USD/h, m5.xlarge 0.192, m7g.xlarge 0.163); t2 also lacks the unlimited-burst default of t3.",
    act_when: "The instance is running and will stay; especially when it is also CPU-bound or pays for t2 burst credits.",
    ignore_when: "It is stopped (no hourly cost), it will be terminated soon, or it is on a reservation that still runs on the old family.",
    steps: [
      "Pick the modern equivalent of the same size: m4 -> m5/m6i (x86) or m7g (Graviton); t2 -> t3/t3a (x86) or t4g (Graviton); c4 -> c5/c6i or c7g; r4 -> r5/r6i or r7g.",
      "Check the AMI supports the new type: a t2/m4 box may run an old kernel without ENA/NVMe drivers (`modinfo ena`, `modinfo nvme`); if missing, update the kernel first or the instance will not boot on Nitro.",
      "Stop the instance, `aws ec2 modify-instance-attribute --instance-id <id> --instance-type m5.xlarge`, start it. Same volumes, same private IP; a public IP changes unless it is an Elastic IP.",
      "For a Graviton target follow the Graviton playbook instead (a new AMI is needed).",
      "Verify it boots and serves; keep the old type in the runbook for a quick rollback.",
    ],
    saving: "(hourly price of the current type - hourly price of the target type) x 730; often small on the same architecture, larger when the target is Graviton.",
    tier: "approve",
    effort: "low",
  },
  [`${T}long_running_ec2_instances`]: {
    control_id: `${T}long_running_ec2_instances`,
    title: "EC2 instance has run for more than 90 days on demand",
    meaning: "Steady, long-lived on-demand usage is the cheapest thing to commit: a 1-year no-upfront Compute Savings Plan cuts about 30% off it, 3-year about 50%. The alarm is about the billing model, not the instance.",
    act_when: "The fleet's baseline of always-on instances is stable, no Savings Plan or reservation covers it yet (the Overview's coverage tile and the commitments query show that), and the account will keep running this much for at least a year.",
    ignore_when: "Coverage is already high, the instance is one of many that will be consolidated or moved to Graviton first (commit after the migration, Compute Savings Plans follow the workload across families but EC2 Instance Savings Plans and RIs do not), or the account is being wound down.",
    steps: [
      "Open Cost Explorer > Savings Plans > Recommendations (payer account) for the 1-year no-upfront Compute plan recommendation; it is computed from the last 30 days of on-demand usage.",
      "Compare with the advisor's on-demand baseline: commit to no more than the hourly spend that never dips below (the minimum hourly on-demand over the last 30 days), not the average.",
      "Finish planned migrations (Graviton, right-sizing) first, or buy a Compute plan (family-agnostic) rather than an EC2 Instance plan.",
      "Purchase in the payer account so the plan applies across member accounts; note the term end date in the commitments list.",
      "Verify after one full month: the coverage tile on the Overview rises and the on-demand EC2 line drops.",
    ],
    saving: "About 30% (1-year) to 50% (3-year) of the committed hourly on-demand spend; nothing on the instance itself.",
    tier: "report",
    effort: "medium",
  },
  [`${T}instances_with_low_utilization`]: {
    control_id: `${T}instances_with_low_utilization`,
    title: "EC2 instance with very low CPU",
    meaning: "The average CPU over the last 30 days is under 20%. CPU alone is not proof of waste (a chain node, a broker or a memory-bound box are naturally low on CPU), but a box that is idle on CPU, memory and network is either oversized or forgotten.",
    act_when: "Memory and network confirm it (run the SSM probe), the workload is known, and either a smaller type or a schedule fits it. Two sizes down halves the bill twice.",
    ignore_when: "Jev classifies it as a blockchain node or cache/broker (low CPU by design), it is a bastion or VPN that must stay up, or it is a burstable type sized for memory rather than CPU.",
    steps: [
      "Run the advisor's SSM probe (Recommendations > Probe) or look at memory in CloudWatch agent metrics; check network in/out and disk I/O for the same 30 days.",
      "Identify the owner from tags or the name; ask whether it is still needed at all: a forgotten box saves 100%.",
      "If needed but oversized: stop, `modify-instance-attribute --instance-type` one or two sizes smaller in the same family, start; watch for a week.",
      "If needed only in working hours (dev/test): an Instance Scheduler or a cron `aws ec2 stop-instances` at night and weekends saves about two thirds.",
      "If idle memory too and nobody claims it: snapshot (AMI) and stop; terminate after 30 days of silence.",
    ],
    saving: "Right-size: price of the current type - price of the smaller type, x 730. Schedule: about 65% of the instance price. Stop and terminate: the whole instance price plus its EBS.",
    tier: "approve",
    effort: "medium",
  },
  [`${T}ec2_reserved_instance_lease_expiration_days`]: {
    control_id: `${T}ec2_reserved_instance_lease_expiration_days`,
    title: "EC2 reserved instance expires within 30 days",
    meaning: "A reservation is about to end. The instances it covered will bill on demand the day after unless it is renewed or replaced by a Savings Plan; nothing breaks, the bill just rises.",
    act_when: "The covered instances (same type and region) will keep running past the expiry date.",
    ignore_when: "The covered type is being retired or migrated to another family; then let it lapse and buy a Compute Savings Plan for the new baseline instead.",
    steps: [
      "List the expiring reservations and what they cover: `aws ec2 describe-reserved-instances --filters Name=state,Values=active` (End, InstanceType, InstanceCount) and compare with running instances of that type.",
      "Decide: renew as an RI (same type only), replace with a Compute Savings Plan (any type/family, covers migrations), or let it lapse.",
      "Buy the replacement a few days before the end date in the payer account; commitments overlap for those days at no extra cost of consequence.",
      "Verify on the commitments list and in Cost Explorer's coverage report after the expiry date.",
    ],
    saving: "Avoided cost: the difference between the reserved rate and on demand for the covered instances (roughly 30-40%) for the term.",
    tier: "report",
    effort: "low",
  },

  // ---- EBS -------------------------------------------------------------------------------------------------
  [`${T}large_ebs_volumes`]: {
    control_id: `${T}large_ebs_volumes`,
    title: "EBS volume larger than 100 GB",
    meaning: "A big volume bills every provisioned GB whether or not it is used (gp3 0.08 USD/GB-month, io1/io2 much more plus IOPS). The control does not know how full it is; that is the first thing to check.",
    act_when: "The filesystem is under half full and will not grow into the space, or the volume is io1/io2 or gp2 and a gp3 volume with the needed IOPS would be cheaper.",
    ignore_when: "It is a database data volume that is sized for growth, a chain node's block store, or it is over 70% full.",
    steps: [
      "Find the instance and mount point (Inventory > EC2 > volumes) and check usage: `df -h` through the SSM probe (disks are in the probe output).",
      "gp2 or io1/io2 -> gp3: `aws ec2 modify-volume --volume-id <id> --volume-type gp3` is online and reversible; gp3 gives 3000 IOPS baseline, add `--iops` only if the workload needs more.",
      "Shrinking is not online: create a smaller volume, `rsync` the data (or restore from a snapshot into a smaller volume for a fresh filesystem), swap the mount, keep the old volume a week, delete.",
      "Unattached and not needed: snapshot first (`aws ec2 create-snapshot`), then `delete-volume`.",
    ],
    saving: "Type change: (old per-GB price - gp3 price) x GB, plus IOPS charges. Shrink: freed GB x 0.08 USD. Delete: GB x per-GB price.",
    tier: "approve",
    effort: "medium",
  },
  [`${T}ebs_with_low_usage`]: {
    control_id: `${T}ebs_with_low_usage`,
    title: "EBS volume with almost no I/O",
    meaning: "The volume saw fewer than a handful of read/write operations per day over 30 days. It is either a forgotten data disk or an attached-but-unused volume.",
    act_when: "The instance that has it does not mount it, or the mount point is empty or archival, or the volume is unattached.",
    ignore_when: "It is a boot volume of a stopped or rarely used instance (I/O is low by definition), or it holds a cold backup the team wants online.",
    steps: [
      "Check attachment and mount (Inventory > EC2 > volumes, `lsblk` and `df` via the probe).",
      "If it is cold data: snapshot it (0.05 USD/GB against 0.08 for gp3, only used blocks) and delete the volume; restore on demand.",
      "If nobody knows what it is: detach (`aws ec2 detach-volume`), wait a week for complaints, snapshot and delete.",
    ],
    saving: "GB x per-GB price of the volume type per month (minus the snapshot's used GB x 0.05 if kept as a snapshot).",
    tier: "approve",
    effort: "low",
  },
  [`${T}ebs_volumes_on_stopped_instances`]: {
    control_id: `${T}ebs_volumes_on_stopped_instances`,
    title: "EBS volumes attached to a stopped instance",
    meaning: "A stopped instance has no compute charge but its volumes bill in full. The alarm is the volume side of the stopped-instance question: is this box coming back?",
    act_when: "The instance has been stopped for more than a couple of weeks and nobody has a date for starting it again.",
    ignore_when: "The name or tags say it is deliberately kept (Jev's protected flag), or it is a cold standby that must start in minutes.",
    steps: [
      "Check how long it has been stopped and who owns it (Inventory > EC2 > stopped, tags).",
      "Create an AMI of the instance: `aws ec2 create-image --instance-id <id> --name <name>-$(date +%F) --no-reboot`; that keeps every volume as a snapshot billed on used blocks only.",
      "Confirm the AMI is available, then terminate the instance (its volumes go with it unless DeleteOnTermination is off; delete those explicitly).",
      "Record the AMI id next to the owner; launching from it restores the box in minutes.",
    ],
    saving: "Sum of the attached GB x per-GB price - the AMI's snapshot cost (used GB x 0.05), per month.",
    tier: "approve",
    effort: "low",
  },
  [`${T}ebs_snapshot_max_age`]: {
    control_id: `${T}ebs_snapshot_max_age`,
    title: "EBS snapshot older than 90 days",
    meaning: "Snapshots bill 0.05 USD per GB-month for the blocks they hold. Old ones from manual backups, AMI experiments or pre-change safety copies pile up because nothing ever deletes them.",
    act_when: "The snapshot is not referenced by an AMI still in use, is not part of a retention policy (Data Lifecycle Manager, AWS Backup), and its source purpose is over.",
    ignore_when: "It backs a registered AMI you launch from, it is the last copy of a retired system the team wants kept, or a compliance policy requires it.",
    steps: [
      "Check references: `aws ec2 describe-images --owners self --filters Name=block-device-mapping.snapshot-id,Values=<snap>`; an AMI's snapshot cannot be deleted until the AMI is deregistered.",
      "Look at the description and tags for what it was; ask the owner if any.",
      "Delete: `aws ec2 delete-snapshot --snapshot-id <snap>` (with `aws ec2 deregister-image` first when an unused AMI holds it).",
      "Prevent the pile-up: a Data Lifecycle Manager policy with a retention count on tagged volumes, and tag manual snapshots with an expiry.",
    ],
    saving: "Snapshot size x 0.05 USD per month (the real figure is the unique blocks, usually less than the nominal size).",
    tier: "approve",
    effort: "low",
  },
  [`${T}ebs_unused_snapshots`]: {
    control_id: `${T}ebs_unused_snapshots`,
    title: "EBS snapshot whose source volume no longer exists",
    meaning: "The volume the snapshot was taken from is gone; the snapshot is either the deliberate last copy of something or a leftover from a deleted instance.",
    act_when: "Nothing references it (no AMI) and its description does not say it is a keepsake.",
    ignore_when: "It is the archive of a decommissioned system, or an AMI still uses it.",
    steps: [
      "Check for an AMI reference (`describe-images` filtered by snapshot id) and read the description/tags.",
      "If it is a keeper, tag it (`Retain=true`, owner) so the next review skips it.",
      "Otherwise `aws ec2 delete-snapshot --snapshot-id <snap>`.",
    ],
    saving: "Snapshot size x 0.05 USD per month.",
    tier: "approve",
    effort: "low",
  },

  // ---- S3 / ECR / Lambda / DynamoDB / ECS ------------------------------------------------------------------------
  [`${T}buckets_with_no_lifecycle`]: {
    control_id: `${T}buckets_with_no_lifecycle`,
    title: "S3 bucket without a lifecycle policy",
    meaning: "Nothing in the bucket ever expires or moves to a cheaper storage class, so logs, exports and old versions accumulate at the Standard rate (0.023 USD/GB-month). A lifecycle rule is free and reversible.",
    act_when: "The bucket holds logs, backups, build artifacts, temporary uploads or versioned objects: anything with a natural age after which nobody reads it.",
    ignore_when: "The bucket is small (a few GB), holds live application data with no age pattern, or an external system deletes objects itself.",
    steps: [
      "Size and age profile: Storage Lens or `aws s3api list-objects-v2 --bucket <b> --query 'sum(Contents[].Size)'`, and CloudWatch BucketSizeBytes by storage class.",
      "Decide the policy per prefix: logs and exports expire after 30-90 days; backups to Glacier Instant Retrieval after 30 days and Deep Archive after 90; noncurrent versions expire after 30 days; abort incomplete multipart uploads after 7 days (always add this one).",
      "Apply: `aws s3api put-bucket-lifecycle-configuration --bucket <b> --lifecycle-configuration file://rules.json`; transitions take effect within a day, expirations run daily.",
      "For mixed buckets with no clear age pattern use Intelligent-Tiering (`--storage-class INTELLIGENT_TIERING` on new objects or a lifecycle transition): it moves cold objects down automatically for a small monitoring fee.",
      "Verify the storage-class breakdown in Storage Lens a month later.",
    ],
    saving: "Expired GB x 0.023 USD; transitioned GB x (0.023 - class price: 0.0125 IA, 0.004 Glacier IR, 0.00099 Deep Archive) per month.",
    tier: "auto",
    effort: "low",
    references: ["https://docs.aws.amazon.com/AmazonS3/latest/userguide/lifecycle-configuration-examples.html"],
  },
  [`${T}ecr_repository_unused_images`]: {
    control_id: `${T}ecr_repository_unused_images`,
    title: "ECR repository with images not pulled in 90 days",
    meaning: "Every pushed image tag stays forever at 0.10 USD per GB-month unless a lifecycle policy prunes it. CI pipelines that push per commit leave hundreds of untagged or stale images behind.",
    act_when: "The repository is fed by CI, nothing pins old digests (check task definitions, Helm values and Karpenter/Kubernetes manifests for digests or old tags), and the images are rebuildable from source.",
    ignore_when: "The repository holds release images you must be able to roll back to (then keep the last N tags rather than all), or a compliance policy keeps every build.",
    steps: [
      "Measure: `aws ecr describe-images --repository-name <r> --query 'sum(imageDetails[].imageSizeInBytes)'` and count untagged images.",
      "Check what still references old images: running task definitions, deployments and Lambda container images by tag or digest.",
      "Put a lifecycle policy: expire untagged images after 7 days and keep only the last 20-50 tagged images (`aws ecr put-lifecycle-policy --repository-name <r> --lifecycle-policy-text file://policy.json`); test with `start-lifecycle-policy-preview` first.",
      "For every repository at once, set the policy in the Terraform/CDK module that creates them.",
      "Verify the repository size drops within a day; ECR deletes on the next evaluation.",
    ],
    saving: "Deleted GB x 0.10 USD per month (images share layers, so the freed GB is what ECR reports after deletion, not the sum of image sizes).",
    tier: "auto",
    effort: "low",
    references: ["https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html"],
  },
  [`${T}lambda_function_excessive_timeout`]: {
    control_id: `${T}lambda_function_excessive_timeout`,
    title: "Lambda function with a timeout over 60 seconds",
    meaning: "A long timeout does not cost anything by itself: a function bills for the milliseconds it runs. The risk is a hung invocation (a stuck HTTP call, a retry loop) billing the full timeout at every retry, and long timeouts hide problems.",
    act_when: "The function's p99 duration is far below the timeout (CloudWatch Duration), it is triggered by events that retry (SQS, EventBridge, async invokes), and it makes network calls that can hang.",
    ignore_when: "It is a batch/ETL function that genuinely runs for minutes, or a Step Functions task whose timeout is managed by the state machine.",
    steps: [
      "Read the Duration metric for 30 days: max and p99; compare with the configured timeout.",
      "Set the timeout to about 2x p99 (minimum a few seconds of headroom); set client-side timeouts on every HTTP/DB call inside the function so a hang fails fast.",
      "For async and SQS triggers, add a dead-letter queue or on-failure destination so a real failure does not retry until the timeout each time.",
      "Deploy and watch the Errors and Throttles metrics for a day.",
    ],
    saving: "Only what hung invocations cost: (timeout - typical duration) x memory GB x 0.0000166667 USD per GB-second, per hung invocation; usually small but unbounded.",
    tier: "approve",
    effort: "low",
  },
  [`${T}dynamodb_table_without_autoscaling`]: {
    control_id: `${T}dynamodb_table_without_autoscaling`,
    title: "DynamoDB table with fixed provisioned capacity and no auto scaling",
    meaning: "Provisioned read/write units bill every hour whether used or not. Without auto scaling the table is sized for its peak all day.",
    act_when: "Consumed capacity is well below provisioned most of the time (CloudWatch ConsumedReadCapacityUnits vs Provisioned), or the traffic is spiky/unpredictable.",
    ignore_when: "The table is tiny (25 free units cover it) or its load is flat and already matches the provisioned units.",
    steps: [
      "Compare consumed vs provisioned capacity for 14 days.",
      "Spiky or low traffic: switch to on-demand (`aws dynamodb update-table --table-name <t> --billing-mode PAY_PER_REQUEST`); this can be done once per 24 h.",
      "Steady traffic: keep provisioned and enable auto scaling with a 70% target (`aws application-autoscaling register-scalable-target` + `put-scaling-policy` for both read and write) and a minimum near the off-peak consumption.",
      "Verify the consumed/provisioned ratio a week later; on-demand tables show up under a separate usage type on the invoice.",
    ],
    saving: "(provisioned units - average consumed units) x unit price (0.00013 USD per WCU-hour, 0.00013/5 per RCU-hour) x 730; on-demand: compare last month's DynamoDB line with consumed units x on-demand rates.",
    tier: "approve",
    effort: "low",
  },
  [`${T}stale_dynamodb_table_data`]: {
    control_id: `${T}stale_dynamodb_table_data`,
    title: "DynamoDB table not written to in 90 days",
    meaning: "The table has had no writes for three months. It still bills for storage (0.25 USD/GB-month) and, if provisioned, for capacity units every hour.",
    act_when: "Nothing reads it either (ConsumedReadCapacityUnits at zero) and the owning application is gone or migrated.",
    ignore_when: "It is a reference or archive table that is read but not written, or the data must be kept for compliance.",
    steps: [
      "Check reads for 30 days and find the owner from tags or IAM policies that mention the table.",
      "If it is read-only reference data on provisioned capacity: switch to on-demand or drop the write units to 1.",
      "If nobody needs it: export to S3 (`aws dynamodb export-table-to-point-in-time` needs PITR, or a scan to S3), then `aws dynamodb delete-table --table-name <t>`.",
      "Keep the export in a bucket with a lifecycle rule to Deep Archive.",
    ],
    saving: "Storage GB x 0.25 USD plus provisioned units x unit price x 730 per month; minus the S3 export cost if kept.",
    tier: "approve",
    effort: "low",
  },
  [`${T}ecs_cluster_low_utilization`]: {
    control_id: `${T}ecs_cluster_low_utilization`,
    title: "ECS cluster with low CPU utilisation",
    meaning: "The cluster's container instances (EC2 launch type) run well under 30% CPU: the instances are paid for whether tasks use them or not.",
    act_when: "The cluster runs on EC2 with fixed capacity, task placement leaves instances mostly empty, or the services could run on Fargate with per-task billing.",
    ignore_when: "The cluster is on Fargate (nothing to right-size at the cluster level) or the capacity is reserved for a known daily peak.",
    steps: [
      "Look at task counts vs instance count and at the reservation metrics (CPUReservation, MemoryReservation).",
      "Enable a capacity provider with managed scaling on the ASG (target 80-90%) so instances follow the task count.",
      "Reduce task sizes if they reserve far more CPU/memory than they use (Container Insights shows the per-task usage).",
      "For small or bursty services consider Fargate (or Fargate Spot for tolerant ones) and drop the EC2 capacity entirely.",
    ],
    saving: "Removed instance-hours x instance price; for Fargate, compare last month's instance cost with tasks x vCPU/GB x hours x Fargate rates.",
    tier: "approve",
    effort: "medium",
  },

  // ---- RDS / ElastiCache --------------------------------------------------------------------------------------
  [`${T}long_running_rds_db_instances`]: {
    control_id: `${T}long_running_rds_db_instances`,
    title: "RDS instance has run for more than 90 days without a reservation",
    meaning: "A database that has been up for months and will stay is the ideal reservation: a 1-year no-upfront RDS reserved instance saves about 30-35% on the instance hours (storage and I/O are unchanged).",
    act_when: "The instance class and engine are settled (no Graviton or size change planned), the workload will run for at least another year, and no active reservation covers it (the advisor's commitments query lists RDS reservations; they are owned by the member account).",
    ignore_when: "A class change is planned (buy after it), the environment is temporary, or the engine/class combination is one you might retire.",
    steps: [
      "Finish any class change first (Graviton, right-size): RDS reservations are tied to engine, class family and region.",
      "Check current reservations in the commitments list (`aws rds describe-reserved-db-instances --filters Name=state,Values=active`) to avoid double-covering.",
      "Find the offering: `aws rds describe-reserved-db-instances-offerings --db-instance-class db.r7g.large --product-description postgresql --duration 31536000 --offering-type 'No Upfront'`.",
      "Purchase in the account that owns the instance: `aws rds purchase-reserved-db-instances-offering --reserved-db-instances-offering-id <id> --db-instance-count 1`. Size-flexible within the family for most engines.",
      "Verify the reservation shows in the commitments list and the RDS instance-hours line drops next month.",
    ],
    saving: "About 30-35% (1-year no upfront) to 50-60% (3-year) of the instance-hour price x 730; storage, I/O and backups are unchanged.",
    tier: "report",
    effort: "low",
  },
  [`${T}rds_db_low_utilization`]: {
    control_id: `${T}rds_db_low_utilization`,
    title: "RDS instance with low CPU",
    meaning: "The instance averaged under 25% CPU for 30 days. Databases are often memory- or I/O-bound, so low CPU alone does not mean oversized; but a class two sizes too big is common after a launch-day guess.",
    act_when: "FreeableMemory stays high (the buffer cache is not full), ReadIOPS/WriteIOPS are low, and connections are few.",
    ignore_when: "Memory is fully used by the cache (a smaller class would hit disk), the instance is a Multi-AZ standby-heavy setup, or it is a dev database that could simply be stopped out of hours.",
    steps: [
      "Check CPUUtilization, FreeableMemory, DatabaseConnections and ReadIOPS/WriteIOPS for 30 days.",
      "Dev/test: stop the instance out of hours (`aws rds stop-db-instance`; RDS starts it again after 7 days) or use Aurora Serverless v2 with a low minimum ACU.",
      "Production with headroom everywhere: modify to one class smaller in the same family in the maintenance window; keep the Graviton playbook in mind (same move, cheaper class).",
      "Watch p99 latency and FreeableMemory for a week; roll back with the same command if the cache starts thrashing.",
    ],
    saving: "(hourly price of the current class - price of the smaller class) x 730; stopping a dev instance out of hours saves about 65% of the instance hours.",
    tier: "approve",
    effort: "medium",
  },
  [`${T}elasticache_cluster_long_running`]: {
    control_id: `${T}elasticache_cluster_long_running`,
    title: "ElastiCache cluster has run for more than 90 days without reserved nodes",
    meaning: "A cache that has been up for months and will stay is cheaper on reserved nodes: about 30-35% off the node hours for a 1-year no-upfront term.",
    act_when: "The node type and count are settled and the cluster will run for another year; no active reserved node covers it (the commitments query lists them; reservations are owned by the member account).",
    ignore_when: "A node type change or a move to Valkey/serverless is planned, or the cluster is an environment that will be torn down.",
    steps: [
      "Confirm the node type is final (t4g/m7g are the cheap Graviton types; move first if not there yet).",
      "Check active reservations (`aws elasticache describe-reserved-cache-nodes`) in the commitments list.",
      "Find the offering: `aws elasticache describe-reserved-cache-nodes-offerings --cache-node-type cache.m7g.large --duration 31536000 --offering-type 'No Upfront'`.",
      "Purchase in the owning account: `aws elasticache purchase-reserved-cache-nodes-offering --reserved-cache-nodes-offering-id <id> --cache-node-count <n>`.",
      "Verify on the commitments list and the ElastiCache line next month.",
    ],
    saving: "About 30-35% (1-year no upfront) of node price x nodes x 730.",
    tier: "report",
    effort: "low",
  },

  // ---- Route 53 / API Gateway / CloudWatch / Secrets / Cost Explorer -------------------------------------------------
  [`${T}route53_record_higher_ttl`]: {
    control_id: `${T}route53_record_higher_ttl`,
    title: "Route 53 record with a short TTL",
    meaning: "A TTL under an hour makes resolvers ask Route 53 more often; queries cost 0.40 USD per million. It matters only at volume: a record answering millions of queries a month.",
    act_when: "The record is not part of a failover, blue/green or weighted routing scheme that needs quick propagation, and the hosted zone's query count (CloudWatch DNSQueries) is in the millions.",
    ignore_when: "The record is an alias (alias queries are free), a health-checked failover record, or the zone's query volume is small (then the saving is cents).",
    steps: [
      "Check the zone's DNSQueries metric for a month and which records answer most (Route 53 query logging if needed).",
      "For stable records (MX, TXT, static A/CNAME) set the TTL to 3600 or more: `aws route53 change-resource-record-sets` with the same value and a new TTL.",
      "Keep short TTLs on records you flip during deploys or failover.",
    ],
    saving: "(queries per month at the old TTL - queries at the new TTL) x 0.40 USD per million; often under a dollar.",
    tier: "auto",
    effort: "low",
  },
  [`${T}apigateway_stage_with_caching_disabled`]: {
    control_id: `${T}apigateway_stage_with_caching_disabled`,
    title: "API Gateway stage without caching",
    meaning: "Every request reaches the backend (Lambda, a service) and bills there. A stage cache answers repeated GETs from memory; it costs 0.02 USD per hour for the smallest cache (about 15 USD a month), so it only pays off when the backend calls it saves cost more than that.",
    act_when: "The API serves many identical GET requests (catalog, config, public reads) and the backend is a Lambda or a paid service billed per call.",
    ignore_when: "Traffic is low (the cache costs more than it saves), responses are personalised, or the stage is a dev/test one.",
    steps: [
      "Look at the stage's Count and Latency metrics and the backend's per-call cost.",
      "Enable a 0.5 GB cache with a TTL matching how stale a response may be: `aws apigateway update-stage --rest-api-id <api> --stage-name <s> --patch-operations op=replace,path=/cacheClusterEnabled,value=true op=replace,path=/cacheClusterSize,value=0.5`.",
      "Enable caching per method with `/~1path/GET/caching/enabled` patches and set cache keys on query parameters that change the response.",
      "Verify CacheHitCount vs CacheMissCount after a day; remove the cache if the hit rate stays under 20%.",
    ],
    saving: "Backend calls avoided x their unit price - cache cluster price (0.02 USD per hour for 0.5 GB) per month.",
    tier: "approve",
    effort: "low",
  },
  [`${T}cw_log_group_retention`]: {
    control_id: `${T}cw_log_group_retention`,
    title: "CloudWatch log group with no retention",
    meaning: "Logs never expire, so the group grows forever at 0.03 USD per GB-month. Ingestion (0.50 USD/GB) is the bigger part of the CloudWatch bill, but stored bytes with no expiry are pure waste.",
    act_when: "Always, for application, Lambda and container logs: 30-90 days covers debugging; anything longer belongs in S3.",
    ignore_when: "The group is an audit trail with a legal retention requirement (then set that period explicitly rather than none).",
    steps: [
      "Set a retention on the group: `aws logs put-retention-policy --log-group-name <g> --retention-in-days 30`. Deletion of older events happens within a few days.",
      "Set the default for new groups in your IaC (every `aws_cloudwatch_log_group` with `retention_in_days`) and add a Lambda or EventBridge rule that applies a default to groups created implicitly.",
      "For logs needed longer, export or subscribe to S3 with a lifecycle rule to Deep Archive.",
    ],
    saving: "Stored GB above the retention window x 0.03 USD per month, growing every month it is not set.",
    tier: "auto",
    effort: "low",
  },
  [`${T}cw_log_stream_unused`]: {
    control_id: `${T}cw_log_stream_unused`,
    title: "CloudWatch log stream with no events for 90 days",
    meaning: "The stream (one per instance, task or Lambda container) is dead; its bytes still bill if the group has no retention. This is the per-stream symptom of the retention problem.",
    act_when: "The group has no retention policy; setting one removes the old streams' data automatically.",
    ignore_when: "The group already has retention (the streams will age out) or the stream is tiny.",
    steps: [
      "Set retention on the group (see the log-group retention playbook); that handles every stale stream at once.",
      "Only if the group must keep everything, delete individual streams: `aws logs delete-log-stream --log-group-name <g> --log-stream-name <s>`.",
    ],
    saving: "Stream size x 0.03 USD per GB-month.",
    tier: "auto",
    effort: "low",
  },
  [`${T}secretsmanager_secret_unused`]: {
    control_id: `${T}secretsmanager_secret_unused`,
    title: "Secrets Manager secret not accessed in 90 days",
    meaning: "A secret bills 0.40 USD a month whether read or not. Unused ones are leftovers of retired services; the money is small, the hygiene value (an orphaned credential) is larger.",
    act_when: "The service that used it is gone, or the secret was created for a test.",
    ignore_when: "It is read only in a rare path (disaster recovery, a yearly job), or it is the source for a rotation you still rely on.",
    steps: [
      "Check who used it: CloudTrail `GetSecretValue` events for the secret over 90 days, and IAM policies that name it.",
      "If the credential is still valid somewhere (a database user), revoke or rotate it at the source first.",
      "Delete with a recovery window: `aws secretsmanager delete-secret --secret-id <s> --recovery-window-in-days 30`; it can be restored during the window.",
    ],
    saving: "0.40 USD per secret per month (plus 0.05 USD per 10,000 API calls it no longer serves).",
    tier: "approve",
    effort: "low",
  },
  [`${T}full_month_cost_changes`]: {
    control_id: `${T}full_month_cost_changes`,
    title: "A service's cost moved notably between the last two full months",
    meaning: "The control compares Cost Explorer's totals per service for the last two complete months and flags large movements. It is a prompt to look, not a problem by itself: a rise can be growth, a drop a migration.",
    act_when: "The rise has no known cause (no launch, no migration, no price change), especially on data-transfer, NAT, CloudWatch or EC2-Other lines, which grow silently.",
    ignore_when: "The change matches something the team did on purpose, or the absolute amount is small.",
    steps: [
      "Open Cost Explorer for the service, group by usage type, then by resource or tag, for the two months side by side.",
      "Correlate with the advisor's alerts (NAT traffic, instance state) and the run's 'What changed' list for the same period.",
      "Name the cause in the recommendation's reason so the agent stops flagging it; if it is waste, follow the specific playbook (NAT: VPC endpoints; CloudWatch: retention and metric filters; EC2-Other: EBS and snapshots).",
    ],
    saving: "None by itself; whatever the underlying cause's playbook saves.",
    tier: "report",
    effort: "low",
  },
  [`${T}unattached_eips`]: {
    control_id: `${T}unattached_eips`,
    title: "Elastic IP not attached to anything",
    meaning: "An allocated public IPv4 address bills every hour (0.005 USD, about 3.65 USD a month) whether or not it is attached. Releasing it loses the address for good.",
    act_when: "Nothing external points at the address (DNS records, partner allow-lists, hard-coded configs) and no stopped instance expects to get it back.",
    ignore_when: "The address is on an allow-list at a partner or a customer, or it belongs to a stopped instance that will start again.",
    steps: [
      "Search for the address: Route 53 records, the team's configs, any allow-list you know of.",
      "If it must stay, attach it to the resource that needs it (attached addresses on running instances also bill since 2024, so 'keep' has a price).",
      "Release: `aws ec2 release-address --allocation-id <eipalloc>`.",
    ],
    saving: "3.65 USD per address per month.",
    tier: "approve",
    effort: "low",
  },

  // ---- the advisor's own controls ----------------------------------------------------------------------------------
  "query.stopped_instance_ebs": {
    control_id: "query.stopped_instance_ebs",
    title: "Stopped instance still holding EBS",
    meaning: "The instance is stopped (no compute charge) but its volumes bill every GB. The rule computes the volume cost and proposes imaging and terminating.",
    act_when: "Stopped for weeks with no restart date; not marked as kept (Jev's protected flag or 'do not delete' in the name).",
    ignore_when: "It is a deliberately parked box (a customer's swarm waiting to be resumed, a cold standby) or the owner has a date for it.",
    steps: [
      "Confirm the owner and the reason it is stopped (name, tags, the Inventory's launch date and last SSM ping).",
      "Create an AMI (`aws ec2 create-image --instance-id <id> --name <name>-$(date +%F)`), wait until it is available.",
      "Terminate the instance; delete volumes whose DeleteOnTermination is off.",
      "Record the AMI id next to the owner; a dev box that is needed now and then gets a scheduler instead.",
    ],
    saving: "Attached GB x 0.08 USD (gp3) per month - AMI snapshot cost (used GB x 0.05).",
    tier: "approve",
    effort: "low",
  },
  "query.idle_instances": {
    control_id: "query.idle_instances",
    title: "Running instance under 10% max CPU for 30 days",
    meaning: "The daily peak CPU never reached 10% in a month: the box is either oversized, a naturally idle role (chain node, broker) or forgotten. The rule attaches the SSM probe's memory and load and Jev's role to say which.",
    act_when: "The probe shows memory and load are low too and the role is one that should be busy (web/API, worker, dev box).",
    ignore_when: "Jev says blockchain node or cache/broker (idle by design), the box is protected, or it is a bastion/VPN.",
    steps: [
      "Probe it (Recommendations > Probe) for memory, load and top processes; ask the owner what it does.",
      "Dev/test box: schedule it (stop nights and weekends) rather than resizing.",
      "Oversized: stop, change to a smaller type in the same family (or the Graviton equivalent), start; watch a week.",
      "Forgotten: AMI, stop, terminate after 30 days of silence.",
    ],
    saving: "Right-size: (current price - smaller type price) x 730; schedule: about 65%; terminate: the whole instance and its EBS.",
    tier: "approve",
    effort: "medium",
  },
  "query.old_snapshots": {
    control_id: "query.old_snapshots",
    title: "EBS snapshot older than 90 days",
    meaning: "Same as the Thrifty snapshot age control, with the source volume's existence attached: an orphaned snapshot (volume gone) is the more likely leftover.",
    act_when: "No AMI references it and its description does not mark it as a keeper.",
    ignore_when: "It backs an AMI in use or is the archive of a retired system.",
    steps: [
      "Check AMI references (`aws ec2 describe-images --owners self --filters Name=block-device-mapping.snapshot-id,Values=<snap>`).",
      "Tag keepers (`Retain=true`) so the next review skips them.",
      "Delete the rest: `aws ec2 delete-snapshot --snapshot-id <snap>`.",
      "Add a Data Lifecycle Manager policy so manual snapshots stop accumulating.",
    ],
    saving: "Snapshot size x 0.05 USD per month.",
    tier: "approve",
    effort: "low",
  },
  "query.eip_unattached": {
    control_id: "query.eip_unattached",
    title: "Elastic IP not attached to anything",
    meaning: "An allocated address that nothing uses bills about 3.65 USD a month. Releasing it is permanent.",
    act_when: "No DNS record, allow-list or stopped instance depends on the address.",
    ignore_when: "It is on a partner's allow-list or reserved for an instance that will start again.",
    steps: [
      "Search DNS and configs for the address.",
      "Attach it where it is needed, or release it: `aws ec2 release-address --allocation-id <eipalloc>`.",
    ],
    saving: "3.65 USD per address per month.",
    tier: "approve",
    effort: "low",
  },
  "query.log_groups_no_retention": {
    control_id: "query.log_groups_no_retention",
    title: "CloudWatch log group with no retention policy",
    meaning: "The group keeps every event forever at 0.03 USD per GB-month. The rule proposes 30 days; the real value is capping future growth.",
    act_when: "Always for application and Lambda logs; set the legal period explicitly for audit groups.",
    ignore_when: "Never entirely: even an audit group should carry an explicit retention.",
    steps: [
      "`aws logs put-retention-policy --log-group-name <g> --retention-in-days 30` (90 for anything you debug across releases).",
      "Put `retention_in_days` in the IaC that creates groups, and a default-retention rule for groups created implicitly by Lambda.",
      "Export long-term logs to S3 with a lifecycle rule instead of keeping them in CloudWatch.",
    ],
    saving: "Stored GB beyond the retention window x 0.03 USD per month, growing until it is set.",
    tier: "auto",
    effort: "low",
  },
  "query.commitments": {
    control_id: "query.commitments",
    title: "Active commitment (reservation or Savings Plan) and its expiry",
    meaning: "Informational: every active reservation and Savings Plan with its end date, so the 'buy a reservation' findings can be checked against what already exists, and expiries are seen coming. Reservations are owned by the member account that bought them; Savings Plans by the payer.",
    act_when: "An expiry is within 60 days and the covered resources will keep running, or a reservation covers a type you are about to migrate away from.",
    ignore_when: "It is simply the list; nothing to do while coverage matches the fleet.",
    steps: [
      "For each entry, compare what it covers with the running fleet (Inventory) and note the end date.",
      "Expiring soon and still needed: renew, or replace with a Compute Savings Plan when the fleet is changing families.",
      "Covering a type you are migrating (Graviton): plan the migration for the expiry, or sell the RI on the Marketplace (EC2 only).",
    ],
    saving: "Avoided on-demand premium after an expiry (30-50% of the covered spend) when renewed in time.",
    tier: "report",
    effort: "low",
  },

  // ---- rules without a control behind them -------------------------------------------------------------------------
  "rule.aurora_storage_tier": {
    control_id: "rule.aurora_storage_tier",
    title: "Aurora storage tier does not match the I/O profile",
    meaning: "Aurora Standard bills per million I/Os on top of cheaper storage; I/O-Optimized removes the I/O charge but costs 2.25x on storage and about 30% more on instance hours. The rule compares 30 days of real I/O with the storage size to pick the cheaper tier.",
    act_when: "I/O charges are under 30% of the storage cost on I/O-Optimized (go Standard), or over ~30% of storage plus instance cost on Standard (go I/O-Optimized).",
    ignore_when: "The workload's I/O pattern is about to change (a migration, a new feature), or the cluster was switched in the last 30 days (I/O-Optimized can only be enabled once every 30 days).",
    steps: [
      "Read VolumeReadIOPs and VolumeWriteIOPs for 30 days and VolumeBytesUsed for the cluster.",
      "Compute both tiers: Standard = storage GB x 0.10 + millions of I/Os x 0.20; I/O-Optimized = storage GB x 0.225 + 30% on instance hours.",
      "Switch: `aws rds modify-db-cluster --db-cluster-identifier <c> --storage-type aurora-iopt1` (or `aurora`); it is online, no failover.",
      "Verify on the next invoice's Aurora storage and I/O lines.",
    ],
    saving: "The difference between the two tiers' monthly totals as computed above.",
    tier: "approve",
    effort: "low",
  },
  "rule.enable_flow_logs": {
    control_id: "rule.enable_flow_logs",
    title: "VPC with NAT traffic alerts and no flow logs",
    meaning: "Without VPC flow logs nobody can say which pod or destination caused a NAT traffic spike; attribution stops at the instance. Flow logs to S3 cost cents per GB of log data.",
    act_when: "The VPC's NAT gateway alerted in the last week and the cause could not be named.",
    ignore_when: "The VPC is being decommissioned, or flow logs already exist at the subnet or ENI level.",
    steps: [
      "Create an S3 bucket (or a CloudWatch group with retention) for the logs.",
      "`aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc> --traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::<bucket> --max-aggregation-interval 60`.",
      "Query with Athena (partitioned by day) to rank destinations by bytes; add gateway endpoints (S3, DynamoDB) or interface endpoints for the top ones.",
      "Keep the logs 30 days with a lifecycle rule.",
    ],
    saving: "None directly; the NAT processing (0.045 USD/GB) the attribution then lets you remove.",
    tier: "approve",
    effort: "low",
  },
};

/** The playbook for a control id (Thrifty control, `query.*` control or `rule.*` id), or null. */
export function playbookFor(controlId: string | null | undefined): Playbook | null {
  if (!controlId) return null;
  return PLAYBOOKS[controlId] ?? null;
}

export function listPlaybooks(): Playbook[] {
  return Object.values(PLAYBOOKS);
}

export interface PlaybookSummary { control_id: string; title: string; tier: PlaybookTier; effort: PlaybookEffort }

/** What the findings list carries per control: enough for a badge, not the whole text. */
export const playbookSummary = (p: Playbook): PlaybookSummary => ({ control_id: p.control_id, title: p.title, tier: p.tier, effort: p.effort });

/** The playbook's steps as one sentence, for the end of a recommendation's rationale: the gist of each step. */
export function stepsSentence(p: Playbook): string {
  const MAX = 70;
  const clause = (step: string) => {
    // Backticked commands may contain ". " or ": "; hide them while cutting the clause.
    const codes: string[] = [];
    let s = step.replace(/`[^`]*`/g, (m) => { codes.push(m); return `\u0000${codes.length - 1}\u0000`; });
    // "Kubernetes: instead of ..." is a label plus the clause; "List what runs on the box: ssh in ..." is a clause plus detail.
    const label = /^([^.;:]{1,28}):\s+/.exec(s);
    if (label && label[1].length >= 14) s = label[1];
    else {
      if (label) s = s.slice(label[0].length);
      s = s.split(/[.;:](?=\s|$)/)[0];
      if (s.length > MAX) { const cut = s.lastIndexOf(",", MAX); s = cut > 20 ? s.slice(0, cut) : s.slice(0, s.lastIndexOf(" ", MAX)) + "…"; }
      if (label) s = `${label[1].toLowerCase()}: ${s}`;
    }
    s = s.trim().replace(/\u0000(\d+)\u0000/g, (_, i) => codes[Number(i)]);
    return s.replace(/^[A-Z](?=[a-z])/, (c) => c.toLowerCase());
  };
  return `Playbook (${p.title}): ${p.steps.map(clause).join(", then ")}.`;
}

/** The control a rules-based recommendation comes from, when the rule has one obvious origin. */
export const RULE_CONTROL: Record<string, string> = {
  stopped_instance_ebs: "query.stopped_instance_ebs",
  old_snapshot: "query.old_snapshots",
  eip_unattached: "query.eip_unattached",
  log_group_no_retention: "query.log_groups_no_retention",
  idle_instance: "query.idle_instances",
  aurora_storage_tier: "rule.aurora_storage_tier",
  enable_flow_logs: "rule.enable_flow_logs",
  review_s3_lifecycle: "aws_thrifty.control.buckets_with_no_lifecycle",
};

/** Origin control of a recommendation: the evidence's `playbook` (the graviton rule sets it), else the rule's control. */
export function controlForRecommendation(rec: { rule: string; evidence?: unknown }): string | null {
  const ev = typeof rec.evidence === "string" ? (() => { try { return JSON.parse(rec.evidence as string); } catch { return null; } })() : rec.evidence;
  const fromEvidence = ev && typeof ev === "object" && typeof (ev as any).playbook === "string" ? (ev as any).playbook : null;
  if (fromEvidence && PLAYBOOKS[fromEvidence]) return fromEvidence;
  return RULE_CONTROL[rec.rule] ?? null;
}
