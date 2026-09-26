/** Registers every action module with the executor; imported once at startup (src/index.ts). */
import { registerAction } from "../executor.js";
import { acuWindowAction } from "./acu_window.js";
import { snapshotArchiveAction } from "./snapshot_archive.js";
import { ebsIopsTrimAction } from "./ebs_iops_trim.js";
import { logRetentionAction } from "./log_retention.js";
import { s3RequestMetricsAction } from "./s3_request_metrics.js";
import { auroraStorageAction } from "./aurora_storage.js";
import { s3LifecycleAction } from "./s3_lifecycle.js";
import { ebsGp3MigrateAction } from "./ebs_gp3_migrate.js";
import { ecrLifecycleAction } from "./ecr_lifecycle.js";
import { swarmParkAction } from "./swarm_park.js";

registerAction(acuWindowAction);
registerAction(snapshotArchiveAction);
registerAction(ebsIopsTrimAction);
registerAction(logRetentionAction);
registerAction(s3RequestMetricsAction);
registerAction(auroraStorageAction);
registerAction(s3LifecycleAction);
registerAction(ebsGp3MigrateAction);
registerAction(ecrLifecycleAction);
registerAction(swarmParkAction);
