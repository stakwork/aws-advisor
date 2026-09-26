/** Registers every action module with the executor; imported once at startup (src/index.ts). */
import { registerAction } from "../executor.js";
import { acuWindowAction } from "./acu_window.js";
import { snapshotArchiveAction } from "./snapshot_archive.js";
import { ebsIopsTrimAction } from "./ebs_iops_trim.js";
import { logRetentionAction } from "./log_retention.js";
import { s3RequestMetricsAction } from "./s3_request_metrics.js";

registerAction(acuWindowAction);
registerAction(snapshotArchiveAction);
registerAction(ebsIopsTrimAction);
registerAction(logRetentionAction);
registerAction(s3RequestMetricsAction);
