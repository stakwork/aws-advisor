import type { ServiceCollector } from "../service_inventory.js";
import { acmCollector } from "./acm.js";
import { athenaCollector } from "./athena.js";
import { backupCollector } from "./backup.js";
import { cloudformationCollector } from "./cloudformation.js";
import { efsCollector } from "./efs.js";
import { guarddutyCollector } from "./guardduty.js";
import { kmsCollector } from "./kms.js";
import { snsCollector } from "./sns.js";
import { wafCollector } from "./waf.js";

/** Every service collector, KMS first so the keys other rows name resolve against this refresh's keys. */
export const SERVICE_COLLECTORS: ServiceCollector[] = [kmsCollector, acmCollector, snsCollector, efsCollector, backupCollector, athenaCollector, wafCollector, cloudformationCollector, guarddutyCollector];
