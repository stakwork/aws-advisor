/** Registers every action module with the executor; imported once at startup (src/index.ts). */
import { registerAction } from "../executor.js";
import { acuWindowAction } from "./acu_window.js";
import { snapshotArchiveAction } from "./snapshot_archive.js";

registerAction(acuWindowAction);
registerAction(snapshotArchiveAction);
