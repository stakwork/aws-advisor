/**
 * The Settings page's view of the runtime settings: every key with its current value (secrets masked), where
 * the value comes from, and a setter that validates, stores, and applies the side effects a change needs
 * (reschedule the crons, drop a cached Neo4j driver or Jev client so the next call uses the new value).
 */
import { RUNTIME_SETTINGS, RuntimeSpec, isSecretSetting, runtimeRaw, validateRuntime } from "./config.js";
import { db, getSetting } from "./db.js";
import { restartScheduler } from "./scheduler.js";
import { resetGraphDriver } from "./graph_mirror.js";
import { resetJevClient } from "./jev.js";

export interface RuntimeSettingView extends Omit<RuntimeSpec, "def"> { value: string; source: "setting" | "env" | "default"; default: string; env_set: boolean }

const mask = (v: string) => (v ? `${"•".repeat(8)}${v.slice(-4)}` : "");

export function listRuntimeSettings(): RuntimeSettingView[] {
  return RUNTIME_SETTINGS.map((s) => {
    const { value, source } = runtimeRaw(s.key);
    const { def, ...rest } = s;
    return { ...rest, default: def, value: s.kind === "secret" ? mask(value) : value, source, env_set: process.env[s.env] !== undefined };
  });
}

/** Stores a value (null clears it, so env or the default applies again) and applies the change. */
export function setRuntimeSetting(key: string, value: string | null): RuntimeSettingView {
  const spec = RUNTIME_SETTINGS.find((s) => s.key === key);
  if (!spec) throw new Error(`unknown setting ${key}`);
  if (value == null) db.prepare("delete from settings where key = ?").run(`cfg:${key}`);
  else {
    const v = validateRuntime(key, value);
    db.prepare("insert into settings(key, value) values (?, ?) on conflict(key) do update set value = excluded.value").run(`cfg:${key}`, v);
  }
  if (spec.kind === "cron" || key === "repo2graphUrl") restartScheduler();
  if (key.startsWith("neo4j")) resetGraphDriver();
  if (key === "typesafeApiKey" || key === "jevModel") resetJevClient();
  return listRuntimeSettings().find((s) => s.key === key)!;
}

export const hasSavedSetting = (key: string) => getSetting(`cfg:${key}`) != null;
export { isSecretSetting };
