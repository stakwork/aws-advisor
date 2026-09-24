/**
 * Task definitions for the agent runs, loaded from tasks/<kind>/ (system.md, schema.json, task.json). The
 * advisor's job is to build the brief and hand the task over; the instruction, the deliverable and the rubric
 * are data. Loaded once at startup; the system prompt becomes the code default of that prompt kind.
 */
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { RubricCheck } from "./rubric.js";
import { PromptKind, registerDefaultPrompt } from "./prompts.js";

export interface TaskDef { kind: PromptKind; title: string; when: string; tools: string[]; max_turns: number; schema: any; rubric: RubricCheck[]; retry: { on_score_below: number; max: number }; system: string; dir: string }

const here = path.dirname(fileURLToPath(import.meta.url));
export const TASKS_DIR = process.env.TASKS_DIR || path.resolve(here, "..", "tasks");
const loaded = new Map<PromptKind, TaskDef>();

export function loadTasks(): TaskDef[] {
  if (loaded.size) return [...loaded.values()];
  for (const kind of ["findings", "incident", "resolution", "observe", "chat"] as PromptKind[]) {
    const dir = path.join(TASKS_DIR, kind);
    const meta = JSON.parse(fs.readFileSync(path.join(dir, "task.json"), "utf8"));
    const schema = JSON.parse(fs.readFileSync(path.join(dir, "schema.json"), "utf8"));
    const system = fs.readFileSync(path.join(dir, "system.md"), "utf8").trim();
    const def: TaskDef = { kind, title: meta.title, when: meta.when, tools: meta.tools || [], max_turns: meta.max_turns || 40, schema, rubric: meta.rubric || [], retry: meta.retry || { on_score_below: 0, max: 0 }, system, dir };
    loaded.set(kind, def);
    registerDefaultPrompt(kind, system);
  }
  return [...loaded.values()];
}
export function taskFor(kind: PromptKind): TaskDef {
  if (!loaded.size) loadTasks();
  const t = loaded.get(kind); if (!t) throw new Error(`no task definition for ${kind}`);
  return t;
}
