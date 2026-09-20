/**
 * Editable system prompts for the three kinds of agent request. The code ships a default for each; an
 * override saved from Settings (settings key `prompt:<kind>`) wins until it is reset.
 */
import { getSetting, setSetting, db } from "./db.js";

export type PromptKind = "findings" | "incident" | "resolution" | "observe";
export const PROMPT_KINDS: PromptKind[] = ["findings", "incident", "resolution", "observe"];
export const PROMPT_LABELS: Record<PromptKind, { title: string; when: string }> = {
  findings: { title: "Findings batch", when: "sent after a collection run, with the findings, the rules' drafts, the diff and the team's decisions" },
  incident: { title: "Incident investigation", when: "sent when an alert is investigated, with the alert, its attribution and the resource facts" },
  resolution: { title: "Tailored resolution", when: "sent when Resolve is pressed on a recommendation, with the playbook, the graph context and the resource facts" },
  observe: { title: "Daily observation", when: "sent every morning after the review, with what changed in the last day: review findings, alerts, spend against baseline, pools, run changes" },
};

const defaults = new Map<PromptKind, string>();

export function registerDefaultPrompt(kind: PromptKind, text: string) { defaults.set(kind, text); }
export const defaultPrompt = (kind: PromptKind) => defaults.get(kind) || "";
export const overridePrompt = (kind: PromptKind) => getSetting(`prompt:${kind}`);
/** The text actually sent: the saved override when there is one, else the code default. */
export const getPrompt = (kind: PromptKind) => overridePrompt(kind) || defaultPrompt(kind);

export function setPromptOverride(kind: PromptKind, text: string) {
  const t = text.trim();
  if (!t) return resetPrompt(kind);
  setSetting(`prompt:${kind}`, t);
  setSetting(`prompt:${kind}:updated_at`, new Date().toISOString());
}

export function resetPrompt(kind: PromptKind) {
  db.prepare("delete from settings where key in (?, ?)").run(`prompt:${kind}`, `prompt:${kind}:updated_at`);
}

export function describePrompts() {
  return PROMPT_KINDS.map((kind) => ({
    kind,
    ...PROMPT_LABELS[kind],
    default: defaultPrompt(kind),
    override: overridePrompt(kind),
    effective: getPrompt(kind),
    overridden: Boolean(overridePrompt(kind)),
    updated_at: getSetting(`prompt:${kind}:updated_at`),
  }));
}
