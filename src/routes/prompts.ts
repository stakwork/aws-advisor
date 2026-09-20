import { Router } from "express";
import { authMiddleware } from "../auth.js";
import { PROMPT_KINDS, PromptKind, describePrompts, resetPrompt, setPromptOverride } from "../prompts.js";

export const prompts = Router();
prompts.use(authMiddleware);

const isKind = (k: string): k is PromptKind => (PROMPT_KINDS as string[]).includes(k);

prompts.get("/prompts", (_req, res) => res.json({ prompts: describePrompts() }));

prompts.put("/prompts/:kind", (req, res) => {
  const kind = req.params.kind;
  if (!isKind(kind)) return res.status(404).json({ error: "unknown prompt kind" });
  const text = typeof req.body?.text === "string" ? req.body.text : "";
  if (text.length > 20000) return res.status(400).json({ error: "prompt too long (20k characters max)" });
  setPromptOverride(kind, text);
  res.json({ prompts: describePrompts() });
});

prompts.delete("/prompts/:kind", (req, res) => {
  const kind = req.params.kind;
  if (!isKind(kind)) return res.status(404).json({ error: "unknown prompt kind" });
  resetPrompt(kind);
  res.json({ prompts: describePrompts() });
});
