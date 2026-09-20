# Tasks

One folder per kind of agent run, the Harvey LAB shape: `system.md` is the instruction (the system prompt the
advisor sends; an override saved from Settings > Agent prompts still wins), `schema.json` the deliverable the
agent must return, and `task.json` the rest: the tools the task is meant to use (documentation for the reader
and the prompt; the fact server exposes every tool), `max_turns`, the `rubric` the answer is graded with
(`src/rubric.ts`: required, numbers, range, enum, min_items, max_items, max_sentences, unique,
no_destructive_auto, covers, flag_consistent) and `retry`: when the score is below `on_score_below` the answer
is sent back once with the failed checks appended, under the agent quota.

Adding a situation is adding a folder; the score of every run is stored on `agent_runs`.
