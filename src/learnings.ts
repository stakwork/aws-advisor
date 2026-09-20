import { createHash } from "node:crypto";
import { config } from "./config.js";
import { db } from "./db.js";

/**
 * Rejection learnings: when a human rejects a recommendation with a reason, the reason is posted to
 * repo2graph's learnings store (POST /learnings) so future agent runs are retrieved with it in scope.
 */

export const LEARNING_SCOPES = ["aws-cost-advisor"];

export interface RejectedRecommendation { id: number; fingerprint: string; title: string; rule: string; resource: string | null; decision_reason: string }

export const learningIdFor = (fingerprint: string) => `aws-advisor:${createHash("sha1").update(fingerprint).digest("hex").slice(0, 20)}`;

export function buildLearning(rec: RejectedRecommendation): { id: string; rule: string; reason: string; scopes: string[] } {
  return {
    id: learningIdFor(rec.fingerprint),
    rule: `Do not recommend "${rec.title}" (rule ${rec.rule}${rec.resource ? `, resource ${rec.resource}` : ""}): the team rejected it because ${rec.decision_reason.trim()}`,
    reason: rec.decision_reason.trim(),
    scopes: LEARNING_SCOPES,
  };
}

/** Fire-and-forget. Records the outcome in the learnings table and logs failures; never throws. */
export function postRejectionLearning(rec: RejectedRecommendation): void {
  if (!config.repo2graphUrl) return;
  const learning = buildLearning(rec);
  const rowId = Number(db.prepare("insert into learnings(learning_id, recommendation_id, rule, scopes) values (?, ?, ?, ?)")
    .run(learning.id, rec.id, learning.rule, JSON.stringify(learning.scopes)).lastInsertRowid);
  const done = (status: "sent" | "failed", error?: string) =>
    db.prepare("update learnings set status = ?, error = ? where id = ?").run(status, error ?? null, rowId);
  (async () => {
    const res = await fetch(`${config.repo2graphUrl}/learnings`, {
      method: "POST",
      headers: { "content-type": "application/json", "x-api-token": config.repo2graphToken },
      body: JSON.stringify([learning]),
      signal: AbortSignal.timeout(30_000),
    });
    if (!res.ok) throw new Error(`repo2graph responded ${res.status}: ${(await res.text()).slice(0, 300)}`);
    done("sent");
    console.log(`[learnings] sent ${learning.id} for recommendation ${rec.id}`);
  })().catch((e: any) => {
    done("failed", e?.message || String(e));
    console.error(`[learnings] failed to send ${learning.id}: ${e?.message || e}`);
  });
}
