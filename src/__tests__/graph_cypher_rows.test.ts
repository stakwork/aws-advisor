import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { test } from "node:test";

/**
 * A batched statement (UNWIND $rows AS row) loses `row` at the first WITH whose projection does not carry it; Neo4j then
 * rejects the whole statement ("Variable `row` not defined") and the layer never syncs again, silently from the UI's
 * point of view (the network layer went that way once the VPC step matched the account by row.account_id after a bare
 * WITH n). The unit tests cannot run Cypher, so this reads every graph module's statements as text: once a WITH drops
 * row, nothing later in the same statement may use it, the rest of that line included.
 */
const SRC = path.join(path.dirname(new URL(import.meta.url).pathname), "..");
const CLAUSE = /\b(MATCH|OPTIONAL|MERGE|UNWIND|WHERE|SET|DELETE|DETACH|CREATE|FOREACH|RETURN|CALL|REMOVE)\b/;

/** The lines of a statement after the row variable is gone: the first WITH whose projection lacks it, and everything after. */
export function rowDroppedAt(stmt: string): { at: string; usedLater: string } | null {
  let dropped: string | null = null;
  for (const line of stmt.split("\n")) {
    const m = /^\s*WITH\b(.*)$/.exec(line);
    if (!dropped && m) {
      const cut = m[1].search(CLAUSE);
      const projection = cut < 0 ? m[1] : m[1].slice(0, cut);
      if (/\brow\b/.test(projection)) continue;
      dropped = line.trim().slice(0, 60);
      if (cut >= 0 && /\brow\b/.test(m[1].slice(cut))) return { at: dropped, usedLater: line.trim().slice(0, 100) };
      continue;
    }
    if (dropped && /\brow\b/.test(line)) return { at: dropped, usedLater: line.trim().slice(0, 100) };
  }
  return null;
}

test("rowDroppedAt: a bare WITH followed by row on the same or a later line is caught; a WITH that carries row is not", () => {
  assert.equal(rowDroppedAt("UNWIND $rows AS row\nMERGE (n {id: row.id})\nWITH n, row MATCH (a {id: row.a}) MERGE (n)-[:X]->(a)"), null);
  assert.ok(rowDroppedAt("UNWIND $rows AS row\nMERGE (n {id: row.id})\nWITH n MATCH (a {id: row.a}) MERGE (n)-[:X]->(a)"));
  assert.ok(rowDroppedAt("UNWIND $rows AS row\nMERGE (n {id: row.id})\nWITH n\nMATCH (a {id: row.a})"));
  assert.equal(rowDroppedAt("UNWIND $rows AS row\nMERGE (n {id: row.id})\nWITH n\nMATCH (a {id: $account})"), null);
});

test("every WITH inside a batched Cypher statement keeps carrying row while row is still used", () => {
  const files = fs.readdirSync(SRC).filter((f) => /^graph_.*\.ts$/.test(f) || f === "swarm_costs_graph.ts");
  assert.ok(files.length >= 5, `graph modules found: ${files.join(", ")}`);
  const bad: string[] = [];
  for (const f of files) {
    const parts = fs.readFileSync(path.join(SRC, f), "utf8").split("`");
    for (let i = 1; i < parts.length; i += 2) {
      if (!/UNWIND \$rows AS row\b/.test(parts[i])) continue;
      const hit = rowDroppedAt(parts[i]);
      if (hit) bad.push(`${f}: "${hit.at}" drops row, but it is still used: "${hit.usedLater}"`);
    }
  }
  assert.deepEqual(bad, []);
});
