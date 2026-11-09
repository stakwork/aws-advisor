import assert from "node:assert/strict";
import { test, mock } from "node:test";
import type { AddressInfo } from "node:net";
import express from "express";
import { config } from "../config.js";
import { db } from "../db.js";
import { BadRequest, EXPORT_TYPES, decodeCursor, encodeCursor, exportPage, type ExportType } from "../inventory_export.js";
import { inventoryExport } from "../routes/inventory_export.js";

const cfg = config as any;
const rows = (n: number) => Array.from({ length: n }, (_, i) => ({ arn: `arn:aws:x:::r${String(n - i).padStart(3, "0")}`, account_id: i % 2 ? "111122223333" : "444455556666", region: "eu-west-1", tags: { n: String(i) } }));
const fake = (collect: ExportType["collect"]): ExportType[] => [{ type: "fake", description: "fake", collect }];

async function serve<T>(fn: (base: string) => Promise<T>): Promise<T> {
  const app = express(); app.use(express.json()); app.use("/api", inventoryExport);
  const server = app.listen(0, "127.0.0.1");
  await new Promise((r) => server.once("listening", r));
  try { return await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}/api`); } finally { server.close(); }
}
const withTokens = async (api: string, exp: string, fn: () => Promise<void>) => {
  const [a, e] = [cfg.apiToken, cfg.inventoryExportToken]; cfg.apiToken = api; cfg.inventoryExportToken = exp;
  try { await fn(); } finally { cfg.apiToken = a; cfg.inventoryExportToken = e; }
};

test("export: pages are sorted, stable, and the cursor walks every row exactly once", async () => {
  const types = fake(async () => ({ rows: rows(7), errors: [] }));
  const seen: string[] = []; let cursor: string | null = null; let pages = 0;
  do {
    const r = await exportPage({ type: "fake", cursor, limit: 3 }, types);
    assert.equal(r.complete, true); seen.push(...r.rows.map((x) => x.id)); cursor = r.nextCursor; pages++;
  } while (cursor);
  assert.equal(pages, 3);
  assert.deepEqual(seen, [...seen].sort());
  assert.equal(new Set(seen).size, 7);
  assert.deepEqual((await exportPage({ type: "fake", limit: 3 }, types)).rows[0].tags, { n: "6" }, "tags survive");
});

test("export: limit is clamped, cursor and limit are validated, account filters", async () => {
  const types = fake(async () => ({ rows: rows(6), errors: [] }));
  assert.equal(encodeCursor(5), encodeCursor(5)); assert.equal(decodeCursor(encodeCursor(5)), 5);
  await assert.rejects(exportPage({ type: "fake", cursor: "!!nope" }, types), BadRequest);
  await assert.rejects(exportPage({ type: "fake", limit: "0" }, types), BadRequest);
  await assert.rejects(exportPage({ type: "fake", limit: "abc" }, types), BadRequest);
  await assert.rejects(exportPage({ type: "fake", account: "12" }, types), BadRequest);
  const big = fake(async () => ({ rows: rows(5100), errors: [] }));
  assert.equal((await exportPage({ type: "fake", limit: 999999 }, big)).rows.length, 5000);
  const one = await exportPage({ type: "fake", account: "111122223333" }, types, () => null);
  assert.equal(one.rows.length, 3); assert.ok(one.rows.every((r) => r.account_id === "111122223333"));
});

test("export: collector errors land in errors with complete=false, rows still returned", async () => {
  const r = await exportPage({ type: "fake" }, fake(async () => ({ rows: rows(2), errors: ["a: denied", "b: timeout"] })));
  assert.equal(r.complete, false); assert.deepEqual(r.errors, ["a: denied", "b: timeout"]); assert.equal(r.rows.length, 2);
});

test("export route: unknown type is a 400 that lists the valid types; bad cursor and limit are 400", async () => {
  await withTokens("", "", () => serve(async (base) => {
    const r = await fetch(`${base}/inventory/export?type=nope`);
    assert.equal(r.status, 400);
    const body: any = await r.json();
    for (const t of EXPORT_TYPES) assert.ok(body.error.includes(t.type), t.type);
    assert.equal((await fetch(`${base}/inventory/export?type=ec2&cursor=zzz`)).status, 400);
    assert.equal((await fetch(`${base}/inventory/export?type=ec2&limit=-1`)).status, 400);
    assert.equal((await fetch(`${base}/inventory/export`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ type: "nope" }) })).status, 400);
  }));
});

test("export types: every collected resource type is listed with a description, plus the accounts", async () => {
  await withTokens("", "", () => serve(async (base) => {
    const body: any = await (await fetch(`${base}/inventory/export/types`)).json();
    const names = body.types.map((t: any) => t.type);
    for (const n of ["ec2", "ebs", "rds", "elasticache", "network", "lambda", "iam", "role_trust", "route53", "dynamodb", "elb", "s3", "sso", "clusters", "services"]) assert.ok(names.includes(n), n);
    assert.ok(body.types.every((t: any) => t.description));
    assert.equal(new Set(names).size, names.length);
    assert.ok(Array.isArray(body.accounts));
  }));
});

test("export auth: rejected without a credential, accepted with API_TOKEN or INVENTORY_EXPORT_TOKEN, the export token opens nothing else", async () => {
  await withTokens("api-secret", "export-secret", () => serve(async (base) => {
    for (const path of ["/inventory/export/types", "/inventory/export?type=nope"]) {
      assert.equal((await fetch(base + path)).status, 401);
      assert.equal((await fetch(base + path, { headers: { authorization: "Bearer wrong" } })).status, 401);
    }
    assert.equal((await fetch(`${base}/inventory/export/types`, { headers: { authorization: "Bearer export-secret" } })).status, 200);
    assert.equal((await fetch(`${base}/inventory/export/types`, { headers: { "x-api-token": "api-secret" } })).status, 200);
    assert.equal((await fetch(`${base}/inventory/export?type=nope`, { headers: { authorization: "Bearer export-secret" } })).status, 400, "authorized, then validated");
  }));
  await withTokens("api-secret", "", () => serve(async (base) => {
    assert.equal((await fetch(`${base}/inventory/export/types`, { headers: { authorization: "Bearer export-secret" } })).status, 401);
  }));
});

test("export: running the real collectors writes nothing to SQLite (Steampipe is down here: the failures come back as errors)", async () => {
  const sql: string[] = [];
  const orig = db.prepare.bind(db);
  const spy = mock.method(db, "prepare", ((s: string) => { sql.push(s); return orig(s); }) as any);
  const exec = mock.method(db, "exec", (() => { throw new Error("db.exec must not be called by the export"); }) as any);
  try {
    for (const type of ["ec2", "security_groups", "iam", "role_trust"]) {
      const r = await exportPage({ type });
      assert.equal(r.type, type); assert.ok(Array.isArray(r.rows)); assert.equal(r.complete, r.errors.length === 0);
    }
  } finally { spy.mock.restore(); exec.mock.restore(); }
  const writes = sql.filter((s) => /^\s*(insert|update|delete|replace|create|drop|alter)\b/i.test(s));
  assert.deepEqual(writes, []);
});
