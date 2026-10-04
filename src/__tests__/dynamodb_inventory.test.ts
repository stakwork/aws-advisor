import assert from "node:assert/strict";
import { test } from "node:test";

test("dynamodb list price: provisioned units by the hour with the indexes' units, on-demand request units scaled to a month, storage by the GB", async () => {
  const { dynamodbMonthlyCost, DYNAMODB_PRICE: p } = await import("../dynamodb_inventory.js");
  const base = { size_bytes: 4e9, read_units_30d: 0, write_units_30d: 0, metric_days: 30, gsi_read_capacity: 0, gsi_write_capacity: 0 };
  // provisioned: 10 RCU + 5 WCU on the table, 5 RCU on an index; usage does not matter
  const prov = dynamodbMonthlyCost({ ...base, billing_mode: "PROVISIONED", read_capacity: 10, write_capacity: 5, gsi_read_capacity: 5, read_units_30d: 9e9 });
  assert.equal(prov.storage_usd, 1);
  assert.equal(prov.capacity_usd, Math.round((15 * p.rcu_hour + 5 * p.wcu_hour) * 730 * 100) / 100);
  assert.equal(prov.usd_month, Math.round((prov.storage_usd + prov.capacity_usd) * 100) / 100);
  // on demand: 15 days of data with 30M reads and 2M writes scale to a month at the request-unit rates
  const od = dynamodbMonthlyCost({ ...base, billing_mode: "PAY_PER_REQUEST", read_capacity: 0, write_capacity: 0, read_units_30d: 30e6, write_units_30d: 2e6, metric_days: 15 });
  assert.equal(od.capacity_usd, Math.round((60 * p.on_demand_read_per_million + 4 * p.on_demand_write_per_million) * 100) / 100);
  // on demand without any metric yet: storage only, never a guess
  const none = dynamodbMonthlyCost({ ...base, billing_mode: "PAY_PER_REQUEST", read_capacity: 0, write_capacity: 0, metric_days: 0, read_units_30d: 0 });
  assert.deepEqual(none, { storage_usd: 1, capacity_usd: 0, usd_month: 1 });
  // a null billing mode reads as provisioned (older plugin rows)
  assert.equal(dynamodbMonthlyCost({ ...base, billing_mode: null, read_capacity: 1, write_capacity: 1 }).capacity_usd, Math.round((p.rcu_hour + p.wcu_hour) * 730 * 100) / 100);
});

test("dynamodb inventory: keyed per account and region, listed and summarised under a scope", async () => {
  const { listDynamodb, dynamodbSummary } = await import("../dynamodb_inventory.js");
  const { db } = await import("../db.js");
  db.prepare("delete from inventory_dynamodb where name = 'orders-test'").run();
  const ins = db.prepare("insert into inventory_dynamodb(account_id, region, name, billing_mode, read_capacity, write_capacity, size_bytes, item_count, monthly_usd, storage_usd, capacity_usd, read_units_30d, write_units_30d, first_seen, last_seen) values (?, ?, 'orders-test', ?, 0, 0, 1e9, 10, ?, 0.25, ?, ?, 0, 'now', 'now')");
  ins.run("111111111111", "us-east-1", "PAY_PER_REQUEST", 5, 4.75, 1000); ins.run("222222222222", "us-east-1", "PROVISIONED", 10, 9.75, 0); ins.run("111111111111", "eu-west-1", "PROVISIONED", 1, 0.75, 0);
  assert.equal(listDynamodb({ q: "orders-test" }).length, 3, "the same name in two accounts and two regions is three rows");
  const one = listDynamodb({ q: "orders-test", scope: { id: "222222222222", primary: false } });
  assert.equal(one.length, 1); assert.equal(one[0].billing_mode, "PROVISIONED");
  const sum = dynamodbSummary({ id: "111111111111", primary: false });
  assert.equal(sum.total, 2); assert.equal(sum.on_demand, 1); assert.equal(sum.active, 1); assert.equal(sum.monthly_usd, 6);
  db.prepare("delete from inventory_dynamodb where name = 'orders-test'").run();
});
