import assert from "node:assert/strict";
import { test } from "node:test";
import { capacityVerdict, onDemandCost, provisionedCost, unitsForPeak, updateInput, type TableFacts, type TableMetrics } from "../actions/dynamodb_capacity_mode.js";
import { baselinePct, creditVerdict, surplusUsd, type CreditMetrics } from "../actions/cpu_credit_spec.js";

const table = (over: Partial<TableFacts> = {}): TableFacts => ({ name: "orders", billing_mode: "PROVISIONED", read_units: 100, write_units: 50, gsis: [], ...over });
const metrics = (over: Partial<TableMetrics> = {}): TableMetrics => ({ read_consumed: 1e6, write_consumed: 2e5, read_peak_hour: 3600, write_peak_hour: 1800, gsi_peak_hour: {}, days: 30, ...over });

test("dynamodb: prices at list, both ways", () => {
  // 100 RCU + 50 WCU for a month, plus one index of 10/10
  assert.equal(provisionedCost(100, 50, [{ name: "i", read: 10, write: 10 }]), Math.round((110 * 0.00013 * 730 + 60 * 0.00065 * 730) * 100) / 100);
  // a million reads and 200k writes over a full 30 days
  assert.equal(onDemandCost({ read_consumed: 1e6, write_consumed: 2e5, days: 30 }), 0.25);
  // fifteen days scale up to a month
  assert.equal(onDemandCost({ read_consumed: 1e6, write_consumed: 2e5, days: 15 }), 0.5);
  assert.equal(unitsForPeak(3600), 2); // one unit per second, plus 30 % → 2
  assert.equal(unitsForPeak(0), 1);
});

test("dynamodb: an idle provisioned table goes on demand, a busy one stays, and the threshold is 20 % and 5 USD", () => {
  const idle = capacityVerdict(table(), metrics());
  assert.equal(idle.target_mode, "PAY_PER_REQUEST");
  assert.ok(idle.cost_now > idle.cost_other);
  assert.match(idle.reason, /would cost 0.25 USD\/month on demand/);
  // consumption that costs more on demand than the provisioned units do
  const busy = capacityVerdict(table(), metrics({ read_consumed: 2e8, write_consumed: 5e7 }));
  assert.equal(busy.target_mode, null);
  assert.match(busy.reason, /provisioned is cheaper/);
  // saving under 5 USD: a tiny table
  const tiny = capacityVerdict(table({ read_units: 5, write_units: 5 }), metrics({ read_consumed: 0, write_consumed: 0 }));
  assert.equal(tiny.target_mode, null);
  assert.match(tiny.reason, /not enough to switch/);
  // too few days
  assert.match(capacityVerdict(table(), metrics({ days: 3 })).reason, /3 days of metrics, 14 needed/);
});

test("dynamodb: a steady on-demand table goes provisioned at the peak plus 30 %, indexes included", () => {
  const t = table({ billing_mode: "PAY_PER_REQUEST", read_units: 0, write_units: 0, gsis: [{ name: "by_user", read: 0, write: 0 }] });
  // 200 reads/s and 40 writes/s all month: on demand ≈ 65 + 65 USD, provisioned for the peak far less
  const m = metrics({ read_consumed: 200 * 86400 * 30, write_consumed: 40 * 86400 * 30, read_peak_hour: 200 * 3600, write_peak_hour: 40 * 3600, gsi_peak_hour: { by_user: { read: 100 * 3600, write: 40 * 3600 } } });
  const v = capacityVerdict(t, m);
  assert.equal(v.target_mode, "PROVISIONED");
  assert.deepEqual(v.provision, { read_units: 260, write_units: 52, gsis: [{ name: "by_user", read: 130, write: 52 }] });
  assert.ok(v.cost_now > v.cost_other);
  const input = updateInput("orders", { billing_mode: "PROVISIONED", ...v.provision });
  assert.equal(input.ProvisionedThroughput?.ReadCapacityUnits, 260);
  assert.equal(input.GlobalSecondaryIndexUpdates?.[0].Update?.IndexName, "by_user");
  assert.deepEqual(updateInput("orders", { billing_mode: "PAY_PER_REQUEST" }), { TableName: "orders", BillingMode: "PAY_PER_REQUEST" });
});

const credit = (over: Partial<CreditMetrics> = {}): CreditMetrics => ({ surplus_credits: 0, balance_zero_days: 0, cpu_avg: 5, days: 30, ...over });

test("credits: baselines per size and the surplus price per vCPU-hour", () => {
  assert.equal(baselinePct("t3.micro"), 10); assert.equal(baselinePct("t4g.large"), 30); assert.equal(baselinePct("t2.xlarge"), 22.5); assert.equal(baselinePct("m5.large"), null);
  // 6000 credits = 100 vCPU-hours at 0.05 (t3) or 0.04 (t4g)
  assert.equal(surplusUsd(6000, "t3.small"), 5); assert.equal(surplusUsd(6000, "t4g.small"), 4);
});

test("credits: unlimited → standard only when the surplus is real money and the CPU sits under the baseline", () => {
  // 12000 credits = 200 vCPU-h = 10 USD on a 15 USD/month t3.small averaging 8 % against a 20 % baseline
  const v = creditVerdict("unlimited", credit({ surplus_credits: 12000, cpu_avg: 8 }), "t3.small", 15);
  assert.equal(v.target, "standard"); assert.equal(v.surplus_usd_30d, 10);
  assert.match(v.reason, /standard mode throttles them/);
  // the same money on an instance that really works above baseline: leave it
  const busy = creditVerdict("unlimited", credit({ surplus_credits: 12000, cpu_avg: 35 }), "t3.small", 15);
  assert.equal(busy.target, null); assert.match(busy.reason, /would throttle it/);
  // 2 USD of surplus: not worth it
  assert.equal(creditVerdict("unlimited", credit({ surplus_credits: 2400, cpu_avg: 5 }), "t3.small", 15).target, null);
  // 10 USD but under a tenth of a 200 USD instance
  assert.equal(creditVerdict("unlimited", credit({ surplus_credits: 12000, cpu_avg: 5 }), "t3.2xlarge", 200).target, null);
  // too few days
  assert.match(creditVerdict("unlimited", credit({ surplus_credits: 12000, days: 5 }), "t3.small", 15).reason, /5 days of metrics/);
});

test("credits: standard → unlimited when the balance hit zero on three days or more", () => {
  const v = creditVerdict("standard", credit({ balance_zero_days: 4 }), "t3.medium", 30);
  assert.equal(v.target, "unlimited"); assert.match(v.reason, /hit zero on 4 of the last 30 days/);
  const fine = creditVerdict("standard", credit({ balance_zero_days: 2 }), "t3.medium", 30);
  assert.equal(fine.target, null); assert.match(fine.reason, /under the 3/);
  assert.match(creditVerdict("standard", credit(), "t3.medium", 30).reason, /never ran out/);
});
