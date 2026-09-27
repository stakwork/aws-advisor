import assert from "node:assert/strict";
import { test } from "node:test";
import { verdictFrom, reusableCheck, checkLine, HOLD_FITS_RECORD, HOLD_IRREVERSIBLE, HOLD_SERVICE_IMPACT, type ProposalCheck } from "../proposal_check.js";

const now = new Date("2026-09-27T12:00:00Z");
const ok = { irreversible: 0.1, service_impact: 0.2, fits_record: 0.1 };

test("second opinion: a harmless change proceeds and the reason carries the scores", () => {
  const v = verdictFrom(ok, { irreversibleKind: true, mode: "hold", now });
  assert.equal(v.verdict, "proceed");
  assert.match(v.reason, /no objection/);
  assert.equal(v.service_impact_label, "No user-visible effect");
  assert.equal(v.checked_at, now.toISOString());
  assert.equal(checkLine(v), "Jev: proceed");
  assert.equal(checkLine(null), null);
});

test("second opinion: irreversibility holds only a kind the executor cannot undo", () => {
  const a = { ...ok, irreversible: HOLD_IRREVERSIBLE };
  assert.equal(verdictFrom(a, { irreversibleKind: true, mode: "hold" }).verdict, "hold");
  assert.match(verdictFrom(a, { irreversibleKind: true, mode: "hold" }).reason, /cannot be recovered/);
  // a trim or a retention change is undone by the revert verb: the score alone does not hold it
  assert.equal(verdictFrom(a, { irreversibleKind: false, mode: "hold" }).verdict, "proceed");
});

test("second opinion: service impact and a contradiction of the record each hold on their own", () => {
  const imp = verdictFrom({ ...ok, service_impact: HOLD_SERVICE_IMPACT }, { irreversibleKind: false, mode: "hold" });
  assert.equal(imp.verdict, "hold"); assert.match(imp.reason, /users would notice/); assert.equal(imp.service_impact_label, "Outage possible");
  assert.equal(verdictFrom({ ...ok, service_impact: 1.2 }, { irreversibleKind: false, mode: "hold" }).service_impact_label, "Brief or degraded");
  const fit = verdictFrom({ ...ok, fits_record: HOLD_FITS_RECORD }, { irreversibleKind: false, mode: "hold" });
  assert.equal(fit.verdict, "hold"); assert.match(fit.reason, /contradicts what the team decided/);
  // two triggers, both named
  const both = verdictFrom({ irreversible: 0.9, service_impact: 2, fits_record: 0.9 }, { irreversibleKind: true, mode: "hold" });
  assert.match(both.reason, /cannot be recovered.*users would notice.*contradicts/);
  assert.equal(checkLine(both), `Jev: hold, ${both.reason}`);
});

test("second opinion: advise mode records the same verdict but words it as advice", () => {
  const v = verdictFrom({ ...ok, fits_record: 0.8 }, { irreversibleKind: false, mode: "advise" });
  assert.equal(v.verdict, "hold");
  assert.match(v.reason, /^Jev advises against it/);
  assert.match(verdictFrom({ ...ok, fits_record: 0.8 }, { irreversibleKind: false, mode: "hold" }).reason, /^Jev holds it/);
});

test("second opinion: an earlier verdict for the same change is reused instead of asking again", () => {
  const check: ProposalCheck = { ...verdictFrom(ok, { irreversibleKind: false, mode: "hold", now }), reason: "Jev sees no objection." };
  const row = { id: 50, dedupe: "ebs_iops_trim:vol-1:3000", account_id: null as string | null, after_json: '{"iops":3000}' };
  const same = { id: 41, dedupe: row.dedupe, account_id: null, after_json: row.after_json, check };
  const r = reusableCheck([same], row, now.getTime());
  assert.ok(r); assert.equal(r!.from.id, 41); assert.equal(r!.check.reused_from, 41); assert.equal(r!.check.reason, "same change as #41: Jev sees no objection.");
  // a copy of a copy still names the original
  const copy = { id: 45, dedupe: row.dedupe, account_id: null, after_json: row.after_json, check: r!.check };
  assert.equal(reusableCheck([copy], row, now.getTime())!.check.reason, "same change as #41: Jev sees no objection.");
  // newest wins
  const newer = { ...same, id: 47 };
  assert.equal(reusableCheck([same, newer], row, now.getTime())!.from.id, 47);
  // a different target state, another account, the row itself, an unchecked row or a stale verdict do not count
  assert.equal(reusableCheck([{ ...same, after_json: '{"iops":3500}' }], row, now.getTime()), null);
  assert.equal(reusableCheck([{ ...same, account_id: "222222222222" }], row, now.getTime()), null);
  assert.equal(reusableCheck([{ ...same, id: 50 }], row, now.getTime()), null);
  assert.equal(reusableCheck([{ ...same, check: null }], row, now.getTime()), null);
  const old = { ...same, check: { ...check, checked_at: new Date(now.getTime() - 31 * 86400000).toISOString() } };
  assert.equal(reusableCheck([old], row, now.getTime()), null);
});
