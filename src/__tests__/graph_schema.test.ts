import { test } from "node:test";
import assert from "node:assert";
import { attrType, buildSchema, specificLabels, type EdgeSample, type LabelSample } from "../graph_schema.js";

test("attribute types: Jarvis's words, mixed ints and floats are floats, mixed kinds are complex, nulls ignored", () => {
  assert.equal(attrType(["a", null]), "string");
  assert.equal(attrType([1, 2]), "int");
  assert.equal(attrType([1, 2.5]), "float");
  assert.equal(attrType([true]), "boolean");
  assert.equal(attrType([["x"]]), "list");
  assert.equal(attrType(["a", 1]), "complex");
  assert.equal(attrType([]), "string");
});

test("a node is filed under its own label, not the base one; the base only when it has nothing else; foreign labels ignored", () => {
  assert.deepEqual(specificLabels(["AdvisorResource", "AdvisorCompute", "Node"]), ["AdvisorCompute"]);
  assert.deepEqual(specificLabels(["AdvisorResource"]), ["AdvisorResource"]);
  assert.deepEqual(specificLabels(["Concept"]), []);
  assert.deepEqual(specificLabels(["KnPattern"]), []); // legacy label
});

const labels: LabelSample[] = [
  { label: "AdvisorResource", total: 3, under_base: 3, props: [{ key: "id", count: 3, values: ["i-1"] }, { key: "name", count: 2, values: ["web"] }, { key: "monthly_usd", count: 3, values: [1.5] }, { key: "cpu_30d", count: 1, values: [12] }] },
  { label: "AdvisorCompute", total: 2, under_base: 2, props: [{ key: "id", count: 2, values: ["i-1"] }, { key: "name", count: 1, values: ["web"] }, { key: "monthly_usd", count: 2, values: [1.5] }, { key: "type", count: 2, values: ["m5.large"] }, { key: "cpu_30d", count: 1, values: [12] }] },
  { label: "AdvisorDatabase", total: 1, under_base: 1, props: [{ key: "id", count: 1, values: ["db-1"] }, { key: "name", count: 1, values: ["db"] }, { key: "monthly_usd", count: 1, values: [3.5] }] },
  { label: "AdvisorFilter", total: 4, under_base: 1, props: [{ key: "id", count: 4, values: ["sg-1"] }, { key: "rules", count: 4, values: [3] }] },
  { label: "AdvisorRecommendation", total: 1, under_base: 0, props: [{ key: "id", count: 1, values: ["rec:1"] }, { key: "action", count: 1, values: ["stop"] }, { key: "title", count: 1, values: ["Stop it"] }] },
];

test("node schemas: hierarchy under Thing and AdvisorResource, subtypes state only what they add, required vs optional, Jarvis's field names kept out", () => {
  const { nodes } = buildSchema(labels, []);
  const by = Object.fromEntries(nodes.map((n) => [n.type, n]));
  assert.equal(by.AdvisorResource.parent, "Thing");
  assert.equal(by.AdvisorCompute.parent, "AdvisorResource");
  assert.equal(by.AdvisorFilter.parent, "Thing", "mostly security groups, which are not resources");
  assert.equal(by.AdvisorRecommendation.parent, "Thing");
  assert.equal(by.AdvisorResource.props.id, "string");
  assert.equal(by.AdvisorResource.props.name, "?string");
  assert.equal(by.AdvisorResource.props.monthly_usd, "float");
  assert.equal(by.AdvisorCompute.props.id, undefined, "inherited from AdvisorResource");
  assert.equal(by.AdvisorCompute.props.cpu_30d, "?int");
  assert.equal(by.AdvisorResource.props.cpu_30d, undefined, "a subtype's own property stays on the subtype, not the base");
  assert.equal(by.AdvisorCompute.props.monthly_usd, undefined, "shared by the resource types, so inherited");
  assert.equal(by.AdvisorCompute.props.type, "AdvisorCompute", "the instance type never overwrites the schema's type");
  assert.match(String(by.AdvisorCompute.props.type_description), /Also carries type/);
  assert.equal(by.AdvisorCompute.props.title_key, "name");
  assert.equal(by.AdvisorRecommendation.props.action, undefined);
  assert.equal(by.AdvisorRecommendation.props.title_key, "id");
  for (const n of nodes) { assert.equal(n.props.domain, "Cloud"); assert.equal(n.props.is_deleted, false); assert.equal(n.props.node_key, `${n.type.toLowerCase()}-id`); }
});

test("edge schemas: one per (source, relationship, target), filed under the specific labels, properties optional, unknown ends and bad types dropped", () => {
  const edges: EdgeSample[] = [
    { source_labels: ["AdvisorResource", "AdvisorCompute"], type: "GUARDED_BY", target_labels: ["AdvisorFilter"], key: null, count: 2, values: [] },
    { source_labels: ["AdvisorRecommendation"], type: "TARGETS", target_labels: ["AdvisorResource", "AdvisorCompute"], key: "since", count: 1, values: ["2026-01-01"] },
    { source_labels: ["AdvisorRecommendation"], type: "TARGETS", target_labels: ["AdvisorResource", "AdvisorCompute"], key: "weight", count: 1, values: [2] },
    { source_labels: ["AdvisorRecommendation"], type: "DECIDED_AS", target_labels: ["Concept"], key: null, count: 1, values: [] },
    { source_labels: ["AdvisorCompute"], type: "bad-type", target_labels: ["AdvisorFilter"], key: null, count: 1, values: [] },
  ];
  const out = buildSchema(labels, edges).edges;
  assert.deepEqual(out.map((e) => `${e.source}-${e.type}->${e.target}`), ["AdvisorCompute-GUARDED_BY->AdvisorFilter", "AdvisorRecommendation-TARGETS->AdvisorCompute"]);
  assert.deepEqual(out[1].props, { since: "?string", weight: "?int" });
});
