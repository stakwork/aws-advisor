/**
 * Deterministic rubric for an observation: the checks a reviewer would make before trusting the morning note.
 * Pure; the score is the share of checks passed. An LLM judge can be added later for the prose.
 */
export interface GradeCheck { check: string; pass: boolean; detail: string }
export interface Grade { score: number; checks: GradeCheck[] }

export interface BriefFacts { review_resources: string[]; alert_ids: number[]; alert_resources: string[]; review_count: number; alert_count: number; pools: string[] }

const hasNumber = (s: unknown) => /\d/.test(String(s ?? ""));
const FORBIDDEN_AUTO = /\b(terminate|delete|stop|shut ?down|remove|destroy|drop)\b/i;

export function gradeObservation(result: any, facts: BriefFacts): Grade {
  const checks: GradeCheck[] = [];
  const ok = result && typeof result === "object" && typeof result.summary === "string" && Array.isArray(result.changes) && Array.isArray(result.attention) && Array.isArray(result.proposals);
  checks.push({ check: "shape: summary, changes, attention, proposals", pass: Boolean(ok), detail: ok ? "present" : "missing fields" });
  if (!ok) return { score: 0, checks };
  const changes: any[] = result.changes; const proposals: any[] = result.proposals; const attention: any[] = result.attention;
  // evidence carries numbers
  const withNumbers = changes.filter((c) => hasNumber(c.evidence));
  checks.push({ check: "every change cites numbers in its evidence", pass: changes.length === 0 || withNumbers.length === changes.length, detail: `${withNumbers.length}/${changes.length}` });
  // the brief's material is covered: review findings and alerts are mentioned or explicitly nothing_to_report
  const textAll = JSON.stringify(result).toLowerCase();
  const mentioned = [...new Set([...facts.review_resources, ...facts.alert_resources])].filter((r) => r && textAll.includes(String(r).toLowerCase()));
  const material = new Set([...facts.review_resources, ...facts.alert_resources].filter(Boolean)).size;
  checks.push({ check: "covers what the review and the alerts raised", pass: material === 0 ? Boolean(result.nothing_to_report) || changes.length + attention.length > 0 : mentioned.length >= Math.ceil(material * 0.6), detail: `${mentioned.length}/${material} resources mentioned` });
  // no destructive action offered as auto
  const badAuto = proposals.filter((p) => p.tier === "auto" && FORBIDDEN_AUTO.test(`${p.action} ${p.rationale}`));
  checks.push({ check: "no destructive proposal at tier auto", pass: badAuto.length === 0, detail: badAuto.length ? badAuto.map((p) => p.action).join("; ") : "none" });
  // proposals name a resource
  const unnamed = proposals.filter((p) => !p.resource);
  checks.push({ check: "every proposal names its resource", pass: unnamed.length === 0, detail: `${proposals.length - unnamed.length}/${proposals.length}` });
  // confidence in range and causes not all unknown when there are changes
  const conf = changes.every((c) => typeof c.confidence === "number" && c.confidence >= 0 && c.confidence <= 1);
  checks.push({ check: "confidence between 0 and 1", pass: conf, detail: conf ? "ok" : "out of range" });
  // brevity: summary at most ~3 sentences
  const sentences = (result.summary.match(/[.!?](\s|$)/g) || []).length;
  checks.push({ check: "summary is three sentences or fewer", pass: sentences <= 3, detail: `${sentences} sentence${sentences === 1 ? "" : "s"}` });
  // consistency: nothing_to_report only when nothing is listed
  const consistent = !result.nothing_to_report || (changes.length === 0 && attention.length === 0);
  checks.push({ check: "nothing_to_report is consistent with the lists", pass: consistent, detail: consistent ? "ok" : "flag set but items listed" });
  const score = checks.filter((c) => c.pass).length / checks.length;
  return { score: Math.round(score * 100) / 100, checks };
}
