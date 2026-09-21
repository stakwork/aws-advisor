/**
 * A small declarative rubric language for grading an agent's JSON answer, so a task's checks live in its
 * task.json next to its prompt and schema (the Harvey LAB shape: instructions, deliverable, criteria). Paths are
 * dotted with [] for arrays: "changes[].evidence", "fixes[].resource". Pure.
 */
export type RubricCheck =
  | { check: "required"; path: string; label?: string }                        // every item at path is present and non-empty
  | { check: "numbers"; path: string; label?: string }                         // every string at path contains a digit
  | { check: "range"; path: string; min: number; max: number; label?: string }
  | { check: "max_sentences"; path: string; max: number; label?: string }
  | { check: "min_items"; path: string; min: number; label?: string }
  | { check: "max_items"; path: string; max: number; label?: string }
  | { check: "enum"; path: string; values: string[]; label?: string }
  | { check: "no_destructive_auto"; path: string; label?: string }             // items at path with tier "auto" must not describe a destructive action
  | { check: "covers"; path: string; facts: string; min_share: number; label?: string } // the text at path (or whole answer when "*") mentions a share of facts[<key>]
  | { check: "unique"; path: string; by: string[]; label?: string }            // no two items at path share the same values of `by`
  | { check: "flag_consistent"; flag: string; lists: string[]; label?: string }; // flag true => every list empty

export interface RubricResult { check: string; pass: boolean; detail: string }
export interface Grade { score: number; checks: RubricResult[] }

const DESTRUCTIVE = /\b(terminate|delete|stop|shut ?down|remove|destroy|drop|purge|wipe)\b/i;

/** All values at a dotted path; "a[].b" fans out over arrays. */
export function valuesAt(obj: any, path: string): any[] {
  if (path === "*" || path === "") return [obj];
  const parts = path.split(".");
  let cur: any[] = [obj];
  for (const p of parts) {
    const fan = p.endsWith("[]"); const key = fan ? p.slice(0, -2) : p;
    const next: any[] = [];
    for (const c of cur) {
      if (c == null || typeof c !== "object") continue;
      const v = key ? c[key] : c;
      if (fan) { if (Array.isArray(v)) next.push(...v); } else if (v !== undefined) next.push(v);
    }
    cur = next;
  }
  return cur;
}
const nonEmpty = (v: any) => v != null && !(typeof v === "string" && !v.trim()) && !(Array.isArray(v) && !v.length);
const label = (c: RubricCheck) => c.label || `${c.check} ${"path" in c ? c.path : ""}`.trim();

export function gradeByRubric(result: any, rubric: RubricCheck[], facts: Record<string, any> = {}): Grade {
  const checks: RubricResult[] = [];
  if (!result || typeof result !== "object") return { score: 0, checks: [{ check: "shape", pass: false, detail: "no JSON object" }] };
  for (const c of rubric) {
    let pass = true; let detail = "";
    switch (c.check) {
      case "required": { const vs = valuesAt(result, c.path); const parent = valuesAt(result, c.path.replace(/\.[^.]+$/, "")); const missing = parent.length - vs.filter(nonEmpty).length; pass = missing <= 0 && (parent.length === 0 || vs.length > 0); detail = parent.length ? `${parent.length - Math.max(0, missing)}/${parent.length}` : "nothing to check"; break; }
      case "numbers": { const vs = valuesAt(result, c.path); const ok = vs.filter((v) => /\d/.test(String(v ?? ""))).length; pass = ok === vs.length; detail = `${ok}/${vs.length}`; break; }
      case "range": { const vs = valuesAt(result, c.path); const ok = vs.filter((v) => typeof v === "number" && v >= c.min && v <= c.max).length; pass = ok === vs.length; detail = `${ok}/${vs.length} within ${c.min}..${c.max}`; break; }
      case "max_sentences": { const t = String(valuesAt(result, c.path)[0] ?? ""); const n = (t.match(/[.!?](\s|$)/g) || []).length; pass = n <= c.max; detail = `${n} sentence${n === 1 ? "" : "s"}`; break; }
      case "min_items": { const n = valuesAt(result, c.path).length; pass = n >= c.min; detail = `${n} item${n === 1 ? "" : "s"}`; break; }
      case "max_items": { const n = valuesAt(result, c.path).length; pass = n <= c.max; detail = `${n} item${n === 1 ? "" : "s"}`; break; }
      case "enum": { const vs = valuesAt(result, c.path); const ok = vs.filter((v) => c.values.includes(String(v))).length; pass = ok === vs.length; detail = `${ok}/${vs.length}`; break; }
      case "no_destructive_auto": { const bad = valuesAt(result, c.path).filter((p) => p && p.tier === "auto" && DESTRUCTIVE.test(`${p.action ?? ""} ${p.title ?? ""} ${p.action_type ?? ""} ${p.rationale ?? ""}`)); pass = bad.length === 0; detail = bad.length ? bad.map((p) => p.action || p.title).join("; ") : "none"; break; }
      case "covers": { const items: string[] = (facts[c.facts] || []).filter(Boolean).map(String); const text = JSON.stringify(c.path === "*" ? result : valuesAt(result, c.path)).toLowerCase(); const hit = [...new Set(items)].filter((f) => text.includes(f.toLowerCase())).length; const total = new Set(items).size; pass = total === 0 || hit >= Math.ceil(total * c.min_share); detail = `${hit}/${total} mentioned`; break; }
      case "unique": { const items = valuesAt(result, c.path); const seen = new Set<string>(); let dup = 0; for (const it of items) { const k = c.by.map((b) => String(it?.[b] ?? "")).join("|"); if (seen.has(k)) dup++; seen.add(k); } pass = dup === 0; detail = dup ? `${dup} duplicate${dup === 1 ? "" : "s"}` : "none"; break; }
      case "flag_consistent": { const flag = Boolean(valuesAt(result, c.flag)[0]); const lists = c.lists.map((l) => valuesAt(result, l).length); pass = !flag || lists.every((n) => n === 0); detail = flag ? `flag set, lists ${lists.join("/")}` : "flag not set"; break; }
    }
    checks.push({ check: label(c), pass, detail });
  }
  const score = checks.length ? checks.filter((x) => x.pass).length / checks.length : 1;
  return { score: Math.round(score * 100) / 100, checks };
}

/** The critique appended to a retry prompt. */
export function critiqueText(grade: Grade): string {
  const failed = grade.checks.filter((c) => !c.pass);
  if (!failed.length) return "";
  return `## Your previous answer failed these checks; fix them and answer again\n${failed.map((c) => `- ${c.check}: ${c.detail}`).join("\n")}`;
}

/** The failed checks' labels when the score is under the task's bar, else null: the only rubric output a person sees. */
export function belowBar(grade: Grade | null | undefined, bar: number): string[] | null {
  if (!grade || typeof grade.score !== "number" || grade.score >= bar) return null;
  return grade.checks.filter((c) => !c.pass).map((c) => c.check);
}
