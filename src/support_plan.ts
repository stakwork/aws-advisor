/**
 * Which AWS Support plan the account is on, asked of the Support API: DescribeSeverityLevels answers on
 * Developer, Business and Enterprise (the severity codes tell them apart) and fails with
 * SubscriptionRequiredException on Basic. Cached in settings and refreshed with the spend refresh, so a cancelled
 * plan stops being charged in the forecast the same day.
 */
import { DescribeSeverityLevelsCommand, SupportClient } from "@aws-sdk/client-support";
import { getSetting, setSetting } from "./db.js";
import { sdkCredentials } from "./steampipe.js";
import { noteSuccess } from "./permissions.js";

export type SupportPlan = "basic" | "developer" | "business" | "enterprise" | "unknown";
export interface SupportPlanFact { plan: SupportPlan; checked_at: string; detail: string }
const KEY = "fact:support_plan";

export function supportPlanFact(): SupportPlanFact | null {
  const raw = getSetting(KEY); if (!raw) return null;
  try { return JSON.parse(raw) as SupportPlanFact; } catch { return null; }
}

export function planFromSeverityCodes(codes: string[]): SupportPlan {
  const c = new Set(codes.map((x) => x.toLowerCase()));
  if (c.has("critical")) return "enterprise";
  if (c.has("urgent") || c.has("high")) return "business";
  if (c.size > 0) return "developer";
  return "unknown";
}

export async function refreshSupportPlan(onLog: (s: string) => void = () => {}): Promise<SupportPlanFact> {
  let fact: SupportPlanFact;
  try {
    const creds = sdkCredentials();
    const client = new SupportClient({ region: "us-east-1", credentials: creds.provider });
    const r = await client.send(new DescribeSeverityLevelsCommand({}));
    const codes = (r.severityLevels ?? []).map((s) => String(s.code || ""));
    fact = { plan: planFromSeverityCodes(codes), checked_at: new Date().toISOString(), detail: `severity levels ${codes.join(", ") || "none"}` };
    noteSuccess(["support:DescribeSeverityLevels"], "support plan");
  } catch (e: any) {
    const name = String(e?.name || e?.Code || ""); const msg = String(e?.message || e);
    if (/SubscriptionRequired/i.test(name + msg)) fact = { plan: "basic", checked_at: new Date().toISOString(), detail: "the Support API says no subscription: Basic, no charge" };
    else if (/AccessDenied|not authorized|UnrecognizedClient/i.test(name + msg)) fact = { plan: "unknown", checked_at: new Date().toISOString(), detail: "missing IAM permission support:DescribeSeverityLevels; add it to the advisor's policy" };
    else fact = { plan: "unknown", checked_at: new Date().toISOString(), detail: msg.slice(0, 200) };
  }
  setSetting(KEY, JSON.stringify(fact));
  onLog(`support plan: ${fact.plan} (${fact.detail})`);
  return fact;
}
