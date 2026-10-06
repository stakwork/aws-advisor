import { useEffect, useState } from "react";
import { NavLink, Route, Routes, useNavigate } from "react-router-dom";
import { ConnectionBanner } from "./components/connection";
import { Activity, Bell, LayoutDashboard, ListChecks, Search, Server, Settings as SettingsIcon, BookOpen, Receipt, History, MessageSquare, Wand2, ShieldAlert, Network as NetworkIcon } from "lucide-react";
import { api, currentScope, onScopeChange, setScope, signIn, token } from "./api";
import { useScopeInfo, type Capability } from "./scope";
import { Gate } from "./components/gate";
import Overview from "./pages/Overview";
import Runs from "./pages/Runs";
import RunDetail from "./pages/RunDetail";
import Alerts from "./pages/Alerts";
import Findings from "./pages/Findings";
import Inventory from "./pages/Inventory";
import Recommendations from "./pages/Recommendations";
import Settings from "./pages/Settings";
import Knowledge from "./pages/Knowledge";
import Bill from "./pages/Bill";
import Changes from "./pages/Changes";
import Chat from "./pages/Chat";
import Actions from "./pages/Actions";
import Security from "./pages/Security";
import Network from "./pages/Network";

/** The pages, each with the capability it needs; a page the scoped provider cannot serve is hidden here and gated on its route. */
const nav: { to: string; label: string; icon: any; need?: Capability }[] = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/runs", label: "Runs", icon: Activity, need: "cost" },
  { to: "/alerts", label: "Alerts", icon: Bell, need: "alerts" },
  { to: "/findings", label: "Findings", icon: Search, need: "findings" },
  { to: "/security", label: "Security", icon: ShieldAlert, need: "compliance" },
  { to: "/inventory", label: "Inventory", icon: Server },
  { to: "/network", label: "Network", icon: NetworkIcon, need: "network" },
  { to: "/recommendations", label: "Recommendations", icon: ListChecks, need: "findings" },
  { to: "/changes", label: "Changes", icon: History, need: "changes" },
  { to: "/bill", label: "This month", icon: Receipt, need: "bill" },
  { to: "/knowledge", label: "Knowledge", icon: BookOpen },
  { to: "/actions", label: "Auto-actions", icon: Wand2, need: "executor" },
  { to: "/chat", label: "Chat", icon: MessageSquare },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

/** Shown instead of the app when the browser has no session: the API token from .env signs you in for 30 days. */
function SignIn({ reason }: { reason: string }) {
  const [t, setT] = useState("");
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-6 text-zinc-200">
      <form onSubmit={(e) => { e.preventDefault(); if (t.trim()) signIn(t); }} className="w-full max-w-md space-y-3 rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <h1 className="text-lg font-semibold text-zinc-100">Cloud Advisor</h1>
        <p className="text-sm text-zinc-400">{reason} Paste the <span className="font-mono text-xs">API_TOKEN</span> from the advisor's <span className="font-mono text-xs">.env</span>; this browser then keeps a 30-day session.</p>
        <input autoFocus type="password" value={t} onChange={(e) => setT(e.target.value)} placeholder="API_TOKEN" className="w-full" />
        <button type="submit" className="rounded bg-zinc-100 px-3 py-1.5 text-sm font-medium text-zinc-900">Sign in</button>
      </form>
    </div>
  );
}

/** The account the pages look at: every account, or one; the choice is kept in this browser and sent on every read. */
function ScopePicker() {
  const [accounts, setAccounts] = useState<{ provider: string; id: string; name: string; parent_id: string | null }[]>([]);
  const [scope, setScopeState] = useState(currentScope());
  const navigate = useNavigate();
  useEffect(() => { api("/accounts").then((d) => setAccounts(d.records || [])).catch(() => setAccounts([])); return onScopeChange(setScopeState); }, []);
  const change = (id: string) => { setScope(id, accounts.find((a) => a.id === id)?.provider ?? null); navigate(0); };
  const current = accounts.find((a) => a.id === scope);
  return (
    <label className="block">
      <span className="text-zinc-500">Looking at</span>
      <select value={accounts.some((a) => a.id === scope) ? scope : "all"} onChange={(e) => change(e.target.value)} className="mt-0.5 w-full !py-1 !text-xs" title="Which account the pages show; every list that knows its account narrows to it">
        <option value="all">All accounts{accounts.length ? ` (${accounts.length})` : ""}</option>
        {accounts.map((a) => <option key={a.id} value={a.id}>{a.provider.toUpperCase()} · {a.name} · {a.id}</option>)}
      </select>
      {current && <div className="mt-1 text-zinc-600">{current.parent_id ? `member of ${current.parent_id}` : "parent account"}</div>}
    </label>
  );
}

export default function App() {
  const [unauthorized, setUnauthorized] = useState(false);
  useEffect(() => {
    const onUnauthorized = () => setUnauthorized(true);
    window.addEventListener("advisor:unauthorized", onUnauthorized);
    // a used ?token= must not stay in the address bar (bookmarks, screenshots, referrers)
    const u = new URL(window.location.href);
    if (u.searchParams.has("token")) { u.searchParams.delete("token"); window.history.replaceState(null, "", u.toString()); }
    return () => window.removeEventListener("advisor:unauthorized", onUnauthorized);
  }, []);
  if (unauthorized) return <SignIn reason="The session expired or the token was wrong." />;
  if (!token() && window.__AUTH_TOKEN__ === "") return <SignIn reason="Not signed in." />;
  return <AppShell />;
}

function AppShell() {
  const scopeInfo = useScopeInfo();
  const [aws, setAws] = useState<any>(null);
  useEffect(() => { api("/settings").then((s) => setAws(s.aws)).catch(() => setAws(null)); }, []);
  return (
    <div className="flex min-h-screen">
      <aside className="w-56 shrink-0 border-r border-zinc-800 bg-zinc-950 p-4">
        <div className="mb-6 text-lg font-semibold text-zinc-100">Cloud Advisor</div>
        <nav className="space-y-1">
          {nav.filter((n) => !n.need || scopeInfo.has(n.need)).map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => `flex items-center gap-2 rounded px-2 py-1.5 text-sm ${isActive ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"}`}>
              <Icon size={16} /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-8 text-xs text-zinc-500">
          {scopeInfo.providers.some((p) => p.configured) || aws?.configured ? <ScopePicker /> : null}
          {aws?.configured ? (
            <>
              <div title={aws.label}>{aws.mode === "profile" ? `profile ${aws.profile}` : aws.mode === "chain" ? "instance / default chain" : `key ${aws.accessKeyMasked || ""}`}{aws.temporary ? " (expires)" : ""}</div>
              {aws.roleArn && <div className="truncate" title={aws.roleArn}>role {String(aws.roleArn).split("/").pop()}</div>}
            </>
          ) : !scopeInfo.providers.some((p) => p.configured) ? (
            <NavLink to="/settings?tab=accounts" className="text-amber-300">No account yet →</NavLink>
          ) : null}
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-6">
        <ConnectionBanner />
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/runs" element={<Gate need="cost"><Runs /></Gate>} />
          <Route path="/runs/:id" element={<Gate need="cost"><RunDetail /></Gate>} />
          <Route path="/alerts" element={<Gate need="alerts"><Alerts /></Gate>} />
          <Route path="/findings" element={<Gate need="findings"><Findings /></Gate>} />
          <Route path="/security" element={<Gate need="compliance"><Security /></Gate>} />
          <Route path="/inventory" element={<Inventory />} />
          <Route path="/network" element={<Gate need="network"><Network /></Gate>} />
          <Route path="/recommendations" element={<Gate need="findings"><Recommendations /></Gate>} />
          <Route path="/knowledge" element={<Knowledge />} />
          <Route path="/bill" element={<Gate need="bill"><Bill /></Gate>} />
          <Route path="/changes" element={<Gate need="changes"><Changes /></Gate>} />
          <Route path="/actions" element={<Gate need="executor"><Actions /></Gate>} />
          <Route path="/chat" element={<Chat />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
