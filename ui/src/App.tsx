import { useEffect, useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { Activity, Bell, LayoutDashboard, ListChecks, Search, Server, Settings as SettingsIcon, BookOpen, Receipt } from "lucide-react";
import { api, signIn, token } from "./api";
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

const nav = [
  { to: "/", label: "Overview", icon: LayoutDashboard },
  { to: "/runs", label: "Runs", icon: Activity },
  { to: "/alerts", label: "Alerts", icon: Bell },
  { to: "/findings", label: "Findings", icon: Search },
  { to: "/inventory", label: "Inventory", icon: Server },
  { to: "/recommendations", label: "Recommendations", icon: ListChecks },
  { to: "/bill", label: "Bill", icon: Receipt },
  { to: "/knowledge", label: "Knowledge", icon: BookOpen },
  { to: "/settings", label: "Settings", icon: SettingsIcon },
];

/** Shown instead of the app when the browser has no session: the API token from .env signs you in for 30 days. */
function SignIn({ reason }: { reason: string }) {
  const [t, setT] = useState("");
  return (
    <div className="flex min-h-screen items-center justify-center bg-zinc-950 p-6 text-zinc-200">
      <form onSubmit={(e) => { e.preventDefault(); if (t.trim()) signIn(t); }} className="w-full max-w-md space-y-3 rounded-lg border border-zinc-800 bg-zinc-900 p-6">
        <h1 className="text-lg font-semibold text-zinc-100">AWS Advisor</h1>
        <p className="text-sm text-zinc-400">{reason} Paste the <span className="font-mono text-xs">API_TOKEN</span> from the advisor's <span className="font-mono text-xs">.env</span>; this browser then keeps a 30-day session.</p>
        <input autoFocus type="password" value={t} onChange={(e) => setT(e.target.value)} placeholder="API_TOKEN" className="w-full" />
        <button type="submit" className="rounded bg-zinc-100 px-3 py-1.5 text-sm font-medium text-zinc-900">Sign in</button>
      </form>
    </div>
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
  const [aws, setAws] = useState<any>(null);
  useEffect(() => { api("/settings").then((s) => setAws(s.aws)).catch(() => setAws(null)); }, []);
  return (
    <div className="flex min-h-screen">
      <aside className="w-56 shrink-0 border-r border-zinc-800 bg-zinc-950 p-4">
        <div className="mb-6 text-lg font-semibold text-zinc-100">AWS Advisor</div>
        <nav className="space-y-1">
          {nav.map(({ to, label, icon: Icon }) => (
            <NavLink key={to} to={to} end={to === "/"} className={({ isActive }) => `flex items-center gap-2 rounded px-2 py-1.5 text-sm ${isActive ? "bg-zinc-800 text-zinc-100" : "text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200"}`}>
              <Icon size={16} /> {label}
            </NavLink>
          ))}
        </nav>
        <div className="mt-8 text-xs text-zinc-500">
          {aws?.configured ? (
            <>
              <div className="text-zinc-400">Account {aws.accountId || "(not tested yet)"}</div>
              <div title={aws.label}>{aws.mode === "profile" ? `profile ${aws.profile}` : aws.mode === "chain" ? "instance / default chain" : `key ${aws.accessKeyMasked || ""}`}{aws.temporary ? " (expires)" : ""}</div>
              {aws.roleArn && <div className="truncate" title={aws.roleArn}>role {String(aws.roleArn).split("/").pop()}</div>}
            </>
          ) : (
            <NavLink to="/settings" className="text-amber-300">No AWS credentials yet →</NavLink>
          )}
        </div>
      </aside>
      <main className="min-w-0 flex-1 p-6">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/runs" element={<Runs />} />
          <Route path="/runs/:id" element={<RunDetail />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="/findings" element={<Findings />} />
          <Route path="/inventory" element={<Inventory />} />
          <Route path="/recommendations" element={<Recommendations />} />
          <Route path="/knowledge" element={<Knowledge />} />
          <Route path="/bill" element={<Bill />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  );
}
