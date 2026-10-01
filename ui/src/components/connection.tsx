import { useEffect, useState } from "react";
import { connectionState, onConnectionChange, retryNow, type ConnectionState } from "../api";

/**
 * The connection banner (src api.ts fetchWithRetry): while a read is being retried or the browser is offline, a bar
 * at the top says so and counts down to the next try; when everything gets through again it says so for a moment.
 */
export function ConnectionBanner() {
  const [s, setS] = useState<ConnectionState>(connectionState());
  const [now, setNow] = useState(Date.now());
  useEffect(() => onConnectionChange(setS), []);
  useEffect(() => { if (!s.trouble && !s.recovered_at) return; const t = setInterval(() => setNow(Date.now()), 500); return () => clearInterval(t); }, [s.trouble, s.recovered_at]);
  const justRecovered = !s.trouble && s.recovered_at != null && now - s.recovered_at < 2500;
  if (!s.trouble && !justRecovered) return null;
  if (justRecovered) return <div role="status" className="sticky top-0 z-50 -mx-6 -mt-6 mb-4 border-b border-emerald-900/60 bg-emerald-950/80 px-6 py-1.5 text-sm text-emerald-200">Connection is back.</div>;
  const secs = s.next_retry_at ? Math.max(0, Math.ceil((s.next_retry_at - now) / 1000)) : null;
  return (
    <div role="status" aria-live="polite" className="sticky top-0 z-50 -mx-6 -mt-6 mb-4 flex flex-wrap items-center justify-between gap-2 border-b border-amber-900/60 bg-amber-950/90 px-6 py-1.5 text-sm text-amber-100">
      <span className="flex items-center gap-2">
        <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-amber-400" aria-hidden />
        {s.offline ? "You are offline. Waiting for the connection to come back; pages will load on their own."
          : <>The connection to the advisor is unstable. Retrying{s.attempt > 1 ? ` (attempt ${s.attempt})` : ""}{secs != null ? `, next try in ${secs}s` : ""}…</>}
      </span>
      {!s.offline && <button onClick={retryNow} className="rounded border border-amber-700/70 px-2 py-0.5 text-xs text-amber-100 hover:bg-amber-900/60">Retry now</button>}
    </div>
  );
}
