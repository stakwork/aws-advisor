import { useEffect, useRef, useState, type ReactNode } from "react";

export const Card = ({ title, children, className = "" }: { title?: ReactNode; children: ReactNode; className?: string }) => (
  <section className={`rounded-lg border border-zinc-800 bg-zinc-900/60 p-4 ${className}`}>
    {title && <h3 className="mb-3 text-sm font-medium text-zinc-400">{title}</h3>}
    {children}
  </section>
);

export const Stat = ({ label, value, hint }: { label: string; value: ReactNode; hint?: ReactNode }) => (
  <div className="rounded-lg border border-zinc-800 bg-zinc-900/60 p-4">
    <div className="text-xs uppercase tracking-wide text-zinc-500">{label}</div>
    <div className="mt-1 text-2xl font-semibold text-zinc-100">{value}</div>
    {hint && <div className="mt-1 text-xs text-zinc-500">{hint}</div>}
  </div>
);

const tone: Record<string, string> = {
  open: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  approved: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  rejected: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  snoozed: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  resolved: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  done: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  completed: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  running: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  failed: "bg-red-500/15 text-red-300 border-red-500/30",
  alarm: "bg-red-500/15 text-red-300 border-red-500/30",
  warning: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  info: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
  auto: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  approve: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  report: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
  rules: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
  agent: "bg-violet-500/15 text-violet-300 border-violet-500/30",
  // inventory: instance states, SSM ping status, resources no longer seen
  stopped: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  terminated: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  available: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  Online: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  ConnectionLost: "bg-red-500/15 text-red-300 border-red-500/30",
  Inactive: "bg-red-500/15 text-red-300 border-red-500/30",
  unmanaged: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
  gone: "bg-zinc-500/10 text-zinc-500 border-zinc-700",
  // route 53: where a record leads
  linked: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  unmatched: "bg-red-500/15 text-red-300 border-red-500/30",
  external: "bg-zinc-500/15 text-zinc-300 border-zinc-500/30",
  none: "bg-zinc-500/10 text-zinc-500 border-zinc-700",
  alias: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  private: "bg-violet-500/15 text-violet-300 border-violet-500/30",
  // permission check
  ok: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  missing: "bg-red-500/15 text-red-300 border-red-500/30",
  error: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  skipped: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

export const Badge = ({ children }: { children: string }) => (
  <span className={`inline-block rounded border px-1.5 py-0.5 text-[11px] font-medium ${tone[children] || tone.info}`}>{children}</span>
);

export const Button = ({ children, variant = "primary", ...rest }: { children: ReactNode; variant?: "primary" | "ghost" | "danger" } & React.ButtonHTMLAttributes<HTMLButtonElement>) => {
  const cls = {
    primary: "bg-zinc-100 text-zinc-900 hover:bg-white disabled:bg-zinc-600",
    ghost: "border border-zinc-700 text-zinc-200 hover:bg-zinc-800",
    danger: "bg-red-600 text-white hover:bg-red-500",
  }[variant];
  return <button {...rest} className={`rounded px-3 py-1.5 text-sm font-medium disabled:cursor-not-allowed disabled:opacity-60 ${cls} ${rest.className || ""}`}>{children}</button>;
};

export const Empty = ({ children }: { children: ReactNode }) => (
  <div className="rounded-lg border border-dashed border-zinc-800 p-8 text-center text-sm text-zinc-500">{children}</div>
);

export const Th = ({ children, className = "" }: { children?: ReactNode; className?: string }) => (
  <th className={`px-3 py-2 text-left text-xs font-medium uppercase tracking-wide text-zinc-500 ${className}`}>{children}</th>
);
export const Td = ({ children, className = "" }: { children?: ReactNode; className?: string }) => (
  <td className={`px-3 py-2 align-top text-sm ${className}`}>{children}</td>
);

export const copyText = async (text: string) => {
  try { await navigator.clipboard.writeText(text); return true; }
  catch {
    const ta = document.createElement("textarea"); ta.value = text; document.body.appendChild(ta); ta.select();
    try { return document.execCommand("copy"); } finally { ta.remove(); }
  }
};

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return <Button type="button" variant="ghost" onClick={async () => { if (await copyText(text)) { setDone(true); setTimeout(() => setDone(false), 1500); } }}>{done ? "Copied" : label}</Button>;
}

export const Code = ({ children, className = "" }: { children: string; className?: string }) => (
  <pre className={`max-h-96 overflow-auto whitespace-pre-wrap rounded bg-zinc-950 p-3 font-mono text-xs leading-5 text-zinc-300 ${className}`}>{children}</pre>
);

/** Prev / next over a server-paginated list: "page X of Y · N total". Hidden when everything fits on one page. */
export const Pager = ({ page, pageSize, total, onPage, className = "", always = false }: { page: number; pageSize: number; total: number; onPage: (page: number) => void; className?: string; always?: boolean }) => {
  const pages = Math.max(1, Math.ceil(total / Math.max(1, pageSize)));
  if (pages <= 1 && !always) return null;
  return (
    <div className={`flex items-center justify-between gap-2 text-xs text-zinc-500 ${className}`}>
      <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => onPage(page - 1)} disabled={page <= 1}>Prev</Button>
      <span>page {page} of {pages} · {total} total</span>
      <Button variant="ghost" className="!px-2 !py-1 !text-xs" onClick={() => onPage(page + 1)} disabled={page >= pages}>Next</Button>
    </div>
  );
};

/**
 * The detail that opens under the row you clicked, full width, inside a colSpan cell. Clicking the row again (or
 * "close") closes it. Scrolls only when its top is out of view (above, or in the bottom third): a tall detail must
 * never be bottom-aligned by "nearest", which pushes the row you clicked off the screen.
 */
export function DetailCell({ id, onClose, title = "Detail", children }: { id: string; onClose: () => void; title?: ReactNode; children: ReactNode }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current; if (!el) return;
    const top = el.getBoundingClientRect().top;
    if (top < 0 || top > window.innerHeight * 0.66) el.scrollIntoView({ block: "start", behavior: "smooth" });
  }, [id]);
  return (
    <div ref={ref} className="min-w-0 break-words" onClick={(e) => e.stopPropagation()}>
      <Card title={<span className="flex items-center justify-between">{title} <button className="text-zinc-500" onClick={onClose}>close</button></span>}>
        {children}
      </Card>
    </div>
  );
}
