import type { ComponentProps } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

/**
 * The agent's replies as rendered Markdown (GitHub flavour: fenced code, lists, tables, links, strikethrough).
 * react-markdown builds React elements from the text, never HTML strings, so nothing the agent writes reaches the
 * page as markup; raw HTML in the text is shown as text. Links open in a new tab. Elements carry the same zinc
 * palette and sizes as the rest of the app (no typography plugin), and fenced blocks look like the step commands.
 */
export function Markdown({ text }: { text: string }) {
  return (
    <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>{text || ""}</ReactMarkdown>
  );
}

const CODE = "rounded bg-zinc-950 px-1 py-0.5 font-mono text-[11px] text-zinc-200";

const components: ComponentProps<typeof ReactMarkdown>["components"] = {
  p: ({ children }) => <p className="my-2 first:mt-0 last:mb-0 leading-relaxed">{children}</p>,
  h1: ({ children }) => <h3 className="mt-3 mb-1 text-sm font-semibold text-zinc-100 first:mt-0">{children}</h3>,
  h2: ({ children }) => <h3 className="mt-3 mb-1 text-sm font-semibold text-zinc-100 first:mt-0">{children}</h3>,
  h3: ({ children }) => <h4 className="mt-3 mb-1 text-[13px] font-semibold text-zinc-100 first:mt-0">{children}</h4>,
  h4: ({ children }) => <h5 className="mt-2 mb-1 text-[13px] font-medium text-zinc-200 first:mt-0">{children}</h5>,
  h5: ({ children }) => <h6 className="mt-2 mb-1 text-xs font-medium uppercase tracking-wide text-zinc-400 first:mt-0">{children}</h6>,
  h6: ({ children }) => <h6 className="mt-2 mb-1 text-xs font-medium uppercase tracking-wide text-zinc-400 first:mt-0">{children}</h6>,
  ul: ({ children }) => <ul className="my-2 list-disc space-y-1 pl-5 first:mt-0 last:mb-0">{children}</ul>,
  ol: ({ children }) => <ol className="my-2 list-decimal space-y-1 pl-5 first:mt-0 last:mb-0">{children}</ol>,
  li: ({ children }) => <li className="leading-relaxed [&>p]:my-0">{children}</li>,
  strong: ({ children }) => <strong className="font-semibold text-zinc-100">{children}</strong>,
  em: ({ children }) => <em className="italic">{children}</em>,
  del: ({ children }) => <del className="text-zinc-500">{children}</del>,
  hr: () => <hr className="my-3 border-zinc-800" />,
  blockquote: ({ children }) => <blockquote className="my-2 border-l-2 border-zinc-700 pl-3 text-zinc-400 [&>p]:my-1">{children}</blockquote>,
  a: ({ href, children }) => <a href={href} target="_blank" rel="noreferrer" className="text-sky-300 underline decoration-sky-300/40 hover:decoration-sky-300">{children}</a>,
  // A fenced block arrives as <pre><code class="language-x">; an inline span as a bare <code>.
  pre: ({ children }) => <pre className="my-2 overflow-x-auto whitespace-pre-wrap rounded bg-zinc-950 p-2 font-mono text-[11px] leading-5 text-zinc-200 first:mt-0 last:mb-0 [&>code]:bg-transparent [&>code]:p-0">{children}</pre>,
  code: ({ children, className }) => <code className={`${CODE} ${className ?? ""}`}>{children}</code>,
  table: ({ children }) => <div className="my-2 overflow-x-auto first:mt-0 last:mb-0"><table className="w-full border-collapse text-xs">{children}</table></div>,
  thead: ({ children }) => <thead className="text-left text-[11px] uppercase tracking-wide text-zinc-500">{children}</thead>,
  th: ({ children }) => <th className="border-b border-zinc-800 px-2 py-1 font-medium">{children}</th>,
  td: ({ children }) => <td className="border-b border-zinc-800/60 px-2 py-1 align-top">{children}</td>,
  // The agent's text never carries images; an image tag becomes its alt text and link rather than a fetch.
  img: ({ alt, src }) => <a href={typeof src === "string" ? src : undefined} target="_blank" rel="noreferrer" className="text-sky-300 underline">{alt || "image"}</a>,
};
