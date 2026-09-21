import express from "express";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { config } from "./config.js";
import { authMiddleware, isAuthenticated, signToken } from "./auth.js";
import { api } from "./routes/api.js";
import { knowledge } from "./routes/knowledge.js";
import { graph } from "./routes/graph.js";
import { prompts } from "./routes/prompts.js";
import { browse } from "./routes/browse.js";
import { mountMcp } from "./mcp.js";
import { startScheduler } from "./scheduler.js";
import { loadTasks } from "./tasks.js";
loadTasks();

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(express.json({ limit: "5mb" }));

app.get("/health", (_req, res) => res.json({ ok: true }));
app.get("/busy", async (_req, res) => {
  const { isBusy } = await import("./collector.js");
  res.json({ busy: isBusy() });
});

// Paginated browsing routes (alerts, findings, recommendations, spend) take precedence for the paths they define.
import { callback } from "./routes/callback.js";

// Last resort: a background job's stray rejection or a library's unhandled error event must not take the daemon
// down with every scheduler, watcher and probe in it. Log it loudly; the job that failed reports its own error.
process.on("unhandledRejection", (reason) => console.error(`[fatal-avoided] unhandled rejection: ${(reason as any)?.stack || reason}`));
process.on("uncaughtException", (err) => console.error(`[fatal-avoided] uncaught exception: ${err?.stack || err}`));

app.use("/api", callback); // the agent webhook: before every authenticated router
app.use("/api", browse);
app.use("/api", knowledge);
app.use("/api", graph);
app.use("/api", prompts);
app.use("/api", api);
mountMcp(app, "/mcp");

// The README as plain text, so the Settings page can point at its "IAM permissions" section.
app.get("/readme", authMiddleware, (_req, res) => {
  const readme = path.resolve(__dirname, "../README.md");
  if (!fs.existsSync(readme)) return res.status(404).type("text").send("README.md not found");
  res.type("text/plain; charset=utf-8").send(fs.readFileSync(readme, "utf8"));
});

// Built UI (ui/dist). The app shell is public (static JS, no data); every /api route stays gated. A request that
// arrives signed in (/?token=<API_TOKEN>, or a valid session) gets a 30-day session token injected, which the
// browser keeps; anyone else gets the shell with a sign-in box.
const dist = path.resolve(__dirname, "../ui/dist");
if (fs.existsSync(dist)) {
  app.use("/assets", express.static(path.join(dist, "assets")));
  app.get(["/", "/index.html", "/{*splat}"], (req, res) => {
    const session = isAuthenticated(req) ? signToken("30d") : "";
    const html = fs.readFileSync(path.join(dist, "index.html"), "utf8")
      .replace("</head>", `<script>window.__AUTH_TOKEN__=${JSON.stringify(session)}</script></head>`);
    res.set("cache-control", "no-store").type("html").send(html);
  });
} else {
  app.get("/", (_req, res) => res.type("text").send("aws-advisor API is up. Build the UI with `npm --prefix ui run build` or run `npm --prefix ui run dev`."));
}

const onListen = () => {
  console.log(`aws-advisor listening on ${config.bindAddr || "all interfaces"}:${config.port}, public URL ${config.publicUrl} (schema "${config.schema}", mod ${config.modDir}); MCP fact server at ${config.publicUrl}/mcp`);
  startScheduler();
  // the fleet's latest probes, judged now: a disk that filled while the advisor was down alerts at once
  import("./disk_alerts.js").then((m) => { const r = m.checkAllDiskLevels(); if (r.raised) console.log(`[disk] ${r.raised} disk alert(s) from the latest probes of ${r.instances} instances`); }).catch((e) => console.error(`[disk] startup check failed: ${e?.message || e}`));
  import("./host_alerts.js").then((m) => { const r = m.checkAllHostLevels(); if (r.raised) console.log(`[host] ${r.raised} host alert(s) from the latest probes of ${r.instances} instances`); }).catch((e) => console.error(`[host] startup check failed: ${e?.message || e}`));
};
if (config.bindAddr) app.listen(config.port, config.bindAddr, onListen); else app.listen(config.port, onListen);
