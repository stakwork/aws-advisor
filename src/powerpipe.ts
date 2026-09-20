import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { config } from "./config.js";

export const ALL_BENCHMARKS = [
  "apigateway", "cloudfront", "cloudtrail", "cloudwatch", "cost_explorer", "dynamodb", "ebs", "ec2", "ecr", "ecs",
  "eks", "elasticache", "emr", "lambda", "network", "rds", "redshift", "route53", "s3", "secretsmanager",
];
/** cloudwatch (hundreds of thousands of log-stream rows), route53 and apigateway are opinion checks, not cost. */
export const DEFAULT_BENCHMARKS = ALL_BENCHMARKS.filter((b) => !["cloudwatch", "route53", "apigateway"].includes(b));

export interface ParsedFinding {
  benchmark: string;
  controlId: string;
  controlTitle: string;
  status: string;
  resource: string;
  reason: string;
  dimensions: Record<string, string>;
}

/** A control that could not run (run_error), or whose results carry status "error" (one entry per control, first reason kept). */
export interface ControlError {
  controlId: string;
  controlTitle: string;
  /** "run_error" when the control itself failed, "error" when individual results did. */
  kind: "run_error" | "error";
  message: string;
  count: number;
}

export interface ParsedBenchmark { findings: ParsedFinding[]; errors: ControlError[] }

export function runBenchmark(name: string, onLog: (line: string) => void): Promise<ParsedBenchmark> {
  return new Promise((resolve, reject) => {
    const out = path.join(os.tmpdir(), `advisor-${name}-${Date.now()}.json`);
    const args = [
      "benchmark", "run", `aws_thrifty.benchmark.${name}`,
      "--output", "none", "--export", out, "--progress=false",
      "--search-path-prefix", config.schema,
      "--mod-location", config.modDir,
    ];
    const env: NodeJS.ProcessEnv = { ...process.env, POWERPIPE_UPDATE_CHECK: "false" };
    if (config.steampipeUrlExplicit) env.POWERPIPE_DATABASE = config.steampipeUrl; // the --database flag is deprecated
    const child = spawn(config.powerpipeBin, args, { env });
    let stderr = "";
    child.stdout.on("data", (d) => onLog(String(d).trimEnd()));
    child.stderr.on("data", (d) => {
      const s = String(d);
      stderr += s;
      if (!/^Warning/.test(s)) onLog(s.trimEnd());
    });
    child.on("error", reject);
    child.on("close", (code) => {
      try {
        if (!fs.existsSync(out)) {
          reject(new Error(`powerpipe exited with code ${code}: ${stderr.trim().slice(0, 400)}`));
          return;
        }
        const json = JSON.parse(fs.readFileSync(out, "utf8"));
        fs.unlinkSync(out);
        resolve(parseExport(name, json));
      } catch (e) {
        reject(e);
      }
    });
  });
}

export function parseExport(benchmark: string, root: any): ParsedBenchmark {
  const out: ParsedFinding[] = [];
  const errors: ControlError[] = [];
  const walk = (node: any) => {
    for (const g of node.groups || []) walk(g);
    for (const c of node.controls || []) {
      // run_status 8 = error in Powerpipe's export; run_error carries the message (e.g. an AccessDenied from Steampipe).
      if (c.run_error || c.run_status === 8) errors.push({ controlId: c.control_id, controlTitle: c.title, kind: "run_error", message: String(c.run_error || "control run failed"), count: 1 });
      const errored = (c.results || []).filter((r: any) => r.status === "error");
      if (errored.length) errors.push({ controlId: c.control_id, controlTitle: c.title, kind: "error", message: String(errored[0].reason || ""), count: errored.length });
      for (const r of c.results || []) {
        const dimensions: Record<string, string> = {};
        for (const d of r.dimensions || []) dimensions[d.key] = d.value;
        out.push({
          benchmark,
          controlId: c.control_id,
          controlTitle: c.title,
          status: r.status,
          resource: r.resource,
          reason: r.reason,
          dimensions,
        });
      }
    }
  };
  walk(root);
  return { findings: out, errors };
}
