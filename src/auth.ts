import type { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";
import { timingSafeEqual } from "node:crypto";
import { config } from "./config.js";

/** Constant-time string equality, so a shared secret cannot be guessed byte by byte from response times. */
export function safeEqual(a: unknown, b: unknown): boolean {
  if (typeof a !== "string" || typeof b !== "string" || !a || !b) return false;
  const x = Buffer.from(a); const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

let warned = false;

/** Same posture as repo2graph: x-api-token, Bearer JWT minted from it, or ?token= for SSE/iframes. Unset = open. */
/** Does this request carry a valid credential: x-api-token, Bearer JWT, the raw token or a JWT in ?token=. */
export function isAuthenticated(req: Request): boolean {
  if (!config.apiToken) return true;
  if (safeEqual(req.header("x-api-token"), config.apiToken)) return true;
  const bearer = req.header("authorization")?.replace(/^Bearer\s+/i, "");
  const candidate = bearer || (typeof req.query.token === "string" ? req.query.token : "");
  if (!candidate) return false;
  // the raw API_TOKEN in ?token= is how a person signs in from a browser: the index page then hands out a session JWT
  if (safeEqual(candidate, config.apiToken)) return true;
  try { jwt.verify(candidate, config.apiToken); return true; } catch { return false; }
}

export function authMiddleware(req: Request, res: Response, next: NextFunction) {
  if (!config.apiToken && !warned) { console.warn("API_TOKEN is not set; the API is open. Fine for local dev only."); warned = true; }
  if (isAuthenticated(req)) return next();
  res.status(401).json({ error: "unauthorized" });
}

export function signToken(expiresIn = "1h"): string {
  if (!config.apiToken) return "";
  return jwt.sign({ app: "aws-advisor" }, config.apiToken, { expiresIn: expiresIn as any });
}
