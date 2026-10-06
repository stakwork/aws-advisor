import { config as loadDotenv } from "dotenv";

/**
 * True under node's test runner however a test was started (npm test, `node --test file`, `tsx --test file`, or a test
 * file run directly). Tests then never read .env: it points at the real data/advisor.db, the swarm's Neo4j, repo2graph
 * and the agent key, and a test file run on its own once wrote its fixtures (an i-ports instance, Vercel projects) into
 * the real database and graph.
 */
export const underTest = process.env.NODE_ENV === "test" || Boolean(process.env.NODE_TEST_CONTEXT)
  || process.execArgv.some((a) => a === "--test" || a.startsWith("--test-"))
  || /\.test\.[cm]?[jt]s$/.test(process.argv[1] ?? "");

if (!underTest) loadDotenv();
