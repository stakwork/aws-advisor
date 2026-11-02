import assert from "node:assert/strict";
import { test } from "node:test";

// Pure-function coverage for the image -> repository (src/graph_containers.ts) and repository -> code graph
// (src/graph_repositories.ts) rows, with a stub resolver in place of src/function_facts.ts repoIdResolver (which reads
// github_repos). Imported lazily, as src/__tests__/graph_functions.test.ts does, so a crash in this environment's
// better-sqlite3 / Neo4j-driver teardown cannot take down the tests that do not need them.

const resolve = (raw: string | null): string | null => {
  if (!raw) return null;
  const m = /^(?:https?:\/\/github\.com\/|git@github\.com:)?([A-Za-z0-9-]+)\/([A-Za-z0-9._-]+?)(\.git)?\/?$/.exec(raw);
  return m && !/gitlab|bitbucket/i.test(raw) ? `github:${m[1]}/${m[2]}` : null;
};

test("imageRepositoryRows: one edge per image whose source label resolves, on an existing node's casing, stubs only for unknown repositories", async () => {
  const { imageRepositoryRows } = await import("../graph_containers.js");
  const rows = [
    { image_node: "image:registry.example.com/web:1.2", source_url: "https://github.com/Example/web", revision: null },
    { image_node: "image:registry.example.com/web:1.2", source_url: "https://github.com/Example/web", revision: "abc123" },
    { image_node: "image:registry.example.com/api:3", source_url: "git@github.com:example/api.git", revision: "def456" },
    { image_node: "image:nginx:1.27", source_url: null, revision: null },
    { image_node: "image:gitlab.example.com/x:1", source_url: "https://gitlab.com/example/x", revision: "f" },
    { image_node: null, source_url: "https://github.com/example/orphan", revision: null },
  ];
  const { nodes, edges } = imageRepositoryRows(rows, resolve, ["github:example/web"]);
  assert.deepEqual(edges.sort((a, b) => a.image_node.localeCompare(b.image_node)), [
    { image_node: "image:registry.example.com/api:3", repo_id: "github:example/api", source_url: "git@github.com:example/api.git", revision: "def456" },
    { image_node: "image:registry.example.com/web:1.2", repo_id: "github:example/web", source_url: "https://github.com/Example/web", revision: "abc123" },
  ]);
  assert.deepEqual(nodes, [{ id: "github:example/api", native_id: "example/api", name: "api" }]);
  assert.deepEqual(imageRepositoryRows([], resolve, []), { nodes: [], edges: [] });
});

test("codeRepositoryRows: a Repository joins by its source_link, by its name only when it has no link, case-insensitively; another host never falls back to the name", async () => {
  const { codeRepositoryRows } = await import("../graph_repositories.js");
  const code = [
    { name: "example/web", source_link: "https://github.com/Example/web.git" },
    { name: "example/api", source_link: null },
    { name: "example/mirror", source_link: "https://gitlab.com/example/mirror" },
    { name: null, source_link: null },
  ];
  const rows = codeRepositoryRows(["github:example/web", "github:Example/api", "github:example/mirror", "github:example/none"], code, resolve);
  assert.deepEqual(rows, [
    { advisor_id: "github:example/web", name: "example/web", source_link: "https://github.com/Example/web.git", via: "source_link", matched: "github:Example/web" },
    { advisor_id: "github:Example/api", name: "example/api", source_link: null, via: "name", matched: "github:example/api" },
  ]);
  assert.deepEqual(codeRepositoryRows([], code, resolve), []);
});
