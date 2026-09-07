import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const source = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const response = (status, body) => new Response(JSON.stringify(body), {
  status, headers: { "content-type": "application/json" },
});

function client(fetch) {
  const exports = {};
  vm.runInNewContext(compiled, { exports, fetch, DOMException, AbortController, structuredClone });
  return exports.api;
}

test("authenticated 401 ends the session once and clears its token", async () => {
  const api = client(async (path) => path === "/api/login"
    ? response(200, { csrf_token: "old" }) : response(401, { error: "requires login" }));
  await api.login("admin", "fixture");
  let ended = 0;
  api.onUnauthorized(() => ended++);
  await assert.rejects(api.getConfig(), { status: 401 });
  await assert.rejects(api.getConfig(), { status: 401 });
  assert.equal(ended, 1);
  assert.equal(api.hasToken(), false);
});

test("a bad login does not invalidate an existing session", async () => {
  let attempts = 0;
  const api = client(async () => ++attempts === 1
    ? response(200, { csrf_token: "valid" }) : response(401, { error: "bad password" }));
  await api.login("admin", "fixture");
  let ended = 0;
  api.onUnauthorized(() => ended++);
  await assert.rejects(api.login("admin", "wrong"), { status: 401 });
  assert.equal(ended, 0);
  assert.equal(api.hasToken(), true);
});

test("expired session discovered during CSRF refresh returns 401", async () => {
  const paths = [];
  const api = client(async (path) => {
    paths.push(path);
    if (path === "/api/login") return response(200, { csrf_token: "old" });
    return response(path === "/api/session" ? 401 : 403, { error: "requires login" });
  });
  await api.login("admin", "fixture");
  let ended = 0;
  api.onUnauthorized(() => ended++);
  await assert.rejects(api.wireGuardKeypair(), { status: 401 });
  assert.equal(paths.at(-1), "/api/session");
  assert.equal(ended, 1);
  assert.equal(api.hasToken(), false);
});

test("late 401 from an older request cannot log out a new session", async () => {
  let finishOld;
  let logins = 0;
  const api = client(async (path) => path === "/api/login"
    ? response(200, { csrf_token: String(++logins) })
    : new Promise((resolve) => { finishOld = resolve; }));
  await api.login("admin", "first");
  const pending = api.getConfig();
  await api.login("admin", "second");
  let ended = 0;
  api.onUnauthorized(() => ended++);
  finishOld(response(401, { error: "old request" }));
  await assert.rejects(pending, { status: 401 });
  assert.equal(ended, 0);
  assert.equal(api.hasToken(), true);
});
