import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const source = readFileSync(new URL("../src/probeType.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
vm.runInNewContext(compiled, { exports, URL });
const { changeProbeType } = exports;

test("changes an HTTP probe to a valid TCP probe atomically", () => {
  const probe = { type: "http", targets: ["https://example.test/check?q=1"] };
  changeProbeType(probe, "tcp");
  assert.equal(probe.type, "tcp");
  assert.deepEqual([...probe.targets], ["example.test:443"]);
  assert.equal(probe.tcp_request, "GET /check?q=1 HTTP/1.0\r\nHost: example.test\r\n\r\n");
  assert.equal(probe.tcp_response, "HTTP/");
});

test("changes a TCP probe to a valid HTTP probe atomically", () => {
  const probe = { type: "tcp", targets: ["192.0.2.1:8080"], tcp_response: "HTTP/" };
  changeProbeType(probe, "http");
  assert.equal(probe.type, "http");
  assert.deepEqual([...probe.targets], ["http://192.0.2.1:8080/"]);
});

test("adds a port when replacing a legacy ICMP probe", () => {
  const probe = { type: "icmp", targets: ["1.1.1.1", "2001:db8::1"] };
  changeProbeType(probe, "tcp");
  assert.deepEqual([...probe.targets], ["1.1.1.1:443", "[2001:db8::1]:443"]);
  assert.equal(probe.tcp_response, "HTTP/");
});
