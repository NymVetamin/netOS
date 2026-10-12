import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const source = readFileSync(new URL("../src/channelComponents.ts", import.meta.url), "utf8");
const exports = {};
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, { exports });
const { channelComponents, channelComponentReady: ready } = exports;

test("each VPN type requires both a selected component and successful installation", () => {
  for (const { type, id } of channelComponents) {
    const selected = { components: [{ id, installed: true }] };
    assert.equal(ready(selected, null, type), false, type);
    assert.equal(ready(selected, {}, type), false, type);
    assert.equal(ready(selected, { [id]: false }, type), false, type);
    assert.equal(ready({}, { [id]: true }, type), false, type);
    assert.equal(ready({ components: [{ id, installed: false }] }, { [id]: true }, type), false, type);
    assert.equal(ready(selected, { [id]: true }, type), true, type);
  }
});
test("IKEv2 uses strongSwan; unknown channel types are never enabled", () => {
  assert.equal(ready({ components: [{ id: "strongswan", installed: true }] }, { strongswan: true }, "ikev2"), true);
  assert.equal(ready({ components: [{ id: "ikev2", installed: true }] }, { ikev2: true }, "ikev2"), false);
  assert.equal(ready({}, {}, "unknown"), false);
});
