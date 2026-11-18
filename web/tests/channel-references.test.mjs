import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";
const source = readFileSync(new URL("../src/channelReferences.ts", import.meta.url), "utf8");
const exports = {};
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, { exports });
const { channelReferences, replacementChannelIDs } = exports;

test("all incoming references are reassigned without touching identities, secrets or unrelated peers", () => {
  const cfg = {
    clients: [{ channel: "old" }], networks: [{ default_channel: "old" }],
    policies: [{ channel: "old" }], channels: [{ id: "old" }, { id: "fallback", fallback: "old" }],
    dns: { upstreams: [{ channel: "old" }], split_rules: [{ channel: "old" }] },
    vpn_servers: [{ id: "s1", default_channel: "old", peers: [{ id: "same", channel: "old", password: "fixture" }] },
                  { id: "s2", peers: [{ id: "same", channel: "other" }] }]
  };
  const refs = channelReferences(cfg, "old");
  assert.equal(refs.length, 8);
  for (const ref of refs) ref.owner[ref.key] = "new";
  assert.equal(channelReferences(cfg, "old").length, 0);
  assert.equal(channelReferences(cfg, "new").length, 8);
  assert.deepEqual(cfg.vpn_servers[0].peers[0], { id: "same", channel: "new", password: "fixture" });
  assert.equal(cfg.vpn_servers[1].peers[0].channel, "other");
});

test("replacement excludes missing, disabled and cyclic fallback paths", () => {
  const cfg = { channels: [
    { id: "old", enabled: true }, { id: "direct", enabled: true },
    { id: "off", enabled: false }, { id: "a", enabled: true, fallback: "old" },
    { id: "b", enabled: true, fallback: "a" }] };
  assert.deepEqual([...replacementChannelIDs(cfg.channels, "old")], ["direct"]);
});

test("replacement preserves shared paths, duplicate rows and fresh edits", () => {
  const channels = [
    { id: "a", fallback: "a" }, { id: "a", enabled: true },
    { id: "b", enabled: true, fallback: "a" },
    { id: "c", enabled: true, fallback: "a" }, { id: "", enabled: true },
  ];
  const choices = () => {
    const ids = replacementChannelIDs(channels, "old");
    return channels.filter(channel => ids.has(channel.id)).map(channel => channel.id);
  };
  assert.deepEqual(choices(), [""]);
  channels[0].fallback = "unknown";
  assert.deepEqual(choices(), ["a", "a", "b", "c", ""]);
  channels[0].fallback = "old";
  assert.deepEqual(choices(), [""]);
  assert.deepEqual([...replacementChannelIDs([], "")], []);
});
