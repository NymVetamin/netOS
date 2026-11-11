const assert = require("node:assert/strict");
const path = require("node:path");
const { test } = require("node:test");
const { buildSync } = require("esbuild");

const compiled = buildSync({
  entryPoints: [path.join(__dirname, "../src/channelNAT.ts")],
  bundle: true, platform: "node", format: "cjs", write: false,
});
const loaded = { exports: {} };
new Function("module", "exports", compiled.outputFiles[0].text)(loaded, loaded.exports);
const { channelNAT, setChannelNAT, managedChannelNAT, removeChannelNAT } = loaded.exports;

for (const [type, iface] of Object.entries({
  wireguard: "wg-ch7", openconnect: "tun-ch7", xray: "tun-ch7",
  l2tp: "ppp-ch7", ikev2: "xfrm-ch7",
})) {
  test(`${type}: default, repeated toggle, ownership and removal`, () => {
    const channel = { id: "test", index: 7, type, name: "Test" };
    const config = { channels: [channel], firewall: { nat: [] } };
    assert.deepEqual(channelNAT(config, channel), { iface, manual: false, enabled: true });
    for (const enabled of [false, true, false, true]) {
      setChannelNAT(config, channel, enabled);
      assert.equal(config.firewall.nat.length, 1);
      assert.equal(channelNAT(config, channel).enabled, enabled);
      assert.equal(managedChannelNAT(config, config.firewall.nat[0]), true);
    }
    const manual = { id: "manual", interface: iface, enabled: false };
    config.firewall.nat.push(manual);
    const previous = structuredClone(config);
    setChannelNAT(config, channel, false);
    assert.deepEqual(config, previous, "manual ownership must prevent edits");
    assert.equal(channelNAT(config, channel).manual, true);
    assert.equal(managedChannelNAT(config, config.firewall.nat[0]), false);
    removeChannelNAT(config, channel.id);
    assert.deepEqual(config.firewall.nat, [manual], "removal must retain manual rules");
  });
}

test("direct output and missing channel do not create NAT rules", () => {
  const config = {};
  setChannelNAT(config, { id: "direct", type: "direct", index: 0 }, false);
  setChannelNAT(config, undefined, false);
  assert.deepEqual(config, {});
});
