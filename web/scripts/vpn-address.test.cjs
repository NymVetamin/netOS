const { test } = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { buildSync } = require("esbuild");

const { outputFiles } = buildSync({
  entryPoints: [path.join(__dirname, "../src/vpnAddress.ts")],
  bundle: true, write: false, platform: "node", format: "cjs",
});
const loaded = { exports: {} };
new Function("module", "exports", outputFiles[0].text)(loaded, loaded.exports);
const { nextVPNPeerAddress } = loaded.exports;

test("VPN peer allocation respects actual pool boundaries and current reservations", () => {
  const server = { type: "wireguard", subnet: "192.0.2.129/30", peers: [] };
  assert.equal(nextVPNPeerAddress(server), "192.0.2.130");
  server.peers.push({ address: "192.0.2.130" });
  assert.throws(() => nextVPNPeerAddress(server), /свободных адресов/);
  server.peers.pop();
  assert.equal(nextVPNPeerAddress(server), "192.0.2.130");
  server.type = "ocserv";
  server.subnet = "192.0.2.17/24";
  assert.equal(nextVPNPeerAddress(server), "192.0.2.2");
  server.subnet = "invalid";
  assert.throws(() => nextVPNPeerAddress(server), /подсеть/);
});

test("VPN allocation crosses octets and reuses a hole after removal", () => {
  const peers = Array.from({length: 254}, (_, i) => ({ address: "10.9.0." + (i + 2) }));
  const server = { type: "wireguard", subnet: "10.9.0.1/23", peers };
  assert.equal(nextVPNPeerAddress(server), "10.9.1.0");
  peers.splice(19, 1);
  assert.equal(nextVPNPeerAddress(server), "10.9.0.21");
});
