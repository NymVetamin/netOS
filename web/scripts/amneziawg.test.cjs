const assert = require("node:assert/strict");
const path = require("node:path");
const { buildSync } = require("esbuild");
function load(file) {
  const result = buildSync({ entryPoints: [path.join(__dirname, "../src", file)], bundle: true, platform: "node", format: "cjs", write: false });
  const module = { exports: {} };
  new Function("module", "exports", result.outputFiles[0].text)(module, module.exports);
  return module.exports;
}
const { parseWireGuardConfig: parse } = load("wireguardImport.ts");
const { wireGuardClientConfig: profile } = load("wireGuardProfiles.ts");
const { newAmneziaOptions, validateAmneziaOptions, amneziaClientParameters } = load("amneziawg.ts");
const { syncWireGuardPeerChannels } = load("wireGuardPeerChannels.ts");
const { channelNATInterface } = load("channelNAT.ts");
const key = Buffer.alloc(32, 7).toString("base64"), nextKey = Buffer.alloc(32, 9).toString("base64");
const options = { ...newAmneziaOptions(), header_protection_key: key, persistent_keepalive: "20-30", i1: "<b 0x0102><r 10><rd 2><rc 3><t>", random_trailers: true };
const server = { type: "amneziawg", subnet: "10.9.0.1/24", config: { public_endpoint: "vpn.example:51820", amnezia: options } };
const peer = { address: "10.9.0.2", credentials: {}, wireguard_profile: { use_router_dns: true, allowed_ips: ["0.0.0.0/0"] } };
const exported = profile(server, peer, key, nextKey);
assert.match(exported, /^RandomTrailers = 1$/m);
assert.match(amneziaClientParameters({ random_trailers: false, disable_cookies: false }), /^RandomTrailers = 0$/m);
assert.match(amneziaClientParameters({ disable_cookies: true }), /^DisableCookies = 1$/m);
const imported = parse(exported, true);
assert.deepEqual(imported.config.amnezia, options);
assert.equal(imported.config.endpoint, "vpn.example:51820");
assert.equal(imported.config.address, "10.9.0.2/32");
assert.equal(imported.warnings.length, 1); // DNS remains managed by netOS.
assert.throws(() => parse(exported), /AmneziaWG/);
assert.equal(parse(exported.replace("20-30", "0"), true).config.amnezia.persistent_keepalive, "0");
for (const broken of [
  { h1: "100002" }, { h1: "0-4294967295" }, { s4: 11 }, { jc: 129 },
  { jmin: 71 }, { i1: "<r 65508>" }, { i1: "<b 0x1>" }, { i1: "<r 1-2>" },
  { i1: "<d 1>" }, { i1: "<r 3>command" }, { i1: "<t >" }, { rekey_timeout: "0-1" },
  { header_protection_key: "bad" }, { persistent_keepalive: "65536" },
]) assert.throws(() => validateAmneziaOptions({ ...options, ...broken }), JSON.stringify(broken));
assert.throws(() => parse(exported.replace("Jc = 3", "Jc = 3\nJc = 4"), true));
assert.throws(() => parse("#".repeat(1024 * 1024 + 1), true));
const largestSignature = "<b 0x" + "00".repeat(32763) + ">";
validateAmneziaOptions({ i1: largestSignature });
assert.throws(() => validateAmneziaOptions({ i1: "<b 0x" + "00".repeat(32764) + ">" }));
const boundaryServer = { ...server, config: { ...server.config, amnezia: { ...options, i1: largestSignature } } };
assert.equal(parse(profile(boundaryServer, peer, key, nextKey), true).config.amnezia.i1, largestSignature);
const scripts = parse(exported.replace("[Peer]", "PostUp = shutdown\n[Peer]"), true);
assert.equal(scripts.config.PostUp, undefined);
assert.ok(scripts.warnings.some(w => w.startsWith("PostUp")));

// Only the masked secret comes from an earlier export. Public edits stay fresh.
const masked = { ...options, header_protection_key: "", jc: 5 };
assert.match(amneziaClientParameters(masked, exported), /^Jc = 5$/m);
assert.match(amneziaClientParameters(masked, exported), new RegExp(`^HeaderProtectionKey = ${key}$`, "m"));
assert.ok(amneziaClientParameters({ ...masked, header_protection_key: nextKey }, exported).includes(nextKey));
const cleared = { ...masked }; delete cleared.header_protection_key;
assert.ok(!amneziaClientParameters(cleared, exported).includes("HeaderProtectionKey"));
const ordinary = profile({ ...server, type: "wireguard" }, peer, key, nextKey);
assert.ok(!ordinary.includes("Jc"));
assert.ok(!ordinary.includes("HeaderProtectionKey"));
assert.equal(parse(ordinary).config.persistent_keepalive, 25);

const shared = { vpn_servers: [{ id: "server", index: 3, type: "amneziawg", peers: [{ id: "exit", name: "Exit", use_as_channel: true }] }], channels: [], firewall: { nat: [] } };
syncWireGuardPeerChannels(shared);
assert.equal(shared.channels[0].type, "amneziawg");
assert.equal(channelNATInterface(shared.channels[0]), "awg-srv3");
shared.firewall.nat.push({ id: "channel-nat-wg-exit-server", system: true, interface: "awg-srv3" });
const previous = structuredClone(shared);
syncWireGuardPeerChannels(shared);
assert.deepEqual(shared, previous);
shared.vpn_servers[0].type = "wireguard";
syncWireGuardPeerChannels(shared);
assert.equal(shared.channels[0].type, "wireguard");
assert.equal(shared.firewall.nat[0].interface, "wg-srv3");
shared.vpn_servers[0].peers[0].use_as_channel = false;
syncWireGuardPeerChannels(shared);
assert.deepEqual(shared.channels, []);
assert.deepEqual(shared.firewall.nat, []);

// Complete export + import, with bounded growing signature input; no packet allocation.
for (const tags of [8, 4096]) {
  const candidate = { ...server, config: { ...server.config, amnezia: { ...options, i1: "<r 1>".repeat(tags) } } };
  const samples = [];
  for (let sample = 0; sample < 3; sample++) {
    const start = performance.now();
    for (let i = 0; i < 50; i++) assert.equal(parse(profile(candidate, peer, key, nextKey), true).config.amnezia.i1, candidate.config.amnezia.i1);
    samples.push((performance.now() - start) / 50);
  }
  console.log(JSON.stringify({ tags, export_import_ms: samples }));
}
console.log("AmneziaWG import/export, validation, masked key freshness/clear and ordinary WireGuard regression PASS");
