const assert = require("node:assert/strict");
const test = require("node:test");
const { buildSync } = require("esbuild");
const { resolve } = require("node:path");
const { outputFiles } = buildSync({ entryPoints: [resolve(__dirname, "../src/segmentAddresses.ts")], bundle: true, format: "cjs", write: false });
const mod = { exports: {} };
new Function("module", outputFiles[0].text)(mod);
const { segmentAddresses } = mod.exports;

test("new segment keeps router and DHCP pool in a free private /24", () => {
  const networks = [];
  for (let i = 1; i <= 256; i++) {
    const { router, start, end } = segmentAddresses(networks, []);
    assert.match(router, /^192\.168\.(\d+)\.1\/24$/);
    const octet = Number(router.split(".")[2]);
    assert.ok(octet <= 255);
    if (i <= 25) assert.equal(octet, 10 * i);
    assert.ok(!networks.some(n => n.router_address === router));
    assert.equal(start, `192.168.${octet}.100`);
    assert.equal(end, `192.168.${octet}.200`);
    networks.push({router_address: router});
  }
  assert.deepEqual(segmentAddresses(networks, []), {router:"", start:"", end:""});
  networks.splice(7, 1);
  assert.equal(segmentAddresses(networks, []).router, "192.168.80.1/24");
  const vpn = {enabled:true, subnet:"192.168.0.1/17"};
  assert.equal(segmentAddresses([], [vpn]).router, "192.168.128.1/24");
  vpn.enabled = false;
  assert.equal(segmentAddresses([], [vpn]).router, "192.168.10.1/24");
});
