const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const { buildSync } = require('esbuild');
const compiled = buildSync({ entryPoints: [path.join(__dirname, '../src/channelComponents.ts')], bundle: true, platform: 'node', format: 'cjs', write: false });
const loaded = { exports: {} };
new Function('module', 'exports', compiled.outputFiles[0].text)(loaded, loaded.exports);
const { channelKind, channelAWGServers, channelComponentReady } = loaded.exports;

// Previous predicate is the compatibility oracle: any matching AWG server wins.
function previous(channel, config) {
  if (channel?.type !== 'wireguard') return channel?.type;
  return (channel.wireguard_peer
    ? (config?.vpn_servers || []).some(server => server.id === channel.wireguard_peer.server_id && server.config?.amneziawg)
    : !!channel.config?.amneziawg) ? 'amneziawg' : 'wireguard';
}
test('kind preserves duplicate IDs, truthiness, unknown types and absent references', () => {
  const ids = ['', 'a', '__proto__', undefined, null, 0, '0'];
  const values = [undefined, null, false, 0, '', {}, { jc: 4 }];
  const servers = ids.flatMap(id => values.map(amneziawg => ({ id, enabled: false, type: 'unknown', config: { amneziawg } })));
  const channels = [undefined, null, {}, { type: 'direct' }, { type: 'unknown' },
    ...values.map(amneziawg => ({ type: 'wireguard', config: { amneziawg } })),
    ...[...ids, 'missing'].map(id => ({ type: 'wireguard', wireguard_peer: { server_id: id }, config: { amneziawg: {} } }))];
  for (const config of [undefined, {}, { vpn_servers: [] }, { vpn_servers: servers }, { vpn_servers: [...servers].reverse() }]) {
    const index = channelAWGServers(config);
    for (const channel of channels) assert.equal(channelKind(channel, index), previous(channel, config));
  }
});
test('edit, cancel, save and other config create fresh kinds and component requirements', () => {
  const channel = { type: 'wireguard', wireguard_peer: { server_id: 's' } };
  const config = { vpn_servers: [{ id: 's', config: {} }], components: [{ id: 'wireguard', installed: true }, { id: 'amneziawg', installed: true }] };
  const original = structuredClone(config);
  const old = channelAWGServers(config);
  config.vpn_servers[0].config.amneziawg = {};
  const edited = channelAWGServers(config);
  assert.equal(channelKind(channel, old), 'wireguard');
  assert.equal(channelKind(channel, edited), 'amneziawg');
  assert.equal(channelComponentReady(config, { wireguard: true }, channelKind(channel, edited)), false);
  assert.equal(channelComponentReady(config, { amneziawg: true }, channelKind(channel, edited)), true);
  for (const next of [original, { vpn_servers: [] }, { vpn_servers: [{ id: 'other', config: { amneziawg: {} } }] }]) {
    assert.equal(channelKind(channel, channelAWGServers(next)), 'wireguard');
  }
  for (let i = 0; i < 3; i++) assert.equal(channelKind(channel, channelAWGServers(structuredClone(config))), 'amneziawg');
  delete config.vpn_servers[0].config.amneziawg;
  assert.equal(channelKind(channel, channelAWGServers(config)), 'wireguard');
});
test('one preparation handles a large channel batch without repeated server reads', () => {
  for (const n of [25, 2500]) {
    let reads = 0;
    const config = { vpn_servers: Array.from({ length: n }, (_, i) => ({ get id() { reads++; return String(i); }, config: { amneziawg: {} } })) };
    const index = channelAWGServers(config);
    for (let i = 0; i < n; i++) for (let pass = 0; pass < 2; pass++) {
      assert.equal(channelKind({ type: 'wireguard', wireguard_peer: { server_id: String(i) } }, index), 'amneziawg');
    }
    assert.equal(reads, n);
  }
});
