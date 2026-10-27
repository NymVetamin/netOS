const assert = require('node:assert/strict');
const test = require('node:test');
const path = require('node:path');
const esbuild = require('esbuild');
const code = esbuild.buildSync({ entryPoints: [path.join(__dirname, '../src/deviceList.ts')], bundle: true, platform: 'node', format: 'cjs', write: false }).outputFiles[0].text;
const loaded = { exports: {} };
new Function('module', 'exports', code)(loaded, loaded.exports);
const { localDevices } = loaded.exports;

function legacy(clients, config) {
  const rows = new Map(clients.map(c => [String(c.mac).toLowerCase(), { ...c, mac: String(c.mac).toLowerCase() }]));
  for (const r of config.dhcp?.reservations || []) {
    const mac = String(r.mac).toLowerCase();
    if (!rows.has(mac)) rows.set(mac, { mac, ip: r.ip, hostname: r.hostname, online: false, source: 'reservation',
      interface: (config.interfaces || []).find(i => i.id === (config.networks || []).find(n => n.id === r.network)?.interface)?.name });
  }
  return [...rows.values()];
}

test('offline reservations preserve ordering, first IDs and live precedence', () => {
  const config = {
    dhcp: { reservations: [
      { mac: 'AA:BB:CC:DD:EE:01', network: 'n1', ip: '192.0.2.2', hostname: 'reserved' },
      { mac: 'aa:bb:cc:dd:ee:01', network: 'n2', ip: '192.0.2.3' },
      { mac: 'aa:bb:cc:dd:ee:02', network: 'missing' },
      { mac: 'aa:bb:cc:dd:ee:03' },
    ] },
    networks: [{ id: 'n1', interface: 'i1' }, { id: 'n1', interface: 'i2' }, { id: 'n2', interface: 'i2' }],
    interfaces: [{ id: 'i1', name: 'br1' }, { id: 'i1', name: 'duplicate' }, { id: 'i2', name: 'br2' }, { name: 'incomplete' }],
  };
  const live = [{ mac: 'AA:BB:CC:DD:EE:01', ip: '192.0.2.9', online: true, interface: 'br9' },
    { mac: 'aa:bb:cc:dd:ee:01', ip: '192.0.2.10', online: true, interface: 'br10' }];
  const original = structuredClone(config);
  for (const clients of [live, [], live]) {
    assert.deepEqual(localDevices(clients, config), legacy(clients, config));
  }
  assert.deepEqual(config, original);
  config.networks.reverse(); config.interfaces.reverse();
  assert.deepEqual(localDevices([], config), legacy([], config));
  config.networks[0].interface = 'i1';
  assert.deepEqual(localDevices([], config), legacy([], config));
});

test('partial configuration and no missing reservations remain supported', () => {
  for (const config of [{}, { dhcp: {} }, { dhcp: { reservations: [] } },
    { dhcp: { reservations: [{ mac: 'aa', network: 'missing' }] } }]) {
    for (const clients of [[], [{ mac: 'AA', online: true }]]) {
      assert.deepEqual(localDevices(clients, config), legacy(clients, config));
    }
  }
});

test('client network lookup preserves explicit selection and first interface matches', () => {
  const { clientNetworkLookup } = loaded.exports;
  const config = {
    interfaces: [{ id: 'i1', name: 'br1' }, { id: 'i1', name: 'duplicate' }, { id: 'i2', name: 'br1' }],
    networks: [{ id: 'n1', interface: 'i1' }, { id: 'n1', interface: 'i2' },
      { id: 'n2', interface: 'i2' }, { id: 'missing', interface: 'absent' }],
  };
  for (const c of [config, {}, { ...config, networks: [...config.networks].reverse() },
    { ...config, interfaces: [...config.interfaces].reverse() }]) {
    const lookup = clientNetworkLookup(c);
    for (const id of [undefined, '', 'n1', 'n2', 'missing', 'not-found']) {
      for (const name of [undefined, '', 'br1', 'duplicate', 'not-found']) {
        const expected = (c.networks || []).find(n => id ? n.id === id
          : (c.interfaces || []).find(i => i.id === n.interface)?.name === name);
        assert.equal(lookup(id, name), expected);
      }
    }
  }
  const first = clientNetworkLookup(config);
  const changed = { ...config, interfaces: [{ id: 'i1', name: 'new-name' }] };
  assert.equal(clientNetworkLookup(changed)(undefined, 'new-name'), config.networks[0]);
  assert.equal(first(undefined, 'new-name'), undefined);
});
