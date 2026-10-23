import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
const exports = {};
vm.runInNewContext(ts.transpileModule(readFileSync(new URL('../src/clientReservation.ts', import.meta.url), 'utf8'), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText, { exports });
const { reservationNetwork, reservationError } = exports;
const mac = '02:00:00:00:00:01';
const cfg = { interfaces: [{ id: 'a', name: 'br0' }, { id: 'b', name: 'br1' }], networks: [
  { id: 'first', interface: 'a', router_address: '192.168.10.1/24' },
  { id: 'second', interface: 'b', router_address: '192.168.20.1/24', dhcp_pool: { gateway: '192.168.20.2' } },
] };
test('DHCP-only client in second subnet never falls back to first network', () => {
  assert.equal(reservationNetwork(cfg, { mac, ip: '192.168.20.100' }), 'second');
  assert.equal(reservationNetwork(cfg, { mac, ip: '192.168.30.100' }), '');
  assert.equal(reservationNetwork({ ...cfg, networks: [...cfg.networks, { id: 'overlap', router_address: '192.168.20.1/24' }] }, { mac, ip: '192.168.20.100' }), '');
});
test('physical interface takes precedence over stale address and configured client segment', () => {
  assert.equal(reservationNetwork({ ...cfg, clients: [{ mac, network: 'first' }] }, { mac, interface: 'br1', ip: '192.168.10.100' }), 'second');
});
test('validate malformed, outside-subnet, infrastructure and conflicting addresses', () => {
  for (const ip of ['', 'word', '1.2.3.999', '192.168.020.5', '::1', '192.168.10.100', '192.168.20.0', '192.168.20.255', '192.168.20.1', '192.168.20.2']) {
    assert.notEqual(reservationError(cfg, mac, ip, 'second'), '', ip);
  }
  for (const ip of ['192.168.20.50', '192.168.20.100']) assert.equal(reservationError(cfg, mac, ip, 'second'), '');
  const other = { mac: '02:00:00:00:00:02', ip: '192.168.20.100' };
  assert.notEqual(reservationError({ ...cfg, dhcp: { reservations: [other] } }, mac, other.ip, 'second'), '');
  assert.notEqual(reservationError(cfg, mac, other.ip, 'second', [other]), '');
  assert.equal(reservationError(cfg, mac, other.ip, 'second', [{ ...other, mac }]), '');
  assert.notEqual(reservationError(cfg, mac, other.ip, ''), '');
});
