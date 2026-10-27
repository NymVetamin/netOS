const assert = require('node:assert/strict');
const path = require('node:path');
const { test } = require('node:test');
const { buildSync } = require('esbuild');
const result = buildSync({ entryPoints: [path.join(__dirname, '../src/clientStatusIndex.ts')], bundle: true, platform: 'node', format: 'cjs', write: false });
const loaded = { exports: {} };
new Function('module', 'exports', result.outputFiles[0].text)(loaded, loaded.exports);
const { indexClientStatuses } = loaded.exports;

test('indexed status preserves both first-match contracts and exact keys', () => {
  const ids = ['a', 'b', '__proto__', 'a\0b', ''];
  const keys = [undefined, null, '', 'old', 'new', 'a\0b'];
  const rows = [];
  for (let i = 0; i < 400; i++) {
    const row = { id: ids[(i * 7) % ids.length], state: i % 2 ? 'online' : 'offline', sequence: i };
    if (i % 7) row.public_key = keys[(i * 11) % keys.length];
    rows.push(row);
  }
  for (const input of [[], rows, [...rows].reverse()]) {
    const index = indexClientStatuses(input);
    for (const id of [...ids, 'missing']) {
      assert.equal(index.get(id), input.find(row => row.id === id));
      for (const key of [...keys, 'absent']) {
        assert.equal(index.getWithKey(id, key), input.find(row => row.id === id && row.public_key === key));
        assert.equal(key ? index.getWithKey(id, key) : index.get(id), input.find(row => row.id === id && (!key || row.public_key === key)));
      }
    }
  }
});

test('new snapshots remove stale statuses and do not reuse old objects', () => {
  const old = { id: 'peer', public_key: 'old', state: 'online' };
  const next = { id: 'peer', public_key: 'new', state: 'offline' };
  const first = indexClientStatuses([old]);
  const failed = indexClientStatuses([]);
  const recovered = indexClientStatuses([next]);
  assert.equal(first.getWithKey('peer', 'old'), old);
  assert.equal(failed.get('peer'), undefined);
  assert.equal(recovered.getWithKey('peer', 'old'), undefined);
  assert.equal(recovered.get('peer'), next);
  assert.equal(first.get('peer'), old);
});
