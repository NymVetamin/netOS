const assert = require('node:assert/strict');
const test = require('node:test');
const esbuild = require('esbuild');
const path = require('node:path');
const code = esbuild.buildSync({ entryPoints: [path.join(__dirname, '../src/storageAccess.ts')], bundle: true, platform: 'node', format: 'cjs', write: false }).outputFiles[0].text;
const loaded = { exports: {} };
new Function('module', 'exports', code)(loaded, loaded.exports);
const { storageAccessIndex } = loaded.exports;

test('access labels, delete guards and checks preserve includes semantics', () => {
  const shares = [
    { id: 'a', name: 'first', users: ['u1', 'u1', 'u2'] },
    { id: 'a', name: 'first', users: ['u2', '__proto__'] },
    { id: 'b', name: '', users: ['u3'] },
    { id: 'c', name: 'none' },
    { id: 'd', name: 'empty', users: [] },
  ];
  for (const list of [shares, [...shares].reverse(), [], [{ name: 'changed', users: ['u1'] }]]) {
    const original = structuredClone(list);
    const index = storageAccessIndex(list);
    for (const id of ['u1', 'u2', 'u3', '__proto__', '', 'missing']) {
      assert.equal((index.namesByUser.get(id) || []).join(', '), list.filter(sh => (sh.users || []).includes(id)).map(sh => sh.name).join(', '));
      assert.equal(index.namesByUser.has(id), list.some(sh => (sh.users || []).includes(id)));
      for (const sh of list) assert.equal(index.usersByShare.get(sh).has(id), (sh.users || []).includes(id));
    }
    assert.deepEqual(list, original);
  }
});

test('volume references preserve strict equality, duplicates and current configuration', () => {
  const shared = {};
  for (const values of [['used', 'used', '', undefined, null, NaN, 0, -0, shared], [], ['changed']]) {
    const shares = values.map((volume, i) => ({volume, enabled: i % 2 === 0}));
    const index = storageAccessIndex(shares);
    for (const id of ['used', 'changed', '', undefined, null, NaN, 0, -0, shared, {}]) {
      assert.equal(index.referencedVolumes.has(id), shares.some(sh => sh.volume === id));
    }
  }
});
