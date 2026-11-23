const assert = require('node:assert/strict');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const path = require('node:path');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const bundle = buildSync({entryPoints: [path.join(__dirname, '../src/pages/Traffic.tsx')], bundle: true, platform: 'node', format: 'cjs', external: ['react', 'react/jsx-runtime'], write: false});
const loaded = {exports: {}};
new Function('require', 'module', 'exports', bundle.outputFiles[0].text)(require, loaded, loaded.exports);
const {TrafficPage} = loaded.exports;
const fixture = (selected, ids = ['A', 'B']) => ({wans: ids.map(id => ({id, name: id, enabled: true})), qos: {enabled: true, wans: selected.map(wan => ({wan, upload_kbit: 1000, download_kbit: 2000, diffserv: 'diffserv4'}))}});
function elements(node, predicate) {
  if (!node || typeof node !== 'object') return [];
  if (Array.isArray(node)) return node.flatMap(child => elements(child, predicate));
  return [...(predicate(node) ? [node] : []), ...elements(node.props?.children, predicate), ...elements(node.props?.actions, predicate)];
}
function page(config) { return TrafficPage({config, patch: mutate => mutate(config)}); }
function select(tree, index) { return elements(tree, n => n.type === 'select' && n.props['aria-label'] === `Аплинк QoS ${index}`)[0]; }
test('availability uses WAN membership, including duplicate and obsolete draft entries', () => {
  for (const selected of [['B', 'B'], ['A', 'obsolete'], [], ['A', '']]) {
    const tree = page(fixture(selected));
    assert.equal(elements(tree, n => n.type === 'button' && n.props.children === 'Добавить')[0].props.disabled, false);
    assert.doesNotMatch(renderToStaticMarkup(tree), /Все включённые аплинки уже добавлены/);
  }
  for (const [selected, ids] of [[['A','B'], ['A','B']], [['A','B','obsolete'], ['A','B']], [[], []]]) {
    assert.equal(elements(page(fixture(selected, ids)), n => n.type === 'button' && n.props.children === 'Добавить')[0].props.disabled, true);
  }
});
test('other selected WANs cannot be chosen; a duplicate can be repaired', () => {
  const config = fixture(['A', 'B']);
  const tree = page(config);
  const options = elements(select(tree, 1), n => n.type === 'option');
  assert.equal(options.find(n => n.props.value === 'B').props.disabled, true);
  assert.ok(!options.find(n => n.props.value === 'A').props.disabled);
  select(tree, 1).props.onChange({target: {value: 'B'}});
  assert.deepEqual(config.qos.wans.map(w => w.wan), ['A', 'B']);
  select(tree, 1).props.onChange({target: {value: ''}});
  assert.equal(config.qos.wans[0].wan, '');
  const duplicate = fixture(['B', 'B']);
  select(page(duplicate), 1).props.onChange({target: {value: 'A'}});
  assert.deepEqual(duplicate.qos.wans.map(w => w.wan), ['A', 'B']);
  assert.equal(duplicate.qos.wans[0].download_kbit, 2000);
});
test('selection guard uses current draft, not a stale render', () => {
  const config = fixture(['A', 'B'], ['A', 'B', 'C']);
  const old = page(config);
  select(old, 2).props.onChange({target: {value: 'C'}});
  select(old, 1).props.onChange({target: {value: 'C'}});
  assert.deepEqual(config.qos.wans.map(w => w.wan), ['A', 'C']);
  select(page(config), 2).props.onChange({target: {value: 'B'}});
  assert.deepEqual(config.qos.wans.map(w => w.wan), ['A', 'B']);
});
test('disabled uplinks do not count as available and re-enabling refreshes choices', () => {
  const config = fixture(['A']);
  config.wans[1].enabled = false;
  assert.equal(elements(page(config), n => n.type === 'button' && n.props.children === 'Добавить')[0].props.disabled, true);
  assert.ok(!elements(select(page(config), 1), n => n.type === 'option').some(n => n.props.value === 'B'));
  config.wans[1].enabled = true;
  assert.equal(elements(page(config), n => n.type === 'button' && n.props.children === 'Добавить')[0].props.disabled, false);
  assert.ok(elements(select(page(config), 1), n => n.type === 'option').some(n => n.props.value === 'B' && !n.props.disabled));
});
if (process.env.QOS_BENCH) test('full QoS render cost', () => {
  for (const size of [8, 128]) {
    const ids = Array.from({length: size}, (_, i) => `wan${i}`);
    const config = fixture(ids, ids);
    const times = [];
    for (let repeat = 0; repeat < 5; repeat++) {
      const start = performance.now();
      renderToStaticMarkup(page(config));
      times.push(+(performance.now() - start).toFixed(2));
    }
    console.log(JSON.stringify({size, ms: times}));
  }
});
