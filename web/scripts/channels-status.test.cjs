const assert = require('node:assert/strict');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const path = require('node:path');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const {createHash} = require('node:crypto');
const bundle = buildSync({stdin: {contents: `export {ChannelsPage} from './src/pages/Channels'; export {StatusPollingProvider} from './src/StatusPollingContext';`, resolveDir: path.join(__dirname, '..'), loader: 'tsx'}, bundle: true, platform: 'node', format: 'cjs', external: ['react', 'react/jsx-runtime'], write: false});
const loaded = {exports: {}};
new Function('require', 'module', 'exports', bundle.outputFiles[0].text)(require, loaded, loaded.exports);
const {ChannelsPage, StatusPollingProvider} = loaded.exports;
function render(ids, live, failed = false) {
  const config = {channels: ids.map(id => ({id, name: `Channel ${id}`, type: 'xray', enabled: true, config: {}})), policies: [], components: [{id: 'xray', installed: true}]};
  const original = React.useState;
  const states = [{xray: true}, false, live, failed];
  let call = 0;
  React.useState = initial => {
    const index = call++ - 1;
    return original(index >= 0 && index < states.length ? states[index] : initial);
  };
  try {
    return renderToStaticMarkup(React.createElement(StatusPollingProvider, null, React.createElement(ChannelsPage, {config, patch: () => assert.fail('render must not write')})));
  } finally { React.useState = original; }
}
test('status lookup retains first duplicate, missing entries and strict ID matching', () => {
  const live = [{id: 'a', up: true, interface: 'first'}, {id: 'a', up: false, interface: 'second'}, {id: 1, up: false, interface: 'numeric'}];
  for (let repeat = 0; repeat < 2; repeat++) {
    const html = render(['a', '1', 'missing'], live);
    assert.match(html, />first</);
    assert.doesNotMatch(html, />second<|>numeric</);
    assert.equal((html.match(/>поднят</g) || []).length, 1);
    assert.equal((html.match(/>включён</g) || []).length, 2);
    assert.match(render(['a'], live, true), /Показаны последние полученные данные/);
    assert.match(render(['a'], [{id: 'a', up: false, probe_down: true}]), />проба не прошла</);
    assert.match(render(['a'], []), />включён</);
    assert.match(render(['a'], null), />включён</);
    assert.match(render([NaN], [{id: NaN, up: true}]), />включён</);
  }
});
test('a full page reads status IDs linearly', () => {
  for (const n of [16, 1000]) {
    let reads = 0;
    const ids = Array.from({length: n}, (_, i) => `c${i}`);
    const live = ids.map(id => ({get id() { reads++; return id; }, up: true}));
    const samples = [];
    let html;
    for (let i = 0; i < (process.env.CHANNEL_STATUS_BENCH ? 7 : 1); i++) {
      reads = 0;
      const start = performance.now();
      html = render(ids, live);
      samples.push(+(performance.now() - start).toFixed(2));
    }
    console.log(JSON.stringify({n, reads, ms: samples, htmlSHA256: createHash('sha256').update(html).digest('hex')}));
    if (!process.env.CHANNEL_STATUS_BENCH) assert.ok(reads <= 3 * n, `${n} channels read ${reads} IDs`);
  }
});
