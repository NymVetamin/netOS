const assert = require('node:assert/strict');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const path = require('node:path');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const {createHash} = require('node:crypto');
const code = buildSync({entryPoints: [path.join(__dirname, '../src/pages/Storage.tsx')], bundle: true, platform: 'node', format: 'cjs', external: ['react', 'react/jsx-runtime'], write: false}).outputFiles[0].text;
const loaded = {exports: {}};
new Function('require', 'module', 'exports', code)(require, loaded, loaded.exports);
function render(volumes, shares) {
  return renderToStaticMarkup(React.createElement(loaded.exports.StoragePage, {
    config: {samba: {volumes, shares}, components: [{id: 'samba', installed: true}]},
    admin: true, patch: () => assert.fail('render must not write'),
  }));
}
test('forget-volume guards preserve enabled state and all share references across renders', () => {
  const ids = ['used', 'free', '', undefined, NaN];
  for (const shares of [[{id: 's', volume: 'used', enabled: false}, {id: 't', volume: ''}, {id: 'u'}, {id: 'n', volume: NaN}], [], [{id: 's', volume: 'free', enabled: true}]]) {
    for (const enabled of [false, true]) {
      const volumes = ids.map((id, i) => ({id, uuid: `disk${i}`, enabled}));
      for (let repeat = 0; repeat < 2; repeat++) {
        const html = render(volumes, shares);
        const buttons = [...html.matchAll(/<button\b([^>]*)>Забыть том<\/button>/g)];
        assert.equal(buttons.length, volumes.length);
        volumes.forEach((v, i) => assert.equal(buttons[i][1].includes('disabled=""'), enabled || shares.some(sh => sh.volume === v.id)));
      }
    }
  }
});
test('volume guards read share references linearly in a complete render', () => {
  for (const n of [16, 512]) {
    let reads = 0;
    const volumes = Array.from({length: n}, (_, i) => ({id: `v${i}`, uuid: `disk${i}`, enabled: false}));
    const shares = Array.from({length: n}, (_, i) => ({id: `s${i}`, name: `Share${i}`, get volume() { reads++; return 'unassigned'; }, users: []}));
    let html;
    const ms = [];
    for (let i = 0; i < (process.env.STORAGE_BENCH ? 5 : 1); i++) {
      reads = 0;
      const start = performance.now();
      html = render(volumes, shares);
      ms.push(+(performance.now() - start).toFixed(2));
    }
    console.log(JSON.stringify({n, reads, ms, htmlSHA256: createHash('sha256').update(html).digest('hex')}));
    if (!process.env.STORAGE_BENCH) assert.ok(reads <= 4*n, `${reads} reads for ${n} shares`);
  }
});
