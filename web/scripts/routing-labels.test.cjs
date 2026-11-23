const assert = require('node:assert/strict');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const path = require('node:path');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const {createHash} = require('node:crypto');
const bundle = buildSync({entryPoints: [path.join(__dirname, '../src/pages/Routing.tsx')], bundle: true, platform: 'node', format: 'cjs', external: ['react', 'react/jsx-runtime'], write: false});
const loaded = {exports: {}};
new Function('require', 'module', 'exports', bundle.outputFiles[0].text)(require, loaded, loaded.exports);
function render(interfaces, names, error = '', routes = []) {
  const config = {interfaces, routing: {static: routes, tables: [], rules: []}};
  const live = {routes: '', rules: '', parsed: names.map(name => ({interface: name, destination: 'default', origin: 'static', table: 'main'}))};
  const original = React.useState;
  let call = 0;
  React.useState = initial => original([live, error, 'all'][call++] ?? initial);
  try { return renderToStaticMarkup(React.createElement(loaded.exports.RoutingPage, {config, patch: () => assert.fail('render must not write')})); }
  finally { React.useState = original; }
}
test('route labels preserve first match, formatting, unknown names and fresh config', () => {
  for (let repeat = 0; repeat < 2; repeat++) {
    const html = render([{name: 'eth0', label: ' First '}, {name: 'eth0', label: 'Second'}, {name: 'eth1', label: 'eth1'}, {name: 'eth2', label: ' '}], ['eth0', 'eth1', 'eth2', 'tun-ch1', '']);
    assert.match(html, />First \(eth0\)</);
    assert.doesNotMatch(html, /Second/);
    assert.match(html, />eth1</);
    assert.match(html, />eth2</);
    assert.match(html, />tun-ch1</);
    assert.match(render([{name: 'eth0', label: 'Changed'}], ['eth0'], 'failed'), /Changed \(eth0\)/);
    assert.match(render([], ['eth0']), />eth0</);
  }
});
test('static route summary keeps gateway precedence and interface fallback', () => {
  const interfaces = [{name: 'eth0', label: 'Uplink'}];
  const route = {id: 'route', enabled: true, destination: '192.0.2.0/24', interface: 'eth0'};
  assert.match(render(interfaces, [], '', [route]), /<span class="mono">Uplink \(eth0\)<\/span>/);
  assert.match(render(interfaces, [], '', [{...route, gateway: '192.0.2.1'}]), /<span class="mono">192.0.2.1<\/span>/);
  assert.match(render([], [], '', [route]), /<span class="mono">eth0<\/span>/);
});
test('live route rendering reads interface names linearly', () => {
  for (const n of [16, 1000]) {
    let reads = 0;
    const names = Array.from({length: n}, (_, i) => `eth${i}`);
    const interfaces = names.map(name => ({get name() { reads++; return name; }, label: `Port ${name}`}));
    const times = [];
    let html;
    for (let i = 0; i < (process.env.ROUTING_BENCH ? 5 : 1); i++) {
      reads = 0;
      const start = performance.now();
      html = render(interfaces, names);
      times.push(+(performance.now() - start).toFixed(2));
    }
    console.log(JSON.stringify({n, reads, ms: times, htmlSHA256: createHash('sha256').update(html).digest('hex')}));
    if (!process.env.ROUTING_BENCH) assert.ok(reads <= 3*n, `read ${reads} names for ${n} rows`);
  }
});
