const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const code = buildSync({
  stdin: {
    contents: "export * from './pages/Dashboard'; export {StatusPollingProvider} from './StatusPollingContext';",
    resolveDir: path.join(__dirname, '../src'),
  },
  bundle: true, platform: 'node', format: 'cjs', write: false,
  external: ['react', 'react/jsx-runtime'],
});
const loaded = {exports: {}};
new Function('require', 'module', 'exports', code.outputFiles[0].text)(require, loaded, loaded.exports);
const {wanInterfaceName} = loaded.exports;

test('a dashboard render reads interface IDs linearly with many ordinary WANs', () => {
  let reads = 0;
  const interfaces = Array.from({length: 100}, (_, i) => ({
    get id() { reads++; return String(i); }, name: 'eth' + i,
  }));
  const wans = interfaces.map((_, i) => ({id: String(i), interface: String(i), enabled: true}));
  const {StatusPollingProvider, Dashboard} = loaded.exports;
  renderToStaticMarkup(React.createElement(StatusPollingProvider, null,
    React.createElement(Dashboard, {config: {interfaces, wans}, patch() {}})));
  assert.ok(reads <= interfaces.length * 2, `interface ID reads: ${reads}`);
});

test('dashboard and map resolve ordinary, missing and PPP ports consistently', () => {
  const config = {interfaces: [{id: 'p', name: 'eth2'}, {id: 'empty', name: ''}]};
  const index = new Map(config.interfaces.map(port => [port.id, port.name]));
  for (const [wan, expected] of [
    [{interface: 'p'}, 'eth2'],
    [{interface: 'missing'}, 'missing'],
    [{interface: 'empty'}, 'empty'],
    [{id: 'dsl', proto: 'pppoe', interface: 'p'}, 'ppp-dsl'],
    [{id: 'vpn', proto: 'l2tp', interface: 'p'}, 'ppp-vpn'],
  ]) {
    assert.equal(wanInterfaceName(config, wan), expected);
    assert.equal(wanInterfaceName(null, wan, index), expected);
  }
});
