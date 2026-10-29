const assert = require('node:assert/strict');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const path = require('node:path');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const bundle = buildSync({stdin: {contents: `export {ChannelsPage} from './src/pages/Channels'; export {StatusPollingProvider} from './src/StatusPollingContext';`, resolveDir: path.join(__dirname, '..'), loader: 'tsx'}, bundle: true, platform: 'node', format: 'cjs', external: ['react', 'react/jsx-runtime'], write: false});
const loaded = {exports: {}};
new Function('require', 'module', 'exports', bundle.outputFiles[0].text)(require, loaded, loaded.exports);
const {ChannelsPage, StatusPollingProvider} = loaded.exports;
const installed = Object.fromEntries(['wireguard', 'openconnect', 'xray', 'strongswan', 'l2tp'].map(id => [id, true]));
const config = {channels: [], policies: [], components: Object.keys(installed).map(id => ({id, installed: true}))};
function render(states) {
  const original = React.useState;
  let call = 0;
  // Provider's first state is the poller; next four belong to ChannelsPage.
  React.useState = initial => {
    const index = call++ - 1;
    return original(index >= 0 && index < states.length ? states[index] : initial);
  };
  try {
    return renderToStaticMarkup(React.createElement(StatusPollingProvider, null, React.createElement(ChannelsPage, {config, patch: () => assert.fail('render must not change config')})));
  } finally { React.useState = original; }
}
const notes = html => html.match(/<div class="rows-notes">([\s\S]*?)<\/div>/)?.[1];
test('initial and repeated page entry have no transient loading block', () => {
  for (let i = 0; i < 2; i++) assert.equal(notes(render([null, false, null, false])), '');
  assert.equal(notes(render([installed, false, [], false])), '');
});
test('missing components are shown only after a successful response', () => {
  assert.doesNotMatch(render([null, false, null, false]), /Для других типов каналов/);
  assert.match(render([{}, false, [], false]), /Для других типов каналов нужны компоненты/);
});
test('failed loading stays actionable and successful retry clears errors', () => {
  const failed = render([null, true, null, true]);
  assert.match(failed, /Не удалось проверить компоненты/);
  assert.match(failed, /Не удалось обновить состояние каналов/);
  assert.match(failed, /Состояние пока неизвестно/);
  assert.match(render([installed, false, [], true]), /Показаны последние полученные данные/);
  assert.equal(notes(render([installed, false, [], false])), '');
});
test('pending component check reserves the creation menu without making it interactive', () => {
  assert.match(render([null, false, null, false]), /visibility:hidden/);
  assert.doesNotMatch(render([installed, false, [], false]), /visibility:hidden/);
  assert.doesNotMatch(render([{}, false, [], false]), /Добавить канал/);
  assert.doesNotMatch(render([null, true, [], false]), /Добавить канал/);
});
