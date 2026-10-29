const assert = require('node:assert/strict');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const path = require('node:path');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const bundle = buildSync({entryPoints:[path.join(__dirname,'../src/pages/Storage.tsx')],bundle:true,platform:'node',format:'cjs',external:['react','react/jsx-runtime'],write:false});
const loaded={exports:{}};
new Function('require','module','exports',bundle.outputFiles[0].text)(require,loaded,loaded.exports);
const config={components:[{id:'samba',installed:true}],samba:{volumes:[{id:'v1',uuid:'test-volume',enabled:true,filesystem:'ext4'}]}};
function render(snapshot,error='',admin=true){
 const original=React.useState;let call=0;
 React.useState=initial=>{const index=call++;return original(index===0?snapshot:index===1?error:initial)};
 try{return renderToStaticMarkup(React.createElement(loaded.exports.StoragePage,{config,admin,patch:()=>assert.fail('render mutated config')}))}finally{React.useState=original}
}
test('pending storage inventory does not claim missing disk or ask to insert one',()=>{
 for(const admin of [true,false]){const html=render(null,'',admin);assert.doesNotMatch(html,/Вставьте USB-диск|Диск отсутствует/);assert.match(html,/Нет данных/)}
});
test('successful empty inventory reports absence, detected volume reports mounted state',()=>{
 assert.match(render([]),/Вставьте USB-диск/);assert.match(render([]),/Диск отсутствует/);
 const html=render([{uuid:'test-volume',label:'Test',size:1024,mountpoints:['/srv/netos/test']}]);
 assert.match(html,/Подключён в системе/);assert.doesNotMatch(html,/Вставьте USB-диск|Диск отсутствует/);
});
test('inventory failure is not presented as a known empty result and recovery clears error',()=>{
 const html=render([],'read failed');assert.match(html,/Список дисков недоступен/);assert.match(html,/Нет данных/);assert.doesNotMatch(html,/Вставьте USB-диск|Диск отсутствует/);
 assert.doesNotMatch(render([]),/Список дисков недоступен/);
});
