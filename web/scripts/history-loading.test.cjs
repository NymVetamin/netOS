const assert=require('node:assert/strict');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const path=require('node:path');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const code=buildSync({entryPoints:[path.join(__dirname,'../src/pages/History.tsx')],bundle:true,platform:'node',format:'cjs',external:['react','react/jsx-runtime'],write:false});
const loaded={exports:{}};
new Function('require','module','exports',code.outputFiles[0].text)(require,loaded,loaded.exports);
function render(loading,error=''){
 const original=React.useState;let call=0;
 React.useState=initial=>{const i=call++;return original(i===3?error:i===4?loading:initial)};
 try{return renderToStaticMarkup(React.createElement(loaded.exports.HistoryPage,{onRestored:()=>assert.fail('render restored a revision')}))}finally{React.useState=original}
}
test('history has one loading state instead of lower sections that will move',()=>{
 const html=render(true);assert.match(html,/Загружаем историю/);assert.doesNotMatch(html,/<table/);
});
test('completed history shows revisions only; actions moved to the System log',()=>{
 const html=render(false);assert.match(html,/История пуста/);assert.doesNotMatch(html,/Журнал действий|Загружаем историю/);
});
test('load failure retains retry and does not claim history is empty',()=>{
 const html=render(false,'test failure');assert.match(html,/Не удалось загрузить историю/);assert.match(html,/Повторить загрузку/);assert.doesNotMatch(html,/История пуста/);
});
