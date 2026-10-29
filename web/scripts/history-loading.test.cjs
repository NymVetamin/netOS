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
 React.useState=initial=>{const i=call++;return original(i===4?error:i===5?loading:initial)};
 try{return renderToStaticMarkup(React.createElement(loaded.exports.HistoryPage,{onRestored:()=>assert.fail('render restored a revision')}))}finally{React.useState=original}
}
test('history has one loading state instead of lower sections that will move',()=>{
 const html=render(true);assert.match(html,/Загружаем историю/);assert.doesNotMatch(html,/Журнал действий|<table/);
});
test('completed history retains both sections and empty-state explanations',()=>{
 const html=render(false);assert.match(html,/Журнал действий/);assert.match(html,/История пуста/);assert.match(html,/Записей нет/);assert.doesNotMatch(html,/Загружаем историю/);
});
test('load failure retains retry and does not claim history is empty',()=>{
 const html=render(false,'test failure');assert.match(html,/Не удалось загрузить историю/);assert.match(html,/Повторить загрузку/);assert.doesNotMatch(html,/История пуста|Записей нет/);
});
