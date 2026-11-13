const assert = require('node:assert/strict');
const {test} = require('node:test');
const path = require('node:path');
const {buildSync} = require('esbuild');
const React = require('react');
const {renderToStaticMarkup} = require('react-dom/server');
const code = buildSync({entryPoints:[path.join(__dirname,'../src/pages/TrafficMonitor.tsx')],bundle:true,platform:'node',format:'cjs',external:['react','react/jsx-runtime'],write:false});
const loaded = {exports:{}};
new Function('require','module','exports',code.outputFiles[0].text)(require,loaded,loaded.exports);
const empty = {enabled:true,limited:false,clients:[],domains:[],points:[]};
function render(report, {hold=null,error='',draft=true,realtimeError=''}={}) {
 const original=React.useState;let call=0;
 // Seed fetched state without running network effects during server render.
 const state=new Map([[9,report],[11,error],[12,hold],[14,realtimeError]]);
 React.useState=initial=>{const index=call++;return original(state.has(index)?state.get(index):initial)};
 try {return renderToStaticMarkup(React.createElement(loaded.exports.TrafficMonitor,{config:{traffic_monitor:{enabled:draft}},patch:()=>assert.fail('render changed config'),interfaces:[],status:{}}))}
 finally {React.useState=original}
}
test('empty history does not invent a startup delay or promise full retention',()=>{
 const html=render(empty);
 assert.match(html,/до 7 дней/);assert.match(html,/нет сохранённых данных/);
 assert.doesNotMatch(html,/двух замеров|Секундная история хранится 7 дней|сейчас выключен|может быть неполной/);
});
test('actual collection state is independent from the unsaved switch',()=>{
 assert.match(render({...empty,enabled:false},{draft:true}),/Сбор клиентов сейчас выключен/);
 assert.doesNotMatch(render(empty,{draft:false}),/Сбор клиентов сейчас выключен/);
});
test('loss source and time range accompany the warning',()=>{
 const html=render({...empty,limited:true,limits:[{kind:'domains',from:1800000000,to:1800000060}],available:{from:1800000100,to:1800000200}});
 assert.match(html,/за выбранный период может быть неполной/);
 assert.match(html,/Ограничен объём истории DNS/);assert.match(html,/Сохранённые замеры/);
 assert.doesNotMatch(html,/двух замеров/);
});
test('pause uses the captured report instead of later loss/error state',()=>{
 const hold={clients:empty,from:1,to:2,frames:[],interval:1,interfaces:[]};
 const html=render({...empty,limited:true,problem:'later collector failure'},{hold,realtimeError:'later stream failure'});
 assert.doesNotMatch(html,/неполной|later collector failure|later stream failure/);
 assert.match(render(empty,{hold:{...hold,clients:null}}),/На момент паузы история клиентов ещё не была загружена/);
});
test('request failure and loading are not reported as empty traffic',()=>{
 assert.match(render(null),/Загрузка истории/);
 const html=render(empty,{error:'Не удалось обновить историю клиентов'});
 assert.match(html,/Не удалось обновить историю клиентов/);assert.doesNotMatch(html,/нет сохранённых данных/);
});
