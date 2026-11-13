const assert=require('node:assert/strict');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const path=require('node:path');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const code=buildSync({entryPoints:[path.join(__dirname,'../src/pages/Logs.tsx')],bundle:true,platform:'node',format:'cjs',external:['react','react/jsx-runtime'],write:false});
const loaded={exports:{}};
new Function('require','module','exports',code.outputFiles[0].text)(require,loaded,loaded.exports);
function render(entries,query=''){
 const original=React.useState;let call=0;
 const values=['services',0,query,{kind:'services',value:{entries}},'',false];
 React.useState=initial=>original(call<values.length?values[call++]:initial);
 try{return renderToStaticMarkup(React.createElement(loaded.exports.LogEntries,{dnsLogging:true}))}finally{React.useState=original}
}
const entry={time:'2026-11-13T10:00:00Z',source:'services',unit:'netos-test.service',event:'Служба перешла в ошибку',severity:'error',message:'process exited <private>'};
test('service event is readable and original message is escaped in closed details',()=>{
 const html=render([entry]);assert.match(html,/Служба перешла в ошибку/);assert.match(html,/· Ошибка/);
 assert.match(html,/<details><summary>Исходная запись<\/summary>process exited &lt;private&gt;<\/details>/);
});
test('search includes translated event and original detail',()=>{
 for(const q of ['ПЕРЕШЛА','exited'])assert.match(render([entry],q),/netos-test.service/);
 assert.match(render([entry],'unrelated'),/Совпадений нет/);
});
test('legacy entries remain visible without invented event',()=>{
 const html=render([{...entry,event:undefined}]);assert.match(html,/process exited &lt;private&gt;/);assert.doesNotMatch(html,/<details>/);
});
test('access records show identity and outcome without treating disconnect as successful login',()=>{
 const html=render([{...entry,source:'access',protocol:'ssh',user:'alice',address:'2001:db8::1',event:'Отказ во входе SSH',result:'failure'}]);
 for(const text of ['Доступ','SSH','Пользователь: alice','Адрес: 2001:db8::1','· Отказ'])assert.ok(html.includes(text));
 const closed=render([{...entry,source:'access',protocol:'ssh',event:'Соединение SSH завершено',result:'info',severity:undefined}]);
 assert.doesNotMatch(closed,/· Успешно|· Отказ/);
});

test('VPN records show server and peer and preserve escaped raw event',()=>{
 const e={...entry,source:'vpn',protocol:'openconnect',server:'srv12',user:'alice',address:'192.0.2.2',event:'Вход в VPN',result:'success'};
 const html=render([e]);for(const text of ['VPN','OPENCONNECT','Сервер: srv12','Пользователь: alice','Адрес: 192.0.2.2'])assert.ok(html.includes(text));
 assert.match(render([e],'srv12'),/Вход в VPN/);
 assert.match(html,/&lt;private&gt;/);
});
