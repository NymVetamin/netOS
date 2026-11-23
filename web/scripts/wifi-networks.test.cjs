const assert=require('node:assert/strict');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const fs=require('node:fs'),path=require('node:path');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const {createHash}=require('node:crypto');
const dir=path.join(__dirname,'../src/pages');
const source=fs.readFileSync(process.env.WIFI_BASELINE||path.join(dir,'WiFi.tsx'),'utf8');
const code=buildSync({stdin:{contents:source,resolveDir:dir,loader:'tsx'},bundle:true,platform:'node',format:'cjs',jsx:'automatic',external:['react','react/jsx-runtime'],write:false}).outputFiles[0].text;
const loaded={exports:{}};new Function('require','module','exports',code)(require,loaded,loaded.exports);
function render(interfaces,networks,radios=2,hardware={countries:[],radios:[],country:'US'}){
 const config={interfaces,networks,components:[],wifi:Array.from({length:radios},(_,i)=>({id:`r${i}`,device:`wlan${i}`,country:'US',band:'2.4',channel:1,width:20,ssids:[{id:`s${i}`,ssid:`SSID${i}`,network:'net0',security:'open'}]}))};
 const original=React.useState;let call=0;
 React.useState=initial=>original(call++===0?hardware:initial);
 try{return renderToStaticMarkup(React.createElement(loaded.exports.WiFiPage,{config,patch:()=>assert.fail('render wrote config')}))}finally{React.useState=original}
}
test('Wi-Fi bridge choices preserve any matching duplicate, disabled networks and freshness',()=>{
 const networks=[{id:'net0',interface:'same',name:'Home',enabled:true},{id:'net1',interface:'missing',name:'Missing',enabled:true},{id:'off',interface:'same',name:'Disabled network',enabled:false},{id:'nan',interface:NaN,name:'NaN interface',enabled:true}];
 for(let repeat=0;repeat<2;repeat++){
 const interfaces=[{id:'same',type:'physical'},{id:'same',type:'bridge'},{id:NaN,type:'bridge'}];
 const html=render(interfaces,networks);
 assert.match(html,/<option value="net0" selected="">Home<\/option>/);
 assert.match(html,/<option value="net1" disabled="">Missing — нужен мост<\/option>/);
 assert.match(html,/<option value="nan" disabled="">NaN interface — нужен мост<\/option>/);
 assert.doesNotMatch(html,/Disabled network/);
 assert.match(render([{id:'same',type:'physical'}],networks),/<option value="net0" disabled="" selected="">Home — нужен мост<\/option>/);
 assert.match(render([{id:'same',type:'bridge'}],[{...networks[0],name:'Changed'}]),/>Changed<\/option>/);
 }
});
test('hidden or absent editors do not prepare network choices',()=>{
 const interfaces=[{type:'bridge',get id(){assert.fail('unused interface read')}}];
 const networks=[{enabled:true,interface:'bridge',name:'unused'}];
 render(interfaces,networks,0);
 render(interfaces,networks,2,null);
});
test('Wi-Fi page prepares interface membership once for all radios',()=>{
 for(const [radios,n] of [[4,16],[16,256]]){
 let reads=0;const interfaces=Array.from({length:n},(_,i)=>({get id(){reads++;return `if${i}`},type:'bridge'}));
 const networks=Array.from({length:n},(_,i)=>({id:`net${i}`,name:`Network ${i}`,interface:`if${i}`,enabled:true}));
 let html;const ms=[];
 for(let repeat=0;repeat<(process.env.WIFI_BENCH?3:1);repeat++){
 reads=0;const start=performance.now();html=render(interfaces,networks,radios);ms.push(+(performance.now()-start).toFixed(2));
 }
 console.log(JSON.stringify({radios,n,reads,ms,sha256:createHash('sha256').update(html).digest('hex')}));
 if(!process.env.WIFI_BENCH)assert.ok(reads<=2*n,`read ${reads} interface IDs`);
 }
});
