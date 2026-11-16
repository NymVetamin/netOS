const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const code = buildSync({entryPoints:[path.join(__dirname,'../src/pages/Logs.tsx')],bundle:true,platform:'node',format:'cjs',write:false,jsx:'automatic',external:['react','react/jsx-runtime']});
const loaded={exports:{}};
new Function('module','exports','require',code.outputFiles[0].text)(loaded,loaded.exports,require);
const {mergeLog}=loaded.exports;
const ev=seq=>({seq,time:seq,topic:'services',level:'info',source:'s',message:String(seq)});

test('new events go on top, the list is capped, an empty poll keeps it',()=>{
 let list=mergeLog(null,{reset:true,events:[ev(3),ev(2),ev(1)]});
 assert.deepEqual(list.map(e=>e.seq),[3,2,1]);
 assert.equal(mergeLog(list,{reset:false,events:[]}),list);
 list=mergeLog(list,{reset:false,events:[ev(5),ev(4)]});
 assert.deepEqual(list.map(e=>e.seq),[5,4,3,2,1]);
 const full=Array.from({length:1000},(_,i)=>ev(1000-i));
 const next=mergeLog(full,{reset:false,events:[ev(1001)]});
 assert.equal(next.length,1000);assert.equal(next[0].seq,1001);assert.equal(next.at(-1).seq,2);
});

test('reset replaces the list instead of mixing epochs',()=>{
 const list=mergeLog([ev(9),ev(8)],{reset:true,events:[ev(1)]});
 assert.deepEqual(list.map(e=>e.seq),[1]);
 assert.deepEqual(mergeLog(null,{reset:false,events:[]}),[]);
});
