const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const code = buildSync({entryPoints:[path.join(__dirname,'../src/trafficTimeline.ts')],bundle:true,platform:'node',format:'cjs',write:false});
const loaded = {exports:{}};
new Function('module','exports',code.outputFiles[0].text)(loaded,loaded.exports);
const {continueTrafficHistory:join} = loaded.exports;
const at=p=>p.at;
test('initial three minutes retain stored measurements without synthesizing seconds',()=>{
 const history=[0,30,60,90,120,150,180,210].map(at=>({at,value:at}));
 assert.deepEqual(join(history,[],at,30,210),history.slice(1));
});
test('live values replace overlapping historical averages exactly once',()=>{
 const history=[{at:30,value:80},{at:60,value:90},{at:90,value:500}];
 const live=[{at:60,value:20},{at:61,value:40}];
 assert.deepEqual(join(history,live,at,0,100),[history[0],...live]);
 assert.equal(history.length,3);assert.equal(live.length,2);
});
test('missing measurements remain gaps, including later history refresh',()=>{
 const history=[{at:30,value:80},{at:60,value:90},{at:90,value:500}];
 const live=[{at:60,value:20},{at:61,value:null},{at:95,value:40}];
 assert.deepEqual(join(history,live,at,0,100),[history[0],...live]);
});
test('window rolls forward and works with ISO WAN timestamps',()=>{
 const history=[{at:'2026-10-21T00:00:00Z',value:1}];
 const live=[{at:'2026-10-21T00:03:01Z',value:2}];
 const stamp=p=>Date.parse(p.at)/1000;
 assert.deepEqual(join(history,live,stamp,stamp(live[0])-180,stamp(live[0])),live);
 assert.deepEqual(join([],[],at,0,180),[]);
});
