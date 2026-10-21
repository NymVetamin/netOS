const assert=require('node:assert/strict');
const path=require('node:path');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const code=buildSync({entryPoints:[path.join(__dirname,'../src/chartProbe.ts')],bundle:true,platform:'node',format:'cjs',write:false});
const loaded={exports:{}};
new Function('module','exports',code.outputFiles[0].text)(loaded,loaded.exports);
const {probeChart}=loaded.exports;
test('pointer follows the visible segment continuously, not nearest sample',()=>{
 const points=[{at:10,value:100},{at:11,value:300}];
 assert.equal(probeChart(points,10.25),150);
 assert.equal(probeChart(points,10.75),250);
 assert.equal(probeChart(points,11),300);
});
test('does not manufacture values outside data or across collection failures',()=>{
 assert.equal(probeChart([],1),null);
 assert.equal(probeChart([{at:1,value:0},{at:5,value:50}],3),null);
 assert.equal(probeChart([{at:1,value:0},{at:2,value:null}],1.5),null);
 assert.equal(probeChart([{at:1,value:0}],2),null);
});
