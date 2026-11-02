const assert = require('node:assert/strict');
const { test } = require('node:test');
const { buildSync } = require('esbuild');
const path = require('node:path');
const compiled = buildSync({entryPoints:[path.join(__dirname,'../src/chartPaths.ts')],bundle:true,platform:'node',format:'cjs',write:false});
const loaded = {exports:{}};
new Function('module','exports',compiled.outputFiles[0].text)(loaded,loaded.exports);
const {chartPaths} = loaded.exports;
const draw = points => chartPaths(points,x=>x,v=>100-v,100,1);
test('areas close separately across missing samples and time gaps',()=>{
 const points=[{at:1,value:20},{at:2,value:40},{at:3,value:null},{at:4,value:10},{at:10,value:30},{at:11,value:0}];
 const before=structuredClone(points), result=draw(points);
 assert.equal(result.stroke,'M1.0,80.0 L2.0,60.0 M4.0,90.0 M10.0,70.0 L11.0,100.0');
 assert.equal(result.area,'M1.0,80.0 L2.0,60.0 L2.0,100 L1.0,100 Z M4.0,90.0 L4.0,100 L4.0,100 Z M10.0,70.0 L11.0,100.0 L11.0,100 L10.0,100 Z');
 assert.deepEqual(points,before);
 assert.deepEqual(draw(points),result);
});
test('empty, null, zero and coarse history samples',()=>{
 assert.deepEqual(draw([]),{stroke:'',area:''});
 assert.deepEqual(draw([{at:1,value:null}]),{stroke:'',area:''});
 assert.equal(draw([{at:1,value:0}]).stroke,'M1.0,100.0');
 assert.equal(draw([{at:1,value:10,gap:30},{at:31,value:20}]).stroke,'M1.0,90.0 L31.0,80.0');
});
