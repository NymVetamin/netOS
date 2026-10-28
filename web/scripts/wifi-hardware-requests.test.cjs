const assert=require('node:assert/strict');const {test}=require('node:test');const path=require('node:path');const {buildSync}=require('esbuild');
const code=buildSync({entryPoints:[path.join(__dirname,'../src/wifiHardwareRequests.ts')],bundle:true,platform:'node',format:'cjs',write:false}).outputFiles[0].text;
const loaded={exports:{}};new Function('module','exports','require',code)(loaded,loaded.exports,require);const create=loaded.exports.createWiFiHardwareRequests;
function fixture(){const calls=[];const get=create((country,signal)=>new Promise((resolve,reject)=>calls.push({country,signal,resolve,reject})));return{get,calls}}
const data={radios:[],countries:['US'],country:'US'};
test('same-country requests share in flight, different countries remain independent',async()=>{
 const {get,calls}=fixture();const a=get('US'),b=get('US'),c=get('FI');assert.equal(calls.length,2);assert.equal(a.result,b.result);a.release();a.release();assert.equal(calls[0].signal.aborted,false);calls[0].resolve(data);assert.equal(await b.result,data);b.release();assert.equal(calls[1].signal.aborted,false);c.release();assert.equal(calls[1].signal.aborted,true);calls[1].resolve(data);await c.result;
 const next=get('US');assert.equal(calls.length,3);calls[2].resolve(data);await next.result;next.release();
});
test('last reader cancels and a stale completion cannot remove its replacement',async()=>{
 const {get,calls}=fixture();const a=get('US'),b=get('US');a.release();b.release();assert.equal(calls[0].signal.aborted,true);const next=get('US');assert.equal(calls.length,2);calls[0].resolve(data);await a.result;const joined=get('US');assert.equal(joined.result,next.result);assert.equal(calls.length,2);calls[1].resolve(data);await next.result;next.release();joined.release();
});
test('errors reach every reader, retry is fresh, completed results are not cached',async()=>{
 const {get,calls}=fixture();const a=get('US'),b=get('US');const failure=new Error('hardware failed');calls[0].reject(failure);await assert.rejects(a.result,e=>e===failure);await assert.rejects(b.result,e=>e===failure);a.release();b.release();const retry=get('US');assert.equal(calls.length,2);calls[1].resolve(data);await retry.result;const fresh=get('US');assert.equal(calls.length,3);retry.release();assert.equal(calls[2].signal.aborted,false);calls[2].resolve(data);await fresh.result;fresh.release();
});
