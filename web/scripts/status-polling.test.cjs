const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const code = buildSync({entryPoints:[path.join(__dirname,'../src/statusPolling.ts')],bundle:true,platform:'node',format:'cjs',write:false});
const loaded={exports:{}};
new Function('module','exports',code.outputFiles[0].text)(loaded,loaded.exports);
const {createStatusPoller}=loaded.exports;
const settle=()=>new Promise(resolve=>setImmediate(resolve));
const receive=(list)=>p=>{void p.then(v=>list.push(v)).catch(e=>list.push(e.message));};
function clock(t){t.mock.timers.enable({apis:['setTimeout','Date'],now:0});return async ms=>{t.mock.timers.tick(ms);await settle();};}

test('5s page and 10s header share requests but retain their delivery cadence',async t=>{
 const tick=clock(t), calls=[],header=[],page=[];
 const poller=createStatusPoller(async overview=>{calls.push(overview);return calls.length;});
 const offHeader=poller.subscribe(10000,false,receive(header));
 const offPage=poller.subscribe(5000,true,receive(page));
 await tick(0);for(let i=0;i<6;i++)await tick(5000);
 assert.equal(calls.length,7);assert(calls.every(Boolean));
 assert.deepEqual(header,[1,3,5,7]);assert.deepEqual(page,[1,2,3,4,5,6,7]);
 offPage();await tick(10000);assert.equal(calls.at(-1),false);assert.equal(calls.length,8);
 offHeader();await tick(30000);assert.equal(calls.length,8);
});

test('navigation starts immediately then aligns with the shared cadence',async t=>{
 const tick=clock(t),calls=[];
 const poller=createStatusPoller(async overview=>{calls.push({at:Date.now(),overview});return Date.now();});
 const offHeader=poller.subscribe(10000,false,receive([]));await tick(0);await tick(2000);
 const offPage=poller.subscribe(5000,false,receive([]));await tick(0);await tick(3000);await tick(5000);
 assert.deepEqual(calls.map(c=>c.at),[0,2000,5000,10000]);
 offPage();offHeader();
});

test('maintenance 1s and update 2s periods share status with the 10s header',async t=>{
 const tick=clock(t),restore=[],update=[],header=[];let calls=0;
 const poller=createStatusPoller(async()=>++calls);
 const off=[poller.subscribe(1000,false,receive(restore)),poller.subscribe(2000,false,receive(update)),poller.subscribe(10000,false,receive(header))];
 await tick(0);for(let i=0;i<10;i++)await tick(1000);
 assert.equal(calls,11);assert.equal(restore.length,11);assert.equal(update.length,6);assert.equal(header.length,2);off.forEach(f=>f());
});

test('slow requests never overlap; a compatible new subscriber joins in-flight data',async t=>{
 const tick=clock(t),calls=[],a=[],b=[];
 const poller=createStatusPoller((overview,signal)=>new Promise(resolve=>calls.push({overview,signal,resolve})));
 const offA=poller.subscribe(5000,true,receive(a));await tick(0);await tick(12000);
 const offB=poller.subscribe(10000,false,receive(b));await tick(0);assert.equal(calls.length,1);
 calls[0].resolve('shared');await settle();assert.deepEqual(a,['shared']);assert.deepEqual(b,['shared']);
 await tick(0);assert.equal(calls.length,2);offA();offB();assert(calls[1].signal.aborted);
});

test('overview subscriber never receives an incomplete basic in-flight response',async t=>{
 const tick=clock(t),calls=[],page=[];
 const poller=createStatusPoller((overview,signal)=>new Promise(resolve=>calls.push({overview,signal,resolve})));
 const offHeader=poller.subscribe(10000,false,receive([]));await tick(0);
 const offPage=poller.subscribe(5000,true,receive(page));calls[0].resolve('basic');await settle();
 assert.deepEqual(page,[]);await tick(0);assert.equal(calls[1].overview,true);
 calls[1].resolve('full');await settle();assert.deepEqual(page,['full']);offPage();offHeader();
});

test('failure is delivered and next poll retries without a cached success',async t=>{
 const tick=clock(t),values=[];let count=0;
 const poller=createStatusPoller(async()=>{if(++count===1)throw Error('offline');return 'recovered';});
 const off=poller.subscribe(5000,false,receive(values));await tick(0);await tick(5000);
 assert.deepEqual(values,['offline','recovered']);assert.equal(count,2);off();
});

test('last unsubscribe aborts; old completion cannot cancel the new session stream',async t=>{
 const tick=clock(t),calls=[];
 const fetcher=(overview,signal)=>new Promise(resolve=>calls.push({overview,signal,resolve}));
 const old=createStatusPoller(fetcher),offOld=old.subscribe(5000,true,receive([]));await tick(0);
 offOld();assert(calls[0].signal.aborted);
 const fresh=createStatusPoller(fetcher),values=[],offNew=fresh.subscribe(10000,false,receive(values));await tick(0);
 calls[0].resolve('old-user');await settle();assert.deepEqual(values,[]);
 calls[1].resolve('new-user');await settle();assert.deepEqual(values,['new-user']);
 await tick(10000);assert.equal(calls.length,3);offNew();
});
