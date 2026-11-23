const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs'),path=require('node:path');
const source=fs.readFileSync(path.join(__dirname,'../src/pages/TrafficMonitor.tsx'),'utf8');
const effects=source.slice(source.indexOf(' const interfaceKey='),source.indexOf(' const to=hold'));
const run=new Function('useEffect','api','query','interfaces','selected','details','hold','setInternet','setError','setClients','setClientError','setInterval','clearInterval',effects);
const flush=()=>new Promise(resolve=>setImmediate(resolve));
function harness(){
 const requests=[],timers=new Map(),values={};let active=[],nextTimer=0;
 const request=(type,query,signal)=>new Promise((resolve,reject)=>requests.push({type,query,signal,resolve,reject}));
 const api={secondHistory:(q,s)=>request('internet',q,s),clientStatistics:(q,ids,details,s)=>request('clients',q,s)};
 const state={query:'minutes=3',interfaces:['eth0'],selected:null,details:false,hold:null};
 const close=()=>{active.forEach(e=>e.cleanup?.());active=[]};
 const render=(patch={})=>{
  Object.assign(state,patch);const next=[];
  run((fn,deps)=>next.push({fn,deps}),api,...['query','interfaces','selected','details','hold'].map(k=>state[k]),
   v=>values.internet=v,v=>values.error=v,v=>values.clients=v,v=>values.clientError=v,
   (fn,ms)=>{assert.equal(ms,30000);timers.set(++nextTimer,fn);return nextTimer},id=>timers.delete(id));
  active=next.map((e,i)=>{
   const old=active[i];if(old&&e.deps.length===old.deps.length&&e.deps.every((v,j)=>Object.is(v,old.deps[j])))return old;
   old?.cleanup?.();return {...e,cleanup:e.fn()};
  });
 };
 return {requests,timers,values,render,close,tick:async()=>{for(const fn of [...timers.values()])void fn();await flush()}};
}
test('details/selection leave internet request alive; obsolete client responses are ignored',async()=>{
 const h=harness();h.render();assert.equal(h.requests.length,2);
 const [internet,client]=h.requests;h.render({details:true});
 assert.equal(h.requests.length,3);assert.equal(internet.signal.aborted,false);assert.equal(client.signal.aborted,true);
 client.resolve('obsolete');internet.resolve('history');h.requests[2].resolve('details');await flush();
 assert.deepEqual(h.values,{internet:'history',error:'',clients:'details',clientError:''});
 h.render({selected:['a']});assert.equal(h.requests.length,4);assert.equal(h.requests[3].type,'clients');
 h.close();h.requests[3].resolve('late');await flush();assert.equal(h.values.clients,'details');assert.equal(h.timers.size,0);
});
test('polls never overlap per endpoint and recover independently after failure',async()=>{
 const h=harness();h.render();await h.tick();assert.equal(h.requests.length,2);
 h.requests[0].reject(new Error('network'));await flush();assert.ok(h.values.error);
 await h.tick();assert.equal(h.requests.length,3);assert.equal(h.requests[2].type,'internet');
 h.requests[2].resolve('retry');h.requests[1].resolve('clients');await flush();assert.equal(h.values.error,'');
 await h.tick();assert.equal(h.requests.length,5);await h.tick();assert.equal(h.requests.length,5);
 h.close();h.requests[3].resolve('late');h.requests[4].reject(new Error('late'));await flush();
 assert.equal(h.values.internet,'retry');assert.equal(h.values.clientError,'');
});
test('range, interface, hold, resume and remount preserve cancellation and freshness',async()=>{
 const h=harness();h.render();const first=h.requests.slice();
 h.render({query:'minutes=5'});assert.ok(first.every(r=>r.signal.aborted));
 first.forEach(r=>r.resolve('old'));await flush();assert.equal(h.values.internet,undefined);
 h.render({hold:{},query:'from=1&to=2'});assert.equal(h.requests.at(-1).type,'clients');assert.equal(h.timers.size,1);
 const count=h.requests.length;h.render({details:true});assert.equal(h.requests.length,count+1);
 h.render({hold:null,query:'minutes=5'});assert.equal(h.timers.size,2);
 const resumed=h.requests.slice(-2);h.render({interfaces:['eth1']});assert.ok(resumed.every(r=>r.signal.aborted));
 h.close();const before=h.requests.length;h.render();assert.equal(h.requests.length,before+2);h.close();
});
