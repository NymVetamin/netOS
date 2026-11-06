import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import vm from "node:vm";
import ts from "typescript";
import {test} from "node:test";

const exports={};
vm.runInNewContext(ts.transpileModule(readFileSync(new URL('../src/wireGuardPeerChannels.ts',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText,{exports});
const sync=exports.syncWireGuardPeerChannels;
const fixture=n=>({channels:[],vpn_servers:Array.from({length:n},(_,i)=>({id:`s${i}`,index:i+1,type:'wireguard',peers:[{id:'vps',name:'VPS',use_as_channel:true}]}))});
test('stable channels preserve user settings; removal cleans only their managed NAT',()=>{
 const c=fixture(2);sync(c);
 assert.equal(c.channels.length,2);assert.notEqual(c.channels[0].index,c.channels[1].index);
 c.channels[0].name='Europe';c.channels[0].probe.interval=23;
 const before=JSON.stringify(c);sync(c);assert.equal(JSON.stringify(c),before);
 c.firewall={nat:[{id:'channel-nat-wg-exit-s0',system:true,interface:'wg-srv1'},{id:'manual',system:false,interface:'wg-srv1'}]};
 c.vpn_servers[0].peers[0].use_as_channel=false;sync(c);
 assert.equal(c.channels.length,1);assert.equal(c.firewall.nat.length,1);assert.equal(c.firewall.nat[0].id,'manual');
});
test('ordinary channels are not rewritten',()=>{
 const c=fixture(1);c.channels=[{id:'normal',index:2,config:{private_key:'test'},enabled:false}];
 const original=JSON.stringify(c.channels[0]);sync(c);assert.equal(JSON.stringify(c.channels[0]),original);assert.equal(c.channels[1].index,1);
});
for(const size of [25,2500]){
 const c=fixture(size);sync(c);for(let i=0;i<10;i++)sync(c);
 const start=performance.now();for(let i=0;i<100;i++)sync(c);
 console.log(`normalize ${size}: ${((performance.now()-start)/100).toFixed(3)} ms/op`);
}
