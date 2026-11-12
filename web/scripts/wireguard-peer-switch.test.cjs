const assert=require('node:assert/strict'),path=require('node:path');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const compiled=buildSync({entryPoints:[path.join(__dirname,'../src/wireGuardPeerChannels.ts')],bundle:true,platform:'node',format:'cjs',write:false});
const loaded={exports:{}};new Function('module','exports',compiled.outputFiles[0].text)(loaded,loaded.exports);
const {syncWireGuardPeerChannels:sync}=loaded.exports;
function fixture(servers,name='Old'){
 return {vpn_servers:[...servers,{id:'s',index:7,type:'wireguard',peers:[{id:'next',name:'New',use_as_channel:true}]}],channels:[{id:'wg-exit-s',index:9,name,enabled:false,type:'wireguard',probe:{interval:23},fail_mode:'block',wireguard_peer:{server_id:'s',peer_id:'old',server_index:4}}],firewall:{nat:[{id:'channel-nat-wg-exit-s',system:true,interface:'wg-srv4'},{id:'manual',interface:'wg-srv4'}]}};
}
test('switch preserves first server/peer lookup, manual and missing names',()=>{
 for(const [servers,name,want] of [
  [[{id:'s',peers:[{id:'old',name:'Old'},{id:'old',name:'Later'}]}],'Old','New'],
  [[{id:'s',peers:[]},{id:'s',peers:[{id:'old',name:'Old'}]}],'Old','Old'],
  [[], '', ''],
  [[{id:'s',peers:[{id:'old',name:''}]}],'','New'],
  [[{id:'s',peers:[{id:'old'}]}],undefined,'New'],
  [[{id:'s',peers:[{id:'old',name:'Old'}]}],'Manual','Manual'],
 ]){
  const cfg=fixture(servers);cfg.channels[0].name=name;
  cfg.vpn_servers.push({id:'prefix',index:1,type:'wireguard',peers:[{id:'b',name:'Prefix',use_as_channel:true}]});
  cfg.channels.unshift({id:'wg-exit-prefix',index:1,wireguard_peer:{server_id:'prefix',peer_id:'a'}});
  sync(cfg);assert.equal(cfg.channels.length,2);cfg.channels.shift();
  // Keep the focused assertions below on the second (indexed) switch.
  cfg.vpn_servers.pop();
  assert.equal(cfg.channels.length,1);assert.equal(cfg.channels[0].name,want);
  assert.equal(cfg.channels[0].index,9);assert.equal(cfg.channels[0].enabled,false);
  assert.equal(cfg.channels[0].probe.interval,23);assert.equal(cfg.channels[0].fail_mode,'block');
  assert.deepEqual(cfg.channels[0].wireguard_peer,{server_id:'s',peer_id:'next',server_index:7});
  assert.deepEqual(cfg.firewall.nat,[{id:'channel-nat-wg-exit-s',system:true,interface:'wg-srv7'},{id:'manual',interface:'wg-srv4'}]);
  const saved=structuredClone(cfg);sync(cfg);assert.deepEqual(cfg,saved);
 }
});
test('batch switch is linear and fresh across edit, cancellation, load and removal',()=>{
 for(const n of [25,2500]){
  let reads=0;
  const cfg={vpn_servers:Array.from({length:n},(_,i)=>({get id(){reads++;return String(i)},type:'wireguard',index:i+1,peers:[{id:'a',name:'First',use_as_channel:true},{id:'b',name:'Second'}]})),channels:[]};
  sync(cfg);const saved=structuredClone(cfg);
  for(let round=0;round<3;round++){
   for(const s of cfg.vpn_servers){s.peers[0].use_as_channel=round%2===1;s.peers[1].use_as_channel=round%2===0}
   reads=0;sync(cfg);assert.ok(reads<=5*n,`nonlinear server reads: ${reads}`);
   assert.equal(cfg.channels.length,n);
   for(let i=0;i<n;i++){assert.equal(cfg.channels[i].name,round%2?'First':'Second');assert.equal(cfg.channels[i].index,i+1)}
  }
  sync(saved);assert.ok(saved.channels.every(c=>c.name==='First'));
  cfg.vpn_servers=[];sync(cfg);assert.deepEqual(cfg.channels,[]);
 }
});
