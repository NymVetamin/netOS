const assert = require('node:assert/strict');
const path = require('node:path');
const {test} = require('node:test');
const {buildSync} = require('esbuild');
const code = buildSync({entryPoints:[path.join(__dirname,'../src/pages/Routing.tsx')],bundle:true,platform:'node',format:'cjs',write:false,jsx:'automatic',external:['react','react/jsx-runtime','react-dom']});
const loaded={exports:{}};
new Function('module','exports','require',code.outputFiles[0].text)(loaded,loaded.exports,require);
const {routeInterfaceOptions}=loaded.exports;

// A route back to a netOS server must be able to point at the channel tunnel
// (wg-ch1), not only at ports: the name used to be typed by hand.
test('route interfaces list ports, PPP sessions, channels and WireGuard servers once each',()=>{
 const config={
  interfaces:[{id:'p1',name:'eth0',label:'Провайдер'},{id:'p2',name:'br-lan'}],
  wans:[{id:'w1',name:'Ростелеком',proto:'pppoe'},{id:'w2',name:'DHCP',proto:'dhcp'}],
  channels:[{id:'direct',type:'direct',index:0,name:'Напрямую'},{id:'c1',type:'wireguard',index:1,name:'WireGuard 1'},{id:'c2',type:'xray',index:2,name:'Xray'},
   {id:'wg-exit-s1',type:'wireguard',index:3,name:'test',wireguard_peer:{server_id:'s1',peer_id:'p',server_index:1}}],
  vpn_servers:[{id:'s1',type:'wireguard',index:1,name:'Дом'},{id:'s2',type:'ocserv',index:2,name:'OC'}],
 };
 const names=routeInterfaceOptions(config).map(o=>o.name);
 assert.deepEqual(names,['eth0','br-lan','ppp-w1','wg-ch1','tun-ch2','wg-srv1']);
 assert.equal(routeInterfaceOptions(config).find(o=>o.name==='eth0').label,'Провайдер (eth0)');
 assert.match(routeInterfaceOptions(config).find(o=>o.name==='wg-ch1').label,/канал «WireGuard 1»/);
 assert.deepEqual(routeInterfaceOptions({}),[]);
});
test('route inactivity follows the device owner when the draft changes',()=>{
 const channel={type:'wireguard',index:1,enabled:false};
 const peer={type:'wireguard',index:2,enabled:false,wireguard_peer:{server_index:1}};
 const server={type:'wireguard',index:1,enabled:true};
 const config={channels:[channel,peer],vpn_servers:[server]};
 const states=()=>routeInterfaceOptions(config).map(o=>o.inactive);
 assert.deepEqual(states(),['Неактивен: канал выключен',undefined]);
 channel.enabled=true;
 server.enabled=false;
 assert.deepEqual(states(),[undefined,'Неактивен: сервер выключен']);
});

test('route interface labels stay fresh and distinct names require linear work', () => {
  let reads = 0;
  const interfaces = Array.from({length: 128}, (_, i) => ({
    get name() { reads++; return `eth${i}`; }, label: ` Port ${i} `,
  }));
  interfaces.push({name: 'eth0', label: 'duplicate'}, {name: '', label: 'unused'});
  const config = {interfaces};
  const options = routeInterfaceOptions(config);
  assert.equal(options.length, 128);
  assert.equal(options[0].label, 'Port 0 (eth0)');
  assert.equal(options[127].name, 'eth127');
  assert.ok(reads <= 4 * interfaces.length, `unexpected name reads: ${reads}`);
  interfaces[0].label = 'eth0';
  assert.equal(routeInterfaceOptions(config)[0].label, 'eth0');
});
