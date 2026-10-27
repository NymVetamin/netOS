const assert=require('node:assert/strict');
const path=require('node:path');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const code=buildSync({entryPoints:[path.join(__dirname,'../src/mapVPN.ts')],bundle:true,platform:'node',format:'cjs',write:false}).outputFiles[0].text;
const loaded={exports:{}};new Function('module','exports',code)(loaded,loaded.exports);
const {vpnMapServers}=loaded.exports;

function legacy(config, telemetry) {
  return (config.vpn_servers || []).map((server) => ({
    id: server.id, name: server.name || server.id, type: server.type, enabled: !!server.enabled,
    subnet: server.subnet || "", server,
    peers: (server.peers || []).map((peer) => {
      const live = (telemetry[server.id] || []).find(row => row.id === peer.id &&
        (!peer.credentials?.public_key || row.public_key === peer.credentials.public_key));
      const state = !server.enabled ? "server_disabled" : !peer.enabled ? "disabled" : live?.state || "unknown";
      const labels = { online: "онлайн", offline: "оффлайн", recent: "недавно на связи", idle: "давно нет handshake", never: "ещё не подключался", disabled: "доступ запрещён", server_disabled: "сервер выключен", unknown: "состояние неизвестно" };
      return { id: peer.id, name: peer.name || peer.id, address: peer.address || "", state, label: labels[state] || labels.unknown,
        endpoint: live?.endpoint || "", handshake: live?.last_seen || live?.last_handshake || 0, trafficKnown: live?.traffic_known ?? !!live?.last_handshake, received: live?.received || 0, sent: live?.sent || 0, peer };
    }),
  }));
}

test('map peers preserve whole output and object references across telemetry changes',()=>{
const peers=Array.from({length:60},(_,i)=>({id:'p'+(i%20),name:i%3?'Client '+i:'',enabled:i%4!==0,credentials:{public_key:[undefined,'','old','new'][i%4]}}));
const config={vpn_servers:[{id:'a',enabled:true,peers},{id:'b',enabled:false,peers},{id:'empty',enabled:true}]};
const rows=Array.from({length:90},(_,i)=>({id:'p'+(i%20),public_key:[undefined,'','old','new'][i%4],state:['online','offline','never','mystery',''][i%5],endpoint:'endpoint-'+i,last_seen:i%3?0:42,last_handshake:7,traffic_known:i%2?false:undefined,received:i,sent:2*i}));
for(const telemetry of [{},{a:[]},{a:rows,b:rows},{a:[...rows].reverse()}]){
const actual=vpnMapServers(config,telemetry);assert.deepEqual(actual,legacy(config,telemetry));assert.equal(actual[0].server,config.vpn_servers[0]);assert.equal(actual[0].peers[0].peer,peers[0]);}
assert.deepEqual(vpnMapServers({},{}),[]);
});
