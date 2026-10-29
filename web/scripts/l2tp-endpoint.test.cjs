const assert=require('node:assert/strict');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const path=require('node:path');
const React=require('react');
const {renderToStaticMarkup}=require('react-dom/server');
const bundle=buildSync({stdin:{contents:`export {VPNServersPage} from './src/pages/VPNServers';export {newVPNEndpoint} from './src/vpnEndpoint';`,resolveDir:path.join(__dirname,'..'),loader:'tsx'},bundle:true,platform:'node',format:'cjs',external:['react','react/jsx-runtime'],write:false});
const loaded={exports:{}};
new Function('require','module','exports',bundle.outputFiles[0].text)(require,loaded,loaded.exports);
const {newVPNEndpoint,VPNServersPage}=loaded.exports;
function render(endpoint,listen='0.0.0.0'){
 const config={components:[{id:'l2tp',installed:true},{id:'strongswan',installed:true}],channels:[],vpn_servers:[{id:'l2',type:'l2tp',name:'L2TP test',index:1,enabled:true,subnet:'10.99.0.1/24',peers:[],config:{listen,ipsec:true,public_endpoint:endpoint}}]};
 return renderToStaticMarkup(React.createElement(VPNServersPage,{config,patch:()=>assert.fail('render changed existing configuration'),beforeRead:async()=>{}}));
}
test('all new VPN types format DNS/IP with the VPN port, not the panel port',()=>{
 for(const host of ['vpn.example.com','203.0.113.10'])for(const type of ['wireguard','ocserv','xray','ikev2','l2tp']){
  assert.equal(newVPNEndpoint({type,port:12345},host),['ikev2','l2tp'].includes(type)?host:host+':12345');
 }
 assert.equal(newVPNEndpoint({type:'xray',port:1080,config:{listen:'127.0.0.1'}},'vpn.example.com'),'127.0.0.1:1080');
 assert.equal(newVPNEndpoint({type:'xray',port:443,config:{listen:'::1'}},'vpn.example.com'),'[::1]:443');
 assert.equal(newVPNEndpoint({type:'l2tp',config:{listen:'0.0.0.0'}},''),'');
});
test('L2TP displays configured connection address independently of wildcard listener',()=>{
 const html=render('vpn.example.com');const summary=html.match(/<summary class="xsum">([\s\S]*?)<\/summary>/)[1];
 assert.match(summary,/vpn\.example\.com/);assert.doesNotMatch(summary,/0\.0\.0\.0/);
});
test('opening existing blank server does not invent or save an address',()=>{
 const html=render('');assert.match(html.match(/<summary class="xsum">([\s\S]*?)<\/summary>/)[1],/>—</);
 assert.match(render('','192.168.20.1').match(/<summary class="xsum">([\s\S]*?)<\/summary>/)[1],/192\.168\.20\.1/);
});
