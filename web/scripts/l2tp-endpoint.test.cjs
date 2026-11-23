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

test('VPN servers and peers share enabled channels in configured order', () => {
  const types = ['wireguard', 'xray', 'ikev2', 'ocserv', 'l2tp'];
  const vpn_servers = types.map(type => ({
    id: type, type, config: {}, peers: [{id: 'peer', name: 'test', channel: 'second'}],
  }));
  let reads = 0;
  const renderPage = (servers, disabled) => {
    reads = 0;
    const channels = ['second', 'off', 'first'].map(id => ({
      id, name: 'channel-' + id, get enabled() { reads++; return id !== disabled; },
    }));
    return renderToStaticMarkup(React.createElement(VPNServersPage, {
      config: {channels, vpn_servers: servers}, patch() {},
    }));
  };
  for (const disabled of ['off', 'second']) {
    const html = renderPage(vpn_servers, disabled);
    assert.equal(reads, 3);
    const selects = [...html.matchAll(/<select\b[^>]*>([\s\S]*?)<\/select>/g)]
      .map(match => [...match[1].matchAll(/>channel-([^<]+)<\/option>/g)].map(option => option[1]))
      .filter(options => options.length > 0);
    assert.equal(selects.length, 2 * types.length);
    for (const options of selects) {
      assert.deepEqual(options, ['second', 'off', 'first'].filter(id => id !== disabled));
    }
  }
  renderPage([], 'off');
  assert.equal(reads, 0);
});
