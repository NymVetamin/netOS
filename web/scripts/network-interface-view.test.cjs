const fs=require('fs'),assert=require('node:assert/strict'),esbuild=require('esbuild');
function load(source){const c=esbuild.transformSync(source,{loader:'ts',format:'cjs'}).code,m={exports:{}};new Function('module','exports',c)(m,m.exports);return m.exports;}
const legacy = `
function masterOf(config: any, id: string): any {
  return (config.interfaces || []).find(
    (i: any) =>
      (i.type === "bridge" || i.type === "bond") && (i.members || []).includes(id),
  );
}
function usageOf(config: any, iface: any): string {
  const parts: string[] = [];
  const master = masterOf(config, iface.id);
  if (master) parts.push((master.type === "bond" ? "в агрегации " : "в мосту ") + master.name);
  const wan = (config.wans || []).find((w: any) => w.interface === iface.id);
  if (wan) parts.push("аплинк «" + wan.name + "»");
  const net = (config.networks || []).find((n: any) => n.interface === iface.id);
  if (net) parts.push("сегмент «" + net.name + "»");
  const vlans = (config.interfaces || []).filter(
    (i: any) => i.type === "vlan" && i.parent === iface.id,
  );
  if (vlans.length > 0) parts.push("VLAN " + vlans.map((v: any) => v.name).join(", "));
  return parts.join(", ");
}
function ifaceOptions(config: any, selected: string): any[] {
  return (config.interfaces || []).filter(
    (i: any) => i.id === selected || !masterOf(config, i.id),
  );
}
`;
const old=load(legacy+'\nexport {usageOf,ifaceOptions};');
const path=require('node:path');
const {networkInterfaceView}=load(fs.readFileSync(path.join(__dirname,'../src/networkInterfaceView.ts'),'utf8'));
require('node:test')('network view preserves labels and selected ports for incomplete drafts',()=>{
let seed=7321;const rand=n=>{seed=(Math.imul(seed,1664525)+1013904223)>>>0;return seed%n};const pick=a=>a[rand(a.length)];
for(let trial=0;trial<1000;trial++){
 const ids=[undefined,'','a','b','c','d'];
 const config={interfaces:Array.from({length:rand(15)},()=>({id:pick(ids),name:'if'+rand(20),type:pick(['physical','vlan','bridge','bond']),members:Array.from({length:rand(5)},()=>pick(ids)),parent:pick(ids)})),wans:Array.from({length:rand(5)},()=>({name:'WAN'+rand(5),interface:pick(ids)})),networks:Array.from({length:rand(5)},()=>({name:'LAN'+rand(5),interface:pick(ids)}))};
 const view=networkInterfaceView(config);for(const i of config.interfaces)assert.equal(view.usage(i),old.usageOf(config,i));for(const id of ids)assert.deepEqual(view.options(id),old.ifaceOptions(config,id));
}
const c={interfaces:[{id:'p',type:'physical',name:'eth0'},{id:'br',type:'bridge',name:'br0',members:['p']}],wans:[],networks:[]};
const first=networkInterfaceView(c);
assert.equal(first.usage(c.interfaces[0]),'в мосту br0');
assert.deepEqual(first.options('p'),c.interfaces);
const next={...c,interfaces:[c.interfaces[0],{...c.interfaces[1],members:[]}]};
assert.equal(networkInterfaceView(next).usage(next.interfaces[0]),'');
assert.equal(first.usage(c.interfaces[0]),'в мосту br0');
});

require('node:test')('system names are separate from labels and use the first matching interface',()=>{
 const first={id:'lan',name:'br-lan',label:'Local bridge',type:'bridge'},duplicate={id:'lan',name:'wrong',label:'Wrong'};
 const cfg={interfaces:[first,duplicate]};const view=networkInterfaceView(cfg);
 assert.equal(view.name('lan'),'br-lan');assert.equal(view.displayName('lan'),'Local bridge (br-lan)');
 assert.equal(view.name('missing'),undefined);assert.equal(view.displayName('missing'),'не выбран');
 const next=networkInterfaceView({interfaces:[{...first,name:'br-new',label:''}]});
 assert.equal(next.name('lan'),'br-new');assert.equal(next.displayName('lan'),'br-new');assert.equal(view.name('lan'),'br-lan');
 assert.equal(networkInterfaceView({}).name('lan'),undefined);
});

require('node:test')('VLAN creation uses valid IDs on eligible parents and recognizes exhaustion', () => {
  const { nextVlan } = load(fs.readFileSync(path.join(__dirname, '../src/networkInterfaceView.ts'), 'utf8'));
  const p = {id: 'p', name: 'eth0', type: 'physical'};
  const q = {id: 'q', name: 'eth1', type: 'physical'};
  const tag = (vlan_id, parent = p.id) => ({type: 'vlan', parent, vlan_id, id: parent + '.' + vlan_id, enabled: false});
  const interfaces = [p, q];
  const next = () => nextVlan({interfaces});
  assert.deepEqual(next(), {parent: p, vlanID: 100});
  for (let i = 100; i < 4094; i++) interfaces.push(tag(i));
  assert.deepEqual(next(), {parent: p, vlanID: 4094});
  interfaces.push(tag(4094));
  assert.deepEqual(next(), {parent: p, vlanID: 1});
  for (let i = 1; i <= 99; i++) interfaces.push(tag(i));
  interfaces.push(tag(100, q.id));
  assert.deepEqual(next(), {parent: q, vlanID: 101});
  interfaces.splice(1, 1);
  assert.deepEqual(next(), {reason: 'full'});
  interfaces.splice(interfaces.findIndex(i => i.vlan_id === 42), 1);
  assert.deepEqual(next(), {parent: p, vlanID: 42});
  const bridge = {id: 'br', type: 'bridge', members: [p.id]};
  assert.deepEqual(nextVlan({interfaces: [p, bridge, tag(100, 'br')]}), {parent: bridge, vlanID: 101});
  assert.deepEqual(nextVlan({interfaces: [tag(1)]}), {reason: 'no-parent'});
});

require('node:test')('bridge membership reasons and VLAN choices follow the current draft', () => {
  const port = {id: 'p', type: 'physical', name: 'eth0', label: ' first '};
  const duplicateName = {id: 'q', type: 'physical', name: 'eth0', label: 'second'};
  const bridge = {id: 'br', type: 'bridge', name: 'br0', members: ['p']};
  const bond = {id: 'bond', type: 'bond', name: 'bond0', members: ['p']};
  const child = {id: 'v', type: 'vlan', name: 'br0.1', parent: 'br'};
  const cfg = {interfaces: [port, duplicateName, bridge, bond, child],
    wans: [{interface: 'p'}], networks: [{interface: 'p', name: 'LAN'}, {interface: 'p', name: 'duplicate'}]};
  const initial = networkInterfaceView(cfg);
  assert.equal(initial.memberBlocker('p', 'bond'), 'уже в br0');
  assert.equal(initial.memberBlocker('p', 'br'), 'занят аплинком');
  assert.deepEqual(initial.vlanParents('v'), [duplicateName, bridge, bond]);
  assert.equal(initial.labelForName('eth0'), ' first ');
  cfg.interfaces = [duplicateName, port, {...bridge, members: []}, {...bond, members: []}, child];
  cfg.wans = [];
  const edited = networkInterfaceView(cfg);
  assert.equal(edited.memberBlocker('p', 'br'), 'занят сегментом «LAN»');
  assert.equal(edited.memberBlocker('q', 'br'), '');
  assert.equal(edited.labelForName('eth0'), 'second');
  assert.deepEqual(edited.vlanParents('v'), cfg.interfaces.slice(0, 4));
  assert.equal(initial.memberBlocker('p', 'bond'), 'уже в br0');
});
