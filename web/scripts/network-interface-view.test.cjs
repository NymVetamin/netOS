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
