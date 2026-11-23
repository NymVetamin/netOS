const assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path'),ts=require('typescript');
const source=fs.readFileSync(path.join(__dirname,'../src/pages/FirewallRules.tsx'),'utf8');
const iface=fs.readFileSync(path.join(__dirname,'../src/interfaceDisplay.ts'),'utf8');
const text=iface+'\n'+source.slice(source.indexOf('const actions:'),source.indexOf('export function AutomaticRuleRow'));
const output=ts.transpileModule(text,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS}}).outputText;
const e={};new Function('exports',output)(e);const include=e.includeAutomatic;
const saved=(id,i)=>({r:{id,enabled:i!==1},i});
const config={interfaces:[],firewall:{zones:[]}};
const line=(name)=>'-A LAN-FWD -m comment --comment "'+name+'" -j ACCEPT';
function data(lines,ids={},family='IPv4',table='filter',chain='LAN-FWD'){
 return {rule_ids:ids,families:[{family,tables:[{name:table,chains:[{name:chain,rules:lines}]}]}]};
}
const groups=[{key:'lan',chain:'LAN-FWD',description:'LAN',items:[saved('a',0),saved('disabled',1),saved('b',2),saved('draft',3)]}];
const ids=items=>items.map(x=>x.automatic?x.r.comment:x.r.id);
const live=data([line('first'),line('B'),line('middle'),line('A'),line('A'),line('last')],{[line('A')]:['a','a'],[line('B')]:['b']});
const baseline=JSON.stringify({groups,live});
const got=include(groups,live,config);
assert.deepEqual(ids(got[0].items),['middle','a','disabled','first','b','draft','last']);
assert.equal(got[0].key,'lan');assert.equal(got[0].items[1],groups[0].items[0]);
assert.equal(JSON.stringify({groups,live}),baseline);
assert.deepEqual(include(groups,live,config),got);
assert.deepEqual(include(groups,{families:[]},config),groups);
const duplicate=structuredClone(groups);duplicate[0].items.push(duplicate[0].items[0]);
assert.deepEqual(ids(include(duplicate,live,config)[0].items),['middle','a','disabled','first','b','draft','a','last']);
const changed=structuredClone(live);changed.rule_ids[line('A')]=['draft','draft'];
assert.deepEqual(ids(include(groups,changed,config)[0].items),['a','disabled','first','b','middle','draft','last']);
assert.deepEqual(include(groups,live,config),got);
const v6=include(groups,data([line('A')],{[line('A')]:['a']},'IPv6'),config);
assert.equal(v6.length,2);assert.equal(v6[1].items[0].automatic,true);
const natGroups=[{key:'nat',chain:'POSTROUTING',description:'NAT',items:[saved('a',0),saved('off',1)]}];
const nat=data([line('before'),line('A'),line('after')],{[line('A')]:['a']},'IPv4','nat','POSTROUTING');
assert.deepEqual(ids(include(natGroups,nat,config,'nat')[0].items),['before','a','off','after']);
assert.deepEqual(include(natGroups,nat,config),natGroups);
const jump=data(['-A INPUT -j LAN-FWD']);jump.families[0].tables[0].chains.push({name:'INPUT',rules:[]});
assert.deepEqual(include(groups,jump,config),groups);
console.log('includeAutomatic: order, duplicate IDs/references, disabled/draft rows, keys, repeated calls, immutability, IPv6, NAT, zone jumps PASS');

const duplicateGroups = [
 {key:'first',chain:'LAN-FWD',description:'first',items:[saved('a',0)]},
 {key:'second',chain:'LAN-FWD',description:'second',items:[saved('b',1)]},
];
const dupeResult = include(duplicateGroups,data([line('extra')]),config);
assert.deepEqual(ids(dupeResult[0].items),['a','extra']);
assert.deepEqual(ids(dupeResult[1].items),['b']);
const earlier = {families:[
 {family:'IPv6',tables:[{name:'filter',chains:[{name:'LAN-FWD',rules:[line('v6')]}]}]},
 {family:'IPv4',tables:[{name:'filter',chains:[{name:'LAN-FWD',rules:[line('v4')]}]}]},
]};
const reused = include([],earlier,config);
assert.equal(reused.length,1);
assert.equal(reused[0].key,'auto:IPv6:filter:LAN-FWD');
assert.deepEqual(ids(reused[0].items),['v6','v4']);
assert.deepEqual(include([],earlier,config),reused);
const repeatedTables={families:[{family:'IPv4',tables:[
 {name:'filter',chains:[{name:'LAN-FWD',rules:[line('one')]},{name:'EMPTY-IN',rules:[]}]},
 {name:'filter',chains:[{name:'LAN-FWD',rules:[line('two')]}]},
]}]};
const repeatedResult=include([],repeatedTables,config);
assert.equal(repeatedResult.length,1);
assert.deepEqual(ids(repeatedResult[0].items),['one','two']);
assert.deepEqual(include([],repeatedTables,config),repeatedResult);

const crypto=require('node:crypto');
for (const n of [16,512]) {
 let reads=0;
 const gs=Array.from({length:n},(_,i)=>({key:`g${i}`,get chain(){reads++;return `Z${i}-FWD`},description:'zone',items:[saved(`r${i}`,i)]}));
 const chains=Array.from({length:n},(_,i)=>({get name(){reads++;return `Z${i}-FWD`},rules:[`-A Z${i}-FWD -j ACCEPT`,`-A Z${i}-FWD -j Z${n-1}-FWD`]}));
 const input={families:[{family:'IPv4',tables:[{name:'filter',chains}]}]};
 const ms=[];let result;
 for(let repeat=0;repeat<(process.env.FIREWALL_BENCH?7:1);repeat++) {
  reads=0;const start=performance.now();result=include(gs,input,config);ms.push(+(performance.now()-start).toFixed(3));
 }
 console.log(JSON.stringify({n,reads,ms,sha256:crypto.createHash('sha256').update(JSON.stringify(result)).digest('hex')}));
 if(!process.env.FIREWALL_BENCH)assert.ok(reads<=12*n,`${reads} chain reads for ${n}`);
}
