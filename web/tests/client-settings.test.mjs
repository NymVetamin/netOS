import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {test} from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
const exports={};
vm.runInNewContext(ts.transpileModule(readFileSync(new URL('../src/clientSettings.ts',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText,{exports});
const update=exports.updateClientSettings,mac='02:00:00:00:00:01';
test('new override disappears after undo, including inferred network and serialized reload',()=>{
 for(const network of ['', 'lan']) {
  let cfg={clients:[]};
  for(const [key,on,off] of [['blocked',true,false],['channel','block',''],['down_kbit',1000,0],['name','phone',''],['comment','note','']]){
   update(cfg,mac,{[key]:on},network,new Set()); assert.equal(cfg.clients.length,1);
   cfg=JSON.parse(JSON.stringify(cfg));
   update(cfg,mac,{[key]:off},network,new Set());assert.equal(cfg.clients.length,0);
  }
 }
});
test('undo preserves other settings, applied entries and unknown future fields',()=>{
 const cfg={clients:[]};update(cfg,mac,{name:'phone',blocked:true},'lan',new Set());update(cfg,mac,{blocked:false},'lan',new Set());assert.equal(cfg.clients[0].name,'phone');
 update(cfg,mac,{name:''},'lan',new Set([mac]));assert.equal(cfg.clients.length,1);
 update(cfg,mac,{future_setting:false},'lan',new Set());assert.equal(cfg.clients.length,1);
});
test('default edit does not insert a record; case-insensitive MAC uses original identity',()=>{
 const cfg={clients:[]};update(cfg,mac,{blocked:false},'',new Set());assert.equal(cfg.clients.length,0);
 const existing={id:'saved',mac:'AA:BB:CC:DD:EE:FF',name:'',blocked:false,up_kbit:0,down_kbit:0};cfg.clients.push(existing);
 update(cfg,'aa:bb:cc:dd:ee:ff',{blocked:true},'',new Set(['aa:bb:cc:dd:ee:ff']));update(cfg,'aa:bb:cc:dd:ee:ff',{blocked:false},'',new Set(['aa:bb:cc:dd:ee:ff']));assert.equal(cfg.clients.length,1);assert.equal(cfg.clients[0],existing);
});
