import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {createRequire} from 'node:module';
import {test} from 'node:test';
import vm from 'node:vm';
import ts from 'typescript';
import {renderToStaticMarkup} from 'react-dom/server';
import React from 'react';
const require=createRequire(import.meta.url);
const exports={};
vm.runInNewContext(ts.transpileModule(readFileSync(new URL('../src/pages/DomainChart.tsx',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022,jsx:ts.JsxEmit.ReactJSX}}).outputText,{exports,require:id=>id==='../ui'?{Empty:({children})=>children}:require(id)});
const {domainCountsByClient,DomainChart}=exports;
const record=(client,domain,count,source='xray-domain')=>({client,domain,count,source});
function check(records,expected){
 const counts=domainCountsByClient(records);
 assert.deepEqual(Object.fromEntries(counts),expected);
 const total=Object.values(expected).reduce((a,b)=>a+b,0);
 const html=renderToStaticMarkup(React.createElement(DomainChart,{records}));
 assert.ok(html.includes(`: ${total}`),html);
}
test('Xray-only client has 31 domain requests in both table data and chart',()=>{
 check([record('phone','www.google.com',20),record('phone','api.apple.com',11,'xray-dns'),record('phone','192.0.2.1',8,'xray-ip')],{phone:31});
});
test('mixed sources, clients and filtered records agree with chart total',()=>{
 const records=[record('a','a.example.com',3,'dns'),record('a','b.example.com',2),record('b','api.bbc.co.uk',4,'xray-dns'),record('b','192.0.2.1',50),record('b','::1',5),record('b','1.in-addr.arpa',5),record('b','example.com',-1),record('b','example.com',NaN)];
 check(records,{a:5,b:4});
 check(records.filter(r=>r.client==='b'),{b:4});
 assert.equal(domainCountsByClient([]).size,0);
});
