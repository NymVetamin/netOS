import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const exports = {};
const source = readFileSync(new URL("../src/deviceList.ts", import.meta.url), "utf8");
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, { exports });
const { localDevices } = exports;
test("offline reservation remains visible and live MAC merges without duplication", () => {
 const cfg={dhcp:{reservations:[{mac:"AA:BB:CC:DD:EE:FF",ip:"192.0.2.10",hostname:"saved",network:"lan"}]},networks:[{id:"lan",interface:"bridge"}],interfaces:[{id:"bridge",name:"br-lan"}]};
 const offline=localDevices([],cfg); assert.equal(offline.length,1);assert.equal(offline[0].online,false);assert.equal(offline[0].interface,"br-lan");
 const live=localDevices([{mac:"aa:bb:cc:dd:ee:ff",ip:"192.0.2.11",online:true}],cfg);
 assert.equal(live.length,1);assert.equal(live[0].ip,"192.0.2.11");assert.equal(live[0].online,true);
 assert.equal(localDevices([],{}).length,0);
});
