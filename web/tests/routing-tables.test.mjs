import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const exports = {};
const source = readFileSync(new URL("../src/routingTables.ts", import.meta.url), "utf8");
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, { exports });
const { observedTables, tableDetails } = exports;
test("observes channel routes, empty rule tables and canonical system names", () => {
  const names = observedTables([{ table: "main" }, { table: "netos-ch1" }, { table: "netos-ch1" }], "0: from all lookup 255\n10001: fwmark 0x1001 lookup netos-ch1\n20000: from all lookup 3001\n32766: from all lookup 254");
  assert.equal(names.join(","), "3001,local,main,netos-ch1");
});
test("channel labels and configured tables do not create draft tables", () => {
  const config = { channels: [{ index: 1, type: "xray", name: "VPN" }], routing: { tables: [{name:"office",number:101}] } };
  const before = JSON.stringify(config);
  assert.equal(tableDetails("netos-ch1",config).owner,"Интернет-канал: VPN (xray)");
  assert.equal(tableDetails("1001",config).number,"1001");
  assert.equal(tableDetails("101",config).manual,true);
  assert.equal(tableDetails("4000",config).owner,"Таблица ОС");
  assert.equal(JSON.stringify(config),before);
});
