import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const exports = {};
const source = readFileSync(new URL("../src/routingTables.ts", import.meta.url), "utf8");
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, { exports });
const { observedTables, automaticTables } = exports;
test("priority selection stays within the owned range and reuses released slots", () => {
  const next = exports.nextRulePriority;
  assert.equal(next([]), 20100);
  assert.equal(next([{priority: 20100}, {priority: 20100}]), 20110);
  const spaced = Array.from({length: 990}, (_, i) => ({priority: 20100 + 10 * i}));
  assert.equal(next(spaced), 20000);
  spaced.splice(40, 1);
  assert.equal(next(spaced), 20500);
  const all = Array.from({length: 10000}, (_, i) => ({priority: 20000 + i}));
  assert.equal(next(all), 20100);
  all.pop();
  assert.equal(next(all), 29999);
});
test("new tables have independent free names and numbers after edits and deletion", () => {
  const tables = [];
  for (let i = 0; i < 252; i++) tables.push(exports.nextRouteTable(tables));
  assert.equal(tables[0].number, 101);
  assert.equal(new Set(tables.map(t => t.number)).size, 252);
  assert.ok(tables.every(t => t.number >= 1 && t.number <= 252));
  assert.equal(exports.nextRouteTable(tables), null);
  tables.splice(0, 1);
  const replacement = exports.nextRouteTable(tables);
  assert.equal(replacement.number, 101);
  assert.ok(!tables.some(t => t.name === replacement.name));
  const edited = [{name: "netos-t2", number: 102}];
  assert.equal(exports.nextRouteTable(edited).name, "netos-t3");
  assert.equal(exports.nextRouteTable(edited).number, 101);
});
test("observes channel routes, empty rule tables and canonical system names", () => {
  const names = observedTables([{ table: "main" }, { table: "netos-ch1" }, { table: "netos-ch1" }], "0: from all lookup 255\n10001: fwmark 0x1001 lookup netos-ch1\n20000: from all lookup 3001\n32766: from all lookup 254");
  assert.equal(names.join(","), "3001,local,main,netos-ch1");
});
test("channel labels and configured tables do not create draft tables", () => {
  const config = { channels: [{ index: 1, type: "xray", name: "VPN" }], routing: { tables: [{name:"office",number:101}] } };
  const before = JSON.stringify(config);
  const names = ["netos-ch1", "1001", "office", "101", "main", "4000", "constructor"];
  const rows = automaticTables(names, config.routing.tables, config.channels);
  assert.deepEqual(Array.from(rows, row => row.name), ["netos-ch1", "1001", "4000", "constructor"]);
  assert.equal(rows[0].owner,"Интернет-канал: VPN (xray)");
  assert.equal(rows[1].number,"1001");
  assert.equal(rows[2].owner,"Таблица ОС");
  assert.equal(rows[3].number,"—");
  assert.equal(JSON.stringify(config),before);
});

test("automatic table owners follow configuration changes and first matching channel", () => {
  const names = ["netos-ch2", "1002", "netos-ch4"];
  const channels = [
    {index: 2, type: "direct", name: "Direct"},
    {index: 2, type: "xray", name: "First"},
    {index: 2, type: "wireguard", name: "Second"},
  ];
  const rows = automaticTables(names, [{name: "netos-ch4", number: 1002}], channels);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].owner, "Интернет-канал: First (xray)");
  const changed = automaticTables(names, [], channels.slice(2));
  assert.equal(changed.length, 3);
  assert.equal(changed[1].owner, "Интернет-канал: Second (wireguard)");
  assert.equal(changed[2].owner, "Таблица ОС");
  assert.equal(automaticTables([], [], channels).length, 0);
});

test("ordinary table names survive canonicalization and sorting", () => {
  const names = observedTables([{table: "main"}, {table: "constructor"}], "lookup __proto__\nlookup constructor\nlookup toString\nlookup 253");
  assert.deepEqual(Array.from(names).sort(), ["__proto__", "constructor", "default", "main", "toString"]);
});
