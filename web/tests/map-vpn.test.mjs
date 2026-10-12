import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const exports = {};
const source = readFileSync(new URL("../src/mapVPN.ts", import.meta.url), "utf8");
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, { exports });
const { vpnMapServers } = exports;
const peer = { id: "same", name:"Phone", address:"10.9.0.2", enabled:true, credentials:{public_key:"key"} };
const server = { id:"server", name:"WG",type:"wireguard",enabled:true,subnet:"10.9.0.1/24",peers:[peer] };
test("VPN peers remain visible before telemetry and after telemetry failure", () => {
  const result=vpnMapServers({vpn_servers:[server]},{});
  assert.equal(result[0].peers.length,1);
  assert.equal(result[0].peers[0].state,"unknown");
});
test("telemetry is scoped to server and public key, not just peer ID", () => {
  const result=vpnMapServers({vpn_servers:[server,{...server,id:"other"}]},{server:[{id:"same",public_key:"key",state:"recent",endpoint:"192.0.2.1:1234"}]});
  assert.equal(result[0].peers[0].state,"recent");
  assert.equal(result[1].peers[0].state,"unknown");
  assert.equal(vpnMapServers({vpn_servers:[server]},{server:[{id:"same",public_key:"old",state:"recent"}]})[0].peers[0].state,"unknown");
});
test("disabled server and denied client override earlier successful handshakes", () => {
  const telemetry={server:[{id:"same",public_key:"key",state:"recent"}]};
  assert.equal(vpnMapServers({vpn_servers:[{...server,enabled:false}]},telemetry)[0].peers[0].state,"server_disabled");
  assert.equal(vpnMapServers({vpn_servers:[{...server,peers:[{...peer,enabled:false}]}]},telemetry)[0].peers[0].state,"disabled");
});
test("other VPN protocols remain visible without fabricated online status", () => {
  const config={vpn_servers:[{...server,type:"xray"}]};
  const before=JSON.stringify(config);
  assert.equal(vpnMapServers(config,{})[0].peers[0].state,"unknown");
  assert.equal(JSON.stringify(config),before);
});
