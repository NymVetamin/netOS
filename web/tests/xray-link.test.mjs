import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const source = readFileSync(new URL("../src/xrayLink.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
vm.runInNewContext(compiled, { exports, URL, atob, TextDecoder, Uint8Array });
const { parseXrayLink } = exports;
const encode = value => Buffer.from(value).toString("base64url");
const vmess = value => "vmess://" + encode(JSON.stringify(value));

test("reject missing credentials and invalid endpoint before replacing outbound", () => {
  for (const link of [
    "", "vless://host:443", "trojan://host:443", "vless://%20@host:443",
    vmess({ add: "host", port: 443 }), vmess({ add: "", port: 443, id: "user" }),
    ...[0, -1, 65536, 1.5, "bad", true].map(port => vmess({ add: "host", port, id: "user" })),
    vmess(null), vmess([]), "vmess://%%%", "vmess://" + encode("{"),
    "ss://" + encode("aes-128-gcm:@host:443"),
    "ss://" + encode("aes-128-gcm:secret@host:65536"),
    "ss://" + encode("aes-128-gcm:secret@:443"),
    "ss://" + encode("aes-128-gcm:secret@host:bad"),
    "https://user@host:443", "vless://user@host:65536",
  ]) assert.throws(() => parseXrayLink(link), undefined, link);
});

test("preserve supported protocols, credential encoding and transports", () => {
  const cases = [
    ["vless://user@host:443?type=grpc&security=tls&serviceName=qa", "vless"],
    ["trojan://secret%3Avalue@host:443?security=tls", "trojan"],
    [vmess({ add: "host", port: "443", id: "user", net: "ws", path: "/qa" }), "vmess"],
    ["ss://" + encode("aes-128-gcm:secret:part@host:443") + "#name", "shadowsocks"],
    ["ss://" + encode("aes-128-gcm:secret:part") + "@host:443#name", "shadowsocks"],
  ];
  for (const [link, protocol] of cases) assert.equal(parseXrayLink(link).protocol, protocol);
  assert.equal(parseXrayLink(cases[1][0]).settings.servers[0].password, "secret:value");
  assert.equal(parseXrayLink(cases[3][0]).settings.servers[0].password, "secret:part");
});
