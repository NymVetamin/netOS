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
const xhttpLink = params => "vless://01234567-89ab-cdef-0123-456789abcdef@cdn.example.com:443?" + new URLSearchParams({ type: "xhttp", security: "tls", ...params });

test("XHTTP import preserves mode, complete extra JSON and TLS ALPN", () => {
  const extra = { scMaxEachPostBytes: "20000", scMinPostsIntervalMs: "7", xPaddingBytes: "100-1000",
    xPaddingObfsMode: true, xPaddingKey: "hash", xPaddingHeader: "X-Client-Ver", xPaddingPlacement: "queryInHeader",
    xPaddingMethod: "tokenish", uplinkHTTPMethod: "GET", seqPlacement: "path", uplinkDataPlacement: "header", uplinkChunkSize: "3000",
    xmux: { maxConcurrency: "4", maxConnections: "0", hMaxReusableSecs: "1800-3000", hMaxRequestTimes: "600-900" },
    downloadSettings: { network: "xhttp", xhttpSettings: { path: "/download%2F", mode: "stream-one" } } };
  const out = JSON.parse(JSON.stringify(parseXrayLink(xhttpLink({ path: "/api/v1/events/", host: "cdn.example.com", mode: "packet-up",
    extra: JSON.stringify(extra), sni: "cdn.example.com", fp: "firefox", alpn: "h2,http/1.1", encryption: "test-encryption" }))));
  assert.deepEqual(out.streamSettings.xhttpSettings, { path: "/api/v1/events/", host: "cdn.example.com", mode: "packet-up", extra });
  assert.deepEqual(out.streamSettings.tlsSettings, { serverName: "cdn.example.com", fingerprint: "firefox", alpn: ["h2", "http/1.1"] });
  assert.equal(out.settings.vnext[0].users[0].encryption, "test-encryption");
});

test("XHTTP rejects malformed/non-object extra and preserves defaults without extra", () => {
  for (const extra of ["{", "null", "[]", "1", '"text"', "true", ""]) {
    assert.throws(() => parseXrayLink(xhttpLink({ extra })), /extra/);
  }
  const out = JSON.parse(JSON.stringify(parseXrayLink(xhttpLink({}))));
  assert.deepEqual(out.streamSettings.xhttpSettings, { path: "/", host: "" });
  assert.deepEqual(out.streamSettings.tlsSettings, { serverName: "", fingerprint: "chrome" });
});

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
    "vless://not-uuid@host:443?security=none",
  ]) assert.throws(() => parseXrayLink(link), undefined, link);
});

test("preserve supported protocols, credential encoding and transports", () => {
  const cases = [
    ["vless://01234567-89ab-cdef-0123-456789abcdef@host:443?type=grpc&security=tls&serviceName=qa", "vless"],
    ["trojan://secret%3Avalue@host:443?security=tls", "trojan"],
    [vmess({ add: "host", port: "443", id: "user", net: "ws", path: "/qa" }), "vmess"],
    ["ss://" + encode("aes-128-gcm:secret:part@host:443") + "#name", "shadowsocks"],
    ["ss://" + encode("aes-128-gcm:secret:part") + "@host:443#name", "shadowsocks"],
  ];
  for (const [link, protocol] of cases) assert.equal(parseXrayLink(link).protocol, protocol);
  assert.equal(parseXrayLink(cases[1][0]).settings.servers[0].password, "secret:value");
  assert.equal(parseXrayLink(cases[3][0]).settings.servers[0].password, "secret:part");
});

test("TLS share links preserve certificate verification on reimport", () => {
  const pin = "ab".repeat(32);
  for (const link of [
    xhttpLink({ pcs: pin, vcn: "vpn.example.com" }),
    `trojan://secret@vpn.example.com:443?security=tls&pcs=${pin}&vcn=vpn.example.com`,
    vmess({ add: "vpn.example.com", port: 443, id: "user", tls: "tls", pcs: pin, vcn: "vpn.example.com" }),
  ]) {
    const tls = parseXrayLink(link).streamSettings.tlsSettings;
    assert.equal(tls.pinnedPeerCertSha256, pin);
    assert.equal(tls.verifyPeerCertByName, "vpn.example.com");
    assert.equal(tls.allowInsecure, undefined);
  }
});

const hy2Link = params => "hysteria2://test-auth@vpn.example.com:2087?" + new URLSearchParams(params) + "#%F0%9F%9A%80%20test";
const salamander = { type: "salamander", settings: { password: "test-obfs" } };

test("Hysteria 2 import preserves auth, TLS and exactly one Salamander mask", () => {
  const params = { sni: "tls.example.com", obfs: "salamander", "obfs-password": "test-obfs" };
  for (const extra of [{}, { fm: JSON.stringify({ udp: [salamander] }) }]) {
    const link = hy2Link({ ...params, ...extra });
    const expected = {
      protocol: "hysteria", settings: { version: 2, address: "vpn.example.com", port: 2087 },
      streamSettings: { method: "hysteria", security: "tls", tlsSettings: { serverName: "tls.example.com" },
        hysteriaSettings: { version: 2, auth: "test-auth" }, finalmask: { udp: [salamander] } },
    };
    for (let i = 0; i < 2; i++) assert.deepEqual(JSON.parse(JSON.stringify(parseXrayLink(link))), expected);
  }
});

test("Hysteria alias, default port, userpass and pinned netOS profiles", () => {
  const pin = "AB".repeat(32);
  for (const auth of ["user:pass%3Aword", "user%3Apass%3Aword"]) {
    const out = parseXrayLink(`hy2://${auth}@vpn.example.com/?insecure=1&pinSHA256=${pin}&alpn=h3`);
    assert.equal(out.settings.port, 443);
    assert.equal(out.streamSettings.hysteriaSettings.auth, "user:pass:word");
    assert.equal(out.streamSettings.tlsSettings.pinnedPeerCertSha256, pin);
    assert.equal(out.streamSettings.tlsSettings.allowInsecure, undefined);
    assert.equal(out.streamSettings.tlsSettings.alpn[0], "h3");
    assert.equal(out.streamSettings.finalmask, undefined);
  }
});

test("Hysteria fm preserves ordered masks and QUIC options", () => {
  const mask = { udp: [salamander, { type: "header-custom", settings: { header: "test" } }], quicParams: { congestion: "bbr" } };
  const out = parseXrayLink(hy2Link({ fm: JSON.stringify(mask), obfs: "salamander", "obfs-password": "test-obfs" }));
  assert.deepEqual(JSON.parse(JSON.stringify(out.streamSettings.finalmask)), mask);
});

test("Hysteria rejects invalid or conflicting settings before replacing outbound", () => {
  for (const params of [
    { fm: "{" }, { fm: "null" }, { fm: "[]" }, { fm: '{"udp":{}}' }, { fm: '{"udp":[null]}' },
    { fm: JSON.stringify({ udp: [salamander] }), obfs: "salamander", "obfs-password": "different" },
    { obfs: "salamander" }, { obfs: "unsupported" }, { insecure: "yes" }, { insecure: "1" },
    { pinSHA256: "bad" }, { alpn: "" },
  ]) assert.throws(() => parseXrayLink(hy2Link(params)));
  for (const link of ["hy2://vpn.example.com", "hy2://%20@vpn.example.com", "hy2://auth@vpn.example.com:0", "hy2://auth@vpn.example.com:65536"]) {
    assert.throws(() => parseXrayLink(link));
  }
  assert.equal(parseXrayLink(hy2Link({})).protocol, "hysteria");
});

test("imports netOS SOCKS5 and HTTP server links with encoded credentials", () => {
  for (const [scheme, protocol, port] of [["socks5", "socks", 1080], ["http", "http", 80]]) {
    for (const address of ["vpn.example", "[2001:db8::1]"]) {
      for (const explicit of ["", ":18080"]) {
        const link = `${scheme}://user%40name:p%3Ass%2Fword@${address}${explicit}#netOS`;
        const expected = { protocol, settings: { servers: [{ address: address.replace(/[\[\]]/g, ""), port: explicit ? 18080 : port, users: [{ user: "user@name", pass: "p:ss/word" }] }] } };
        for (let i = 0; i < 2; i++) assert.deepEqual(JSON.parse(JSON.stringify(parseXrayLink(link))), expected);
      }
    }
    for (const link of [`${scheme}://host:1080`, `${scheme}://user@host:1080`, `${scheme}://user:pass@host:65536`, `${scheme}://user:pass@host:0`]) assert.throws(() => parseXrayLink(link));
  }
});
