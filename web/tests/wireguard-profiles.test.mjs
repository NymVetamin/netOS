import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const exports = {};
const source = readFileSync(new URL("../src/wireGuardProfiles.ts", import.meta.url), "utf8");
vm.runInNewContext(ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText, { exports });
const { newWireGuardProfile, effectiveWireGuardProfile: profile, wireGuardClientConfig: render } = exports;
const server = { subnet: "10.9.0.1/24", config: { public_endpoint: "vpn.example.test:51820", client_dns: ["192.0.2.53"], client_allowed_ips: ["192.0.2.0/24"] } };
const peer = { address: "10.9.0.2", credentials: { preshared_key: "psk" } };

test("new clients use router DNS, full tunnel and independent arrays", () => {
  const a = { ...peer, wireguard_profile: newWireGuardProfile() };
  const b = { ...peer, wireguard_profile: newWireGuardProfile() };
  assert.equal(profile(server, a).dns.join(), "10.9.0.1");
  assert.equal(profile({ ...server, subnet: "10.44.0.254/24" }, a).dns.join(), "10.44.0.254");
  a.wireguard_profile.allowed_ips.push("198.51.100.0/24");
  assert.equal(b.wireguard_profile.allowed_ips.join(), "0.0.0.0/0");
});

test("per-client DNS and AllowedIPs reach exports without affecting another client", () => {
  const a = { ...peer, wireguard_profile: { use_router_dns: false, dns: ["198.51.100.53"], allowed_ips: ["198.51.100.0/24"] } };
  const b = { ...peer, address: "10.9.0.3", wireguard_profile: newWireGuardProfile() };
  const textA = render(server, a, "client-a", "server-public");
  const textB = render(server, b, "client-b", "server-public");
  assert.match(textA, /DNS = 198\.51\.100\.53\n/);
  assert.match(textA, /AllowedIPs = 198\.51\.100\.0\/24\n/);
  assert.match(textB, /DNS = 10\.9\.0\.1\n/);
  assert.match(textB, /AllowedIPs = 0\.0\.0\.0\/0\n/);
  assert.match(textA, /PresharedKey = psk\n/);
  assert.match(textA, /Endpoint = vpn\.example\.test:51820\n/);
});

test("old exports and explicit no-DNS settings survive JSON reload", () => {
  assert.match(render(server, peer, "private", "public"), /DNS = 192\.0\.2\.53\n/);
  assert.match(render(server, peer, "private", "public"), /AllowedIPs = 192\.0\.2\.0\/24\n/);
  const empty = { ...peer, wireguard_profile: { use_router_dns: false, dns: [], allowed_ips: ["10.9.0.1/32"] } };
  const body = render(server, empty, "private", "public");
  assert.doesNotMatch(body, /^DNS =/m);
  assert.equal(render(server, JSON.parse(JSON.stringify(empty)), "private", "public"), body);
  assert.doesNotMatch(render({ ...server, config: {} }, peer, "private", "public"), /^DNS =/m);
  assert.equal(profile(server, { wireguard_profile: { dns: [], allowed_ips: [] } }).allowed_ips.length, 0);
});
