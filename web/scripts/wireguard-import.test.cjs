const assert = require("node:assert/strict");
const {buildSync}=require("esbuild");
const path=require("node:path");
const compiled=buildSync({entryPoints:[path.join(__dirname,"../src/wireguardImport.ts")],bundle:true,platform:"node",format:"cjs",write:false});
const loaded={exports:{}};new Function("module","exports",compiled.outputFiles[0].text)(loaded,loaded.exports);
const {parseWireGuardConfig:parse}=loaded.exports;
const key=Buffer.alloc(32,7).toString("base64");
const config=`[Interface]
PrivateKey = ${key}
Address = 10.2.0.2/32
MTU = 1380
[Peer]
PublicKey = ${key}
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 0
`;
const parsed=parse(config);
assert.equal(parsed.config.address,"10.2.0.2/32");assert.equal(parsed.config.persistent_keepalive,0);assert.equal(parsed.config.mtu,1380);assert.ok(!Object.hasOwn(parsed.config,"preshared_key"));
assert.equal(parse(config+`PresharedKey=${key}`).config.preshared_key,key);
for(const broken of [config+"[Peer]",config.replace("10.2.0.2/32","10.2.0.2/99"),config.replace("PrivateKey = "+key,"PrivateKey = bad"),config.replace("51820","99999"),config+"MTU=1\nMTU=2"]){assert.throws(()=>parse(broken));}
for (const allowed of ["10.0.0.0/8", "::/0", "0.0.0.0/0, ::/0", "invalid", ""]) {
 assert.deepEqual(parse(config.replace("AllowedIPs = 0.0.0.0/0", `AllowedIPs = ${allowed}`)),parsed);
}
assert.deepEqual(parse(config.replace("AllowedIPs = 0.0.0.0/0\n", "")),parsed);
const dual=parse(config.replace("10.2.0.2/32","10.2.0.2/32, fd00::2/128").replace("0.0.0.0/0","0.0.0.0/0, ::/0").replace("MTU = 1380","MTU = 1380\nDNS = 1.1.1.1\nPostUp = arbitrary-command"));
assert.equal(dual.warnings.length,3);assert.deepEqual(dual.config.allowed_ips,["0.0.0.0/0"]);assert.ok(!Object.hasOwn(dual.config,"PostUp"));
assert.deepEqual(parse("\ufeff"+config.replaceAll("\n","\r\n")),parsed);
console.log("WireGuard import valid, invalid, unconditional AllowedIPs normalization, IPv6/DNS/hooks warnings, absent PSK PASS");

for(const size of [1000,100000]) {
 const input="# comment\n".repeat(size)+config;
 const started=performance.now();
 for(let i=0;i<5;i++) assert.deepEqual(parse(input),parsed);
 console.log(JSON.stringify({bytes:input.length,parse_ms:(performance.now()-started)/5}));
}
// AmneziaVPN profile: obfuscation goes into config.amneziawg without warnings.
const awgConf=config.replace("MTU = 1380","MTU = 1380\nJc = 4\nJmin = 40\nJmax = 70\nS1 = 15\nS2 = 25\nH1 = 100-200\nH2 = 300\nH3 = 400\nH4 = 500\nI1 = <b 0xc0ffee><r 8><t>");
const awg=parse(awgConf);
assert.deepEqual(awg.config.amneziawg,{jc:4,jmin:40,jmax:70,s1:15,s2:25,h1:"100-200",h2:"300",h3:"400",h4:"500",i1:"<b 0xc0ffee><r 8><t>"});
assert.equal(awg.warnings.length,0);
assert.ok(!Object.hasOwn(parsed.config,"amneziawg"),"plain WireGuard file gained obfuscation");
assert.throws(()=>parse(awgConf.replace("Jc = 4","Jc = x")),/Jc/);
console.log("AmneziaWG import: parameters, no warnings, plain file unchanged, invalid number PASS");
