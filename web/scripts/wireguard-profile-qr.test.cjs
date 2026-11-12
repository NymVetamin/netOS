const assert=require('node:assert/strict'),path=require('node:path');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const React=require('react'),{renderToStaticMarkup}=require('react-dom/server'),{QRCodeSVG}=require('qrcode.react');
const compiled=buildSync({entryPoints:[path.join(__dirname,'../src/wireGuardProfiles.ts')],bundle:true,platform:'node',format:'cjs',write:false});
const loaded={exports:{}};new Function('module','exports',compiled.outputFiles[0].text)(loaded,loaded.exports);
const {wireGuardProfileFitsQR:fits,wireGuardClientConfig:profile}=loaded.exports;
const qr=value=>renderToStaticMarkup(React.createElement(QRCodeSVG,{value,level:'M',size:176,marginSize:2}));
test('actual level M encoder accepts the byte boundary and rejects its successor',()=>{
 const prefix='[Interface]\nI1 = ';
 const maximum=prefix+'a'.repeat(2331-prefix.length);
 assert.equal(fits(maximum),true);assert.match(qr(maximum),/^<svg/);
 assert.equal(fits(maximum+'a'),false);assert.throws(()=>qr(maximum+'a'),/Data too long/);
});
test('Unicode is measured in UTF-8 bytes rather than UTF-16 units',()=>{
 const prefix='[Interface]\nI1 = ';
 for(const text of [prefix+'я'.repeat(1100),prefix+'😀'.repeat(550)]){assert.equal(fits(text),true);assert.doesNotThrow(()=>qr(text))}
 for(const text of [prefix+'я'.repeat(1200),prefix+'😀'.repeat(600)]){assert.ok(text.length<2331);assert.equal(fits(text),false);assert.throws(()=>qr(text),/Data too long/)}
});
test('large AWG export remains intact and a short replacement gets its QR back',()=>{
 const server={subnet:'10.9.0.1/24',config:{public_endpoint:'vpn.example:51820',amneziawg:{jc:4,i1:'<b 0x'+'ab'.repeat(2000)+'>'}}};
 const peer={address:'10.9.0.2',credentials:{}};
 const large=profile(server,peer,'private','public');assert.ok(large.includes(server.config.amneziawg.i1));assert.equal(fits(large),false);
 server.config.amneziawg.i1='<b 0xc0ffee>';
 const small=profile(server,peer,'private','public');assert.equal(fits(small),true);assert.doesNotThrow(()=>qr(small));
 assert.equal(fits(large),false);assert.equal(fits(''),true);
});
