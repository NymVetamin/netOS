const assert=require('node:assert/strict');
const {test}=require('node:test');
const fs=require('node:fs');const path=require('node:path');
const {buildSync}=require('esbuild');
const dir=path.join(__dirname,'../src/pages');
const code=buildSync({stdin:{contents:fs.readFileSync(path.join(dir,'WiFi.tsx'),'utf8')+'\nexport {countryOptions};',resolveDir:dir,loader:'tsx'},bundle:true,platform:'node',format:'cjs',jsx:'automatic',write:false}).outputFiles[0].text;
const loaded={exports:{}};new Function('module','exports','require',code)(loaded,loaded.exports,require);
const choices=loaded.exports.countryOptions;
const names=new Intl.DisplayNames(['ru'],{type:'region'});
const old=(codes)=>[...codes].sort((a,b)=>(names.of(a)||a).localeCompare(names.of(b)||b,'ru')).map(c=>({value:c,label:[names.of(c),' (',c,')']}));
const view=(options)=>options.map(o=>({value:o.props.value,label:o.props.children}));
test('country choices preserve Russian ordering, labels, duplicates and the input',()=>{
 for(const codes of [[],['RU'],['US','RU','FI','DE','CN','ZZ'],['RU','FI','RU']]){
 const input=[...codes];assert.deepEqual(view(choices(codes)),old(codes));assert.deepEqual(codes,input);
 }
 assert.deepEqual(view(choices(['FI'])),old(['FI']));
 assert.deepEqual(view(choices(['DE','US'])),old(['DE','US']));
});
test('localize each country once per new choices snapshot',()=>{
 const original=Intl.DisplayNames.prototype.of;let calls=0;
 Intl.DisplayNames.prototype.of=function(code){calls++;return original.call(this,code)};
 try{choices(['RU','FI','US','DE','CN']);assert.equal(calls,5)}finally{Intl.DisplayNames.prototype.of=original}
});
