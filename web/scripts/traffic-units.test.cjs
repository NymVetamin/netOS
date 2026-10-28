const assert = require('node:assert/strict');
const {test} = require('node:test');
const path = require('node:path');
const {buildSync} = require('esbuild');
const code = buildSync({entryPoints:[path.join(__dirname,'../src/api.ts')],bundle:true,platform:'node',format:'cjs',write:false}).outputFiles[0].text;
const loaded={exports:{}};
new Function('module','exports',code)(loaded,loaded.exports);
const {formatBytes}=loaded.exports;
test('traffic scales independently from bytes through terabytes',()=>{
 for(const [bytes,want] of [[0,'0 Б'],[1,'1 Б'],[1023,'1023 Б'],[1024,'1.0 КБ'],[1024**2,'1.0 МБ'],[1024**3,'1.0 ГБ'],[1024**4,'1.0 ТБ'],[1516.4*1024**2,'1.5 ГБ'],[150000*1024**2,'146 ГБ']])assert.equal(formatBytes(bytes),want);
 assert.equal(`${formatBytes(613.8*1024**2)} / ${formatBytes(1516.4*1024**2)}`,'614 МБ / 1.5 ГБ');
});
