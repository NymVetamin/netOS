const assert=require('node:assert/strict');
const {test}=require('node:test');
const {buildSync}=require('esbuild');
const path=require('node:path');
const code=buildSync({stdin:{contents:`import React from 'react'; import {renderToStaticMarkup} from 'react-dom/server'; import {Notice} from './src/ui'; import {HintContext} from './src/HintContext'; import {ProblemsFor} from './src/pages/Network'; export function render(enabled){return renderToStaticMarkup(<HintContext.Provider value={enabled}><Notice hint tone="info" title="explanation"/><Notice hint tone="warn" title="advice"/><Notice tone="info" title="operation result"><button>recover</button></Notice><Notice tone="warn" title="unavailable"/><Notice hint tone="danger" title="failure"/><ProblemsFor prefixes={['dns']} problems={[{path:'dns',severity:'warning',message:'dns advice'},{path:'dns',severity:'error',message:'invalid dns'}]}/></HintContext.Provider>)}; export function defaultRender(){return renderToStaticMarkup(<Notice hint tone="info" title="default hint"/>);}`,resolveDir:path.join(__dirname,'..'),loader:'tsx'},bundle:true,platform:'node',format:'cjs',write:false}).outputFiles[0].text;
const loaded={exports:{}};new Function('module','exports','require',code)(loaded,loaded.exports,require);
test('hints are opt-in; disabling preserves operation results, recovery controls and validation errors',()=>{
 const on=loaded.exports.render(true),off=loaded.exports.render(false);
 for(const text of ['explanation','advice','dns advice']){assert.ok(on.includes(text));assert.ok(!off.includes(text));}
 for(const text of ['operation result','recover','unavailable','failure','invalid dns'])assert.ok(off.includes(text));
 assert.ok(loaded.exports.defaultRender().includes('default hint'));
 assert.equal(loaded.exports.render(true),on);
});
