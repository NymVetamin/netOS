const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { test } = require('node:test');
const ts = require('typescript');

const source = fs.readFileSync(path.join(__dirname, '../src/pages/Diagnostics.tsx'), 'utf8');
const ast = ts.createSourceFile('page.tsx', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const declarations = ast.statements.filter(node =>
  (ts.isFunctionDeclaration(node) && node.name?.text === 'Highlight') ||
  (ts.isVariableStatement(node) && node.declarationList.declarations.some(d => d.name.getText(ast) === 'TOKEN')));
assert.equal(declarations.length, 2);
const code = ts.transpileModule(declarations.map(n => n.getText(ast)).join('\n'), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX },
}).outputText;
const element = (type, props, key) => ({ type, props, key });
const Highlight = new Function('require', 'exports', code + ';return Highlight;')(
  name => { assert.equal(name, 'react/jsx-runtime'); return { jsx: element, jsxs: element, Fragment: 'fragment' }; }, {});

function textOf(node) {
  if (Array.isArray(node)) return node.map(textOf).join('');
  return typeof node === 'string' ? node : node ? textOf(node.props.children) : '';
}
function inspect(text) {
  const tree = Highlight({ text });
  const tokens = [];
  function visit(node) {
    if (Array.isArray(node)) return node.forEach(visit);
    if (!node || typeof node !== 'object') return;
    if (node.props.className) tokens.push([node.props.className, textOf(node), node.key]);
    else visit(node.props.children);
  }
  visit(tree);
  assert.equal(textOf(tree), text + '\n');
  return tokens;
}

test('diagnostic strings retain escaping, token boundaries and keys', () => {
  assert.deepEqual(inspect('"a\\"b" -j ACCEPT 192.0.2.1/24 DROP'), [
    ['hl-string', '"a\\"b"', 0], ['hl-flag', '-j', 7], ['hl-ok', 'ACCEPT', 10],
    ['hl-number', '192.0.2.1/24', 17], ['hl-bad', 'DROP', 30],
  ]);
  assert.deepEqual(inspect('x--flag wordDROP 1.2.3.4x'), []);
});

test('failed quoted strings retain later tokens and recover after invalid escapes', () => {
  for (const separator of ['\r', '\u2028', '\u2029']) {
    const prefix = '"bad\\' + separator + ' ';
    assert.deepEqual(inspect(prefix + '-j "ok"'), [
      ['hl-flag', '-j', prefix.length], ['hl-string', '"ok"', prefix.length + 3],
    ]);
  }
  const prefix = '"' + '\\"'.repeat(8000);
  assert.deepEqual(inspect(prefix), []);
  assert.deepEqual(inspect(prefix + ' -j DROP'), [
    ['hl-flag', '-j', prefix.length + 1], ['hl-bad', 'DROP', prefix.length + 4],
  ]);
  assert.deepEqual(inspect('"recovered"'), [['hl-string', '"recovered"', 0]]);
});

test('comments, headers, empty lines and UTF-16 text remain intact across calls', () => {
  assert.deepEqual(inspect('# "note"\n*filter\nCOMMIT\n'), [
    ['hl-comment', '# "note"\n', 0], ['hl-head', '*filter\n', 1], ['hl-head', 'COMMIT\n', 2],
  ]);
  for (const value of ['😀', '\ud800', '\udfff', '\\😀', '\\"', 'a\rb']) {
    const input = '"' + value + '"';
    assert.deepEqual(inspect(input), [['hl-string', input, 0]]);
  }
  assert.deepEqual(inspect(''), []);
});
