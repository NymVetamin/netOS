const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { createHash, webcrypto } = require('node:crypto');
const { test } = require('node:test');
const ts = require('typescript');

// Exercise the page's actual function without mounting its polling components.
const source = fs.readFileSync(path.join(__dirname, '../src/pages/VPNServers.tsx'), 'utf8');
const ast = ts.createSourceFile('page.tsx', source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const declaration = ast.statements.find(node => ts.isFunctionDeclaration(node) && node.name?.text === 'certificateFingerprint');
assert.ok(declaration);
const code = ts.transpile(declaration.getText(ast), { target: ts.ScriptTarget.ES2022 });
const fingerprint = new Function('crypto', code + ';return certificateFingerprint;')(webcrypto);
const begin = '-----BEGIN CERTIFICATE-----', end = '-----END CERTIFICATE-----';
const pem = bytes => begin + '\n' + Buffer.from(bytes).toString('base64') + '\n' + end;
const expected = bytes => createHash('sha256').update(Buffer.from(bytes)).digest('hex');
const missing = /Не удалось прочитать TLS-сертификат сервера/;

test('fingerprint preserves bytes, whitespace and first certificate in a chain', async () => {
  const bytes = Array.from({ length: 256 }, (_, i) => i);
  assert.equal(await fingerprint(pem(bytes)), expected(bytes));
  assert.equal(await fingerprint(pem(bytes).replace(/\n/g, '\r\n\t\u00a0\ufeff')), expected(bytes));
  assert.equal(await fingerprint('prefix' + end + pem(bytes) + pem([1, 2, 3])), expected(bytes));
});

test('malformed certificates retain errors and do not affect subsequent downloads', async () => {
  for (const value of ['', end, begin, begin + end, begin + ' \n\t' + end, begin.repeat(8000)]) {
    await assert.rejects(fingerprint(value), missing);
    assert.equal(await fingerprint(pem([1, 2, 3])), expected([1, 2, 3]));
  }
  for (const value of [begin + '!' + end, begin + 'A' + end, begin + pem([1, 2, 3])]) {
    await assert.rejects(fingerprint(value), { name: 'InvalidCharacterError' });
  }
});
