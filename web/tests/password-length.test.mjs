import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";

const source = readFileSync(new URL("../src/api.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;
const exports = {};
vm.runInNewContext(compiled, { exports, TextEncoder });

test("password length is measured in UTF-8 bytes like the server", () => {
  const { passwordBytes, MIN_PASSWORD_BYTES } = exports;
  assert.equal(MIN_PASSWORD_BYTES, 12);
  // Шесть русских букв — 12 байт: сервер их принимает, прежняя проверка по .length — нет.
  assert.equal(passwordBytes("пароль"), 12);
  assert.equal(passwordBytes("abcdefghijk"), 11);
  assert.equal(passwordBytes("🔑"), 4);
  assert.equal(passwordBytes(""), 0);
});
