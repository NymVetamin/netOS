import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import vm from "node:vm";
import ts from "typescript";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";

function load(name, require = () => { throw new Error("unexpected import"); }) {
  const source = readFileSync(new URL(`../src/${name}`, import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX,
  } }).outputText;
  const exports = {};
  vm.runInNewContext(compiled, { exports, require });
  return exports;
}
const formatter = load("describeActionError.ts");
const { describeActionError } = formatter;
const jsx = await import("react/jsx-runtime");
const { ActionError } = load("ActionError.tsx", name => name === "react/jsx-runtime" ? jsx : formatter);
const dns = "применение не удалось: подсистема components: не удалось изменить компоненты: Samba — диски и сетевые папки: установка пакетов samba: apt-get: exit status 100: " +
  "E: Failed to fetch https://deb.example/package.deb Temporary failure resolving 'deb.example' ".repeat(50);

test("draft conflicts and lost response explain the result without inventing a rollback", () => {
  assert.match(describeActionError("версия черновика изменилась; применение не началось").reason, /не выполнено/);
  assert.match(describeActionError("применённая конфигурация изменилась").hint, /Отмените старый черновик/);
  assert.match(describeActionError("черновик или применённая конфигурация изменились").title, /черновика/);
  assert.match(describeActionError("Показаны актуальные настройки").hint, /ещё раз/);
  assert.match(describeActionError("Нет связи с роутером: изменение не сохранено").reason, /неизвестен/);
});

test("repeated apt DNS output becomes a short cause and next step", () => {
  const result = describeActionError(dns);
  assert.match(result.title, /пакеты/);
  assert.match(result.reason, /DNS/);
  assert.match(result.hint, /Проверьте DNS/);
  assert.equal(result.context, "Компонент: Samba — диски и сетевые папки");
  assert.ok(JSON.stringify(result).length < 500);
  assert.doesNotMatch(JSON.stringify(result), /Failed to fetch|package.deb|exit status/);
});

test("known errors have distinct guidance; unknown exit codes do not imply DNS", () => {
  assert.match(describeActionError("apt-get: Could not get lock /var/lib/dpkg/lock").reason, /занят/);
  assert.match(describeActionError("No space left on device").reason, /места/);
  assert.match(describeActionError("Network is unreachable").reason, /подключиться/);
  assert.match(describeActionError("certificate verification failed").reason, /сертификат/);
  assert.doesNotMatch(describeActionError("exit status 100").reason, /DNS|пакет/);
  assert.match(describeActionError("unexpected error").hint, /подробности/);
});

test("rollback failure takes priority over a package error", () => {
  const result = describeActionError(dns + " Не удалось восстановить прежнюю конфигурацию");
  assert.match(result.title, /восстановить/);
  assert.match(result.reason, /требует проверки/);
  assert.match(describeActionError(dns + " и откат тоже не удался: timeout. Система откачена к прежней конфигурации").title, /восстановить/);
});

test("details are collapsed, retained and HTML-escaped", () => {
  const html = renderToStaticMarkup(React.createElement(ActionError, { message: dns + "<script>alert(1)</script>" }));
  assert.match(html, /role="alert"/);
  assert.match(html, /<details class="action-error-details">/);
  assert.doesNotMatch(html, /<details[^>]*\bopen\b|<script>/);
  assert.equal((html.match(/Temporary failure resolving/g) || []).length, 50);
  assert.match(html, /&lt;script&gt;/);
});
