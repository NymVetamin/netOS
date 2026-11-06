"""OpenConnect P12 controls against the built panel; no router requests."""
import asyncio,copy,importlib.util,os
from pathlib import Path
from playwright.async_api import async_playwright,expect
spec=importlib.util.spec_from_file_location("fixture",Path(__file__).with_name("ui-review-regressions.browser.py"));f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(executable_path=str(Path(os.environ["ProgramFiles"])/"Google/Chrome/Application/chrome.exe") if os.name=="nt" else None)
  cfg=copy.deepcopy(f.CONFIG);cfg["policies"]=[]
  cfg["channels"]=[{"id":"oc","index":2,"name":"OC test","enabled":False,"type":"openconnect","mode":"tun","fail_mode":"block","config":{"server":"https://vpn.example","auth_mode":"certificate","client_certificate":"","certificate_password":""},"secrets_set":{"client_certificate":True,"certificate_password":True},"probe":{"enabled":False}}]
  page,state=await f.fixture(browser,{"role":"admin"},cfg)
  await page.goto("http://netos.test/#channels");await page.get_by_text("OC test",exact=True).click()
  mode=page.get_by_label("Авторизация OpenConnect",exact=True);await expect(mode).to_have_value("certificate")
  await expect(page.get_by_text("Сертификат сохранён",exact=True)).to_be_visible()
  password=page.get_by_label("Пароль P12/PFX",exact=True);await expect(password).to_have_value("")
  await password.fill("old-password")
  await page.get_by_label("Клиентский сертификат P12",exact=True).set_input_files({"name":"test.p12","mimeType":"application/x-pkcs12","buffer":b"test-encrypted-container"})
  await expect(page.get_by_text("Новый файл загружен",exact=True)).to_be_visible();await expect(password).to_have_value("")
  await password.fill("new-password")
  await mode.select_option("both");await expect(page.get_by_text("Пользователь",exact=True)).to_be_visible()
  await mode.select_option("password");await expect(password).to_have_count(0)
  await mode.select_option("certificate");await expect(password).to_have_value("new-password")
  await page.get_by_role("button",name="Удалить сертификат",exact=True).click()
  await expect(page.get_by_text("Файл не загружен",exact=True)).to_be_visible();await expect(password).to_have_value("")
  assert not state["errors"],state["errors"]
  await page.screenshot(path=str(Path(__file__).resolve().parents[2]/".codex/openconnect-p12.png"),full_page=True)
  await browser.close();print("P12 upload/password reset/saved-secret presence/auth modes/removal PASS")
asyncio.run(main())
