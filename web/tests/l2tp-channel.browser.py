"""Production L2TP editor; intercepted requests, no router changes."""
import asyncio, base64, copy, importlib.util, os
from pathlib import Path
from playwright.async_api import async_playwright, expect
spec=importlib.util.spec_from_file_location("fixture",Path(__file__).with_name("ui-review-regressions.browser.py"))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(executable_path=str(Path(os.environ["ProgramFiles"])/"Google/Chrome/Application/chrome.exe") if os.name=="nt" else None)
  cfg=copy.deepcopy(f.CONFIG)
  cfg["channels"]=[{"id":"l2","index":1,"name":"L2TP test","enabled":False,"type":"l2tp","mode":"tun","fail_mode":"block","config":{"server":"vpn.example","username":"test","password":"","ipsec":False},"probe":{"enabled":False}}]
  cfg["policies"]=[]
  page,state=await f.fixture(browser,{"role":"admin"},cfg)
  await page.goto("http://netos.test/#channels")
  await page.get_by_text("L2TP test",exact=True).click()
  await expect(page.get_by_text("L2TP без шифрования",exact=True)).to_be_visible()
  toggle=page.get_by_role("group",name="Защита IPsec",exact=True).locator("label.switch")
  await toggle.click()
  key=page.get_by_label("Общий ключ IPsec",exact=True)
  await key.fill("test-shared-key")
  await expect(page.get_by_text("L2TP без шифрования",exact=True)).to_have_count(0)
  await toggle.click()
  await expect(key).to_have_count(0)
  await expect(page.get_by_text("L2TP без шифрования",exact=True)).to_be_visible()
  await toggle.click()
  await expect(key).to_have_value("test-shared-key")
  assert not state["errors"],state["errors"]
  await page.screenshot(path=str(Path(__file__).resolve().parents[2]/".codex/l2tp-channel.png"),full_page=True)
  await browser.close()
  print("L2TP IPsec toggle, PSK field, plaintext notice and repeat PASS")
asyncio.run(main())
