"""Policy block selection in the production bundle; requests remain local."""
import asyncio, copy, importlib.util, os
from pathlib import Path
from playwright.async_api import async_playwright, expect
spec=importlib.util.spec_from_file_location("fixture",Path(__file__).with_name("ui-review-regressions.browser.py"))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(executable_path=str(Path(os.environ["ProgramFiles"])/"Google/Chrome/Application/chrome.exe") if os.name=="nt" else None)
  cfg=copy.deepcopy(f.CONFIG)
  cfg["channels"]=[{"id":"direct","name":"Напрямую","type":"direct","enabled":True}]
  cfg["policies"]=[{"id":"deny","name":"Deny","enabled":False,"priority":100,"channel":"direct","dst_ip":"192.0.2.2"}]
  page,state=await f.fixture(browser,{"role":"admin"},cfg)
  await page.goto("http://netos.test/#channels")
  await page.get_by_text("Deny",exact=True).click()
  field=page.get_by_label("Канал политики Deny",exact=True)
  await field.select_option("block")
  await expect(field).to_have_value("block")
  await expect(page.get_by_label("IP назначения политики Deny",exact=True)).to_have_value("192.0.2.2")
  await field.select_option("direct")
  await expect(field).to_have_value("direct")
  assert not state["errors"],state["errors"]
  await browser.close()
  print("policy block/direct selection and destination preservation PASS")
asyncio.run(main())
