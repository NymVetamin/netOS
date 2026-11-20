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
  mac="02:00:00:00:00:01"
  cfg["vpn_servers"]=[{"id":s,"name":s,"peers":[{"id":"same","name":peer}]} for s,peer in [("vpn-a","Phone"),("vpn-b","Tablet")]]
  cases=[
   ("MAC",{"src_mac":mac},mac),
   ("Segment",{"network":"lan"},"Сегмент LAN"),
   ("Combined",{"src_ip":"192.0.2.2","src_mac":mac,"network":"lan","vpn_server":"vpn-b","vpn_peer":"same"},
    f"192.0.2.2, {mac}, Сегмент LAN, VPN vpn-b, Пир Tablet"),
   ("Missing",{"network":"removed"},"Сегмент removed"),
  ]
  for i,(name,fields,_) in enumerate(cases):
   cfg["policies"].append(dict(cfg["policies"][0],id=str(i),name=name,**fields))
  page,state=await f.fixture(browser,{"role":"admin"},cfg)
  await page.goto("http://netos.test/#channels")
  def source(name):
   return page.locator("summary.xsum").filter(has=page.get_by_text(name,exact=True)).locator('[data-label="Источник"]')
  await expect(source("Deny")).to_have_text("любой")
  for name,_,want in cases:
   await expect(source(name)).to_have_text(want)
  card=page.locator("section.card").filter(has=page.get_by_role("heading",name="Политики",exact=True))
  await expect(card.locator("option")).to_have_count(0)
  await page.get_by_text("Deny",exact=True).click()
  field=page.get_by_label("Канал политики Deny",exact=True)
  await field.select_option("block")
  await expect(field).to_have_value("block")
  await expect(page.get_by_label("IP назначения политики Deny",exact=True)).to_have_value("192.0.2.2")
  await field.select_option("direct")
  await expect(field).to_have_value("direct")
  ip=page.get_by_label("IP источника политики Deny",exact=True)
  await ip.fill("192.0.2.55")
  await expect(source("Deny")).to_have_text("192.0.2.55")
  await page.get_by_text("Deny",exact=True).click()
  await expect(ip).to_be_hidden()
  await page.get_by_text("Deny",exact=True).click()
  await expect(ip).to_have_value("192.0.2.55")
  await ip.fill("")
  await expect(source("Deny")).to_have_text("любой")
  await card.get_by_role("button",name="Добавить",exact=True).click()
  added=card.locator("details.xd").last
  await expect(added).to_have_attribute("open","")
  await expect(added.get_by_label("Название политики",exact=True)).to_be_visible()
  await added.get_by_role("button",name="Убрать").click()
  await expect(card.locator("details.xd")).to_have_count(len(cfg["policies"]))
  assert not state["errors"],state["errors"]
  await browser.close()
  print("policy block/direct selection and destination preservation PASS")
asyncio.run(main())
