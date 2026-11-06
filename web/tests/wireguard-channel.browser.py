"""Production WireGuard editor; intercepted requests, no router changes."""
import asyncio, base64, copy, importlib.util, os
from pathlib import Path
from playwright.async_api import async_playwright, expect
spec=importlib.util.spec_from_file_location("fixture",Path(__file__).with_name("ui-review-regressions.browser.py"))
f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
KEY=base64.b64encode(bytes([7])*32).decode();PUB=base64.b64encode(bytes([8])*32).decode()
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(executable_path=str(Path(os.environ["ProgramFiles"])/"Google/Chrome/Application/chrome.exe") if os.name=="nt" else None)
  cfg=copy.deepcopy(f.CONFIG)
  cfg["channels"]=[{"id":"wg","index":1,"name":"WG test","enabled":False,"type":"wireguard","mode":"tun","fail_mode":"block","secrets_set":{"private_key":True,"preshared_key":True},"config":{"private_key":"","address":"10.1.0.2/32","peer_public_key":PUB,"endpoint":"old.example:51820","allowed_ips":["0.0.0.0/0"]},"probe":{"enabled":False}}]
  cfg["policies"]=[]
  page,state=await f.fixture(browser,{"role":"admin"},cfg)
  async def keys(route):
   body=route.request.post_data_json or {}
   await route.fulfill(json={"private_key":"" if body else KEY,"public_key":PUB})
  await page.route("**/api/wireguard/keypair",keys)
  await page.goto("http://netos.test/#channels")
  await page.get_by_text("WG test",exact=True).click()
  public=page.get_by_label("Ваш публичный ключ WireGuard",exact=True)
  private=page.get_by_label("Приватный ключ WireGuard",exact=True)
  await expect(public).to_have_value(PUB)
  await expect(private).to_have_value("")
  assert await page.get_by_label("AllowedIPs WireGuard",exact=True).get_attribute("readonly") is not None
  await page.get_by_role("button",name="Сгенерировать новые ключи",exact=True).click()
  await expect(private).to_have_value(KEY)
  await expect(public).to_have_value(PUB)
  await private.fill(base64.b64encode(bytes([9])*32).decode())
  await expect(public).to_have_value(PUB)
  file=page.get_by_label("Импорт конфигурации WireGuard",exact=True)
  text=f"[Interface]\nPrivateKey={KEY}\nAddress=10.9.0.2/32,fd00::2/128\nDNS=1.1.1.1\nMTU=1380\n[Peer]\nPublicKey={PUB}\nEndpoint=new.example:51821\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=15\n"
  await file.set_input_files({"name":"test.conf","mimeType":"text/plain","buffer":text.encode()})
  await expect(page.get_by_text("Конфигурация перенесена",exact=False)).to_be_visible()
  await expect(page.locator('input[placeholder="10.8.0.2/32"]')).to_have_value("10.9.0.2/32")
  await expect(page.locator('input[placeholder="vpn.example.com:51820"]')).to_have_value("new.example:51821")
  await expect(public).to_have_value(PUB)
  split=text.replace("0.0.0.0/0,::/0","10.0.0.0/8").replace(",fd00::2/128", "").replace("DNS=1.1.1.1\n", "").replace("new.example", "split.example")
  for _ in range(2):
   await file.set_input_files({"name":"split.conf","mimeType":"text/plain","buffer":split.encode()})
   await expect(page.get_by_text("Конфигурация перенесена",exact=False)).to_be_visible()
   await expect(page.get_by_label("AllowedIPs WireGuard",exact=True)).to_have_value("0.0.0.0/0")
   await expect(page.locator('input[placeholder="vpn.example.com:51820"]')).to_have_value("split.example:51821")
   await expect(page.get_by_text("не перенесён",exact=False)).to_have_count(0)
  await file.set_input_files({"name":"bad.conf","mimeType":"text/plain","buffer":text.replace("10.9.0.2/32","10.9.0.2/99").encode()})
  await expect(page.get_by_text("Нужен один IPv4-адрес туннеля с маской.",exact=True)).to_be_visible()
  await expect(page.locator('input[placeholder="vpn.example.com:51820"]')).to_have_value("split.example:51821")
  assert not state["errors"],state["errors"]
  output=Path(__file__).resolve().parents[2]/".codex/wireguard-form.png"
  await page.screenshot(path=str(output),full_page=True)
  await browser.close()
  print("saved public key, generation, manual key, read-only AllowedIPs, file import/warnings and failed-import preservation PASS")
asyncio.run(main())
