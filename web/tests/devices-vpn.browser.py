"""Local production UI regression; all API calls are mocked, no router access."""
import asyncio
import re
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def scenario(browser, mode):
    page = await browser.new_page(viewport={"width":1600,"height":1000})
    errors, writes = [], []
    page.on("pageerror",lambda e:errors.append(str(e)))
    cfg={"system":{"hostname":"router"},"interfaces":[{"id":"lan","name":"br-lan","type":"bridge"}],"wans":[],"channels":[],"policies":[],
         "networks":[{"id":"lan","name":"LAN","enabled":True,"interface":"lan","router_address":"192.168.10.1/24"}],"vpn_servers":[]}
    if mode!="no-vpn":
        cfg["vpn_servers"]=[{"id":"wg1","name":"VPN server","type":"wireguard","enabled":True,"subnet":"10.9.0.1/24",
           "peers":[{"id":"phone","name":"Phone","address":"10.9.0.2","enabled":True},
                    {"id":"tablet","name":"Tablet","address":"10.9.0.3","enabled":True},
                    {"id":"denied","name":"Denied","address":"10.9.0.4","enabled":False}]}]
    if mode=="many":
        cfg["vpn_servers"].append({"id":"wg2","name":"Other server","type":"wireguard","enabled":False,"peers":[{"id":"phone","name":"Other phone","enabled":True}]})
    cfg["dhcp"]={"reservations":[{"id":"saved","mac":"aa:bb:cc:dd:ee:ff","ip":"192.168.10.50","hostname":"Offline laptop","network":"lan","enabled":True}]}
    cfg["channels"]=[{"id":"direct","name":"Напрямую","enabled":True},{"id":"exit","name":"Xray Riga","enabled":True},{"id":"off","name":"Disabled exit","enabled":False}]
    cfg["networks"][0]["default_channel"]="exit"
    telemetry_error=mode=="error"
    async def route_request(route):
        req,path=route.request,urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file=DIST/("index.html" if path=="/" else path.lstrip("/"))
            await route.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream");return
        body,status={},200
        if req.method!="GET":writes.append(path)
        if path=="/api/session":body={"username":"admin","role":"admin","csrf_token":"test"}
        elif path=="/api/config":
            if req.method=="PUT":
                updated=req.post_data_json
                cfg.clear();cfg.update(updated)
            body={"config":cfg,"dirty":bool(writes),"draft_version":1,"problems":[],"pending_confirmation":False}
        elif path=="/api/status":body={"interfaces":[],"wans":[],"channels":[],"uptime_seconds":100}
        elif path=="/api/clients":body={"clients":[]}
        elif path.endswith("/clients") and path.startswith("/api/vpn-servers/"):
            body=[{"id":"phone","state":"recent","endpoint":"192.0.2.10:4567","last_handshake":1700000000,"received":1234,"sent":5678},
                  {"id":"tablet","state":"never"}]
            if telemetry_error:status,body=503,{"error":"unavailable"}
        await route.fulfill(status=status,json=body)
    await page.route("**/*",route_request)
    await page.goto("http://netos-ui.test/#clients")
    await expect(page.get_by_text("Offline laptop",exact=True)).to_be_visible()
    await expect(page.get_by_role("button",name="Открепить адрес устройства aa:bb:cc:dd:ee:ff",exact=True)).to_be_visible()
    await expect(page.get_by_text("Закреплённые адреса",exact=True)).to_have_count(0)
    await expect(page.get_by_text("Закрепить адрес",exact=True)).to_have_count(0)
    await expect(page.get_by_role("button",name="Добавить по MAC",exact=True)).to_be_visible()
    if mode!="no-vpn":
        await expect(page.get_by_text("Phone",exact=True)).to_be_visible()
        await expect(page.get_by_text("VPN · VPN server · WireGuard",exact=True)).to_have_count(3)
        if mode=="many":
            await expect(page.get_by_text("Other phone",exact=True)).to_be_visible()
            await expect(page.get_by_text("сервер выключен",exact=True)).to_be_visible()
        elif mode=="error":
            await expect(page.get_by_text("Состояние VPN-клиентов недоступно",exact=True)).to_be_visible()
        else:
            await expect(page.get_by_text("недавно на связи",exact=True)).to_be_visible()
            settings=page.get_by_role("link",name="Настройки VPN-клиента").first
            await expect(settings).to_be_visible()
            await expect(settings).to_have_attribute("title", "Настройки VPN-клиента")
            await expect(settings.locator("svg")).to_have_count(1)
            await page.get_by_text("Phone",exact=True).click()
            await expect(page.get_by_text("192.0.2.10:4567",exact=True)).to_be_visible()
            await expect(page.get_by_role("link",name="Настройки VPN-клиента").first).to_have_attribute("href","#vpn-servers?server=wg1&client=phone")
            telemetry_error=True
            await expect(page.get_by_text("Состояние VPN-клиентов недоступно",exact=True)).to_be_visible(timeout=10000)
            await expect(page.get_by_text("недавно на связи",exact=True)).to_have_count(0)
            telemetry_error=False
            await expect(page.get_by_text("недавно на связи",exact=True)).to_be_visible(timeout=10000)
    if mode=="many":
        first=page.get_by_label("Канал VPN-клиента VPN server / Phone",exact=True)
        second=page.get_by_label("Канал VPN-клиента Other server / Other phone",exact=True)
        await expect(first).to_have_value("")
        async with page.expect_response(lambda r:r.request.method=="PUT" and r.url.endswith("/api/config")):
            await first.select_option("exit")
        assert cfg["vpn_servers"][0]["peers"][0]["channel"]=="exit"
        assert not cfg["vpn_servers"][1]["peers"][0].get("channel")
        await expect(second).to_have_value("")
        await page.reload()
        await expect(first).to_have_value("exit")
        async with page.expect_response(lambda r:r.request.method=="PUT" and r.url.endswith("/api/config")):
            await first.select_option("")
        assert cfg["vpn_servers"][0]["peers"][0]["channel"]==""
        lan=page.get_by_label("Канал для устройства aa:bb:cc:dd:ee:ff",exact=True)
        await expect(lan.locator("option:checked")).to_have_text("По сегменту — Xray Riga")
        async with page.expect_response(lambda r:r.request.method=="PUT" and r.url.endswith("/api/config")):
            await lan.select_option("direct")
        assert cfg["clients"][0]["channel"]=="direct"
        await page.reload()
        await expect(lan).to_have_value("direct")
        await page.screenshot(path="output/playwright/client-channels.png")
    if mode in ('healthy','many'):
        target_server='wg2' if mode=='many' else 'wg1'
        settings=page.get_by_role('link',name='Настройки VPN-клиента').last if mode=='many' else page.get_by_role('link',name='Настройки VPN-клиента').first
        await settings.click()
        target=page.locator(f'.peer-card[data-vpn-server="{target_server}"][data-vpn-client="phone"] > details')
        await expect(target).to_have_attribute('open','')
        await expect(target.locator(':scope > summary')).to_be_focused()
        box=await target.locator(':scope > summary').bounding_box()
        assert box['y']>50 and box['y']+box['height']<1000,box
        if mode=='many':
            await expect(page.locator('.peer-card[data-vpn-server="wg1"][data-vpn-client="phone"] > details')).not_to_have_attribute('open','')
        await page.reload()
        await expect(target).to_have_attribute('open','')
        await expect(target.locator(':scope > summary')).to_be_focused()
        await page.goto('http://netos-ui.test/#clients')
    await page.get_by_role("button",name="Добавить по MAC",exact=True).click()
    await expect(page.get_by_text("Добавить устройство по MAC",exact=True)).to_be_visible()
    await page.get_by_role("button",name="Закрыть добавление",exact=True).click()
    await expect(page.get_by_text("Добавить устройство по MAC",exact=True)).to_have_count(0)
    await page.set_viewport_size({"width":390,"height":844})
    assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth"), "Horizontal overflow"
    assert not errors,errors
    async with page.expect_response(lambda r: r.request.method=="PUT" and r.url.endswith("/api/config")):
        await page.get_by_role("button",name="Открепить адрес устройства aa:bb:cc:dd:ee:ff",exact=True).click()
    assert cfg["dhcp"]["reservations"]==[]
    await page.reload()
    await expect(page.get_by_text("Offline laptop",exact=True)).to_have_count(0)
    assert writes==["/api/config"]*(4 if mode=="many" else 1),writes
    await page.close();print(mode,"PASS")

async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("healthy", "error", "many", "no-vpn"):
            await scenario(browser, mode)
        await browser.close()

asyncio.run(main())
