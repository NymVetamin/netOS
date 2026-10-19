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
        if path=="/api/session":body={"username":"operator","role":"limited","permissions":{"clients":mode,"map":"view"},"csrf_token":"test"}
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
        await route.fulfill(status=status,json=body,content_type="application/json")
    await page.route("**/*",route_request)
    await page.goto("http://netos-ui.test/#clients")
    await expect(page.get_by_text("Offline laptop",exact=True)).to_be_visible()
    assert await page.locator('.nav-item').count()==2
    assert await page.get_by_role("link",name="Настройки VPN-клиента").count()==0
    control=page.get_by_label("Канал VPN-клиента VPN server / Phone",exact=True)
    if mode=="view":
        await expect(control).to_be_disabled()
    else:
        await expect(control).to_be_enabled()
        await control.select_option("exit")
        await page.wait_for_timeout(1000)
        assert cfg["vpn_servers"][0]["peers"][0]["channel"]=="exit"
    await page.evaluate("location.hash='system'")
    await expect(page.get_by_text("Нет доступа к разделу",exact=True)).to_be_visible()
    assert await page.get_by_text("Пользователи панели",exact=True).count()==0
    await page.evaluate("location.hash='map'")
    await expect(page.get_by_role("heading",name="Карта сети",exact=True)).to_be_visible()
    assert not errors,errors
    await page.close();print(mode,"PASS")

async def users_scenario(browser):
    page=await browser.new_page(viewport={"width":1440,"height":1000})
    errors=[]; users=[{"username":"admin","role":"admin","enabled":True,"permissions":{}}]
    page.on("pageerror",lambda e:errors.append(str(e)))
    cfg={"system":{"hostname":"router","ntp":{"enabled":False,"servers":[]}},"interfaces":[],"networks":[],"channels":[],"policies":[]}
    async def route_request(route):
        req,path=route.request,urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file=DIST/("index.html" if path=="/" else path.lstrip("/"))
            await route.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream");return
        body={}
        if path=="/api/session":body={"username":"admin","role":"admin","csrf_token":"test"}
        elif path=="/api/config":body={"config":cfg,"dirty":False,"draft_version":1,"problems":[]}
        elif path=="/api/panel-users":
            if req.method=="POST":
                user=req.post_data_json;assert user.pop("password")=="temporary-test-password";users.append(user)
            body=users if req.method=="GET" else {"ok":True}
        elif path=="/api/status":body={"interfaces":[],"channels":[]}
        await route.fulfill(json=body,content_type="application/json")
    await page.route("**/*",route_request)
    await page.goto("http://netos-ui.test/#system")
    await page.get_by_role("button",name="Добавить пользователя панели",exact=True).click()
    await page.get_by_label("Логин пользователя панели",exact=True).fill("operator")
    await page.get_by_label("Пароль пользователя панели",exact=True).fill("temporary-test-password")
    await page.get_by_label("Управление: Клиенты",exact=True).check()
    await expect(page.get_by_label("Просмотр: Клиенты",exact=True)).to_be_checked()
    await page.get_by_label("Просмотр: Клиенты",exact=True).uncheck()
    await expect(page.get_by_label("Управление: Клиенты",exact=True)).not_to_be_checked()
    await page.get_by_label("Управление: Клиенты",exact=True).check()
    await expect(page.get_by_label("Управление: Карта сети",exact=True)).to_have_count(0)
    await page.get_by_label("Просмотр: Карта сети",exact=True).check()
    Path("output/playwright").mkdir(parents=True, exist_ok=True)
    matrix=page.get_by_role("table",name="Права по страницам")
    await matrix.screenshot(path="output/playwright/permissions-table.png")
    await page.set_viewport_size({"width":390,"height":800})
    box=await matrix.bounding_box()
    assert box["x"]>=0 and box["x"]+box["width"]<=390,box
    assert await matrix.evaluate("el => el.scrollWidth <= el.clientWidth"), "table overflows on mobile"
    await matrix.screenshot(path="output/playwright/permissions-mobile.png")
    await page.get_by_role("button",name="Сохранить пользователя",exact=True).click()
    await expect(page.get_by_text("operator",exact=True)).to_be_visible()
    assert users[-1]["permissions"]=={"clients":"manage","map":"view"}
    listing=page.locator('.panel-users-table')
    card=listing.locator('xpath=ancestor::section[1]')
    await expect(listing.locator('tbody tr')).to_have_count(2)
    await card.screenshot(path="output/playwright/panel-users-mobile.png")
    assert await card.evaluate("el => el.scrollWidth <= el.clientWidth"), "users overflow on mobile"
    await page.set_viewport_size({"width":1440,"height":1000})
    await card.screenshot(path="output/playwright/panel-users-desktop.png")
    await listing.locator('tr').filter(has_text='operator').get_by_role('button',name='Изменить',exact=True).click()
    await expect(page.get_by_label('Логин пользователя панели',exact=True)).to_have_value('operator')
    await expect(page.get_by_label('Логин пользователя панели',exact=True)).to_be_disabled()
    await page.get_by_role('button',name='Отмена',exact=True).click()
    await expect(page.get_by_role('button',name='Добавить пользователя панели',exact=True)).to_be_enabled()
    assert not errors,errors
    await page.close();print("user form PASS")

async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("view", "manage"):
            await scenario(browser, mode)
        await users_scenario(browser)
        await browser.close()

asyncio.run(main())
