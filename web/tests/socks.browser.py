"""Local production UI regression; all API calls are mocked, no router access."""
import asyncio
import copy
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
TYPES = [("wireguard", "wireguard", "WireGuard"), ("openconnect", "openconnect", "OpenConnect"),
         ("xray", "xray", "Xray"), ("ikev2", "strongswan", "IKEv2"), ("l2tp", "l2tp", "L2TP")]


# Записи свёрнуты в строки; сценарий проверяет их настройки, поэтому раскрывает
# каждую строку сразу, как только она появляется.
OPEN_ROWS = """new MutationObserver(() => document.querySelectorAll('details.xd:not([data-opened])')
  .forEach((row) => { row.dataset.opened = '1'; row.open = true; })).observe(document, {childList: true, subtree: true})"""


async def scenario(browser, mode):
    page = await browser.new_page()
    cfg = {"system": {"hostname": "test"}, "interfaces": [], "policies": [],
           "networks": [{"id":"lan","name":"LAN","enabled":True,"router_address":"192.0.2.1/24"}],
           "components": [{"id":"xray","installed":True}],
           "channels": [{"id":"direct","enabled":True,"name":"Напрямую","type":"direct"}],
           "socks":{"enabled":False,"port":0,"auth":False}}
    cfg['interfaces']=[{'id':'br','name':'br-lan','kind':'bridge','enabled':True},{'id':'br2','name':'br-guests','kind':'bridge','enabled':True}]
    cfg['networks'][0]['interface']='br'
    cfg['networks'].append({'id':'guest','name':'Guests','interface':'br2','enabled':True,'router_address':'192.0.3.1/24'})
    cfg['vpn_servers']=[{'id':'wg','name':'WG test','type':'wireguard','enabled':True,'index':1,'subnet':'10.9.0.1/24'}, {'id':'ike','name':'IKE test','type':'ikev2','enabled':True,'index':2,'subnet':'10.10.0.1/24'}]
    cfg['firewall']={'enabled':True,'zones':[],'rules':[],'nat':[]}
    state = {"config": cfg, "ready": True, "error": False, "version": 1}
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def config():
        return {"config": state["config"], "dirty": False, "draft_version": state["version"], "problems": [], "pending_confirmation": False}

    async def route_request(route):
        req, path = route.request, urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        body, status = {}, 200
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "test"}
        elif path == "/api/catalog":
            body = {"components": [], "installed": {cid: state["ready"] for _, cid, _ in TYPES}}
            if state["error"]:
                status, body = 503, {"error": "unavailable"}
        elif path == "/api/status":
            body = {"interfaces": [], "channels": [], "uptime_seconds": 1}
        elif path == "/api/socks/status": body = {"enabled":False,"running":False}
        elif path == "/api/socks/credentials": body = {"username":"proxy","password":"fixture-password"}
        elif path == "/api/config":
            if req.method == "PUT":
                state["config"] = req.post_data_json
                state["version"] += 1
            body = config()
        await route.fulfill(status=status, json=body)

    await page.add_init_script(OPEN_ROWS)
    await page.add_init_script("Object.defineProperty(navigator, 'clipboard', {value: {writeText: async text => {window.copiedText=text}}})")
    await page.route("**/*", route_request)
    await page.goto("https://netos-ui.test/#services")
    await expect(page.get_by_role("heading",name="Сетевые службы",exact=True)).to_be_visible()
    toggle = page.get_by_role("checkbox",name="Включить SOCKS5",exact=True)
    await expect(toggle).to_be_enabled()
    await expect(page.get_by_label("Порт SOCKS5",exact=True)).to_have_count(0)
    await toggle.locator("..").click()
    await expect(toggle).to_be_checked()
    await expect(page.get_by_role("checkbox",name="Логин и пароль SOCKS5",exact=True)).to_be_checked()
    await page.wait_for_timeout(700)
    assert state["config"]["socks"]["networks"] == ["lan", "guest"]
    assert not state["config"]["socks"].get("allow_wan")
    for first, second in [('LAN','Guests'),('WG test','IKE test')]:
        a=await page.get_by_role('checkbox',name=first,exact=True).locator('..').bounding_box()
        b=await page.get_by_role('checkbox',name=second,exact=True).locator('..').bounding_box()
        assert b['y'] >= a['y']+a['height'] and abs(b['x']-a['x'])<2
    copy_button=page.get_by_role('button',name='Скопировать',exact=True).first
    await expect(copy_button.locator('svg')).to_have_count(1)
    await copy_button.click()
    await expect(page.get_by_role('button',name='Скопировано',exact=True)).to_be_visible()
    assert await page.evaluate('window.copiedText')=='192.0.2.1:1080'
    await page.get_by_role('checkbox',name='WG test',exact=True).locator('..').click()
    await page.get_by_label("Логин SOCKS5",exact=True).fill("proxy")
    await page.get_by_label("Пароль SOCKS5",exact=True).fill("fixture-password")
    await page.get_by_text("Дополнительные настройки",exact=True).click()
    await expect(page.get_by_role("checkbox",name="UDP через SOCKS5",exact=True)).to_have_count(0)
    wan = page.get_by_role("checkbox",name="Разрешить SOCKS5 с WAN — небезопасно",exact=True)
    await wan.locator("..").click()
    dialog = page.get_by_role("dialog")
    await expect(dialog).to_be_visible()
    await dialog.get_by_role("button",name="Отмена",exact=True).click()
    await expect(wan).not_to_be_checked()
    await wan.locator("..").click()
    await dialog.get_by_role("button",name="Открыть SOCKS5 в интернет",exact=True).click()
    await expect(wan).to_be_checked()
    await expect(page.get_by_text("ОПАСНО: SOCKS5 открыт со стороны интернета",exact=True)).to_be_visible()
    await expect(page.get_by_role("checkbox",name="Логин и пароль SOCKS5",exact=True)).to_be_disabled()
    await page.wait_for_timeout(700)
    assert state["config"]["socks"]["allow_wan"] and state["config"]["socks"]["auth"]
    await wan.locator("..").click()
    await expect(wan).not_to_be_checked()
    await expect(page.get_by_text("ОПАСНО: SOCKS5 открыт со стороны интернета",exact=True)).to_have_count(0)
    await page.get_by_role("button",name="Показать пароль",exact=True).click()
    await expect(page.locator("code").filter(has_text="fixture-password")).to_be_visible()
    await toggle.scroll_into_view_if_needed()
    Path("output/playwright").mkdir(parents=True,exist_ok=True)
    await page.screenshot(path="output/playwright/socks5-ui.png")
    await page.wait_for_timeout(700)  # Дождаться сохранения последнего переключения WAN.
    before=copy.deepcopy(state['config']['socks'])
    async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
        await toggle.locator('..').click()
    await expect(page.get_by_label('Порт SOCKS5',exact=True)).to_have_count(0)
    expected={**before,'enabled':False};assert state['config']['socks']==expected
    async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
        await toggle.locator('..').click()
    assert state['config']['socks']==before
    await expect(page.get_by_label('Порт SOCKS5',exact=True)).to_be_visible()
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("socks-wan",):
            await scenario(browser, mode)
        await browser.close()

asyncio.run(main())
