"""Local production UI regression; all API calls are mocked, no router access."""
import asyncio
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def scenario(browser, mode):
    page = await browser.new_page()
    gate = asyncio.Event()
    errors, writes = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    cfg = {"system":{"hostname":"test"},"interfaces":[],"networks":[],"policies":[],
           "components":[{"id":"xray","installed":True}],
           "channels":[{"id":"vpn","index":1,"type":"xray","name":"Xray test","enabled":True,
                        "probe":{"enabled":True,"type":"http","targets":["https://example.test"],"interval":10},"config":{}}]}
    async def route_request(route):
        req, path = route.request, urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        body, status = {}, 200
        if req.method != "GET": writes.append(path)
        if path == "/api/session": body = {"username":"admin","role":"admin","csrf_token":"test"}
        elif path == "/api/config": body = {"config":cfg,"dirty":False,"draft_version":1,"problems":[],"pending_confirmation":False}
        elif path == "/api/catalog":
            await gate.wait()
            body = {"components":[],"installed":{"xray":mode!="missing"}}
            if mode == "error": status, body = 503,{"error":"unavailable"}
        elif path == "/api/status":
            await gate.wait()
            body = {"interfaces":[],"channels":[{"id":"vpn","name":"Xray test","interface":"tun-ch1","up":mode!="down","probe_down":mode=="down"}]}
            if mode == "error": status, body = 503,{"error":"unavailable"}
        await route.fulfill(status=status,json=body)
    await page.route("**/*",route_request)
    await page.goto("http://netos-ui.test/#channels")
    await expect(page.get_by_role("heading",name="Интернет-каналы",exact=True)).to_be_visible()
    await expect(page.get_by_text("Проверяем установленные VPN-компоненты…",exact=True)).to_be_visible()
    await expect(page.get_by_text("Загрузка состояния каналов…",exact=True)).to_be_visible()
    await expect(page.get_by_text("Xray test: включение недоступно",exact=True)).to_have_count(0)
    await expect(page.get_by_text("Активных VPN-каналов нет",exact=True)).to_have_count(0)
    await expect(page.get_by_text("нет связи",exact=True)).to_have_count(0)
    gate.set()
    if mode == "missing":
        await expect(page.get_by_text("Xray test: включение недоступно",exact=True)).to_be_visible()
    elif mode == "down":
        await expect(page.get_by_text("проба не прошла",exact=True)).to_be_visible()
    elif mode == "error":
        await expect(page.get_by_text("Не удалось проверить компоненты",exact=True)).to_be_visible()
        await expect(page.get_by_text("Не удалось обновить состояние каналов",exact=True)).to_be_visible()
        await expect(page.get_by_text("Xray test: включение недоступно",exact=True)).to_have_count(0)
        await expect(page.get_by_text("Активных VPN-каналов нет",exact=True)).to_have_count(0)
    else:
        await expect(page.get_by_text("поднят",exact=True)).to_be_visible()
        await expect(page.get_by_text("Xray test: включение недоступно",exact=True)).to_have_count(0)
        # Re-enter the page with a fresh, deliberately delayed catalog request.
        await page.goto("http://netos-ui.test/#components")
        await expect(page.get_by_role("heading",name="Компоненты",exact=True)).to_be_visible()
        gate.clear()
        await page.goto("http://netos-ui.test/#channels")
        await expect(page.get_by_text("Проверяем установленные VPN-компоненты…",exact=True)).to_be_visible()
        await expect(page.get_by_text("Xray test: включение недоступно",exact=True)).to_have_count(0)
        gate.set()
        await expect(page.get_by_text("поднят",exact=True)).to_be_visible()
    assert not errors, errors
    assert not writes, writes
    await page.close()
    print(mode,"PASS")

async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("healthy", "down", "missing", "error"):
            await scenario(browser, mode)
        await browser.close()

asyncio.run(main())
