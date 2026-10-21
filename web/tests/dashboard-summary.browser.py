"""Production bundle, Chrome; mocked read-only API, no router changes."""
import asyncio
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"

async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        page = await browser.new_page(viewport={"width":1280,"height":1000})
        errors, writes = [], []
        page.on("pageerror", lambda e: errors.append(str(e)))
        mode = "healthy"
        status = {"interfaces":[], "wans":[], "channels":[], "uptime_seconds":90000,
                  "clients_online":0,"clients_total":0,"conntrack_count":23,
                  "firewall_enabled":True,"ipv6_mode":"off",
                  "client_summary":{"lan_online":0,"lan_total":0,"vpn_online":3,"vpn_total":12,"vpn_unknown":1},
                  "resources":{"cpu_percent":12.5,"memory_total":4294967296,"memory_used":1073741824,"cpu_temperature":49},
                  "services_available":True,"services":[
                      {"unit":"netosd.service","state":"active","substate":"running"},
                      {"unit":"netos-unbound.service","state":"failed","substate":"failed"},
                      {"unit":"netos-kea-dhcp4.service","state":"active","substate":"running"},
                      {"unit":"netos-samba.service","state":"inactive","substate":"dead"},
                      {"unit":"netos-xray-srv3.service","title":"Xray · VPN server","state":"activating","substate":"start"}]}
        cfg={"system":{"hostname":"router"},"interfaces":[],"networks":[],"channels":[],"wans":[],"vpn_servers":[],"policies":[]}
        async def route_request(route):
            parsed=urlparse(route.request.url)
            path=parsed.path
            if not path.startswith("/api/"):
                file=DIST/("index.html" if path=="/" else path.lstrip("/"))
                await route.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream");return
            if route.request.method!="GET": writes.append(path)
            body,code={},200
            if path=="/api/session":body={"username":"admin","role":"admin","csrf_token":"test"}
            elif path=="/api/config":body={"config":cfg,"dirty":False,"draft_version":1,"problems":[]}
            elif path=="/api/status":
                body=dict(status)
                if mode=="error":body,code={"error":"unavailable"},503
                elif mode=="missing":body.update(resources={},services=[],services_available=False)
                if parse_qs(parsed.query).get("overview")!=["1"]:
                    for key in ("client_summary","resources","services","services_available"):body.pop(key,None)
            await route.fulfill(status=code,json=body)
        await page.route("**/*",route_request)
        await page.goto("http://netos-ui.test/#dashboard")
        await expect(page.get_by_text("3 / 12",exact=True)).to_be_visible()
        await expect(page.get_by_text("12.5 %",exact=True)).to_be_visible()
        await expect(page.get_by_text("25.0 %",exact=True)).to_be_visible()
        await expect(page.get_by_text("49.0 °C",exact=True)).to_be_visible()
        await expect(page.locator('.dashboard-service').first).to_contain_text("Ошибка")
        await expect(page.locator('.dashboard-service').filter(has_text="Samba")).to_contain_text("Остановлена")
        await expect(page.get_by_text("Запускается / обновляется",exact=True)).to_be_visible()
        for theme in ("dark","light"):
            await page.evaluate("theme=>document.documentElement.dataset.theme=theme",theme)
            for width in (360,768,1280,1920):
                await page.set_viewport_size({"width":width,"height":1000})
                await page.wait_for_timeout(150)
                assert await page.evaluate("document.documentElement.scrollWidth<=innerWidth"), (theme,width)
                services=await page.locator('.dashboard-services').bounding_box()
                resources=await page.locator('.dashboard-resources').bounding_box()
                assert services['y']>resources['y']
                if width in (360,1280):
                    await page.screenshot(path=f"output/playwright/dashboard-summary-{theme}-{width}.png",full_page=True)
        mode="missing"
        await expect(page.get_by_text("Датчик недоступен",exact=True)).to_be_visible(timeout=10000)
        await expect(page.get_by_text("Не удалось получить состояние служб.",exact=False)).to_be_visible()
        mode="error"
        await expect(page.get_by_text("Не удалось обновить состояние роутера",exact=True)).to_be_visible(timeout=10000)
        mode="healthy"
        await expect(page.get_by_text("49.0 °C",exact=True)).to_be_visible(timeout=10000)
        await expect(page.get_by_text("Не удалось обновить состояние роутера",exact=True)).to_have_count(0)
        assert not errors,errors
        assert not writes,writes
        await browser.close()
        print("dashboard summary, themes, 360/768/1280/1920, failure/recovery PASS")

asyncio.run(main())
