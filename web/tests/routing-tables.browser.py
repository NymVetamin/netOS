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
    errors, writes = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    cfg = {"system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [], "components": [],
           "routing": {"static": [], "tables": [], "rules": []},
           "channels": [{"id": "vpn", "index": 1, "type": "xray", "name": "Xray test"}]}
    live = {"rules": "0: from all lookup local\n10001: from all fwmark 0x1001 lookup netos-ch1\n20000: from all lookup 3001\n32766: from all lookup main",
            "routes": "", "parsed": [
                {"table": "main", "type": "unicast", "destination": "default", "interface": "eth0", "origin": "dhcp"},
                {"table": "netos-ch1", "type": "unicast", "destination": "default", "interface": "tun-ch1", "origin": "netos"},
                {"table": "netos-ch1", "type": "blackhole", "destination": "default", "interface": "", "metric": 1000, "origin": "netos"}]}
    async def route_request(route):
        req, path = route.request, urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        body, status = {}, 200
        if req.method != "GET": writes.append(path)
        if path == "/api/session": body = {"username":"admin", "role":"admin", "csrf_token":"test"}
        elif path == "/api/catalog": body = {"components":[],"installed":{}}
        elif path == "/api/status": body = {"interfaces":[],"channels":[]}
        elif path == "/api/config": body = {"config": cfg,"dirty": False,"draft_version":1,"problems":[],"pending_confirmation":False}
        elif path == "/api/routes":
            assert urlparse(req.url).query == "table=all", req.url
            if mode == "error": status,body = 500,{"error":"route collection failed"}
            else: body = live
        await route.fulfill(status=status,json=body)
    await page.route("**/*",route_request)
    await page.goto("http://netos-ui.test/#routing")
    await expect(page.get_by_role("heading",name="Маршрутизация",exact=True)).to_be_visible()
    await expect(page.get_by_text("Пока весь трафик идёт по основной таблице.",exact=False)).to_have_count(0)
    if mode == "error":
        await expect(page.get_by_text("Действующие таблицы недоступны",exact=True)).to_be_visible()
    else:
        tables = page.get_by_role("table",name="Автоматические таблицы маршрутизации")
        await expect(tables.get_by_text("Интернет-канал: Xray test (xray)",exact=True)).to_be_visible()
        await expect(tables.get_by_text("3001",exact=True).first).to_be_visible()
        await tables.get_by_role("row").filter(has_text="netos-ch1").get_by_role("button").click()
        await expect(page.get_by_role("combobox",name="Показать таблицу маршрутизации")).to_have_value("netos-ch1")
        await expect(page.get_by_text("blackhole default",exact=True)).to_be_visible()
        await expect(page.get_by_text("eth0",exact=True)).to_have_count(0)
        await page.get_by_role("combobox",name="Показать таблицу маршрутизации").select_option("3001")
        await expect(page.get_by_text("Таблица пуста",exact=True)).to_be_visible()
        await page.get_by_role("combobox",name="Показать таблицу маршрутизации").select_option("all")
        await expect(page.get_by_text("eth0",exact=True)).to_be_visible()
    assert not writes, writes
    assert not errors, errors
    await page.close()
    print(mode,"PASS")

async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("live", "error"):
            await scenario(browser, mode)
        await browser.close()

asyncio.run(main())
