"""Run after npm run build: python tests/component-required.browser.py.

dnsmasq installed without a selection but kept by the draft (internal DNS of an
L2TP server) must not be promised for removal; once nothing needs it, it is.
All requests are intercepted locally; no router is contacted or modified.
"""
import asyncio
import json
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
CATALOG = [{"id": "dnsmasq", "title": "dnsmasq", "group": "Сеть", "description": "DNS и DHCP"}]
REASON = "внутреннему DNS для VPN-клиентов, доменных политик или мониторинга трафика"


async def scenario(browser, mode):
    page = await browser.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    required = {"dnsmasq": REASON} if mode != "free" else {}
    installed = {"dnsmasq": mode != "missing"}

    async def route_request(route):
        req = route.request
        path = urlparse(req.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        body = {}
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "local-test"}
        elif path == "/api/catalog":
            body = {"components": CATALOG, "installed": installed, "running": {}, "unavailable": {}, "required": required}
        elif path == "/api/status":
            body = {"interfaces": [], "uptime_seconds": 1}
        elif path == "/api/config" and req.method == "GET":
            body = {"config": {"system": {"hostname": "r"}, "interfaces": [], "components": []},
                    "dirty": False, "draft_version": 1, "problems": [], "pending_confirmation": False}
        elif path == "/api/components/updates":
            body = {"components": {}, "operations": {}}
        else:
            raise AssertionError((req.method, path))
        await route.fulfill(content_type="application/json", body=json.dumps(body))

    await page.route("**/*", route_request)
    await page.goto("http://netos.test/#components")
    box = page.get_by_role("checkbox", name="Компонент dnsmasq включён")
    await expect(box).to_be_attached()
    await expect(box).not_to_be_checked()
    removal = page.get_by_text("отключён · удаляются только пакеты netOS", exact=True)
    need = page.get_by_text("нужен " + REASON, exact=True)
    install = page.get_by_text("будет установлен или исправлен", exact=True)
    if mode == "required":
        await expect(need).to_be_visible()
        await expect(removal).to_have_count(0)
        await expect(install).to_have_count(0)
    elif mode == "free":
        await expect(removal).to_be_visible()
        await expect(need).to_have_count(0)
    else:  # нужен, но пакета ещё нет: DNS его поставит
        await expect(need).to_be_visible()
        await expect(install).to_be_visible()
        await expect(removal).to_have_count(0)
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("required", "free", "missing"):
            await scenario(browser, mode)
        await browser.close()


asyncio.run(main())
