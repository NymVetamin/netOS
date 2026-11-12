"""Run after npm run build: python tests/component-unavailable.browser.py.

A component the machine cannot install (AmneziaWG without headers for the
running kernel) shows the reason and cannot be selected; once selected or
installed it stays switchable, and an installable one is unaffected.
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
REASON = "Невозможно установить AmneziaWG: требуется обновление ядра Linux."
CATALOG = [{"id": "amneziawg", "title": "AmneziaWG", "group": "VPN", "description": "WireGuard с маскировкой"},
           {"id": "wireguard", "title": "WireGuard", "group": "VPN", "description": "Туннель"}]


async def scenario(browser, mode):
    page = await browser.new_page()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    components = [{"id": "amneziawg", "installed": True}] if mode == "selected" else []
    installed = {"amneziawg": mode == "installed", "wireguard": False}
    unavailable = {} if mode == "installed" else {"amneziawg": REASON}

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
            body = {"components": CATALOG, "installed": installed, "running": {}, "unavailable": unavailable}
        elif path == "/api/status":
            body = {"interfaces": [], "uptime_seconds": 1}
        elif path == "/api/config" and req.method == "GET":
            body = {"config": {"system": {"hostname": "r"}, "interfaces": [], "components": components},
                    "dirty": False, "draft_version": 1, "problems": [], "pending_confirmation": False}
        elif path == "/api/components/updates":
            body = {"components": {}, "operations": {}}
        else:
            raise AssertionError((req.method, path))
        await route.fulfill(content_type="application/json", body=json.dumps(body))

    await page.route("**/*", route_request)
    await page.goto("http://netos.test/#components")
    awg = page.get_by_role("checkbox", name="Компонент AmneziaWG включён")
    wg = page.get_by_role("checkbox", name="Компонент WireGuard включён")
    await expect(awg).to_be_attached()
    await expect(wg).to_be_enabled()
    reason = page.get_by_text("требуется обновление ядра Linux", exact=False)
    if mode == "blocked":
        await expect(reason).to_be_visible()
        await expect(awg).to_be_disabled()
        await expect(awg).not_to_be_checked()
    elif mode == "selected":
        # Turning a selected component off must stay possible.
        await expect(reason).to_be_visible()
        await expect(awg).to_be_enabled()
        await expect(awg).to_be_checked()
    else:
        await expect(reason).to_have_count(0)
        await expect(awg).to_be_enabled()
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("blocked", "selected", "installed"):
            await scenario(browser, mode)
        await browser.close()


asyncio.run(main())
