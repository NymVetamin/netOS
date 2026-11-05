"""Production UI regression fixtures; all traffic is intercepted, no router access."""
import asyncio
import copy
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
CONFIG = {
    "system": {"hostname": "test"}, "wans": [], "channels": [], "multiwan": {},
    "interfaces": [{"id": "lan", "name": "br-lan", "type": "bridge", "enabled": True, "members": []}],
    "networks": [{"id": "lan", "name": "LAN", "interface": "lan", "enabled": True,
                  "router_address": "192.0.2.1/24", "dhcp_pool": {"enabled": False}}],
    "components": [{"id": "dnsmasq", "installed": True}],
    "dns": {"enabled": True, "provider": "dnsmasq", "port": 53},
    "dhcp": {"enabled": True, "provider": "dnsmasq"}, "ddns": {},
}


async def fixture(browser, session, config=None):
    page = await browser.new_page()
    state = {"config": copy.deepcopy(config or CONFIG), "status_error": False,
             "up": True, "polls": 0, "writes": [], "errors": []}
    page.on("pageerror", lambda e: state["errors"].append(str(e)))

    async def route(r):
        req, path = r.request, urlparse(r.request.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await r.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        if req.method != "GET":
            state["writes"].append(path)
        body, status = {}, 200
        if path == "/api/session":
            body = {"username": "test", "csrf_token": "test", **session}
        elif path == "/api/config":
            body = {"config": state["config"], "dirty": False, "draft_version": 1,
                    "problems": [], "pending_confirmation": False}
        elif path == "/api/status":
            state["polls"] += 1
            body = {"interfaces": [{"name": "br-lan", "up": state["up"]}], "wans": [], "channels": []}
            if state["status_error"]:
                status, body = 503, {"error": "offline"}
        elif path == "/api/interfaces":
            body = {"interfaces": [{"name": "br-lan", "up": True}]}
        elif path == "/api/catalog":
            body = {"components": []}
        elif path == "/api/components/status":
            body = {"installed": {"dnsmasq": True}}
        await r.fulfill(status=status, json=body)

    await page.route("**/*", route)
    return page, state


async def service_tabs(browser, session, editable):
    page, state = await fixture(browser, session)
    await page.goto("http://netos.test/#services")
    for label in ["DNS", "DDNS", "SOCKS5", "IPTV", "DHCP", "DNS"]:
        tab = page.get_by_role("tab", name=label, exact=True)
        await tab.click()
        await expect(tab).to_have_attribute("aria-selected", "true")
        await expect(page.get_by_role("tabpanel", name=label, exact=True)).to_be_visible()
        assert await page.locator('[role="tabpanel"]:not([hidden])').count() == 1
    await page.reload()
    await expect(page.get_by_role("tab", name="DNS", exact=True)).to_have_attribute("aria-selected", "true")
    tab = page.get_by_role("tab", name="DHCP", exact=True)
    await tab.focus()
    await page.keyboard.press("Enter")
    toggle = page.get_by_role("checkbox", name="DHCP сервер", exact=True)
    if editable:
        await expect(toggle).to_be_enabled()
    else:
        await expect(toggle).to_be_disabled()
    assert not state["writes"] and not state["errors"], state
    await page.close()
    print("service tabs", session, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for session, editable in [({"role": "viewer"}, False),
                                  ({"role": "limited", "permissions": {"services": "view"}}, False),
                                  ({"role": "admin"}, True)]:
            await service_tabs(browser, session, editable)
        await browser.close()


asyncio.run(main())
