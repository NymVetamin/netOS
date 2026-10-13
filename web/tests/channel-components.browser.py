"""Local production UI regression; all API calls are mocked, no router access."""
import asyncio
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
    selected = mode != "absent"
    cfg = {"system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [],
           "components": [{"id": cid, "installed": selected} for _, cid, _ in TYPES],
           "channels": [{"id": "direct", "type": "direct", "enabled": True, "name": "Напрямую"},
                        {"id": "saved", "type": "wireguard", "name": "Poland", "enabled": mode == "enabled-missing",
                         "index": 1, "config": {"address": "192.0.2.2/32", "endpoint": "example.test:51820"}, "probe": {"enabled": False}}]}
    state = {"config": cfg, "ready": mode == "ready", "error": mode == "error", "version": 1}
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
        elif path == "/api/config":
            if req.method == "PUT":
                state["config"] = req.post_data_json
                state["version"] += 1
            body = config()
        await route.fulfill(status=status, json=body)

    await page.add_init_script(OPEN_ROWS)
    await page.route("**/*", route_request)
    await page.goto("http://netos-ui.test/#channels")
    await expect(page.get_by_role("heading", name="Интернет-каналы", exact=True)).to_be_visible()
    toggle = page.get_by_role("checkbox", name="Использовать", exact=True).first
    await expect(page.locator('input[value="Poland"]')).to_be_visible()
    add = page.locator("details.addmenu > summary")
    if mode == "ready":
        await add.click()
        for _, _, label in TYPES:
            await expect(page.get_by_role("button", name=label, exact=True)).to_be_visible()
        # Escape closes the menu; it must not stay over the row switches.
        await page.keyboard.press("Escape")
        await expect(page.get_by_role("button", name="WireGuard", exact=True)).to_have_count(0)
        await expect(toggle).to_be_enabled()
        await toggle.locator("..").click()
        await expect(toggle).to_be_checked()
        await add.click()
        await page.get_by_role("button", name="WireGuard", exact=True).click()
        # The menu closes after a choice and the new channel opens by itself.
        await expect(page.get_by_role("button", name="WireGuard", exact=True)).to_have_count(0)
        await expect(page.locator('input[value="WireGuard 2"]')).to_be_visible()
    else:
        if mode == "error":
            await expect(page.get_by_text("Не удалось проверить компоненты", exact=True)).to_be_visible()
        else:
            await expect(page.get_by_text("Для других типов каналов нужны компоненты", exact=True)).to_be_visible()
        # No type can be created, so there is no "add" menu at all.
        await expect(add).to_have_count(0)
        if mode == "error":
            await expect(page.get_by_text("Poland: включение недоступно", exact=True)).to_have_count(0)
        else:
            await expect(page.get_by_text("Poland: включение недоступно", exact=True)).to_be_visible()
        if mode == "enabled-missing":
            await expect(toggle).to_be_enabled()
            await toggle.locator("..").click()
            await expect(toggle).not_to_be_checked()
        else:
            await expect(toggle).to_be_disabled()
            await expect(page.get_by_text("выключен", exact=True)).to_be_visible()
        if mode in ("pending", "error"):
            state.update(ready=True, error=False)
            await add.click(timeout=10000)
            await expect(page.get_by_role("button", name="WireGuard", exact=True)).to_be_visible()
            await expect(toggle).to_be_enabled()
            await expect(page.locator('input[value="Poland"]')).to_be_visible()
        else:
            await page.get_by_role("link", name="Открыть «Компоненты»", exact=True).click()
            await expect(page.get_by_role("heading", name="Компоненты", exact=True)).to_be_visible()
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("absent", "pending", "error", "ready", "enabled-missing"):
            await scenario(browser, mode)
        await browser.close()

asyncio.run(main())
