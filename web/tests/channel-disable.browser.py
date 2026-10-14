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
    cfg = {"system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [],
           "components": [{"id": "xray", "installed": True}],
           "channels": [
               {"id": "direct", "type": "direct", "enabled": True, "name": "Напрямую"},
               {"id": "busy", "type": "xray", "enabled": True, "name": "Busy", "config": {}, "probe": {}},
               {"id": "free", "type": "xray", "enabled": True, "name": "Free", "config": {}, "probe": {}},
               {"id": "dependent", "type": "xray", "enabled": True, "name": "Dependent", "fallback": "busy", "config": {}, "probe": {}}],
           "vpn_servers": [{"id": "vpn", "name": "VPN", "peers": [
               {"id": "phone", "name": "Phone", "channel": "busy", "password": "synthetic-secret"}]}]}
    state = {"config": cfg, "ready": True, "error": False, "version": 1, "writes": 0}
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
                state["writes"] += 1
                state["config"] = req.post_data_json
                state["version"] += 1
            body = config()
        await route.fulfill(status=status, json=body)

    await page.add_init_script(OPEN_ROWS)
    await page.route("**/*", route_request)
    await page.goto("http://netos-ui.test/#channels")
    await expect(page.get_by_role("heading", name="Интернет-каналы", exact=True)).to_be_visible()
    toggle = page.get_by_role("checkbox", name="Использовать", exact=True).first
    await toggle.locator("..").click()
    confirm = page.get_by_role("button", name="Переназначить и выключить", exact=True)
    await expect(confirm).to_be_disabled()
    await expect(page.get_by_text("VPN-клиент: VPN / Phone", exact=True)).to_be_visible()
    await expect(page.get_by_text("Запасной выход канала: Dependent", exact=True)).to_be_visible()
    choice = page.get_by_label("Новый канал вместо отключаемого")
    await expect(choice.locator('option[value="dependent"]')).to_have_count(0)
    await expect(toggle).to_be_checked()
    assert state["writes"] == 0
    await page.get_by_role("button", name="Отмена", exact=True).click()
    await expect(confirm).to_have_count(0)
    assert state["writes"] == 0
    await toggle.locator("..").click()
    await choice.select_option("direct")
    await expect(page.get_by_text("Связанный трафик пойдёт напрямую, без этого VPN-канала.", exact=True)).to_be_visible()
    await choice.select_option("free")
    await confirm.click()
    await expect(toggle).not_to_be_checked()
    await page.wait_for_timeout(800)
    assert state["writes"] == 1, state["writes"]
    assert state["config"]["vpn_servers"][0]["peers"][0] == {
        "id": "phone", "name": "Phone", "channel": "free", "password": "synthetic-secret"}
    assert state["config"]["channels"][3]["fallback"] == "free"
    await page.reload()
    await expect(toggle).not_to_be_checked()
    # The now unused channel can be enabled and disabled without a replacement prompt.
    await toggle.locator("..").click()
    await expect(toggle).to_be_checked()
    await page.wait_for_timeout(800)
    await toggle.locator("..").click()
    await expect(toggle).not_to_be_checked()
    await expect(confirm).to_have_count(0)
    await page.wait_for_timeout(800)
    assert state["writes"] == 3, state["writes"]
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("disable-with-dependencies",):
            await scenario(browser, mode)
        await browser.close()

asyncio.run(main())
