"""Run after npm run build: python tests/channel-amneziawg.browser.py.

An AmneziaWG channel is a WireGuard channel with obfuscation parameters:
it needs its own component, is created from the add menu, shows its own
type and fields, and an AmneziaVPN .conf turns a channel into one.
All requests are intercepted locally; no router is contacted or modified.
"""
import asyncio
import base64
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
KEY = base64.b64encode(bytes([7]) * 32).decode()
OPEN_ROWS = """new MutationObserver(() => document.querySelectorAll('details.xd:not([data-opened])')
  .forEach((row) => { row.dataset.opened = '1'; row.open = true; })).observe(document, {childList: true, subtree: true})"""
AWG_CONF = f"""[Interface]
PrivateKey = {KEY}
Address = 10.8.1.2/32
Jc = 5
Jmin = 50
Jmax = 1000
S1 = 30
S2 = 40
H1 = 100-200
H2 = 300
H3 = 400
H4 = 500
I1 = <b 0xc0ffee><r 8><t>
[Peer]
PublicKey = {KEY}
Endpoint = vpn.example:51820
AllowedIPs = 0.0.0.0/0
"""


async def scenario(browser, mode):
    page = await browser.new_page()
    ready = mode != "missing"
    channels = [{"id": "direct", "type": "direct", "enabled": True, "name": "Напрямую"}]
    if mode == "import":
        channels.append({"id": "plain", "type": "wireguard", "name": "Plain", "enabled": False, "index": 1, "mode": "tun",
                         "config": {"address": "192.0.2.2/32", "endpoint": "example.test:51820", "allowed_ips": ["0.0.0.0/0"]},
                         "probe": {"enabled": False}})
    state = {"config": {"system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [], "channels": channels,
                        "components": [{"id": "wireguard", "installed": True}, {"id": "amneziawg", "installed": ready}]}, "version": 1}
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    async def route_request(route):
        req, path = route.request, urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        body = {}
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "test"}
        elif path == "/api/catalog":
            body = {"components": [], "installed": {"wireguard": True, "amneziawg": ready}}
        elif path == "/api/status":
            body = {"interfaces": [], "channels": [], "uptime_seconds": 1}
        elif path == "/api/wireguard/keypair":
            body = {"private_key": KEY, "public_key": KEY}
        elif path == "/api/config":
            if req.method == "PUT":
                state["config"] = req.post_data_json
                state["version"] += 1
            body = {"config": state["config"], "dirty": False, "draft_version": state["version"], "problems": [], "pending_confirmation": False}
        await route.fulfill(json=body)

    await page.add_init_script(OPEN_ROWS)
    await page.route("**/*", route_request)
    await page.goto("http://netos-ui.test/#channels")
    await expect(page.get_by_role("heading", name="Интернет-каналы", exact=True)).to_be_visible()
    add = page.locator("details.addmenu > summary")
    jc = page.get_by_role("spinbutton", name="AmneziaWG Jc", exact=True)
    if mode == "missing":
        await add.click()
        item = page.get_by_role("button", name="AmneziaWG", exact=True)
        await expect(item).to_be_disabled()
        await expect(page.get_by_role("button", name="WireGuard", exact=True)).to_be_enabled()
    elif mode == "create":
        await add.click()
        await page.get_by_role("button", name="AmneziaWG", exact=True).click()
        await expect(page.locator('input[value="AmneziaWG 1"]')).to_be_visible()
        await expect(page.locator(".channel-row").get_by_text("AmneziaWG", exact=True)).to_be_visible()
        await expect(jc).to_have_value("4")
        await jc.fill("6")
        saved = lambda: next((c["config"].get("amneziawg", {}).get("jc") for c in state["config"]["channels"] if c["type"] == "wireguard"), None)
        for _ in range(50):  # the draft is saved after a short debounce
            if saved() == 6:
                break
            await asyncio.sleep(0.1)
        assert saved() == 6, state["config"]["channels"]
    else:
        await expect(jc).to_have_count(0)
        await page.get_by_label("Импорт конфигурации WireGuard").set_input_files(
            files=[{"name": "awg.conf", "mimeType": "text/plain", "buffer": AWG_CONF.encode()}])
        await expect(page.get_by_text("канал станет каналом AmneziaWG", exact=False)).to_be_visible()
        await expect(jc).to_have_value("5")
        await expect(page.get_by_role("textbox", name="AmneziaWG H1", exact=True)).to_have_value("100-200")
        await expect(page.get_by_role("textbox", name="AmneziaWG I1", exact=True)).to_have_value("<b 0xc0ffee><r 8><t>")
        await expect(page.locator(".channel-row").get_by_text("AmneziaWG", exact=True)).to_be_visible()
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("missing", "create", "import"):
            await scenario(browser, mode)
        await browser.close()


asyncio.run(main())
