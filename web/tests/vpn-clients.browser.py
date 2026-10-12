"""Production UI with mocked API; never connects to a router."""
import asyncio
import base64
import copy
import mimetypes
import os
import sys
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
PRIVATE = base64.b64encode(b"a" * 32).decode()
PUBLIC = base64.b64encode(b"b" * 32).decode()
NEW_PRIVATE = base64.b64encode(b"c" * 32).decode()
NEW_PUBLIC = base64.b64encode(b"d" * 32).decode()
SERVER_PUBLIC = base64.b64encode(b"e" * 32).decode()


async def scenario(browser, mode):
    page = await browser.new_page()
    peer = {"id": "phone", "name": "Телефон", "enabled": True, "address": "10.9.0.2", "credentials": {"public_key": PUBLIC, "preshared_key": "stored-psk"}}
    if mode != "legacy":
        peer["credentials"]["private_key"] = PRIVATE
    cfg = {"system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [],
           "components": [{"id": "wireguard", "installed": True}],
           "channels": [{"id": "direct", "type": "direct", "enabled": True, "name": "Напрямую"}],
           "vpn_servers": [{"id": "srv", "type": "wireguard", "name": "WireGuard", "index": 1, "enabled": True,
                            "subnet": "10.9.0.1/24", "port": 51820, "peers": [peer],
                            "config": {"public_endpoint": "vpn.example.test:51820", "client_dns": ["1.1.1.1"]}}]}
    original = copy.deepcopy(cfg)
    state = {"dirty": False, "config": cfg, "telemetry": "recent", "profiles": 0, "keys": 0}
    errors = []
    page.on("pageerror", lambda err: errors.append(str(err)))

    def config_response():
        redacted = copy.deepcopy(state["config"])
        for p in redacted["vpn_servers"][0]["peers"]:
            for key in ("private_key", "preshared_key"):
                if key in p["credentials"]:
                    p["credentials"][key] = ""
        return {"config": redacted, "dirty": state["dirty"], "draft_version": 1, "problems": []}

    async def route_request(route):
        req, path = route.request, urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        body, code = {}, 200
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "test"}
        elif path == "/api/status":
            body = {"interfaces": [], "channels": [], "uptime_seconds": 1}
        elif path == "/api/config":
            if req.method == "PUT":
                updated = req.post_data_json
                old = {p["id"]: p for p in state["config"]["vpn_servers"][0]["peers"]}
                for p in updated["vpn_servers"][0]["peers"]:
                    for key in ("private_key", "preshared_key"):
                        if key in p["credentials"] and not p["credentials"][key]:
                            p["credentials"][key] = old.get(p["id"], {}).get("credentials", {}).get(key, "")
                state["config"] = updated
                state["dirty"] = True
            body = config_response()
        elif path == "/api/config/discard":
            state["config"] = copy.deepcopy(original)
            state["dirty"] = False
            body = {"ok": True, "draft_version": 1}
        elif path.endswith("/clients"):
            if state["telemetry"] == "error":
                code, body = 503, {"error": "unavailable"}
            else:
                body = [{"id": "phone", "public_key": PUBLIC, "state": state["telemetry"], "last_handshake": 1791800000,
                         "endpoint": "192.0.2.5:43210", "received": 1048576, "sent": 2097152}]
        elif path.endswith("/profile"):
            state["profiles"] += 1
            creds = state["config"]["vpn_servers"][0]["peers"][0]["credentials"]
            assert creds.get("private_key"), "read occurred before pending save"
            body = {"privateKey": creds["private_key"], "publicKey": creds["public_key"], "serverPublicKey": SERVER_PUBLIC, "presharedKey": creds["preshared_key"]}
        elif path == "/api/wireguard/keypair":
            data = req.post_data_json or {}
            if data.get("server_id"):
                body = {"public_key": SERVER_PUBLIC, "private_key": ""}
            elif data.get("private_key"):
                body = {"public_key": PUBLIC if data["private_key"] == PRIVATE else "wrong", "private_key": ""}
            else:
                state["keys"] += 1
                body = {"private_key": NEW_PRIVATE, "public_key": NEW_PUBLIC}
        await route.fulfill(status=code, json=body)

    await page.route("**/*", route_request)
    await page.goto("https://netos-ui.test/#vpn-servers")
    await expect(page.get_by_role("heading", name="VPN-доступ", exact=True, level=1)).to_be_visible()
    await expect(page.get_by_text("В сети · недавнее рукопожатие", exact=True)).to_be_visible()
    await expect(page.get_by_text("192.0.2.5:43210", exact=True)).to_be_visible()
    await expect(page.get_by_text("1 МиБ", exact=True)).to_be_visible()
    await expect(page.get_by_text("2 МиБ", exact=True)).to_be_visible()
    assert state["profiles"] == 0, "secrets fetched without user action"
    if mode == "legacy":
        await expect(page.get_by_text("Профиль создан в прежней версии", exact=True)).to_be_visible()
        upload = page.get_by_label("Загрузить прежний .conf", exact=True)
        await upload.set_input_files({"name": "other.conf", "mimeType": "text/plain", "buffer": b"PrivateKey = wrong\n"})
        await expect(page.get_by_text("Этот профиль принадлежит другому клиенту", exact=True)).to_be_visible()
        await upload.set_input_files({"name": "phone.conf", "mimeType": "text/plain", "buffer": f"[Interface]\nPrivateKey = {PRIVATE}\n".encode()})
    elif mode == "telemetry":
        state["telemetry"] = "idle"
        await expect(page.get_by_text("Нет недавней связи", exact=True)).to_be_visible(timeout=10000)
        state["telemetry"] = "error"
        await expect(page.get_by_text("Статистика недоступна", exact=True)).to_be_visible(timeout=10000)
        await expect(page.get_by_text("192.0.2.5:43210", exact=True)).to_have_count(0)
        state["telemetry"] = "never"
        await expect(page.get_by_text("Ещё не подключался", exact=True)).to_be_visible(timeout=10000)
    elif mode == "create":
        await page.get_by_role("button", name="Добавить устройство", exact=True).click()
        await expect(page.get_by_role("button", name="Скачать .conf", exact=True)).to_be_visible()
        # Opening an existing profile flushes pending changes in the app.
        await page.get_by_role("button", name="Открыть профиль и QR-код", exact=True).click()
        assert state["config"]["vpn_servers"][0]["peers"][1]["credentials"]["private_key"] == NEW_PRIVATE
        await page.close()
        assert not errors, errors
        print(mode, "PASS")
        return
    await page.get_by_role("button", name="Открыть профиль и QR-код", exact=True).click()
    await expect(page.get_by_role("button", name="Скачать .conf", exact=True)).to_be_visible()
    if mode in ("reissue", "cancel"):
        button = page.locator(".peer-card").get_by_role("button", name="Перевыпустить", exact=True)
        page.once("dialog", lambda dialog: dialog.dismiss())
        await button.click()
        assert state["keys"] == 0
        page.once("dialog", lambda dialog: dialog.accept())
        async with page.expect_response(lambda response: response.request.method == "PUT" and response.url.endswith("/api/config")):
            await button.click()
        assert state["keys"] == 1
        assert state["config"]["vpn_servers"][0]["peers"][0]["credentials"]["private_key"] == NEW_PRIVATE
        await expect(page.get_by_text("Нет данных для этого профиля", exact=True)).to_be_visible()
        if mode == "cancel":
            await page.get_by_role("button", name="Отменить", exact=True).click()
            await expect(page.get_by_role("button", name="Открыть профиль и QR-код", exact=True)).to_be_visible()
            await expect(page.get_by_role("button", name="Скачать .conf", exact=True)).to_have_count(0)
            await page.get_by_role("button", name="Открыть профиль и QR-код", exact=True).click()
            async with page.expect_download() as event:
                await page.get_by_role("button", name="Скачать .conf", exact=True).click()
            body = Path(await (await event.value).path()).read_text()
            assert f"PrivateKey = {PRIVATE}" in body and NEW_PRIVATE not in body
            assert not errors, errors
            await page.close()
            print(mode, "PASS")
            return
        await page.reload()
        await page.get_by_role("button", name="Открыть профиль и QR-код", exact=True).click()
        async with page.expect_download() as event:
            await page.get_by_role("button", name="Скачать .conf", exact=True).click()
        body = Path(await (await event.value).path()).read_text()
        assert f"PrivateKey = {NEW_PRIVATE}" in body and PRIVATE not in body
        assert not errors, errors
        await page.close()
        print(mode, "PASS")
        return
    async with page.expect_download() as event:
        await page.get_by_role("button", name="Скачать .conf", exact=True).click()
    download = await event.value
    body = Path(await download.path()).read_text()
    assert f"PrivateKey = {PRIVATE}" in body and "PresharedKey = stored-psk" in body
    assert "Endpoint = vpn.example.test:51820" in body and "Address = 10.9.0.2/32" in body
    await page.reload()
    await page.get_by_role("button", name="Открыть профиль и QR-код", exact=True).click()
    async with page.expect_download() as event:
        await page.get_by_role("button", name="Скачать .conf", exact=True).click()
    assert Path(await (await event.value).path()).read_text() == body
    assert state["keys"] == 0, "repeat export rotated key"
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in (sys.argv[1:] or ("saved", "legacy", "telemetry", "create", "reissue", "cancel")):
            await scenario(browser, mode)
        await browser.close()


asyncio.run(main())
