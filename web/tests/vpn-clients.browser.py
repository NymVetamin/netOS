"""Production UI with mocked API; never connects to a router."""
import asyncio
import json
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


# Записи свёрнуты в строки; настройки раскрываются под строкой. Остальные
# сценарии проверяют сами настройки, поэтому раскрывают каждую строку сразу,
# в том числе после перезагрузки страницы и отмены черновика.
OPEN_ROWS = """new MutationObserver(() => document.querySelectorAll('details.xd:not([data-opened])')
  .forEach((row) => { row.dataset.opened = '1'; row.open = true; })).observe(document, {childList: true, subtree: true})"""


async def scenario(browser, mode):
    page = await browser.new_page()
    if mode not in ("collapsed", "mobile"):
        await page.add_init_script(OPEN_ROWS)
    peer = {"id": "phone", "name": "Телефон", "enabled": True, "address": "10.9.0.2", "credentials": {"public_key": PUBLIC, "preshared_key": "stored-psk"}}
    if mode != "legacy":
        peer["credentials"]["private_key"] = PRIVATE
    cfg = {"system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [],
           "components": [{"id": "wireguard", "installed": True}],
           "channels": [{"id": "direct", "type": "direct", "enabled": True, "name": "Напрямую"}],
           "vpn_servers": [{"id": "srv", "type": "wireguard", "name": "WireGuard", "index": 1, "enabled": True,
                            "subnet": "10.9.0.1/24", "port": 51820, "peers": [peer],
                            "config": {"public_endpoint": "vpn.example.test:51820", "client_dns": ["1.1.1.1"]}}]}
    if mode in ("multi", "isolation"):
        for i, kind in enumerate(("xray", "ocserv", "ikev2", "l2tp"), 2):
            cfg["vpn_servers"].append({"id": kind, "name": kind, "type": kind, "index": i,
                "enabled": False, "subnet": f"10.{8+i}.0.1/24", "port": 443, "peers": [],
                "config": {"protocol": "reality"} if kind == "xray" else {}})
    if mode.startswith("sessions-"):
        kind = mode.removeprefix("sessions-")
        cfg["vpn_servers"][0].update(type=kind, config={"protocol": "reality"} if kind == "xray" else {})
        peer["credentials"] = {"username": "alice"}
        cfg["components"].append({"id": kind, "installed": True})
    original = copy.deepcopy(cfg)
    state = {"dirty": False, "config": cfg, "telemetry": "recent", "profiles": 0, "keys": 0}
    if mode.startswith("sessions-"): state["telemetry"] = "online"
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
            elif state["telemetry"] == "malformed":
                body = {"unexpected": "response"}
            else:
                body = [{"id": "phone", "public_key": PUBLIC, "state": state["telemetry"], "last_handshake": 1791800000,
                         "last_seen": 1791800000, "traffic_known": True, "endpoint": "192.0.2.5:43210", "received": 1048576, "sent": 2097152}]
        elif path.endswith('/reality-profile'):
            fp=state['config']['vpn_servers'][0]['peers'][0].get('tls_fingerprint') or 'chrome'
            body={'link':f'vless://123e4567-e89b-12d3-a456-426614174000@vpn.example.test:443?security=reality&sni=example.com&pbk=fixture&sid=abcd&fp={fp}'}
        elif path.endswith("/profile"):
            state["profiles"] += 1
            creds = next(p for p in state["config"]["vpn_servers"][0]["peers"] if p["id"] == path.split("/")[-2])["credentials"]
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
    await expect(page.get_by_text("Онлайн", exact=True)).to_be_visible()
    await expect(page.get_by_text("192.0.2.5:43210", exact=True)).to_be_visible()
    if mode == "isolation":
        label="Изолировать от других локальных и VPN-сетей"
        for server in cfg["vpn_servers"]:
            row=page.locator(f'[data-server-id="{server["id"]}"]')
            toggle=row.get_by_role("checkbox",name=label,exact=True)
            await expect(toggle).not_to_be_checked()
            await toggle.locator("..").click()
            await expect(toggle).to_be_checked()
            await page.wait_for_timeout(700)
            assert next(s for s in state["config"]["vpn_servers"] if s["id"]==server["id"])["isolated"]
        await page.reload()
        for server in cfg["vpn_servers"]:
            await expect(page.locator(f'[data-server-id="{server["id"]}"]').get_by_role("checkbox",name=label,exact=True)).to_be_checked()
        toggle=page.locator('[data-server-id="srv"]').get_by_role("checkbox",name=label,exact=True)
        await toggle.locator("..").click()
        await page.wait_for_timeout(700)
        assert not state["config"]["vpn_servers"][0]["isolated"]
        assert all(s["isolated"] for s in state["config"]["vpn_servers"][1:])
        assert not errors,errors
        await page.close();print(mode,"PASS");return
    if mode == "sessions-xray":
        fingerprint=page.get_by_role('combobox',name='TLS fingerprint клиента',exact=True)
        await expect(fingerprint).to_have_value('')
        async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
            await fingerprint.select_option('firefox')
        assert state['config']['vpn_servers'][0]['peers'][0]['tls_fingerprint']=='firefox'
        await page.reload()
        await expect(fingerprint).to_have_value('firefox')
        async with page.expect_download() as pending:
            await page.get_by_role('button',name='Скачать JSON Xray',exact=True).click()
        download=await pending.value
        profile=json.loads(Path(await download.path()).read_text(encoding='utf-8'))
        assert profile['outbounds'][0]['streamSettings']['realitySettings']['fingerprint']=='firefox'
        toggle=page.get_by_role('checkbox',name='Включить sniffing',exact=True)
        await expect(toggle).not_to_be_checked()
        async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
            await toggle.locator('..').click()
        assert state['config']['vpn_servers'][0]['config']['sniffing'] is True
        await page.reload()
        await expect(toggle).to_be_checked()
        async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
            await toggle.locator('..').click()
        assert state['config']['vpn_servers'][0]['config']['sniffing'] is False
    if mode.startswith("sessions-"):
        await expect(page.get_by_text("Последний раз замечен онлайн", exact=True)).to_be_visible()
        state["telemetry"] = "offline"
        await expect(page.get_by_text("Оффлайн", exact=True)).to_be_visible(timeout=8000)
        state["telemetry"] = "error"
        await expect(page.get_by_text("Нет данных", exact=True)).to_be_visible(timeout=8000)
        await expect(page.get_by_text("192.0.2.5:43210", exact=True)).to_have_count(0)
        state["telemetry"] = "malformed"
        await page.wait_for_timeout(5500)
        await expect(page.get_by_text("Нет данных", exact=True)).to_be_visible()
        state["telemetry"] = "online"
        await expect(page.get_by_text("Онлайн", exact=True)).to_be_visible(timeout=8000)
        await page.locator(".peer-card .xsw label.switch").click()
        await expect(page.locator(".peer-card").get_by_text("Отключён", exact=True)).to_be_visible()
        assert not errors, errors
        await page.close()
        print(mode, "PASS")
        return
    if mode in ("multi", "isolation"):
        await expect(page.locator("form.vpn-server").get_by_text("Отключён", exact=True)).to_have_count(4)
        await expect(page.locator("form.vpn-server").get_by_text("черновик", exact=True)).to_have_count(0)
        await expect(page.locator("details.addmenu > summary").filter(has_text="Добавить клиента")).to_have_count(1)
        for sid, name in (("srv", "WireGuard"), ("xray", "xray"), ("ocserv", "ocserv"), ("ikev2", "ikev2"), ("l2tp", "l2tp")):
            before = {s["id"]: len(s["peers"]) for s in state["config"]["vpn_servers"]}
            await page.locator("details.addmenu > summary").filter(has_text="Добавить клиента").click()
            async with page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith("/api/config")):
                await page.get_by_role("button", name=f"Добавить клиента на {name}", exact=True).click()
            after = {s["id"]: len(s["peers"]) for s in state["config"]["vpn_servers"]}
            assert after == {key: value + (key == sid) for key, value in before.items()}, (sid, before, after)
            await expect(page.locator(f'[data-peers-of="{sid}"] .peer-card').last.locator(".xbody")).to_be_visible()
        assert not errors, errors
        await page.set_viewport_size({"width": 390, "height": 844})
        await page.locator(".card-sub").screenshot(path="output/playwright/vpn-clients-menu-mobile.png")
        await page.close()
        print(mode, "PASS")
        return
    if mode == "mobile":
        await page.set_viewport_size({"width": 390, "height": 844})
        await expect(page.get_by_text("192.0.2.5:43210", exact=True)).to_be_visible()
        await page.locator(".peer-card summary.xsum").click()
        await expect(page.get_by_text("192.0.2.5:43210", exact=True)).to_be_visible()
        await page.locator(".peer-card").screenshot(path="output/playwright/vpn-client-mobile.png")
        assert not errors, errors
        await page.close()
        print(mode, "PASS")
        return
    if mode == "collapsed":
        # The state and the external address are readable without opening the row.
        name = page.get_by_role("textbox", name="Название клиента", exact=True)
        row = page.locator(".peer-card")
        await expect(name).to_have_count(0)
        await row.locator("summary.xsum").click()
        await expect(name).to_be_visible()
        await row.locator("summary.xsum").click()
        await expect(name).to_have_count(0)
        # The access switch sits in the row and must not open it.
        async with page.expect_response(lambda response: response.request.method == "PUT" and response.url.endswith("/api/config")):
            await row.locator(".xsw label.switch").click()
        assert state["config"]["vpn_servers"][0]["peers"][0]["enabled"] is False
        await expect(row.get_by_text("Отключён", exact=True)).to_be_visible()
        await expect(name).to_have_count(0)
        # A device added by the administrator opens by itself.
        await page.locator("details.addmenu > summary").filter(has_text="Добавить клиента").click()
        await page.get_by_role("button", name="Добавить клиента на WireGuard", exact=True).click()
        await expect(page.get_by_role("button", name="Скачать .conf", exact=True)).to_be_visible()
        # Thirteen "add" buttons became one menu; the items keep their names.
        await page.locator("details.addmenu > summary").filter(has_text="Добавить сервер").click()
        await page.get_by_role("button", name="Добавить L2TP", exact=True).click()
        await expect(page.locator("form.vpn-server")).to_have_count(2)
        await expect(page.get_by_role("textbox", name="Адрес прослушивания", exact=True)).to_be_visible()
        assert not errors, errors
        await page.close()
        print(mode, "PASS")
        return
    await expect(page.get_by_text("1 МиБ", exact=True)).to_be_visible()
    await expect(page.get_by_text("2 МиБ", exact=True)).to_be_visible()
    assert state["profiles"] == 0, "secrets fetched without user action"
    if mode == "settings":
        # Profile settings are in client cards, never in the server form.
        cards = page.locator(".peer-card")
        await expect(page.get_by_role("textbox", name="Трафик через VPN (AllowedIPs)", exact=True)).to_have_count(1)
        await expect(cards.first.get_by_role("textbox", name="DNS в профиле", exact=True)).to_have_value("1.1.1.1")
        await page.locator("details.addmenu > summary").filter(has_text="Добавить клиента").click()
        await page.get_by_role("button", name="Добавить клиента на WireGuard", exact=True).click()
        await expect(cards).to_have_count(2)
        first, second = cards.nth(0), cards.nth(1)
        await expect(second.get_by_role("textbox", name="DNS в профиле", exact=True)).to_have_value("10.9.0.1")
        await expect(second.get_by_role("textbox", name="DNS в профиле", exact=True)).to_be_disabled()
        await expect(second.get_by_role("textbox", name="Трафик через VPN (AllowedIPs)", exact=True)).to_have_value("0.0.0.0/0")
        routes = first.get_by_role("textbox", name="Трафик через VPN (AllowedIPs)", exact=True)
        await routes.fill("192.0.2.0/24")
        await routes.press("End")
        await routes.press("Enter")
        await routes.press_sequentially("198.51.100.0/24")
        await expect(routes).to_have_value("192.0.2.0/24\n198.51.100.0/24")
        await first.get_by_role("textbox", name="DNS в профиле", exact=True).fill("192.0.2.53\n198.51.100.53")
        toggle = first.get_by_role("checkbox", name="DNS роутера", exact=True)
        await toggle.locator("..").click()
        await expect(first.get_by_role("textbox", name="DNS в профиле", exact=True)).to_have_value("10.9.0.1")
        await toggle.locator("..").click()
        await expect(first.get_by_role("textbox", name="DNS в профиле", exact=True)).to_have_value("192.0.2.53\n198.51.100.53")
        await first.get_by_role("button", name="Открыть профиль и QR-код", exact=True).click()
        expected = []
        for card in (first, second):
            async with page.expect_download() as event:
                await card.get_by_role("button", name="Скачать .conf", exact=True).click()
            expected.append(Path(await (await event.value).path()).read_text())
        assert "DNS = 192.0.2.53, 198.51.100.53\n" in expected[0]
        assert "AllowedIPs = 192.0.2.0/24, 198.51.100.0/24\n" in expected[0]
        assert "DNS = 10.9.0.1\n" in expected[1]
        assert "AllowedIPs = 0.0.0.0/0\n" in expected[1]
        await page.reload()
        for i in range(2):
            card = page.locator(".peer-card").nth(i)
            await card.get_by_role("button", name="Открыть профиль и QR-код", exact=True).click()
            async with page.expect_download() as event:
                await card.get_by_role("button", name="Скачать .conf", exact=True).click()
            assert Path(await (await event.value).path()).read_text() == expected[i]
        # Explicitly empty DNS must remain empty after another reload.
        first = page.locator(".peer-card").first
        async with page.expect_response(lambda response: response.request.method == "PUT" and response.url.endswith("/api/config")):
            await first.get_by_role("textbox", name="DNS в профиле", exact=True).fill("")
        await page.reload()
        first = page.locator(".peer-card").first
        await expect(first.get_by_role("textbox", name="DNS в профиле", exact=True)).to_have_value("")
        await first.get_by_role("button", name="Открыть профиль и QR-код", exact=True).click()
        async with page.expect_download() as event:
            await first.get_by_role("button", name="Скачать .conf", exact=True).click()
        assert "DNS =" not in Path(await (await event.value).path()).read_text()
        if os.environ.get("VPN_PROFILE_SCREENSHOT"):
            await first.screenshot(path=os.environ["VPN_PROFILE_SCREENSHOT"])
        assert not errors, errors
        await page.close()
        print(mode, "PASS")
        return
    if mode == "legacy":
        await expect(page.get_by_text("Профиль создан в прежней версии", exact=True)).to_be_visible()
        upload = page.get_by_label("Загрузить прежний .conf", exact=True)
        await upload.set_input_files({"name": "other.conf", "mimeType": "text/plain", "buffer": b"PrivateKey = wrong\n"})
        await expect(page.get_by_text("Этот профиль принадлежит другому клиенту", exact=True)).to_be_visible()
        await upload.set_input_files({"name": "phone.conf", "mimeType": "text/plain", "buffer": f"[Interface]\nPrivateKey = {PRIVATE}\n".encode()})
    elif mode == "telemetry":
        state["telemetry"] = "idle"
        await expect(page.get_by_text("Оффлайн", exact=True)).to_be_visible(timeout=10000)
        await expect(page.get_by_text("Последняя связь:", exact=False)).to_be_visible()
        state["telemetry"] = "error"
        await expect(page.get_by_text("Нет данных", exact=True)).to_be_visible(timeout=10000)
        await expect(page.get_by_text("192.0.2.5:43210", exact=True)).to_have_count(0)
        state["telemetry"] = "never"
        await expect(page.get_by_text("Оффлайн", exact=True)).to_be_visible(timeout=10000)
    elif mode == "create":
        await page.locator("details.addmenu > summary").filter(has_text="Добавить клиента").click()
        await page.get_by_role("button", name="Добавить клиента на WireGuard", exact=True).click()
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
        await button.click()
        await page.get_by_role("dialog").get_by_role("button", name="Отмена", exact=True).click()
        assert state["keys"] == 0
        async with page.expect_response(lambda response: response.request.method == "PUT" and response.url.endswith("/api/config")):
            await button.click()
            await page.get_by_role("dialog").get_by_role("button", name="Перевыпустить профиль", exact=True).click()
        assert state["keys"] == 1
        assert state["config"]["vpn_servers"][0]["peers"][0]["credentials"]["private_key"] == NEW_PRIVATE
        await expect(page.get_by_text("Нет данных", exact=True)).to_be_visible()
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
        for mode in (sys.argv[1:] or ("sessions-ocserv", "sessions-ikev2", "sessions-l2tp", "sessions-xray", "collapsed", "mobile", "multi", "saved", "legacy", "telemetry", "create", "reissue", "cancel", "settings")):
            await scenario(browser, mode)
        await browser.close()


asyncio.run(main())
