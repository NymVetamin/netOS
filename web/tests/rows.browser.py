"""Production UI with mocked API; never connects to a router.

Records are collapsed rows; their settings open under the row. For every page
that lists records this checks the contract of that layout: a field is hidden
until its row is opened by a click, and an edit in the opened row still reaches
the same place in the configuration as before.
"""
import asyncio
import copy
import mimetypes
import os
import sys
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
MAC = "aa:bb:cc:00:00:02"
PROBE = {"enabled": True, "type": "icmp", "targets": ["1.1.1.1"], "interval": 10, "timeout": 3, "fail_threshold": 3, "rise_threshold": 2}
CONFIG = {
    "system": {"hostname": "test", "ntp": {"enabled": True, "servers": []}, "panel": {"port": 8443}},
    "interfaces": [{"id": "if1", "name": "eth0", "type": "physical", "enabled": True},
                   {"id": "if2", "name": "eth1", "type": "physical", "enabled": True},
                   {"id": "br1", "name": "br-lan", "type": "bridge", "members": ["if2"], "enabled": True}],
    "networks": [{"id": "lan", "name": "LAN", "interface": "br1", "router_address": "192.168.10.1/24", "enabled": True, "zone": "lan",
                  "isolated": False, "dhcp_pool": {"enabled": False, "start": "192.168.10.100", "end": "192.168.10.200", "lease_time": 43200}}],
    "wans": [{"id": "wan1", "index": 1, "name": "Uplink", "interface": "if1", "enabled": True, "proto": "dhcp", "metric": 100, "weight": 1, "probe": PROBE}],
    "multiwan": {}, "ipv6": {}, "ddns": {}, "clients": [], "vpn_servers": [],
    "firewall": {"enabled": True, "output_policy": "accept", "ipsets": [],
                 "zones": [{"name": "lan", "title": "Локальная сеть", "policy": "accept", "mss_clamp": False, "description": "Доверенные устройства"},
                           {"name": "wan", "title": "Интернет", "policy": "drop", "mss_clamp": True, "description": "Провайдер"}],
                 "rules": [{"id": "r1", "name": "SSH", "enabled": True, "system": True, "zone": "global", "flow": "in", "action": "accept", "protocol": "tcp", "dst_port": "22"}],
                 "nat": [{"id": "n1", "name": "SNAT", "enabled": True, "system": False, "direction": "source", "interface": "eth0", "source": "", "to_source": "", "comment": ""},
                         {"id": "n2", "name": "Web", "enabled": True, "system": False, "direction": "destination", "interface": "eth0", "protocol": "tcp",
                          "ext_port": "443", "dest_ip": "192.168.10.5", "dest_port": "", "allow_from": "", "comment": ""}]},
    "dhcp": {"enabled": False, "provider": "", "reservations": [{"id": "res1", "enabled": True, "mac": "aa:bb:cc:00:00:01", "ip": "192.168.10.50", "hostname": "nas", "network": "lan"}]},
    "dns": {"enabled": True, "provider": "unbound",
            "upstreams": [{"id": "up1", "type": "dot", "address": "1.1.1.1", "channel": "direct", "enabled": True, "comment": "CF"}],
            "static_records": [{"id": "dns1", "type": "A", "name": "nas.lan", "value": "192.168.10.50"}],
            "split_rules": [{"id": "sp1", "domains": ["corp.example"], "upstream": "up1", "channel": "direct", "enabled": False}],
            "blocklists": [{"id": "bl1", "name": "Ads", "url": "https://example.org/hosts.txt", "ca_file": "", "enabled": False}]},
    "channels": [{"id": "direct", "type": "direct", "enabled": True, "name": "Напрямую"}],
    "policies": [{"id": "p1", "name": "Kids", "enabled": False, "priority": 100, "channel": "direct", "src_ip": "192.168.10.9", "protocol": "any", "domains": []}],
    "routing": {"static": [{"id": "rt1", "name": "Office", "enabled": True, "destination": "10.20.0.0/16", "gateway": "192.168.10.254", "metric": 0, "table": "", "type": "unicast"}],
                "tables": [{"id": "t1", "name": "netos-t1", "number": 101, "system": False}],
                "rules": [{"id": "ru1", "name": "Rule", "enabled": True, "priority": 20100, "from": "", "to": "", "fwmark": "", "table": "netos-t1"}]},
    "wifi": [{"id": "radio1", "device": "wlan0", "enabled": False, "band": "2.4", "channel": 6, "width": 20, "country": "RU", "tx_power": 0,
              "ssids": [{"id": "ssid1", "ssid": "home", "enabled": False, "security": "wpa2", "password": "", "network": "lan", "hidden": False, "isolate": False}]}],
    "qos": {"enabled": False, "wans": [{"wan": "wan1", "upload_kbit": 1000, "download_kbit": 2000, "diffserv": "diffserv4"}]},
    "samba": {"enabled": False, "discovery": True, "workgroup": "WORKGROUP", "networks": [], "vpns": [], "volumes": [], "shares": [], "users": [{"id": "u1", "name": "bob", "password": ""}]},
    "components": [{"id": "unbound", "installed": True}, {"id": "hostapd", "installed": True}, {"id": "samba", "installed": True}],
}
LIVE = [{"name": "eth0", "physical": True, "up": True, "mac": "02:00:00:00:00:01", "mtu": 1500},
        {"name": "eth1", "physical": True, "up": True, "mac": "02:00:00:00:00:02", "mtu": 1500},
        {"name": "eth9", "physical": True, "up": False, "mac": "02:00:00:00:00:09", "mtu": 1500}]

# page, accessible name of a field inside a row, value, where it must land
EDITS = [
    ("firewall", "Источник правила NAT", "10.0.0.0/8", lambda c: c["firewall"]["nat"][0]["source"]),
    ("firewall", "Внешний порт проброса Web", "8443", lambda c: c["firewall"]["nat"][1]["ext_port"]),
    ("services", "Адрес DNS-сервера 1", "9.9.9.9", lambda c: c["dns"]["upstreams"][0]["address"]),
    ("services", "Значение DNS-записи 1", "192.168.10.51", lambda c: c["dns"]["static_records"][0]["value"]),
    ("services", "URL DNS blocklist 1", "https://example.org/b.txt", lambda c: c["dns"]["blocklists"][0]["url"]),
    ("routing", "Назначение статического маршрута Office", "10.30.0.0/16", lambda c: c["routing"]["static"][0]["destination"]),
    ("routing", "Источник правила маршрутизации Rule", "192.168.10.0/24", lambda c: c["routing"]["rules"][0]["from"]),
    ("clients", f"Имя устройства {MAC}", "Laptop", lambda c: c["clients"][0]["name"]),
    ("network", "MTU интерфейса eth0", "1400", lambda c: str(c["interfaces"][0]["mtu"])),
    ("channels", "IP источника политики Kids", "192.168.10.77", lambda c: c["policies"][0]["src_ip"]),
    ("traffic", "Загрузка QoS 1, Кбит/с", "5000", lambda c: str(c["qos"]["wans"][0]["download_kbit"])),
    ("wifi", "Имя сети (SSID)", "guest", lambda c: c["wifi"][0]["ssids"][0]["ssid"]),
    ("storage", "Логин", "alice", lambda c: c["samba"]["users"][0]["name"]),
]


def is_put(response):
    return response.request.method == "PUT" and response.url.endswith("/api/config")


async def open_rows_above(control):
    """Open the row holding a control the way an administrator does: by clicking it."""
    while True:
        closed = control.locator("xpath=ancestor::details[not(@open)]")
        if await closed.count() == 0:
            return
        await closed.first.locator("xpath=./summary").click()


async def main():
    state = {"config": copy.deepcopy(CONFIG), "hostname": "laptop"}
    errors = []
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        page = await browser.new_page(viewport={"width": 1440, "height": 1000})
        page.on("pageerror", lambda err: errors.append(str(err)))

        async def route_request(route):
            req, path = route.request, urlparse(route.request.url).path
            if not path.startswith("/api/"):
                file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
                await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
                return
            body = {}
            if path == "/api/session":
                body = {"username": "admin", "role": "admin", "csrf_token": "test"}
            elif path == "/api/config":
                if req.method == "PUT":
                    state["config"] = req.post_data_json
                body = {"config": state["config"], "dirty": True, "draft_version": 1, "problems": []}
            elif path == "/api/status":
                body = {"interfaces": LIVE, "channels": [], "wans": [], "uptime_seconds": 1}
            elif path == "/api/clients":
                body = {"clients": [{"mac": MAC, "ip": "192.168.10.23", "hostname": state["hostname"], "interface": "br-lan", "source": "dhcp", "online": True}]}
            elif path == "/api/leases":
                body = {"leases": []}
            elif path == "/api/interfaces":
                body = {"interfaces": LIVE}
            await route.fulfill(json=body)

        await page.route("**/*", route_request)
        shots = os.environ.get("ROWS_SCREENSHOTS")
        for name, label, value, read in EDITS:
            await page.goto(f"http://netos-ui.test/#{name}")
            control = page.get_by_label(label, exact=True)
            await expect(control).to_have_count(1)
            assert not await control.is_visible(), f"{name}: «{label}» is visible while its row is collapsed"
            await open_rows_above(control)
            await expect(control).to_be_visible()
            async with page.expect_response(is_put):
                await control.fill(value)
            assert read(state["config"]) == value, (name, label, read(state["config"]))
            if shots:
                await page.locator("main.main").screenshot(path=str(Path(shots) / f"{name}.png"))
            print(name, label, "PASS")

        # Display names never become DHCP hostnames; invalid discovered names
        # are omitted so a quick reservation cannot block applying the draft.
        state["config"]["clients"][0]["name"] = "Ноутбук мамы"
        for hostname, expected in [("laptop", "laptop"), ("pc-1.home", "pc-1.home"),
                                   ("bad name", ""), ("Ноутбук", ""), ("-pc", ""),
                                   ("a" * 64, ""), ("", "")]:
            state["hostname"] = hostname
            await page.goto("http://netos-ui.test/#clients")
            await page.reload()
            pin = page.get_by_role("button", name=f"Закрепить адрес за устройством {MAC}", exact=True)
            async with page.expect_response(is_put):
                await pin.click()
            pinned = [item for item in state["config"]["dhcp"]["reservations"] if item["mac"] == MAC]
            assert len(pinned) == 1 and pinned[0]["ip"] == "192.168.10.23" and pinned[0]["network"] == "lan", pinned
            assert pinned[0]["hostname"] == expected, pinned
            assert state["config"]["clients"][0]["name"] == "Ноутбук мамы"
            assert not await page.get_by_label(f"Комментарий устройства {MAC}", exact=True).is_visible()
            async with page.expect_response(is_put):
                await page.get_by_role("button", name=f"Открепить адрес устройства {MAC}", exact=True).click()
            assert not [item for item in state["config"]["dhcp"]["reservations"] if item["mac"] == MAC]
        print("clients pin hostname cases PASS")

        # One "add" menu for bridges, bonds and VLANs; the new record opens by itself.
        await page.goto("http://netos-ui.test/#network")
        await page.locator("section.card", has=page.get_by_role("heading", name="Порты, агрегации, мосты и VLAN", exact=True)).locator("details.addmenu > summary").click()
        async with page.expect_response(is_put):
            await page.get_by_role("button", name="Добавить мост", exact=True).click()
        bridges = [item for item in state["config"]["interfaces"] if item["type"] == "bridge"]
        assert len(bridges) == 2, bridges
        await expect(page.get_by_label(f"MAC интерфейса {bridges[1]['name']}", exact=True)).to_be_visible()
        print("network add PASS")

        # Mobile rows retain data and actions, including rows without details.
        state["config"]["samba"]["volumes"] = [{"id": "vol1", "uuid": "test-volume", "filesystem": "ext4", "enabled": False}]
        await page.set_viewport_size({"width": 390, "height": 844})
        await page.goto("http://netos-ui.test/#storage")
        await page.reload()
        forget = page.get_by_role("button", name="Забыть том", exact=True)
        await expect(forget).to_be_visible()
        async with page.expect_response(is_put):
            await forget.click()
        assert state["config"]["samba"]["volumes"] == []
        await page.goto("http://netos-ui.test/#clients")
        pin = page.get_by_role("button", name=f"Закрепить адрес за устройством {MAC}", exact=True)
        await expect(pin).to_be_visible()
        await expect(page.get_by_text(MAC, exact=True)).to_be_visible()
        print("mobile storage action and client address PASS")

        assert not errors, errors
        await browser.close()


asyncio.run(main())
