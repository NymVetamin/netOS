"""Production UI regression; API is mocked and no router is modified."""
import asyncio
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def scenario(browser):
    page = await browser.new_page(viewport={"width": 1440, "height": 1000})
    state = {"version": 1, "config": {
        "system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [],
        "components": [{"id": x, "installed": True} for x in ("dnsmasq", "unbound", "dnsproxy")],
        "channels": [{"id": "direct", "type": "direct", "name": "Напрямую", "enabled": True}],
        "dhcp": {"enabled": False, "provider": "dnsmasq", "reservations": []},
        "dns": {"enabled": True, "provider": "unbound", "port": 53, "bootstrap": ["1.1.1.1"],
                "upstreams": [{"id": "up-1", "type": "dot", "address": "1.1.1.1", "enabled": True, "comment": "Old comment"},
                              {"id": "up-2", "type": "dot", "address": "192.0.2.53@8853#dns.example", "enabled": True}],
                "split_rules": [], "static_records": [], "blocklists": []}}}
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    async def route_request(route):
        req, path = route.request, urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        body = {}
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "test"}
        elif path == "/api/catalog":
            body = {"components": [], "installed": {"dnsmasq": True, "unbound": True, "dnsproxy": True}}
        elif path == "/api/status":
            body = {"interfaces": [], "channels": [], "uptime_seconds": 1}
        elif path == "/api/config":
            if req.method == "PUT":
                state["config"] = req.post_data_json
                state["version"] += 1
            body = {"config": state["config"], "dirty": False, "draft_version": state["version"], "problems": []}
        await route.fulfill(json=body)

    await page.route("**/*", route_request)
    await page.goto("http://netos-ui.test/#services")
    await expect(page.get_by_role("heading", name="Сетевые службы", exact=True)).to_be_visible()
    row = page.locator("details.xd").filter(has=page.get_by_label("Резолвер DNS-сервера 1", exact=True))
    await row.locator("summary").click()
    choice = page.get_by_label("Резолвер DNS-сервера 1", exact=True)
    kind = page.get_by_label("Тип DNS-сервера 1", exact=True)
    await expect(choice).to_have_value("cloudflare")
    await expect(row.get_by_text("Old comment")).to_have_count(0)
    await expect(page.get_by_label("Комментарий DNS-сервера 1", exact=True)).to_have_count(0)

    async def change(control, value):
        async with page.expect_response(lambda r: urlparse(r.url).path == "/api/config" and r.request.method == "PUT"):
            await control.select_option(value)

    await change(kind, "plain")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "1.1.1.1"
    await change(kind, "dot")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "1.1.1.1#cloudflare-dns.com"
    await change(kind, "doh")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "https://1.1.1.1/dns-query"
    await change(kind, "doq")
    await expect(choice).to_have_value("")
    assert state["config"]["dns"]["upstreams"][0]["address"] == ""
    await expect(choice.locator('option[value="cloudflare"]')).to_have_count(0)
    await change(choice, "adguard")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "quic://dns.adguard-dns.com"
    await change(kind, "dot")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "94.140.14.14#dns.adguard-dns.com"
    engine = page.get_by_label("Чем резолвить", exact=True)
    await change(engine, "dnsproxy")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "tls://dns.adguard-dns.com"
    # A custom endpoint is never rewritten on daemon changes.
    assert state["config"]["dns"]["upstreams"][1]["address"] == "192.0.2.53@8853#dns.example"
    await change(choice, "google")
    await change(kind, "doh")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "https://dns.google/dns-query"
    await choice.select_option("custom")
    address = page.get_by_label("Адрес DNS-сервера 1", exact=True)
    await expect(address).to_be_visible()
    async with page.expect_response(lambda r: urlparse(r.url).path == "/api/config" and r.request.method == "PUT"):
        await address.fill("https://resolver.example/dns-query")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "https://resolver.example/dns-query"
    async with page.expect_response(lambda r: urlparse(r.url).path == "/api/config" and r.request.method == "PUT"):
        await address.fill("https://1.1.1.1/dns-query")
    await expect(choice).to_have_value("custom")
    await expect(address).to_be_visible()
    await change(choice, "quad9")
    await change(kind, "doq")
    assert state["config"]["dns"]["upstreams"][0]["address"] == "quic://dns.quad9.net"
    for width in (1440, 390):
        await page.set_viewport_size({"width": width, "height": 1000})
        await row.scroll_into_view_if_needed()
        assert await row.locator(".dns-upstream-editor").evaluate(
            "el => el.scrollWidth <= el.clientWidth + 1")
        for control in await row.locator("select").all():
            bounds = await control.bounding_box()
            assert bounds["x"] >= 0 and bounds["x"] + bounds["width"] <= width + 1, bounds
    wrapper = row.locator("..")
    async with page.expect_response(lambda r: urlparse(r.url).path == "/api/config" and r.request.method == "PUT"):
        await wrapper.get_by_role("checkbox").locator("..").click()
    assert state["config"]["dns"]["upstreams"][0]["enabled"] is False
    async with page.expect_response(lambda r: urlparse(r.url).path == "/api/config" and r.request.method == "PUT"):
        await row.get_by_role("button", name="Убрать", exact=True).click()
    assert [u["id"] for u in state["config"]["dns"]["upstreams"]] == ["up-2"]
    assert not errors, errors
    await page.close()


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        await scenario(browser)
        await browser.close()
        print("DNS presets: PASS")


asyncio.run(main())
