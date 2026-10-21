"""Production import UI with mocked API; no router connections."""
import asyncio
import copy
import json
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse, urlencode
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
EXTRA = {"scMaxEachPostBytes": "20000", "scMinPostsIntervalMs": "7", "xPaddingBytes": "100-1000",
         "xPaddingObfsMode": True, "xPaddingKey": "hash", "xPaddingHeader": "X-Client-Ver",
         "xPaddingPlacement": "queryInHeader", "xPaddingMethod": "tokenish", "uplinkHTTPMethod": "GET",
         "seqPlacement": "path", "uplinkDataPlacement": "header", "uplinkChunkSize": "3000",
         "xmux": {"maxConcurrency": "4", "maxConnections": "0", "hMaxReusableSecs": "1800-3000", "hMaxRequestTimes": "600-900"}}
BASE = "vless://01234567-89ab-cdef-0123-456789abcdef@cdn.example.com:443?"
PARAMS = {"encryption": "none", "security": "tls", "type": "xhttp", "path": "/api/v1/events/",
          "host": "cdn.example.com", "mode": "packet-up", "extra": json.dumps(EXTRA),
          "sni": "cdn.example.com", "fp": "firefox", "alpn": "h2"}

async def main():
    cfg = {"system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [],
           "components": [{"id": "xray", "installed": True}],
           "channels": [{"id": "direct", "type": "direct", "enabled": True, "name": "Direct"},
                        {"id": "ch1", "index": 1, "type": "xray", "enabled": True, "name": "Test XHTTP",
                         "probe": {"enabled": False}, "config": {"outbound": {"protocol": "freedom"}}}]}
    state = {"config": cfg, "puts": 0}
    errors = []
    async with async_playwright() as p:
        exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not exe and os.name == "nt":
            exe = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=exe)
        page = await browser.new_page(viewport={"width": 1920, "height": 1080})
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
            elif path == "/api/config":
                if req.method == "PUT":
                    state["config"] = req.post_data_json
                    state["puts"] += 1
                body = {"config": state["config"], "dirty": True, "draft_version": state["puts"]+1, "problems": []}
            elif path == "/api/status":
                body = {"channels": [], "interfaces": [], "wans": []}
            await route.fulfill(json=body)
        await page.route("**/*", route_request)
        await page.goto("http://netos-ui.test/#channels")
        await page.locator("summary").filter(has_text="Test XHTTP").click()
        await page.get_by_label("Ссылка подключения", exact=True).fill(BASE + urlencode(PARAMS))
        async with page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith('/api/config')):
            await page.get_by_role("button", name="Импортировать", exact=True).click()
        saved = copy.deepcopy(state["config"]["channels"][1]["config"]["outbound"])
        assert saved["streamSettings"]["xhttpSettings"] == {"path": PARAMS["path"], "host": PARAMS["host"], "mode": "packet-up", "extra": EXTRA}
        assert saved["streamSettings"]["tlsSettings"]["alpn"] == ["h2"]
        await page.reload()
        await page.locator("summary").filter(has_text="Test XHTTP").click()
        await page.get_by_text("Outbound Xray (JSON)", exact=True).first.click()
        assert json.loads(await page.get_by_label("Outbound Xray (JSON)", exact=True).input_value()) == saved
        puts = state["puts"]
        await page.get_by_label("Ссылка подключения", exact=True).fill(BASE + urlencode({**PARAMS, "extra": "{"}))
        await page.get_by_role("button", name="Импортировать", exact=True).click()
        await expect(page.get_by_text("Параметр XHTTP extra должен содержать корректный JSON-объект", exact=True)).to_be_visible()
        assert state["puts"] == puts
        assert state["config"]["channels"][1]["config"]["outbound"] == saved
        await page.get_by_label("Ссылка подключения", exact=True).fill(BASE + urlencode(PARAMS))
        async with page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith('/api/config')):
            await page.get_by_role("button", name="Импортировать", exact=True).click()
        assert state["config"]["channels"][1]["config"]["outbound"] == saved
        await expect(page.get_by_text("Конфигурация Xray не разобрана", exact=True)).to_have_count(0)
        assert not errors, errors
        await browser.close()
    print("XHTTP import, saved JSON reload and invalid extra preservation PASS")

asyncio.run(main())
