"""Check the revision sent by a stale panel and by the same panel after reload."""
import asyncio
import json
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse

from playwright.async_api import async_playwright, expect


DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def scenario(browser, action, label):
    page = await browser.new_page()
    first = "9007199254740992"
    second = "9007199254740993"
    current = first
    sent = []

    async def route_request(route):
        req = route.request
        path = urlparse(req.url).path
        if not path.startswith("/api/"):
            asset = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert asset.parent == DIST and asset.is_file(), path
            await route.fulfill(body=asset.read_bytes(), content_type=mimetypes.guess_type(str(asset))[0])
            return

        status, body = 200, {}
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "test"}
        elif path == "/api/config":
            body = {"config": {"system": {"hostname": "test-router"}, "interfaces": [], "components": []},
                    "dirty": False, "draft_version": 8, "problems": [], "pending_confirmation": True,
                    "pending_revision": current, "confirm_deadline": "2099-01-01T00:00:00Z"}
        elif path == "/api/catalog":
            body = {"components": []}
        elif req.method == "POST":
            assert path == "/api/config/" + action, path
            sent.append(req.headers.get("if-match"))
            if sent[-1] != current:
                status, body = 409, {"error": "Ревизия изменилась"}
        await route.fulfill(status=status, content_type="application/json", body=json.dumps(body))

    await page.route("**/*", route_request)
    await page.goto("http://netos.test/#components")
    button = page.get_by_role("button", name=label, exact=True)
    await expect(button).to_be_enabled()
    current = second
    for revision in [first, second]:
        async with page.expect_response(lambda r: r.url.endswith("/api/config/" + action)):
            await button.click()
        await expect(button).to_be_enabled()
        assert sent[-1] == revision, sent
    assert sent == [first, second], sent
    await page.close()


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for action, label in [("confirm", "Всё работает"), ("rollback", "Откатить")]:
            await scenario(browser, action, label)
            print(action, "PASS")
        await browser.close()


asyncio.run(main())
