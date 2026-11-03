"""Run after npm run build. Uses local API fixtures; never contacts a router."""
import asyncio
import json
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def scenario(browser, width, storage_blocked=False):
    page = await browser.new_page(viewport={"width": width, "height": 800})
    errors, writes = [], []
    page.on("pageerror", lambda error: errors.append(str(error)))
    state = {"at": "2026-11-03T10:00:00Z", "revision": 263, "reason": "timeout",
             "details": "Подтверждение не получено в отведённое время"}
    if storage_blocked:
        await page.add_init_script("Object.defineProperty(window, 'sessionStorage', {get() {throw new Error('blocked')}})")

    async def route_request(route):
        req = route.request
        path = urlparse(req.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        if req.method != "GET":
            writes.append((req.method, path))
        body = {}
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "test"}
        elif path == "/api/config":
            body = {"config": {"system": {"hostname": "test-router"}, "interfaces": [], "components": []},
                    "dirty": False, "draft_version": 1, "problems": [], "pending_confirmation": False, "rollback": state}
        elif path == "/api/catalog":
            body = {"components": []}
        elif path == "/api/status":
            body = {"interfaces": [], "uptime_seconds": 1}
        await route.fulfill(content_type="application/json", body=json.dumps(body))

    await page.route("**/*", route_request)
    await page.goto("http://netos.test/#components")
    notice = page.locator(".notice").filter(has_text="Ревизия 263")
    await expect(notice).to_be_visible()
    close = notice.get_by_role("button", name="Закрыть уведомление")
    box = await close.bounding_box()
    assert box and box["x"] >= 0 and box["x"] + box["width"] <= width
    await close.click()
    await expect(notice).to_have_count(0)
    if not storage_blocked:
        await page.reload()
        await expect(page.get_by_role("heading", name="Компоненты", exact=True)).to_be_visible()
        await expect(notice).to_have_count(0)
        state.update(at="2026-11-03T11:00:00Z", revision=264)
        await page.reload()
        notice = page.locator(".notice").filter(has_text="Ревизия 264")
        await expect(notice).to_be_visible()
        close = notice.get_by_role("button", name="Закрыть уведомление")
        await close.focus()
        await page.keyboard.press("Enter")
        await expect(notice).to_have_count(0)
    assert not errors, errors
    assert not writes, writes
    await page.close()
    print(width, "storage blocked" if storage_blocked else "reload/new event/keyboard", "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for width in (1440, 390):
            await scenario(browser, width)
        await scenario(browser, 1440, storage_blocked=True)
        await browser.close()


asyncio.run(main())
