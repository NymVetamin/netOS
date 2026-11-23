"""Bound confirmation reloads with clock skew; all HTTP stays local."""
import asyncio
import mimetypes
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def scenario(browser, size):
    page = await browser.new_page()
    state = dict(reads=0, active=0, peak=0, pending=True, revision="42", delay=0, fail=False,
                 deadline="2000-01-01T00:00:00Z")
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    async def route_request(route):
        path = urlparse(route.request.url).path
        if not path.startswith("/api/"):
            asset = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert asset.parent == DIST and asset.is_file()
            await route.fulfill(body=asset.read_bytes(), content_type=mimetypes.guess_type(str(asset))[0])
            return
        body = {}
        if path == "/api/session":
            body = dict(username="admin", role="admin", csrf_token="test")
        elif path == "/api/catalog":
            body = dict(components=[])
        elif path == "/api/config":
            state["reads"] += 1
            state["active"] += 1
            state["peak"] = max(state["peak"], state["active"])
            await asyncio.sleep(state["delay"])
            state["active"] -= 1
            if state["fail"]:
                state["fail"] = False
                await route.fulfill(status=503, json=dict(error="temporary config failure"))
                return
            body = dict(config=dict(system=dict(hostname="test"), interfaces=[], components=[],
                                    clients=[dict(mac=f"02:00:00:00:{i//256:02x}:{i%256:02x}") for i in range(size)]),
                        dirty=False, draft_version=8, problems=[], pending_confirmation=state["pending"],
                        pending_revision=state["revision"], confirm_deadline=state["deadline"])
        await route.fulfill(json=body)
    await page.route("**/*", route_request)
    await page.goto("http://netos.test/#components")
    await expect(page.locator(".countdown")).to_have_text("0")
    start = state["reads"]
    await page.wait_for_timeout(2400)
    count = state["reads"] - start
    print(f"clients={size}, reloads/2.4s={count}", flush=True)
    assert 1 <= count <= 3, state
    state.update(delay=1.3, peak=0, fail=True)
    await page.wait_for_timeout(5100)
    assert state["peak"] == 1 and not state["fail"], state
    state.update(delay=0, revision="43", deadline=(datetime.now(timezone.utc)+timedelta(seconds=5)).isoformat())
    await expect(page.locator(".countdown")).not_to_have_text("0", timeout=5000)
    start = state["reads"]
    await page.wait_for_timeout(700)
    assert state["reads"] == start, "future deadline must not poll"
    state["pending"] = False
    await expect(page.locator(".applybar")).to_have_count(0, timeout=7000)
    start = state["reads"]
    await page.wait_for_timeout(1300)
    assert state["reads"] == start, "timer survived pending completion"
    assert not errors, errors
    await page.close()
    print(f"clients={size}: retry, slow response, revision, countdown, cleanup PASS", flush=True)


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for size in (10, 2000):
            await scenario(browser, size)
        await browser.close()


asyncio.run(main())
