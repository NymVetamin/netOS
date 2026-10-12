"""Run after npm run build: python tests/discard-draft.browser.py.

Requires Python Playwright and Chromium (or PLAYWRIGHT_CHROMIUM_EXECUTABLE).
All requests are intercepted locally; no router is contacted or modified.
"""
import asyncio
import copy
import json
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
CLEAN = {"system": {"hostname": "test-router"}, "interfaces": [], "components": []}


async def scenario(browser, mode):
    page = await browser.new_page()
    state = {"config": {**copy.deepcopy(CLEAN), "components": [{"id": "samba", "installed": True}]},
             "dirty": True, "version": 1, "calls": [], "failed": False}
    started, release = asyncio.Event(), asyncio.Event()
    errors, navigations = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("framenavigated", lambda f: navigations.append(f.url) if f == page.main_frame else None)

    def config():
        return {"config": state["config"], "dirty": state["dirty"], "draft_version": state["version"],
                "problems": [], "pending_confirmation": False}

    async def route_request(route):
        req = route.request
        path = urlparse(req.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        state["calls"].append((req.method, path))
        status, body = 200, {}
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "local-test"}
        elif path == "/api/catalog":
            body = {"components": [{"id": "samba", "title": "Samba", "group": "Files", "description": "Test component"}]}
        elif path == "/api/status":
            body = {"interfaces": [], "uptime_seconds": 1}
        elif path == "/api/config" and req.method == "GET":
            if mode == "reload failure" and not state["dirty"] and not state["failed"]:
                state["failed"] = True
                status, body = 503, {"error": "Не удалось загрузить конфигурацию"}
            else:
                body = config()
        elif path == "/api/config" and req.method == "PUT":
            started.set()
            if mode.startswith("inflight"):
                await release.wait()
            if mode == "inflight failure":
                status, body = 500, {"error": "Сохранение не удалось"}
            else:
                state.update(config=req.post_data_json, dirty=True, version=state["version"] + 1)
                body = config()
        elif path == "/api/config/apply":
            status, body = 500, {"error": "apt-get: Temporary failure resolving 'repo.example'"}
        elif path == "/api/config/discard":
            assert req.headers["if-match"] == str(state["version"])
            if mode == "discard failure" and not state["failed"]:
                state["failed"] = True
                status, body = 500, {"error": "Отмена не удалась"}
            else:
                state.update(config=copy.deepcopy(CLEAN), dirty=False, version=state["version"] + 1)
                body = {"ok": True, "draft_version": state["version"]}
        else:
            raise AssertionError((req.method, path))
        await route.fulfill(status=status, content_type="application/json", body=json.dumps(body))

    await page.route("**/*", route_request)
    await page.goto("http://netos.test/#components")
    toggle = page.get_by_role("checkbox", name="Компонент Samba включён")
    await expect(toggle).to_be_checked()
    await page.get_by_role("button", name="Применить", exact=True).click()
    await expect(page.locator(".action-error")).to_be_visible()
    if mode == "queued" or mode.startswith("inflight"):
        await toggle.locator("..").click()
        await expect(toggle).not_to_be_checked()
    if mode.startswith("inflight"):
        await asyncio.wait_for(started.wait(), 5)
    await page.get_by_role("button", name="Отменить", exact=True).click()
    if mode.startswith("inflight"):
        await expect(toggle).to_be_disabled()
        assert not any(path.endswith("/discard") for _, path in state["calls"])
        release.set()
    if mode in ("discard failure", "reload failure"):
        await expect(page.locator(".action-error")).to_be_visible()
        await expect(page.get_by_role("button", name="Отменить", exact=True)).to_be_enabled()
        if mode == "discard failure":
            await expect(toggle).to_be_checked()
        await page.get_by_role("button", name="Отменить", exact=True).click()
    await expect(page.locator(".applybar")).to_have_count(0)
    await expect(toggle).not_to_be_checked()
    await page.wait_for_timeout(750)  # exceed the debounce delay
    await expect(page.locator(".applybar")).to_have_count(0)
    assert not state["dirty"]
    calls = state["calls"]
    discard_index = next(i for i, (_, path) in enumerate(calls) if path.endswith("/discard"))
    assert not any(method == "PUT" for method, _ in calls[discard_index:]), calls
    if mode == "queued":
        assert not any(method == "PUT" for method, _ in calls), calls
    assert len(navigations) == 1, navigations
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("normal", "queued", "inflight success", "inflight failure", "discard failure", "reload failure"):
            await scenario(browser, mode)
        await browser.close()


asyncio.run(main())
