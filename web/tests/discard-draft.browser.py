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
    saves = []
    errors, navigations = [], []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.on("framenavigated", lambda f: navigations.append(f.url) if f == page.main_frame else None)

    def config():
        problems = []
        if mode == "invalid applied config" and not saves:
            problems.append({"severity": "error", "path": "vpn_servers[0].config.tls.email",
                             "message": "Выберите общий email ACME для панели и VPN."})
        return {"config": state["config"], "dirty": state["dirty"], "draft_version": state["version"],
                "problems": problems, "pending_confirmation": False}

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
        elif path == "/api/components/updates" and req.method == "GET":
            body = {"components": {}}
        elif path == "/api/catalog":
            body = {"components": [{"id": "samba", "title": "Samba", "group": "Files", "description": "Test component"}]}
        elif path == "/api/status":
            body = {"interfaces": [], "uptime_seconds": 1}
        elif path == "/api/config" and req.method == "GET":
            if mode in ("reload failure", "reload failure then apply") and not state["dirty"] and not state["failed"]:
                state["failed"] = True
                status, body = 503, {"error": "Не удалось загрузить конфигурацию"}
            else:
                body = config()
        elif path == "/api/config" and req.method == "PUT":
            saves.append(req.post_data_json)
            started.set()
            if mode.startswith("inflight") or mode in ("newer save", "retry failed"):
                await release.wait()
            if mode in ("inflight failure", "retry failed") or (mode == "inflight discard then apply" and len(saves) == 1) or (mode == "newer save" and len(saves) == 1):
                status, body = 500, {"error": "Сохранение не удалось"}
            else:
                state.update(config=req.post_data_json, dirty=True, version=state["version"] + 1)
                body = config()
        elif path == "/api/config/apply":
            if mode.startswith("edit during apply"):
                started.set()
                await release.wait()
                if mode.endswith("success"):
                    state.update(dirty=False, version=state["version"] + 1)
                    await route.fulfill(json={"needs_confirm": False, "revision": 2})
                    return
            if mode == "lost apply response":
                state.update(config=copy.deepcopy(CLEAN), dirty=False, version=state["version"] + 1)
                await route.abort("connectionreset")
                return
            status, body = 500, {"error": "apt-get: Temporary failure resolving 'repo.example'"}
        elif path == "/api/config/discard":
            if req.headers["if-match"] != str(state["version"]):
                status, body = 409, {"error": "черновик уже изменён"}
            elif mode in ("discard failure", "discard then apply", "inflight discard then apply") and not state["failed"]:
                state["failed"] = True
                status, body = 500, {"error": "Отмена не удалась"}
            else:
                state.update(config=copy.deepcopy(CLEAN), dirty=False, version=state["version"] + 1)
                body = {"ok": True, "draft_version": state["version"]}
        else:
            raise AssertionError((req.method, path))
        await route.fulfill(status=status, content_type="application/json", body=json.dumps(body))

    if mode == "invalid applied config":
        state["dirty"] = False
    await page.route("**/*", route_request)
    await page.goto("http://netos.test/#components")
    toggle = page.get_by_role("checkbox", name="Компонент Samba включён")
    await expect(toggle).to_be_checked()
    if mode.endswith("then apply"):
        await toggle.locator("..").click()
        await expect(toggle).not_to_be_checked()
        if mode.startswith("inflight"):
            await asyncio.wait_for(started.wait(), 5)
        if mode == "conflict then apply":
            state["version"] += 1
        await page.get_by_role("button", name="Отменить", exact=True).click()
        release.set()
        await expect(page.locator(".action-error")).to_be_visible()
        if mode == "conflict then apply":
            await expect(toggle).to_be_checked()
        else:
            await expect(toggle).not_to_be_checked()
        before = len(saves)
        await page.wait_for_timeout(750)
        assert len(saves) == before, "failed discard must not autosave"
        await page.get_by_role("button", name="Применить", exact=True).click()
        await expect(page.locator(".action-error")).to_contain_text("apt-get")
        conflicted = mode == "conflict then apply"
        assert len(saves) == before + (0 if conflicted else 1), (mode, saves, state["calls"])
        assert state["config"]["components"][0]["installed"] == conflicted, state
        assert not errors, errors
        await page.close()
        print(mode, "PASS")
        return
    if mode.startswith("edit during apply"):
        await page.get_by_role("button", name="Применить", exact=True).click()
        await asyncio.wait_for(started.wait(), 5)
        try:
            await expect(toggle).to_be_disabled(timeout=1500)
        finally:
            release.set()
        await expect(toggle).to_be_enabled()
        if mode.endswith("failure"):
            await expect(page.locator(".action-error")).to_be_visible()
        assert not saves
        async with page.expect_response(lambda r: r.request.method == "PUT" and r.ok):
            await toggle.locator("..").click()
        assert len(saves) == 1 and not errors
        await page.close()
        print(mode, "PASS")
        return
    if mode == "invalid applied config":
        message = page.get_by_text("Выберите общий email ACME для панели и VPN.", exact=True)
        await expect(message).to_be_visible()
        await expect(page.get_by_role("button", name="Применить", exact=True)).to_have_count(0)
        assert not saves
        await toggle.locator("..").click()
        await expect(message).to_have_count(0)
        assert len(saves) == 1 and not errors
        await page.close()
        print(mode, "PASS")
        return
    if mode in ("newer save", "retry failed"):
        apply = page.get_by_role("button", name="Применить", exact=True)
        await toggle.locator("..").click()
        await asyncio.wait_for(started.wait(), 5)
        if mode == "newer save":
            await toggle.locator("..").click()
            await expect(toggle).to_be_checked()
            await page.wait_for_timeout(750)  # let the second save enter the queue
            async with page.expect_response(lambda r: r.request.method == "PUT" and r.status == 200):
                release.set()
            await apply.click()
            await expect(page.locator(".action-error")).to_be_visible()
            assert len(saves) == 2, saves
            assert state["config"]["components"][0]["installed"]
            assert ("POST", "/api/config/apply") in state["calls"]
        else:
            await apply.click()
            await expect(page.get_by_role("button", name="Подождите…")).to_be_visible()
            release.set()
            await expect(page.locator(".action-error")).to_be_visible()
            assert ("POST", "/api/config/apply") not in state["calls"], state["calls"]
            assert len(saves) == 2 and saves[0] == saves[1], saves
        assert not errors, errors
        await page.close()
        print(mode, "PASS")
        return
    await page.get_by_role("button", name="Применить", exact=True).click()
    await expect(page.locator(".action-error")).to_be_visible()
    if mode == "queued" or mode.startswith("inflight"):
        await toggle.locator("..").click()
        await expect(toggle).not_to_be_checked()
    if mode.startswith("inflight"):
        await asyncio.wait_for(started.wait(), 5)
    if mode in ("stale clean", "stale new draft"):
        state["version"] += 1
        state["dirty"] = mode == "stale new draft"
        if not state["dirty"]:
            state["config"] = copy.deepcopy(CLEAN)
    await page.get_by_role("button", name="Отменить", exact=True).click()
    if mode == "stale new draft":
        await expect(page.locator(".action-error")).to_contain_text("Настройки обновились")
        assert state["dirty"], "new draft was silently discarded"
        assert sum(path.endswith("/discard") for _, path in state["calls"]) == 1
        await expect(toggle).to_be_checked()
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
        for mode in ("discard then apply", "inflight discard then apply", "reload failure then apply", "conflict then apply", "edit during apply success", "edit during apply failure", "newer save", "retry failed", "lost apply response", "stale clean", "stale new draft", "normal", "queued", "inflight success", "inflight failure", "discard failure", "reload failure", "invalid applied config"):
            await scenario(browser, mode)
        await browser.close()


asyncio.run(main())
