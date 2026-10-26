"""Production UI regression: local API fixtures only; never contacts a router."""
import asyncio
import json
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"

async def scenario(browser, width):
    page = await browser.new_page(viewport={"width": width, "height": 900})
    if width == 1280:
        await page.add_init_script("localStorage.setItem('netos-theme', 'dark')")
    state = {"version": 3, "slow": False, "config": {"system": {"hostname": "test-router"}, "interfaces": [], "components": []}}
    started, release = asyncio.Event(), asyncio.Event()
    errors = []
    page.on("pageerror", lambda error: errors.append(str(error)))

    def config():
        return {"config": state["config"], "dirty": True, "draft_version": state["version"], "problems": [], "pending_confirmation": False}

    async def route_request(route):
        req = route.request
        path = urlparse(req.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "fixture"}
        elif path == "/api/catalog":
            body = {"components": [{"id": "samba", "title": "Samba", "group": "Files", "description": "Test"}]}
        elif path == "/api/status":
            body = {"interfaces": [], "uptime_seconds": 1}
        elif path == "/api/config" and req.method == "GET":
            body = config()
        elif path == "/api/config" and req.method == "PUT":
            assert req.headers["if-match"] == str(state["version"])
            state.update(config=req.post_data_json, version=state["version"] + 1)
            body = config()
        elif path == "/api/config/plan":
            version = state["version"]
            if state["slow"]:
                started.set()
                await release.wait()
            body = {"draft_version": version, "needs_confirm": True,
                    "changes": [
                        {"path": "/wans/wan/enabled", "label": "Аплинки «Аплинк» · Состояние", "kind": "change", "before": "Включено", "after": "Выключено"},
                        {"path": "/clients/phone/channel", "label": "Клиенты «phone» · Канал", "kind": "change", "before": "Напрямую", "after": "Xray Riga (ch1)"},
                        {"path": "/socks/password", "label": "Прокси SOCKS · Пароль", "kind": "change", "before": "Скрыто", "after": "Скрыто"}],
                    "actions": [{"subsystem": "wan", "kind": "update", "target": "Аплинк (static)", "disruptive": True},
                                {"subsystem": "firewall", "kind": "update", "target": "iptables", "detail": "+0 правил, -8 правил", "disruptive": False}]}
        else:
            raise AssertionError((req.method, path))
        await route.fulfill(content_type="application/json", body=json.dumps(body))

    await page.route("**/*", route_request)
    await page.goto("http://netos.test/#components")
    show = page.get_by_role("button", name="Показать план", exact=True)
    await show.click()
    preview = page.get_by_role("region", name="План изменений")
    await expect(preview).to_contain_text("Включено")
    await expect(preview).to_contain_text("Выключено")
    await expect(preview).to_contain_text("Xray Riga (ch1)")
    await expect(preview).to_contain_text("содержимое скрыто")
    await expect(preview).to_contain_text("Потребуется подтверждение")
    await expect(preview.locator("details")).not_to_have_attribute("open", "")
    await preview.locator("summary").click()
    await expect(preview.locator("details")).to_have_attribute("open", "")
    assert await page.evaluate("document.documentElement.scrollWidth <= window.innerWidth"), "horizontal overflow"
    if os.environ.get("PLAN_SCREENSHOTS"):
        target = Path(os.environ["PLAN_SCREENSHOTS"])
        target.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(target / f"plan-{width}.png"))
    toggle = page.get_by_role("checkbox", name="Компонент Samba включён")
    await toggle.locator("..").click()
    await expect(preview).to_have_count(0)
    # A late preview must not reappear after editing while it was being built.
    state["slow"] = True
    await show.click()
    await asyncio.wait_for(started.wait(), 5)
    await toggle.locator("..").click()
    await page.wait_for_timeout(650)
    release.set()
    await expect(show).to_be_enabled()
    await expect(preview).to_have_count(0)
    state["slow"] = False
    await show.click()
    await expect(preview).to_be_visible()
    assert not errors, errors
    await page.close()
    print(f"plan preview {width}: PASS")

async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for width in (1280, 390):
            await scenario(browser, width)
        await browser.close()

asyncio.run(main())
