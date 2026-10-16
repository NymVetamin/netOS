"""Local production UI regression; all API calls are mocked, no router access."""
import asyncio
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"
TYPES = [("wireguard", "wireguard", "WireGuard"), ("openconnect", "openconnect", "OpenConnect"),
         ("xray", "xray", "Xray"), ("ikev2", "strongswan", "IKEv2"), ("l2tp", "l2tp", "L2TP")]


# Записи свёрнуты в строки; сценарий проверяет их настройки, поэтому раскрывает
# каждую строку сразу, как только она появляется.
OPEN_ROWS = """new MutationObserver(() => document.querySelectorAll('details.xd:not([data-opened])')
  .forEach((row) => { row.dataset.opened = '1'; row.open = true; })).observe(document, {childList: true, subtree: true})"""


async def scenario(browser, mode):
    page = await browser.new_page()
    cfg = {"system": {"hostname": "test"}, "interfaces": [], "networks": [], "policies": [], "channels": []}
    state = {"config": cfg, "version": 1, "ready": True, "error": False, "posts": [], "current": "v0.09"}
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))

    def config():
        return {"config": state["config"], "dirty": False, "draft_version": state["version"], "problems": [], "pending_confirmation": False}

    async def route_request(route):
        req, path = route.request, urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file = DIST / ("index.html" if path == "/" else path.lstrip("/"))
            assert file.parent == DIST and file.is_file(), path
            await route.fulfill(body=file.read_bytes(), content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream")
            return
        body, status = {}, 200
        if path == "/api/session":
            body = {"username": "admin", "role": "admin", "csrf_token": "test"}
        elif path == "/api/panel-users": body = []
        elif path == "/api/catalog":
            body = {"components": [], "installed": {cid: state["ready"] for _, cid, _ in TYPES}}
            if state["error"]:
                status, body = 503, {"error": "unavailable"}
        elif path == "/api/status":
            body = {"interfaces": [], "channels": [], "uptime_seconds": 1, "version": state["current"]}
        elif path == "/api/maintenance/releases":
            if state["error"]: status, body = 502, {"error": "GitHub временно недоступен"}
            else: body = {"releases": [{"tag_name": "v0.10", "name": "Релиз 0.10", "body": "## Исправления\n- Исправлена сеть", "published_at": "2026-10-14T00:00:00Z"}]}
        elif path == "/api/maintenance/update":
            state["posts"].append(req.post_data_json)
            body = {"scheduled": True}
        elif path == "/api/maintenance/status": body = {"state": "idle", "failed": False}
        elif path == "/api/backups": body = {"backups": []}
        elif path == "/api/config":
            if req.method == "PUT":
                state["config"] = req.post_data_json
                state["version"] += 1
            body = config()
        await route.fulfill(status=status, json=body,content_type="application/json")

    await page.add_init_script(OPEN_ROWS)
    await page.route("**/*", route_request)
    await page.goto("https://netos-ui.test/#system")
    check = page.get_by_role("button", name="Проверить обновления", exact=True)
    update = page.get_by_role("button", name="Обновить", exact=True)
    await expect(check).to_be_visible()
    await expect(update).to_have_count(0)
    await expect(page.get_by_role("button", name="Откат", exact=True)).to_have_count(0)
    await check.click()
    await expect(update).to_be_visible()
    await expect(page.get_by_text("• Исправлена сеть", exact=True)).to_be_visible()
    await update.click()
    confirm = page.get_by_role("button", name="Подтвердить установку", exact=True)
    await expect(confirm).to_be_disabled()
    await confirm.scroll_into_view_if_needed()
    Path("output/playwright").mkdir(parents=True, exist_ok=True)
    await page.screenshot(path="output/playwright/updates-confirmation.png")
    await page.get_by_role("button", name="Отмена", exact=True).click()
    assert not state["posts"]
    for choice in ("yes", "no"):
        await update.click()
        await page.get_by_label("Резервная копия перед установкой").select_option(choice)
        await confirm.click()
        await page.wait_for_timeout(200)
        assert state["posts"][-1] == {"version": "v0.10", "confirm": "UPDATE", "backup": choice == "yes"}
        await page.reload()
        await check.click()
        await expect(update).to_be_visible()
    for current in ("v0.10", "v0.11", "dev"):
        state["current"] = current
        await page.reload()
        await check.click()
        await expect(page.get_by_text("Релиз 0.10", exact=True)).to_be_visible()
        await expect(update).to_have_count(0)
    state["error"] = True
    await check.click()
    await expect(page.get_by_text("GitHub временно недоступен", exact=True)).to_be_visible()
    await expect(update).to_have_count(0)
    assert not errors, errors
    await page.close()
    print(mode, "PASS")


async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("updates",):
            await scenario(browser, mode)
        await browser.close()

asyncio.run(main())
