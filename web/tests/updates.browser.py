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
    state = {"config": cfg, "version": 1, "ready": True, "error": False, "posts": [], "current": "v0.09", "maintenance": "idle", "unavailable": False, "start_error": False}
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
        if state["unavailable"] and path in ("/api/status", "/api/maintenance/status"):
            await route.abort(); return
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
            else: body = {"releases": [{"tag_name": "v0.10", "name": "Релиз 0.10", "body": "## Исправления\n- Исправлена сеть\n" + "Подробное описание изменений.\n" * 100, "published_at": "2026-10-14T00:00:00Z"}]}
        elif path == "/api/maintenance/update":
            state["posts"].append(req.post_data_json)
            if state["start_error"]:
                await route.fulfill(status=500,json={"error":"Не удалось запустить установщик"});return
            state["maintenance"] = "activating"
            body = {"scheduled": True}
        elif path == "/api/maintenance/status": body = {"state": state["maintenance"], "failed": state["maintenance"] == "failed"}
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
    dialog = page.get_by_role("dialog")
    box = await dialog.bounding_box()
    viewport = page.viewport_size
    assert box and box["y"] >= 0 and box["y"] + box["height"] <= viewport["height"], (box, viewport)
    # Long release notes must not put the confirmation below the viewport.
    assert await confirm.is_visible()
    await page.set_viewport_size({"width": 390, "height": 740})
    box = await dialog.bounding_box()
    assert box["y"] >= 0 and box["y"] + box["height"] <= 740, box
    Path("output/playwright").mkdir(parents=True, exist_ok=True)
    await page.screenshot(path="output/playwright/updates-confirmation.png")
    await page.get_by_role("button", name="Отмена", exact=True).click()
    assert not state["posts"]
    await page.set_viewport_size({"width": 1280, "height": 900})
    for choice in ("yes", "no"):
        state["current"] = "v0.09"
        await page.reload()
        await check.click()
        await update.click()
        await page.get_by_label("Резервная копия перед установкой").select_option(choice)
        await confirm.click()
        bar = page.get_by_role("progressbar", name="Прогресс обновления")
        await expect(bar).to_be_visible()
        assert await bar.get_attribute("value") is None, "fake percentage"
        await page.locator(".update-toolbar").scroll_into_view_if_needed()
        await page.screenshot(path="output/playwright/update-running.png")
        assert state["posts"][-1] == {"version": "v0.10", "confirm": "UPDATE", "backup": choice == "yes"}
        await expect(page.get_by_role("button", name="Создать копию",exact=True)).to_be_disabled()
        state["maintenance"] = "active"
        await page.reload()
        await expect(bar).to_be_visible()
        state["unavailable"] = True
        await expect(page.get_by_role("status").filter(has_text="Связь с панелью прервана")).to_be_visible(timeout=10000)
        state["unavailable"] = False
        state["maintenance"] = "idle"
        state["current"] = "v0.10"
        await expect(page.get_by_role("status").filter(has_text="Обновление завершено")).to_be_visible(timeout=10000)
        await expect(bar).to_have_attribute("value", "1")
        assert await page.evaluate("sessionStorage.getItem('netos-pending-update')") is None
    # Failed systemd operation must not turn into a completed progress bar.
    state["current"] = "v0.09"
    await page.reload(); await check.click(); await update.click()
    await page.get_by_label("Резервная копия перед установкой").select_option("no")
    await confirm.click()
    await expect(page.get_by_role("status").filter(has_text="ожидает запуска")).to_be_visible()
    state["maintenance"] = "active"
    await expect(page.get_by_role("status").filter(has_text="Устанавливается")).to_be_visible(timeout=10000)
    state["maintenance"] = "failed"
    await expect(page.get_by_text("Обновление завершилось ошибкой. Проверьте журнал службы netos-maintenance.",exact=True)).to_be_visible(timeout=10000)
    await expect(page.get_by_role("progressbar", name="Прогресс обновления")).to_have_count(0)
    state["maintenance"] = "idle"
    await page.reload(); await check.click(); await update.click()
    await page.keyboard.press("Escape")
    await expect(page.get_by_role("dialog")).to_have_count(0)
    state["start_error"] = True
    await update.click()
    await page.get_by_label("Резервная копия перед установкой").select_option("yes")
    await confirm.click()
    await expect(page.locator(".update-panel").get_by_text("Не удалось запустить установщик",exact=True)).to_be_visible()
    await expect(page.get_by_role("button", name="Создать копию",exact=True)).to_be_enabled()
    state["start_error"] = False
    for current in ("v0.10", "v0.11", "unknown"):
        state["current"] = current
        await page.reload()
        await check.click()
        await expect(page.get_by_text("Релиз 0.10", exact=True)).to_be_visible()
        await expect(update).to_have_count(0)
    state["current"] = "dev"
    await page.reload(); await check.click()
    await expect(page.get_by_text("Установлена тестовая сборка. Доступен релиз v0.10.", exact=True)).to_be_visible()
    release_install = page.get_by_role("button", name="Установить релиз", exact=True)
    await release_install.click()
    await expect(confirm).to_be_disabled()
    await page.get_by_role("button", name="Отмена", exact=True).click()
    before = len(state["posts"])
    await release_install.click()
    await page.get_by_label("Резервная копия перед установкой").select_option("yes")
    await confirm.click()
    assert len(state["posts"]) == before + 1
    assert state["posts"][-1] == {"version": "v0.10", "confirm": "UPDATE", "backup": True}
    state["maintenance"] = "idle"
    state["current"] = "v0.10"
    await expect(page.get_by_role("status").filter(has_text="Обновление завершено")).to_be_visible(timeout=10000)
    await expect(release_install).to_have_count(0)
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
