"""Production QoS UI with mocked persistence; no router or tc commands."""
import asyncio
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def main():
    state = {"puts": 0, "config": {
        "system": {"hostname": "test"}, "interfaces": [], "networks": [],
        "components": [{"id": "qos", "installed": True}],
        "wans": [{"id": name, "name": name, "enabled": True} for name in ["A", "B"]],
        "qos": {"enabled": True, "wans": [
            {"wan": "B", "upload_kbit": 1234, "download_kbit": 5678, "diffserv": "diffserv3"},
            {"wan": "B", "upload_kbit": 3000, "download_kbit": 4000, "diffserv": "diffserv4"}]}}}
    errors = []
    async with async_playwright() as p:
        exe = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not exe and os.name == "nt":
            exe = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=exe)
        page = await browser.new_page()
        page.on("pageerror", lambda e: errors.append(str(e)))
        await page.add_init_script("""new MutationObserver(() => document.querySelectorAll('details.xd')
            .forEach(row => { row.open = true; })).observe(document, {childList: true, subtree: true})""")

        async def handle(route):
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

        await page.route("**/*", handle)
        await page.goto("http://netos-ui.test/#traffic")
        add = page.get_by_role("button", name="Добавить", exact=True)
        await expect(add).to_be_enabled()
        await expect(page.get_by_text("Все включённые аплинки уже добавлены", exact=True)).to_have_count(0)
        async with page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith('/api/config')):
            await page.get_by_label("Аплинк QoS 1", exact=True).select_option("A")
        assert [w["wan"] for w in state["config"]["qos"]["wans"]] == ["A", "B"]
        assert state["config"]["qos"]["wans"][0]["upload_kbit"] == 1234
        await expect(add).to_be_disabled()
        await expect(page.get_by_label("Аплинк QoS 1", exact=True).locator('option[value="B"]')).to_be_disabled()
        await expect(page.get_by_label("Аплинк QoS 2", exact=True).locator('option[value="A"]')).to_be_disabled()
        for repeat in range(2):
            async with page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith('/api/config')):
                await page.get_by_role("button", name="Убрать", exact=True).last.click()
            await expect(add).to_be_enabled()
            await expect(page.get_by_label("Аплинк QoS 1", exact=True).locator('option[value="B"]')).to_be_enabled()
            async with page.expect_response(lambda r: r.request.method == "PUT" and r.url.endswith('/api/config')):
                await add.click()
            assert [w["wan"] for w in state["config"]["qos"]["wans"]] == ["A", "B"]
            await expect(add).to_be_disabled()
        await page.reload()
        await expect(page.get_by_label("Аплинк QoS 1", exact=True)).to_have_value("A")
        await expect(page.get_by_label("Аплинк QoS 2", exact=True)).to_have_value("B")
        await expect(page.get_by_label("Отдача QoS 1, Кбит/с", exact=True)).to_have_value("1234")
        await expect(page.get_by_label("Приоритеты QoS 1", exact=True)).to_have_value("diffserv3")
        assert not errors, errors
        await browser.close()
    print("QoS duplicate repair, occupied options, remove/add twice, persistence and reload PASS")


asyncio.run(main())
