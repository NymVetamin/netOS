"""Live connections UI with local API fixtures; never accesses a router."""
import asyncio
import importlib.util
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright, expect

spec = importlib.util.spec_from_file_location("shared", Path(__file__).with_name("ui-review-regressions.browser.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=True)
        page, base = await shared.fixture(browser, {"role":"limited", "permissions":{"diagnostics":"view"}})
        state = {"requests":[], "error":False, "bytes":100, "empty":False, "many":False}
        async def connections(r):
            query = parse_qs(urlparse(r.request.url).query)
            state["requests"].append(query)
            if state["error"]:
                await r.fulfill(status=503, json={"error":"fixture unavailable"})
                return
            row = {"protocol":"TCP", "state":"ESTABLISHED", "source":{"address":"192.0.2.10","port":"45000"}, "destination":{"address":"198.51.100.2","port":"443"}, "reply_source":{"address":"198.51.100.2","port":"443"}, "reply_destination":{"address":"203.0.113.1","port":"55000"}, "nat":"SNAT", "timeout":120, "bytes":state["bytes"], "reply_bytes":20, "process":"test-process"}
            await r.fulfill(json={"rows":[] if state["empty"] else [row] * (100 if state["many"] else 1), "total":0 if state["empty"] else (100000 if state["many"] else 1), "scanned":1, "unparsed":0, "page":0, "updated":"2026-11-05T15:00:00Z"})
        await page.route("**/api/diagnostics/connections?*", connections)
        await page.route("**/api/diagnostics/tools", lambda r: r.fulfill(json={"available":{"ping":True}, "interfaces":[]}))
        await page.goto("http://netos.test/#diagnostics?tab=connections")
        await expect(page.get_by_role("cell", name="192.0.2.10:45000", exact=True)).to_be_visible()
        await expect(page.get_by_role("button", name="Запустить", exact=True)).to_have_count(0)
        state["bytes"] = 500
        await expect(page.get_by_role("cell", name="500 / 20", exact=True)).to_be_visible()
        state["error"] = True
        await expect(page.get_by_text("Показан последний успешный снимок", exact=False)).to_be_visible()
        state["error"] = False
        await expect(page.get_by_text("Показан последний успешный снимок", exact=False)).to_have_count(0)
        await page.get_by_label("IP-адрес или подсеть", exact=True).fill("192.0.2.0/24")
        await page.get_by_label("Порты", exact=True).fill("443,8000-8100")
        await page.get_by_label("Протокол", exact=True).select_option("TCP")
        await page.get_by_label("NAT", exact=True).select_option("SNAT")
        await expect(page.get_by_role("cell", name="192.0.2.10:45000", exact=True)).to_be_visible()
        assert state["requests"][-1]["address"] == ["192.0.2.0/24"] and state["requests"][-1]["ports"] == ["443,8000-8100"]
        assert state["requests"][-1]["nat"] == ["SNAT"]
        await page.get_by_role("button", name="Приостановить обновление", exact=True).click()
        await asyncio.sleep(.7)
        count = len(state["requests"])
        await asyncio.sleep(1.3)
        assert len(state["requests"]) == count
        await page.get_by_role("button", name="Обновить сейчас", exact=True).click()
        await asyncio.sleep(.7)
        assert len(state["requests"]) == count + 1
        await page.get_by_label("Показывать", exact=True).select_option("local")
        await expect(page.get_by_role("cell", name="test-process", exact=True)).to_be_visible()
        assert "nat" not in state["requests"][-1]
        await page.get_by_role("button", name="Продолжить обновление", exact=True).click()
        state["empty"] = True
        await expect(page.get_by_text("Соединений по выбранным фильтрам нет", exact=True)).to_be_visible()
        state["empty"] = False
        await expect(page.get_by_role("cell", name="test-process", exact=True)).to_be_visible()
        await page.set_viewport_size({"width":390,"height":844})
        assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
        out = Path(__file__).resolve().parents[2] / "output/playwright"
        out.mkdir(parents=True, exist_ok=True)
        await page.screenshot(path=str(out / "connections-mobile.png"), full_page=True)
        state["many"] = True
        await expect(page.locator("tbody tr")).to_have_count(100)
        await expect(page.get_by_text("Страница 1 из 1000", exact=True)).to_be_visible()
        async with page.expect_request(lambda r: "/api/diagnostics/connections?" in r.url and "page=1" in r.url):
            await page.get_by_role("button", name="Далее", exact=True).click()
        await expect(page.get_by_text("Страница 2 из 1000", exact=True)).to_be_visible()
        assert state["requests"][-1]["page"] == ["1"]
        await page.get_by_role("tab", name="Ping", exact=True).click()
        await asyncio.sleep(.3)
        count = len(state["requests"])
        await asyncio.sleep(1.3)
        assert len(state["requests"]) == count
        assert not base["errors"], base["errors"]
        await browser.close()
        print("connections live/filters/NAT/local/view/pause/error-recovery/unmount/mobile PASS")

asyncio.run(main())
