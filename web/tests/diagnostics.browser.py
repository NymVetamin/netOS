"""Diagnostic tools in the production UI, with all APIs intercepted locally."""
import asyncio
import importlib.util
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

spec = importlib.util.spec_from_file_location("fixture", Path(__file__).with_name("ui-review-regressions.browser.py"))
shared = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shared)


async def setup(browser, permissions=None):
    session = {"role": "admin"} if permissions is None else {"role": "limited", "permissions": permissions}
    page, base = await shared.fixture(browser, session)
    state = {"starts": [], "stops": [], "polls": 0, "done": False, "fail": False, "delay": None, "missing": False}

    async def route(r):
        path = urlparse(r.request.url).path
        if path.endswith("/tools"):
            available = {k: True for k in ["ping", "traceroute", "mtr", "dns", "capture", "torch", "iperf", "connections", "route"]}
            if state["missing"]:
                available["iperf"] = False
            await r.fulfill(json={"available": available, "interfaces": [{"name": "lo", "addresses": ["127.0.0.1"]}]})
        elif path.endswith("/jobs"):
            state["starts"].append(r.request.post_data_json)
            if state["delay"]:
                await state["delay"].wait()
            state["done"] = False
            await r.fulfill(status=202, json={"id": "test-job"})
        elif r.request.method == "DELETE":
            state["stops"].append(path)
            state["done"] = True
            await r.fulfill(json={"ok": True})
        elif path.endswith("/capture"):
            await r.fulfill(body=b"pcap-test-data", content_type="application/vnd.tcpdump.pcap", headers={"Content-Disposition": "attachment; filename=test.pcap"})
        else:
            state["polls"] += 1
            if state["fail"]:
                await r.fulfill(status=503, json={"error": "temporary fixture failure"})
                return
            kind = state["starts"][-1]["kind"]
            body = {"id": "test-job", "kind": kind, "state": "done" if state["done"] else "running", "output": "<script>safe</script> diagnostic output", "error": "", "elapsed": 2, "capture_bytes": 128}
            if kind == "torch":
                body["torch"] = {"total_flows": 1, "packets": 10, "skipped": 0, "flows": [{"source": "192.0.2.1", "destination": "192.0.2.2", "protocol": "UDP", "source_port": 5000, "destination_port": 53, "packets": 10, "bytes": 1000, "bitrate": 4000}]}
            await r.fulfill(json=body)
    await page.route("**/api/diagnostics/**", route)
    return page, state, base


async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel="chrome", headless=True)
        page, state, base = await setup(browser)
        await page.goto("http://netos.test/#diagnostics?tab=ping")
        tabs = page.get_by_role("tablist", name="Диагностика", exact=True)
        await expect(tabs.get_by_role("tab")).to_have_count(11)
        await page.get_by_label("Адрес назначения", exact=True).fill("127.0.0.1")
        await page.get_by_role("button", name="Запустить", exact=True).click()
        await expect(page.locator("pre.output")).to_contain_text("<script>safe</script>")
        await expect(page.get_by_label("Адрес назначения", exact=True)).to_be_disabled()
        state["fail"] = True
        await expect(page.get_by_text("temporary fixture failure", exact=False)).to_be_visible(timeout=5000)
        state["fail"] = False
        await expect(page.get_by_text("temporary fixture failure", exact=False)).to_have_count(0, timeout=5000)
        await page.get_by_role("button", name="Остановить", exact=True).click()
        await expect(page.get_by_role("button", name="Запустить", exact=True)).to_be_enabled(timeout=5000)
        assert len(state["stops"]) == 1
        assert state["starts"][0]["count"] == 5

        for tab, kind in [("Traceroute / MTR", "mtr"), ("DNS", "dns"), ("Захват пакетов", "capture"), ("Torch", "torch"), ("iPerf3", "iperf"), ("Соединения", "connections"), ("Поиск маршрута", "route")]:
            await tabs.get_by_role("tab", name=tab, exact=True).click()
            await expect(page.get_by_role("heading", name=tab, exact=True)).to_be_visible()
            if kind == "mtr":
                await page.get_by_label("Инструмент", exact=True).select_option("mtr")
            if kind in ["mtr", "route"]:
                await page.get_by_label("Адрес назначения", exact=True).fill("127.0.0.1")
            if kind == "dns":
                await page.get_by_label("Имя для запроса", exact=True).fill("example.test")
            if kind in ["capture", "torch"]:
                await page.get_by_label("Интерфейс", exact=True).select_option("lo")
                await page.get_by_label("Фильтр BPF", exact=True).fill("udp port 53")
            if kind == "iperf":
                await page.get_by_label("Режим", exact=True).select_option("server")
                await page.get_by_label("Локальный адрес", exact=True).select_option("127.0.0.1")
            await page.get_by_role("button", name="Запустить", exact=True).click()
            await expect(page.locator("pre.output")).to_be_visible()
            assert state["starts"][-1]["kind"] == kind
            if kind == "torch":
                await expect(page.get_by_role("cell", name="192.0.2.1:5000", exact=True)).to_be_visible()
                await page.set_viewport_size({"width": 390, "height": 844})
                assert await page.evaluate("document.documentElement.scrollWidth <= innerWidth + 1")
                artifacts = Path(__file__).resolve().parents[2] / "output/playwright"
                artifacts.mkdir(parents=True, exist_ok=True)
                await page.screenshot(path=str(artifacts / "diagnostics-mobile.png"), full_page=True)
                await page.set_viewport_size({"width": 1440, "height": 1000})
                await page.screenshot(path=str(artifacts / "diagnostics-desktop.png"), full_page=True)
            state["done"] = True
            await expect(page.get_by_role("button", name="Запустить", exact=True)).to_be_enabled(timeout=5000)
            if kind == "capture":
                async with page.expect_download() as download:
                    await page.get_by_role("button", name="Скачать PCAP", exact=False).click()
                assert Path(await (await download.value).path()).read_bytes() == b"pcap-test-data"

        # Unmount before the start response arrives still stops the created job.
        await tabs.get_by_role("tab", name="Ping", exact=True).click()
        await expect(page.get_by_role("heading", name="Ping", exact=True)).to_be_visible()
        await page.get_by_label("Адрес назначения", exact=True).fill("127.0.0.1")
        state["delay"] = asyncio.Event()
        await page.get_by_role("button", name="Запустить", exact=True).click()
        await expect(page.get_by_role("button", name="Запуск…", exact=True)).to_be_visible()
        await tabs.get_by_role("tab", name="DNS", exact=True).click()
        state["delay"].set()
        for _ in range(50):
            if len(state["stops"]) == 2:
                break
            await asyncio.sleep(.1)
        assert len(state["stops"]) == 2, state
        await page.reload()
        await expect(tabs.get_by_role("tab", name="DNS", exact=True)).to_have_attribute("aria-selected", "true")
        assert not base["errors"], base["errors"]
        await page.close()

        page, state, base = await setup(browser, {"diagnostics": "view"})
        await page.goto("http://netos.test/#diagnostics?tab=ping")
        await expect(page.get_by_role("button", name="Запустить", exact=True)).to_be_disabled()
        await expect(page.get_by_role("tab", name="Конфиги", exact=True)).to_have_count(0)
        await page.get_by_role("tab", name="Torch", exact=True).click()
        await expect(page.get_by_role("heading", name="Torch", exact=True)).to_be_visible()
        assert not state["starts"] and not base["errors"]
        await page.close()

        page, state, base = await setup(browser, {"diagnostics": "manage"})
        state["missing"] = True
        await page.goto("http://netos.test/#diagnostics?tab=iperf")
        await expect(page.get_by_text("Для установки обратитесь к администратору", exact=True)).to_be_visible()
        await expect(page.get_by_role("button", name="Запустить", exact=True)).to_be_disabled()
        state["missing"] = False
        await page.get_by_role("button", name="Проверить после установки", exact=True).click()
        await expect(page.get_by_role("button", name="Запустить", exact=True)).to_be_enabled()
        assert not base["errors"]
        await browser.close()
        print("diagnostics tabs/tools/permissions/stop/late-start/retry/pcap/mobile PASS")


asyncio.run(main())
