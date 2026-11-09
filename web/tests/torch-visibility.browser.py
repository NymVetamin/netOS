"""Visibility controls only the Torch viewer; all APIs are local fixtures."""
import asyncio, importlib.util, json
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright, expect
spec = importlib.util.spec_from_file_location('diagnostics', Path(__file__).with_name('diagnostics.browser.py'))
d = importlib.util.module_from_spec(spec)
spec.loader.exec_module(d)

async def visibility(page, hidden):
    await page.evaluate("""hidden => {
        Object.defineProperty(document, 'hidden', {configurable:true, get:()=>hidden});
        document.dispatchEvent(new Event('visibilitychange'));
    }""", hidden)
    await page.wait_for_timeout(100)

async def scenario(browser, total):
    page, state, base = await d.setup(browser)
    calls=[]; mode={'error':0, 'hold':False}; entered=asyncio.Event(); release=asyncio.Event()
    async def job(r):
        if r.request.method!='GET':
            await r.fallback(); return
        calls.append(parse_qs(urlparse(r.request.url).query).get('page',['0'])[0])
        if mode['hold']:
            entered.set(); await release.wait()
        if mode['error']:
            await r.fulfill(status=mode['error'], json={'error':'fixture failure'}); return
        await r.fulfill(json={'id':'test-job','kind':'torch','state':'done' if state['done'] else 'running',
            'output':'','error':'','elapsed':2,'capture_bytes':128,
            'torch':{'total_flows':total,'packets':10,'skipped':0,'flows':[]}})
    await page.route('**/jobs/test-job*', job)
    await page.goto('http://netos.test/#diagnostics?tab=torch')
    await page.get_by_label('IP-адрес или подсеть',exact=True).fill('192.0.2.0/24')
    await page.get_by_role('button',name='Запустить',exact=True).click()
    await expect(page.get_by_text(f'Страница 1 из {max(1,(total+99)//100)}',exact=True)).to_be_visible()
    if total>100:
        await page.get_by_role('button',name='Далее',exact=True).click()
        await expect(page.get_by_text('Страница 2 из 1000',exact=True)).to_be_visible()
    await visibility(page, True)
    count=len(calls); await page.wait_for_timeout(2200)
    assert len(calls)==count and not state['stops'], (calls,state)
    await visibility(page, False)
    await page.wait_for_timeout(200)
    assert len(calls)>count
    if total>100: assert calls[-1]=='1', calls
    # Abort a slow snapshot while hidden, then ignore its late completion.
    mode['hold']=True
    await asyncio.wait_for(entered.wait(),3)
    await visibility(page, True)
    count=len(calls); release.set(); mode['hold']=False
    await page.wait_for_timeout(1200)
    assert len(calls)==count and not state['stops']
    # Repeated notifications cannot create parallel polling loops.
    await visibility(page,False)
    for _ in range(5): await page.evaluate("document.dispatchEvent(new Event('visibilitychange'))")
    count=len(calls); await page.wait_for_timeout(2200)
    assert 1<=len(calls)-count<=3, calls
    mode['error']=503
    await expect(page.get_by_text('fixture failure',exact=False)).to_be_visible(timeout=4000)
    mode['error']=0
    await expect(page.get_by_text('fixture failure',exact=False)).to_have_count(0,timeout=4000)
    await page.get_by_role('tab',name='DNS',exact=True).click()
    count=len(calls); await page.wait_for_timeout(1200); assert len(calls)==count
    await page.get_by_role('tab',name='Torch',exact=True).click()
    await expect(page.get_by_label('IP-адрес или подсеть',exact=True)).to_have_value('192.0.2.0/24')
    assert not state['stops'] and len(state['starts'])==1
    await page.get_by_role('button',name='Остановить',exact=True).click()
    await expect(page.get_by_role('button',name='Запустить',exact=True)).to_be_enabled(timeout=4000)
    assert len(state['stops'])==1 and not base['errors'], base['errors']
    mode['error']=403 if total==1 else 404
    await page.get_by_role('button',name='Запустить',exact=True).click()
    await expect(page.get_by_text('fixture failure',exact=False)).to_be_visible(timeout=4000)
    await expect(page.get_by_role('button',name='Запустить',exact=True)).to_be_enabled()
    await page.wait_for_timeout(200)
    count=len(calls); await page.wait_for_timeout(1200)
    assert len(calls)==count and len(state['stops'])==1
    await page.close()
    print(json.dumps({'flows':total,'hidden_polls':0,'starts_before_terminal_error':1,'terminal_error':mode['error'],'explicit_stops':1,'errors':base['errors']}))

async def main():
    async with async_playwright() as p:
        browser=await p.chromium.launch(channel='chrome',headless=True)
        try:
            for total in [1,100000]: await scenario(browser,total)
        finally: await browser.close()

if __name__=='__main__': asyncio.run(main())
