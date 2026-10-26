"""Slow SOCKS polling, cancellation and retry with a local production UI."""
import asyncio, mimetypes, os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST=Path(os.environ.get('SOCKS_TEST_DIST',Path(__file__).resolve().parents[2]/'backend/internal/api/webdist'))

async def main():
    async with async_playwright() as p:
        browser=await p.chromium.launch(channel='chrome',headless=True)
        page=await browser.new_page()
        errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        cfg={'system':{'hostname':'test'},'networks':[],'interfaces':[],'channels':[],
             'components':[{'id':'xray','installed':True}],'socks':{'enabled':False}}
        async def route(r):
            path=urlparse(r.request.url).path
            if not path.startswith('/api/'):
                file=DIST/('index.html' if path=='/' else path.lstrip('/'))
                await r.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
            assert r.request.method=='GET'
            body={}
            if path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'test'}
            elif path=='/api/config':body={'config':cfg,'dirty':False,'draft_version':1,'problems':[]}
            await r.fulfill(json=body)
        await page.route('**/*',route)
        await page.add_init_script("""window.polls=[];window.pollMode='hold';const original=window.fetch;
          window.fetch=(url,options)=>{
            const u=String(url);if(!u.endsWith('/api/socks/status')&&!u.endsWith('/api/catalog?installed=xray'))return original(url,options);
            const entry={url:u,aborted:false,done:false,signal:!!options?.signal};window.polls.push(entry);
            return new Promise((resolve,reject)=>{
              const done=()=>{entry.done=true;resolve(new Response(JSON.stringify(window.pollMode==='fail'?{error:'fixture unavailable'}:u.includes('/catalog')?{installed:{xray:true}}:{enabled:false,running:false}),{status:window.pollMode==='fail'?503:200,headers:{'Content-Type':'application/json'}}))};
              entry.release=done;
              options?.signal?.addEventListener('abort',()=>{entry.aborted=true;entry.done=true;reject(new DOMException('aborted','AbortError'))});
              if(window.pollMode!=='hold')done();
            });
          };""")
        await page.goto('http://netos.test/#services')
        await page.wait_for_timeout(11200)
        assert await page.evaluate('polls.length')==2, await page.evaluate('polls.length')
        assert await page.evaluate('polls.every(p=>p.signal&&!p.done)')
        await page.get_by_role('button',name='Сеть',exact=True).click()
        await page.wait_for_timeout(100)
        assert await page.evaluate('polls.every(p=>p.aborted)')
        await page.evaluate("window.pollMode='fail'")
        await page.get_by_role('button',name='Сетевые службы',exact=True).click()
        await expect(page.get_by_text('Не удалось проверить компонент Xray',exact=True)).to_be_visible()
        assert await page.evaluate('polls.length')==4
        await page.evaluate("window.pollMode='ok'")
        await expect(page.get_by_text('Не удалось проверить компонент Xray',exact=True)).to_have_count(0,timeout=7000)
        assert await page.evaluate('polls.length')==6
        assert not errors,errors
        await browser.close()
        print('SOCKS slow polls: one pair, both aborted; reopen, failure and 5s retry PASS')

asyncio.run(main())
