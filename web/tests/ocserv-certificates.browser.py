"""Certificate UI contracts with a local API fixture; no router mutations."""
import asyncio, copy, mimetypes, os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
DIST = Path(os.environ.get('OC_TEST_DIST', ROOT/'backend/internal/api/webdist'))

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(channel='chrome', headless=True)
        page = await browser.new_page(viewport={'width':1280,'height':900})
        errors, calls, actions = [], [], []
        page.on('pageerror', lambda e: errors.append(str(e)))
        peers = [{'id':f'p{i}','name':f'Phone {i}','enabled':False,'address':f'10.99.0.{i+2}','credentials':{}} for i in range(2)]
        cfg = {'system':{'hostname':'router'},'interfaces':[],'networks':[],'channels':[],
               'vpn_servers':[{'id':'oc','name':'OC','type':'ocserv','enabled':False,'index':1,'port':443,
                               'subnet':'10.99.0.1/24','default_channel':'direct','config':{'auth_mode':'certificate'},'peers':peers}]}
        status = {'serial':'1','expires':'2030-01-01T00:00:00Z','revoked':False,'username':'phone'}
        control = {'hold':False,'fail':False}
        entered, release = asyncio.Event(), asyncio.Event()
        await page.add_init_script("""window.abortedCertificates=0;const f=window.fetch;window.fetch=(url,opts)=>{
          if(String(url).endsWith('/certificates'))opts?.signal?.addEventListener('abort',()=>window.abortedCertificates++);
          return f(url,opts)}""")

        async def route_request(route):
            req,path=route.request,urlparse(route.request.url).path
            if not path.startswith('/api/'):
                file=DIST/('index.html' if path=='/' else path.lstrip('/'))
                await route.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
            body={}
            if path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'test'}
            elif path=='/api/config':
                assert req.method=='GET'
                body={'config':cfg,'dirty':False,'draft_version':1,'problems':[],'pending_confirmation':False}
            elif path.endswith('/clients') or path=='/api/certificates':body=[]
            elif path=='/api/vpn-servers/oc/certificates':
                calls.append(path)
                body={peer['id']:copy.deepcopy(status) for peer in peers}
                if control['hold']:
                    entered.set();await release.wait()
                if control['fail']:
                    await route.fulfill(status=500,json={'error':'fixture unavailable'});return
            elif '/certificate' in path:
                calls.append(path)
                action=path.rsplit('/',1)[-1]
                if action in ['revoke','reissue']:
                    assert req.method=='POST';actions.append(action)
                    status['revoked']=action=='revoke'
                    if action=='reissue':status['serial']=str(int(status['serial'])+1)
                    body=copy.deepcopy(status)
                elif action=='password':body={'password':'fixture-password'}
                elif action=='download':
                    await route.fulfill(body=b'fixture-p12',content_type='application/x-pkcs12');return
                else:body=copy.deepcopy(status)
            else:assert req.method=='GET', (req.method,path)
            try:await route.fulfill(json=body)
            except Exception:
                if not control['hold']:raise

        await page.route('**/*',route_request)
        await page.goto('http://netos.test/#vpn-servers')
        row=page.locator('[data-vpn-client="p0"]')
        await expect(row).to_be_visible()
        if not os.environ.get('OC_VISUAL_ONLY'):assert not calls,calls
        summary=row.locator(':scope > details > summary')
        await summary.click()
        download=row.get_by_role('button',name='Скачать P12',exact=True)
        await expect(download).to_be_enabled()
        await page.mouse.move(0,0)
        await page.locator('h1').click()
        if os.environ.get('OC_SCREENSHOT'):
            await row.screenshot(path=os.environ['OC_SCREENSHOT'])
        if os.environ.get('OC_VISUAL_ONLY'):
            await browser.close();return
        await row.get_by_role('button',name='Показать пароль P12',exact=True).click()
        await expect(row.locator('input[readonly]')).to_have_value('fixture-password')
        async with page.expect_download() as pending:
            await download.click()
        downloaded=await pending.value
        assert Path(await downloaded.path()).read_bytes()==b'fixture-p12'
        # Reopen with a delayed old status; a completed revoke must win.
        await summary.click();control['hold']=True
        await summary.click();await asyncio.wait_for(entered.wait(),5)
        await row.get_by_role('button',name='Отозвать сертификат',exact=True).click()
        await page.get_by_role('dialog').get_by_role('button',name='Отмена',exact=True).click()
        assert not actions
        await row.get_by_role('button',name='Отозвать сертификат',exact=True).click()
        await page.get_by_role('dialog').get_by_role('button',name='Отозвать сертификат',exact=True).click()
        await expect(download).to_be_disabled()
        await expect(row.locator('input[readonly]')).to_have_count(0)
        release.set();await page.wait_for_timeout(200)
        await expect(row.get_by_text('Отозван',exact=False)).to_be_visible()
        await expect(download).to_be_disabled()
        control['hold']=False
        await row.get_by_role('button',name='Перевыпустить профиль',exact=True).click()
        await page.get_by_role('dialog').get_by_role('button',name='Перевыпустить профиль',exact=True).click()
        await expect(download).to_be_enabled();assert actions==['revoke','reissue']
        # Failed refresh is visible; closing/reopening retries immediately.
        await summary.click();control['fail']=True;await summary.click()
        await expect(row.get_by_text('fixture unavailable',exact=True)).to_be_visible()
        await summary.click();control['fail']=False;await summary.click()
        await expect(row.get_by_text('fixture unavailable',exact=True)).to_have_count(0)
        # Last close aborts a request and must not apply its stale response.
        await summary.click();entered.clear();release.clear();control['hold']=True
        await summary.click();await asyncio.wait_for(entered.wait(),5)
        before=await page.evaluate('window.abortedCertificates')
        await summary.click()
        await page.wait_for_timeout(100)
        assert await page.evaluate('window.abortedCertificates')==before+1
        release.set();await page.wait_for_timeout(100)
        assert not errors,errors
        await browser.close()
        print('certificate actions, stale poll, cancellation, failure/retry and closed cards PASS')

asyncio.run(main())
