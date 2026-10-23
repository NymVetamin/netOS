"""Reservation UI against a local API fixture; never touches a router."""
import asyncio, mimetypes, os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / 'backend/internal/api/webdist'

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True, executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE') or (str(Path(os.environ['ProgramFiles'])/'Google/Chrome/Application/chrome.exe') if os.name=='nt' else None))
        page = await browser.new_page(viewport={'width':1280,'height':900})
        errors, writes = [], []
        page.on('pageerror', lambda e: errors.append(str(e)))
        mac='02:00:00:00:00:01'
        client={'mac':mac,'ip':'192.168.20.100','hostname':'Test laptop','source':'dhcp','online':False}
        cfg={'system':{'hostname':'router'},'interfaces':[{'id':'a','name':'br0'},{'id':'b','name':'br1'}],
             'networks':[{'id':'first','name':'First','interface':'a','router_address':'192.168.10.1/24','enabled':True},
                         {'id':'second','name':'Second','interface':'b','router_address':'192.168.20.1/24','enabled':True}],
             'vpn_servers':[],'channels':[],'clients':[],'dhcp':{'reservations':[]}}
        async def route_request(route):
            req,path=route.request,urlparse(route.request.url).path
            if not path.startswith('/api/'):
                file=DIST/('index.html' if path=='/' else path.lstrip('/'))
                await route.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
            body={}
            if path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'test'}
            elif path=='/api/config':
                if req.method=='PUT':
                    updated=req.post_data_json;cfg.clear();cfg.update(updated);writes.append(updated)
                body={'config':cfg,'dirty':bool(writes),'draft_version':len(writes)+1,'problems':[],'pending_confirmation':False}
            elif path=='/api/clients':body={'clients':[client]}
            elif path=='/api/dhcp/leases':body={'leases':[client]}
            await route.fulfill(json=body)
        await page.route('**/*',route_request)
        await page.goto('http://netos.test/#clients')
        await expect(page.get_by_text('Test laptop',exact=True)).to_be_visible()
        await expect(page.get_by_label('Адрес закреплён',exact=True)).to_have_count(0)
        await page.get_by_text('Test laptop',exact=True).click()
        await expect(page.get_by_text('Second (192.168.20.1/24)',exact=True)).to_be_visible()
        await expect(page.get_by_role('combobox',name='Сегмент DHCP')).to_have_count(0)
        ip=page.get_by_label('Закреплённый IPv4-адрес',exact=True)
        save=page.get_by_role('button',name='Закрепить адрес',exact=True)
        for value in ['bad','192.168.10.20','192.168.20.1','192.168.20.255']:
            await ip.fill(value);await expect(save).to_be_disabled()
        assert not writes
        async with page.expect_response(lambda r:r.request.method=='PUT'):
            await page.get_by_label('Лимит загрузки',exact=True).fill('12.345')
        assert cfg['clients'][0]['down_kbit']==12345
        assert cfg['clients'][0]['network']=='second'
        async with page.expect_response(lambda r:r.request.method=='PUT'):
            await page.get_by_label('Лимит отдачи',exact=True).fill('0.5')
        assert cfg['clients'][0]['up_kbit']==500
        await ip.fill('192.168.20.110')
        async with page.expect_response(lambda r:r.request.method=='PUT'):
            await save.click()
        assert cfg['dhcp']['reservations'][0]['network']=='second'
        assert cfg['dhcp']['reservations'][0]['ip']=='192.168.20.110'
        await expect(page.get_by_label('Адрес закреплён',exact=True)).to_be_visible()
        await page.reload();await page.get_by_text('Test laptop',exact=True).click()
        await expect(page.get_by_label('Лимит загрузки',exact=True)).to_have_value('12.345')
        await expect(page.get_by_label('Лимит отдачи',exact=True)).to_have_value('0.5')
        await expect(ip).to_have_value('192.168.20.110')
        await ip.fill('192.168.20.120')
        async with page.expect_response(lambda r:r.request.method=='PUT'):
            await page.get_by_role('button',name='Изменить закрепление',exact=True).click()
        assert len(cfg['dhcp']['reservations'])==1 and cfg['dhcp']['reservations'][0]['ip']=='192.168.20.120'
        async with page.expect_response(lambda r:r.request.method=='PUT'):
            await page.get_by_role('button',name='Снять закрепление',exact=True).click()
        assert cfg['dhcp']['reservations']==[]
        await expect(page.get_by_label('Адрес закреплён',exact=True)).to_have_count(0)
        async with page.expect_response(lambda r:r.request.method=='PUT'):
            await save.click()
        assert cfg['dhcp']['reservations'][0]['network']=='second'
        for width in [1280,768,390]:
            await page.set_viewport_size({'width':width,'height':900})
            await expect(ip).to_be_visible()
            assert await ip.evaluate('(el)=>el.getBoundingClientRect().right<=window.innerWidth'), width
        if os.environ.get('NETOS_RESERVATION_SCREENSHOT'):
            await page.set_viewport_size({'width':1280,'height':900})
            await page.screenshot(path=os.environ['NETOS_RESERVATION_SCREENSHOT'], full_page=True)
        assert not errors,errors
        await browser.close()
        print('reservation create/edit/reload/remove/repeat/validation/responsive PASS')

asyncio.run(main())
