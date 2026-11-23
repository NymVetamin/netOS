"""Clients poll lifecycle against a local production-build API fixture."""
import asyncio, mimetypes, os
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright, expect
DIST=Path(__file__).resolve().parents[2]/'backend/internal/api/webdist'

async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(headless=True,executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE') or ('C:/Program Files/Google/Chrome/Application/chrome.exe' if os.name=='nt' else None))
  page=await browser.new_page(viewport={'width':1280,'height':900})
  errors=[];calls=[];mode='normal';generation=1;pending=asyncio.Event();release=asyncio.Event()
  page.on('pageerror',lambda e:errors.append(str(e)))
  cfg={'system':{'hostname':'router'},'interfaces':[{'id':'lan','name':'br0'}],'networks':[{'id':'lan','name':'LAN','interface':'lan','enabled':True,'router_address':'192.168.20.1/24'}],'channels':[],'clients':[],'vpn_servers':[],'dhcp':{'reservations':[]}}
  async def route(r):
   u=urlparse(r.request.url);path=u.path;body={}
   if not path.startswith('/api/'):
    f=DIST/('index.html' if path=='/' else path.lstrip('/'));await r.fulfill(body=f.read_bytes(),content_type=mimetypes.guess_type(str(f))[0] or 'application/octet-stream');return
   if path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'test'}
   elif path=='/api/config':body={'config':cfg,'draft_version':1,'dirty':False,'problems':[]}
   elif path=='/api/status':body={'interfaces':[],'wans':[],'channels':[]}
   elif path=='/api/leases':calls.append('leases');body={'leases':[]}
   elif path=='/api/clients':
    calls.append(u.query)
    assert parse_qs(u.query).get('leases')==['1'],u.query
    current=generation
    if mode=='slow':pending.set();await release.wait()
    if mode=='error':await r.fulfill(status=503,json={'error':'fixture lease failure'});return
    client={'mac':'02:00:00:00:00:01','ip':'192.168.20.100','hostname':f'Laptop {current}','source':'dhcp','interface':'br0','online':True}
    body={'clients':[client],'leases':[dict(client,expires='2099-01-02T03:04:05Z')]}
   await r.fulfill(json=body)
  await page.route('**/*',route)
  await page.goto('http://netos.test/#clients')
  await expect(page.get_by_text('Laptop 1',exact=True)).to_be_visible()
  await expect(page.get_by_text('br0 · DHCP · до ',exact=False)).to_be_visible()
  assert calls==['leases=1'],calls
  mode='error'
  await expect(page.get_by_text('fixture lease failure',exact=False)).to_be_visible(timeout=12000)
  await expect(page.get_by_text('Laptop 1',exact=True)).to_be_visible()
  mode='normal';generation=2
  await expect(page.get_by_text('Laptop 2',exact=True)).to_be_visible(timeout=12000)
  assert calls==['leases=1']*3,calls
  mode='slow'
  await asyncio.wait_for(pending.wait(),12)
  await page.evaluate("location.hash='network'")
  await expect(page.get_by_text('Laptop 2',exact=True)).to_have_count(0)
  mode='normal';generation=3
  await page.evaluate("location.hash='clients'")
  await expect(page.get_by_text('Laptop 3',exact=True)).to_be_visible()
  release.set();await page.wait_for_timeout(300)
  await expect(page.get_by_text('Laptop 3',exact=True)).to_be_visible()
  await expect(page.get_by_text('Laptop 2',exact=True)).to_have_count(0)
  before=len(calls)
  await page.evaluate("location.hash='network'")
  await page.wait_for_timeout(8500)
  assert len(calls)==before,calls
  assert 'leases' not in calls,calls
  assert not errors,errors
  print('clients single-read poll: data, lease expiry, 503/retry, late response and unmount PASS; requests='+str(len(calls)))
  await browser.close()
asyncio.run(main())
