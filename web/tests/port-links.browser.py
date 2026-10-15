"""Production UI with mocked API: labels, live speed, supported mode selection."""
import asyncio,mimetypes
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright,expect
DIST=Path(__file__).resolve().parents[2]/"backend/internal/api/webdist"
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch()
  page=await browser.new_page(viewport={"width":1440,"height":1000})
  cfg={"system":{"hostname":"qa"},"interfaces":[{"id":"port1","name":"eth0","type":"physical","enabled":True},{"id":"bridge1","name":"br-lan","type":"bridge","enabled":True,"members":[]}],"networks":[],"wans":[],"channels":[],"policies":[],"firewall":{"zones":[],"rules":[],"nat":[]}}
  state={"cfg":cfg,"saves":0};errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
  interfaces=[{"name":"eth0","physical":True,"up":True,"admin_up":True,"speed_mbps":1000,"duplex":"full","addresses":[],"rx_bytes":0,"tx_bytes":0}]
  async def route(r):
   path=urlparse(r.request.url).path
   if not path.startswith('/api/'):
    file=DIST/('index.html' if path=='/' else path.lstrip('/'));await r.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
   body={}
   if path=='/api/config':
    if r.request.method=='PUT':state['cfg']=r.request.post_data_json;state['saves']+=1
    body={'config':state['cfg'],'dirty':False,'draft_version':1,'problems':[]}
   elif path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'qa'}
   elif path=='/api/interfaces':body={'interfaces':interfaces}
   elif path=='/api/interfaces/eth0/modes':body={'supported':['100baseT/Full','1000baseT/Full'],'advertised':['100baseT/Full','1000baseT/Full'],'can_autoneg':True,'autoneg':True}
   elif path=='/api/status':body={'interfaces':interfaces,'channels':[],'uptime_seconds':1}
   elif path.endswith('/clients') or path=='/api/render':body=[]
   await r.fulfill(json=body)
  await page.route('**/*',route)
  await page.goto('https://netos-ui.test/#network')
  await expect(page.get_by_text('1 Гбит/с',exact=True)).to_be_visible()
  await page.locator('summary.xsum').filter(has_text='eth0').click()
  await page.get_by_label('Имя порта eth0',exact=True).fill('Кабинет')
  await page.get_by_role('button',name='Проверить режимы порта',exact=True).click()
  mode=page.get_by_label('Режим порта eth0',exact=True)
  await expect(mode).to_be_enabled()
  await mode.select_option('100baseT/Full')
  await expect(mode).to_have_value('100baseT/Full')
  for _ in range(50):
   if state['cfg']['interfaces'][0].get('link_mode')=='100baseT/Full':break
   await asyncio.sleep(.1)
  assert state['cfg']['interfaces'][0]['label']=='Кабинет'
  assert state['cfg']['interfaces'][0]['link_mode']=='100baseT/Full'
  assert state['cfg']['interfaces'][0]['name']=='eth0' and state['cfg']['interfaces'][0]['id']=='port1'
  await page.locator('summary.xsum').filter(has_text='br-lan').click()
  await page.get_by_label('Имя порта br-lan',exact=True).fill('Офис')
  await expect(page.get_by_label('Режим порта br-lan',exact=True)).to_have_count(0)
  await asyncio.sleep(.6)
  await page.reload()
  await expect(page.locator('summary.xsum').filter(has_text='Кабинет')).to_be_visible()
  await expect(page.locator('summary.xsum').filter(has_text='Офис')).to_be_visible()
  await page.locator('summary.xsum').filter(has_text='Кабинет').click()
  await expect(page.get_by_label('Режим порта eth0',exact=True)).to_have_value('100baseT/Full')
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.screenshot(path='output/playwright/port-links-network.png',full_page=True)
  await page.goto('https://netos-ui.test/#dashboard')
  await expect(page.get_by_text('Кабинет',exact=True)).to_be_visible()
  await expect(page.get_by_text('1 Гбит/с · полный дуплекс',exact=True)).to_be_visible()
  await page.screenshot(path='output/playwright/port-links-dashboard.png',full_page=True)
  assert not errors,errors
  await browser.close();print('port labels, identity preserved, mode draft/reload, live speed Network/Dashboard PASS')
asyncio.run(main())
