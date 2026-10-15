"""Firewall rule form in production UI, mocked API only."""
import asyncio, copy, mimetypes
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect
DIST=Path(__file__).resolve().parents[2]/"backend/internal/api/webdist"
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch()
  page=await browser.new_page(viewport={"width":1440,"height":1000})
  cfg={"system":{"hostname":"qa"},"interfaces":[{"id":"a","name":"br-lan"},{"id":"b","name":"br1"},{"id":"w","name":"eth0"}],"networks":[{"id":"a","enabled":True,"interface":"a","zone":"lan","router_address":"192.168.10.1/24"},{"id":"b","enabled":True,"interface":"b","zone":"lan","router_address":"192.168.20.1/24"}],"wans":[{"id":"wan","enabled":True,"interface":"w","proto":"static"}],"channels":[],"policies":[],"firewall":{"enabled":True,"zones":[{"name":"lan","title":"LAN","policy":"accept"},{"name":"wan","title":"WAN","policy":"drop"}],"nat":[],"rules":[{"id":"rule","name":"Allow s1 to s2","enabled":True,"zone":"lan","dst_zone":"lan","flow":"forward","action":"accept","interface":"br-lan","dst_ip":"192.168.20.0/24","conn_state":"new,established","log":True,"comment":"keep this","schedule":{"days":["Mon"],"time_start":"10:00","time_stop":"18:00"}}]}}
  cfg['wans'][0]['name']='Uplink'
  cfg['firewall']['nat']=[{'id':'old-nat','name':'Old NAT','system':True,'enabled':False,'direction':'source','interface':'eth0'}]
  live={'captured_at':'2026-10-15T10:00:00Z','sources':{},'comments':{'-A LAN-FWD -s 192.0.2.0/24 -j REJECT':'intersegment default'},'families':[{'family':'IPv4','tables':[{'name':'filter','chains':[{'name':'WAN-IN','policy':'-','counters':'[0:0]','rules':['-A WAN-IN -p udp --dport 51820 -j ACCEPT']},{'name':'LAN-FWD','policy':'-','counters':'[0:0]','rules':['-A LAN-FWD -s 192.0.2.0/24 -j REJECT']},{'name':'FOREIGN','policy':'-','counters':'[0:0]','rules':[]}]}]},{'family':'IPv6','tables':[],'error':'fixture IPv6 unavailable'}]}
  state={"cfg":cfg};errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
  async def route(r):
   path=urlparse(r.request.url).path
   if not path.startswith('/api/'):
    file=DIST/('index.html' if path=='/' else path.lstrip('/'));await r.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
   body={}
   if path=='/api/config':
    if r.request.method=='PUT':state['cfg']=r.request.post_data_json
    body={'config':state['cfg'],'dirty':False,'draft_version':1,'problems':[]}
   elif path=='/api/firewall/live':body=live
   elif path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'qa'}
   elif path=='/api/status':body={'interfaces':[],'channels':[],'uptime_seconds':1}
   elif path.endswith('/clients'):body=[]
   await r.fulfill(json=body)
  await page.route('**/*',route)
  await page.goto('https://netos-ui.test/#firewall')
  await page.get_by_role('checkbox',name='Показать автоматические правила',exact=True).check()
  await expect(page.get_by_text('WAN-IN',exact=True)).to_be_visible()
  await expect(page.get_by_text('FOREIGN',exact=True)).to_be_visible()
  await expect(page.get_by_text('Запрет между локальными сегментами',exact=True)).to_be_visible()
  await expect(page.get_by_text('fixture IPv6 unavailable',exact=True)).to_be_visible()
  await expect(page.locator('[draggable="true"]')).to_have_count(0)
  await expect(page.get_by_role('button',name='Создать правило',exact=True)).to_have_count(0)
  await page.get_by_role('button',name='Обновить правила',exact=True).click()
  await expect(page.get_by_text('WAN-IN',exact=True)).to_be_visible()
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.screenshot(path='output/playwright/firewall-live.png')
  await page.get_by_role('checkbox',name='Показать автоматические правила',exact=True).uncheck()
  await expect(page.get_by_role('button',name='Создать правило',exact=True)).to_be_visible()
  await expect(page.get_by_text('Old NAT',exact=True)).to_have_count(0)
  await page.goto('https://netos-ui.test/#network')
  await page.locator('summary').filter(has_text='Uplink').first.click()
  nat=page.get_by_role('checkbox',name='Подменять адреса клиентов (NAT)',exact=True)
  await expect(nat).not_to_be_checked()
  async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
   await nat.locator('..').click()
  assert state['cfg']['firewall']['nat'][0]['enabled']
  assert len(state['cfg']['firewall']['nat'])==1 and state['cfg']['firewall']['nat'][0]['id']=='old-nat'
  await page.reload();await page.locator('summary').filter(has_text='Uplink').first.click()
  await expect(nat).to_be_checked()
  assert not errors,errors
  await browser.close();print('firewall live and uplink NAT PASS')
asyncio.run(main())
