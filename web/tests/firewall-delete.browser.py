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
  cfg['firewall']['rules']=[{'id':'sys-ssh','system':True,'name':'SSH default','enabled':True,'zone':'global','flow':'in','protocol':'tcp','dst_port':'22','action':'accept'},{'id':'custom','name':'Custom','enabled':True,'zone':'global','flow':'in','action':'drop'}]
  state={"cfg":cfg};errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
  async def route(r):
   path=urlparse(r.request.url).path
   if not path.startswith('/api/'):
    file=DIST/('index.html' if path=='/' else path.lstrip('/'));await r.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
   body={}
   if path=='/api/config':
    if r.request.method=='PUT':state['cfg']=r.request.post_data_json
    body={'config':state['cfg'],'dirty':False,'draft_version':1,'problems':[]}
   elif path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'qa'}
   elif path=='/api/status':body={'interfaces':[],'channels':[],'uptime_seconds':1}
   elif path.endswith('/clients'):body=[]
   await r.fulfill(json=body)
  await page.route('**/*',route)
  await page.goto('https://netos-ui.test/#firewall')
  row=page.locator('tr').filter(has_text='SSH default')
  await expect(row.locator('button[title="удалить"]')).to_be_visible()
  async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
   await row.locator('button[title="удалить"]').click()
  assert 'removed_defaults' not in state['cfg']['firewall']
  assert [r['id'] for r in state['cfg']['firewall']['rules']]==['custom']
  await page.reload()
  await expect(page.get_by_text('SSH default',exact=True)).to_have_count(0)
  row=page.locator('tr').filter(has_text='Custom')
  async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
   await row.locator('button[title="удалить"]').click()
  assert 'removed_defaults' not in state['cfg']['firewall']
  assert not errors,errors
  await browser.close();print('delete default and manual firewall rules PASS')
asyncio.run(main())
