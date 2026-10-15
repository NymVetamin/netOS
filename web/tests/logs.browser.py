"""Firewall rule form in production UI, mocked API only."""
import asyncio, copy, mimetypes
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright, expect
DIST=Path(__file__).resolve().parents[2]/"backend/internal/api/webdist"
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch()
  page=await browser.new_page(viewport={"width":1440,"height":1000})
  cfg={"system":{"hostname":"qa"},"interfaces":[{"id":"a","name":"br-lan"},{"id":"b","name":"br1"},{"id":"w","name":"eth0"}],"networks":[{"id":"a","enabled":True,"interface":"a","zone":"lan","router_address":"192.168.10.1/24"},{"id":"b","enabled":True,"interface":"b","zone":"lan","router_address":"192.168.20.1/24"}],"wans":[{"id":"wan","enabled":True,"interface":"w","proto":"static"}],"channels":[],"policies":[],"firewall":{"enabled":True,"zones":[{"name":"lan","title":"LAN","policy":"accept"},{"name":"wan","title":"WAN","policy":"drop"}],"nat":[],"rules":[{"id":"rule","name":"Allow s1 to s2","enabled":True,"zone":"lan","dst_zone":"lan","flow":"forward","action":"accept","interface":"br-lan","dst_ip":"192.168.20.0/24","conn_state":"new,established","log":True,"comment":"keep this","schedule":{"days":["Mon"],"time_start":"10:00","time_stop":"18:00"}}]}}
  state={"cfg":cfg};errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
  state['fail']=False
  async def route(r):
   path=urlparse(r.request.url).path
   if not path.startswith('/api/'):
    file=DIST/('index.html' if path=='/' else path.lstrip('/'));await r.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
   body={}
   if path=='/api/config':
    if r.request.method=='PUT':state['cfg']=r.request.post_data_json
    body={'config':state['cfg'],'dirty':False,'draft_version':1,'problems':[]}
   elif path=='/api/render':body=[]
   elif path=='/api/logs':
    if state['fail']:
     await r.fulfill(status=503,json={'error':'fixture unavailable'});return
    kind=parse_qs(urlparse(r.request.url).query).get('kind',['all'])[0]
    entries=[{'time':'2026-10-15T10:00:00Z','source':v,'unit':v,'message':v+' fixture.example <script>safe</script>'} for v in ['dns','firewall','services'] if kind=='all' or kind==v]
    body={'kind':kind,'entries':entries,'warnings':['fixture partial source warning'],'captured_at':'2026-10-15T10:00:01Z'}
   elif path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'qa'}
   elif path=='/api/status':body={'interfaces':[],'channels':[],'uptime_seconds':1}
   elif path.endswith('/clients'):body=[]
   await r.fulfill(json=body)
  await page.route('**/*',route)
  await page.goto('https://netos-ui.test/#diagnostics?log=dns')
  await expect(page.get_by_role('tab',name='DNS',exact=True)).to_have_attribute('aria-selected','true')
  await expect(page.get_by_text('dns fixture.example <script>safe</script>',exact=True)).to_be_visible()
  await page.get_by_role('tab',name='Общий',exact=True).click()
  await expect(page.get_by_text('services fixture.example <script>safe</script>',exact=True)).to_be_visible()
  await page.get_by_label('Поиск в журнале',exact=True).fill('firewall')
  await expect(page.get_by_text('dns fixture.example <script>safe</script>',exact=True)).to_have_count(0)
  async with page.expect_download() as pending:
   await page.get_by_role('button',name='Скачать журнал',exact=True).click()
  download=await pending.value
  text=Path(await download.path()).read_text(encoding='utf-8')
  assert 'firewall fixture.example' in text and 'dns fixture.example' not in text
  state['fail']=True
  await page.get_by_role('button',name='Обновить журнал',exact=True).click()
  await expect(page.get_by_text('fixture unavailable',exact=True)).to_be_visible()
  await expect(page.get_by_role('button',name='Скачать журнал',exact=True)).to_be_disabled()
  state['fail']=False
  await page.get_by_role('button',name='Обновить журнал',exact=True).click()
  await expect(page.get_by_text('firewall fixture.example <script>safe</script>',exact=True)).to_be_visible()
  await page.get_by_label('Поиск в журнале',exact=True).fill('')
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.screenshot(path='output/playwright/logs.png')
  await page.goto('https://netos-ui.test/#firewall')
  await page.get_by_role('button',name='Изменить',exact=True).click()
  await page.get_by_text('Дополнительно',exact=True).click()
  await page.get_by_role('link',name='Открыть журнал firewall',exact=True).click()
  await expect(page.get_by_role('tab',name='Firewall',exact=True)).to_have_attribute('aria-selected','true')
  assert not errors,errors
  await browser.close();print('logs tabs, deep link, search, export, error/retry PASS')
asyncio.run(main())
