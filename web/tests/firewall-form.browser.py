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
  await page.get_by_role('button',name='Изменить',exact=True).click()
  form=page.locator('.rule-form')
  await expect(form.get_by_label('Направление',exact=True)).to_have_value('forward')
  await expect(form.get_by_label('Входящий интерфейс',exact=True)).to_have_value('br-lan')
  outgoing=form.get_by_label('Исходящий интерфейс',exact=True)
  assert await outgoing.locator('option').evaluate_all('(els)=>els.map(e=>e.value)')==['','br-lan','br1']
  await outgoing.select_option('br1')
  await form.get_by_text('Дополнительно',exact=True).click()
  await expect(form.get_by_role('checkbox',name='NEW',exact=True)).to_be_checked()
  await expect(form.get_by_role('checkbox',name='ESTABLISHED',exact=True)).to_be_checked()
  await form.get_by_role('checkbox',name='RELATED',exact=True).check()
  await expect(form.get_by_label('Описание правила')).to_contain_text('br1')
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.screenshot(path='output/playwright/firewall-form.png',full_page=True)
  async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
   await form.get_by_role('button',name='Сохранить',exact=True).click()
  saved=state['cfg']['firewall']['rules'][0]
  assert saved['interface']=='br-lan' and saved['out_interface']=='br1' and saved['dst_ip']=='192.168.20.0/24'
  assert set(saved['conn_state'].split(','))=={'new','established','related'}
  assert saved['log'] and saved['comment']=='keep this' and saved['schedule']['days']==['Mon']
  await page.reload();await page.get_by_role('button',name='Изменить',exact=True).click()
  await expect(form.get_by_label('Исходящий интерфейс',exact=True)).to_have_value('br1')
  await form.get_by_label('В какую зону',exact=True).select_option('wan')
  await expect(form.get_by_role('button',name='Сохранить',exact=True)).to_be_disabled()
  await expect(form.get_by_text('Выберите интерфейс заново',exact=True)).to_be_visible()
  await form.get_by_label('Исходящий интерфейс',exact=True).select_option('eth0')
  await expect(form.get_by_role('button',name='Сохранить',exact=True)).to_be_enabled()
  await form.get_by_label('Направление',exact=True).select_option('out')
  await expect(form.get_by_label('Входящий интерфейс',exact=True)).to_have_count(0)
  await expect(form.get_by_label('Исходящий интерфейс',exact=True)).to_have_value('eth0')
  async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
   await form.get_by_role('button',name='Сохранить',exact=True).click()
  saved=state['cfg']['firewall']['rules'][0];assert saved['flow']=='out' and saved['interface']=='eth0' and not saved['out_interface'] and not saved['dst_zone']
  await page.get_by_role('button',name='Изменить',exact=True).click()
  await form.get_by_label('Направление',exact=True).select_option('in')
  await expect(form.get_by_label('Исходящий интерфейс',exact=True)).to_have_count(0)
  await expect(form.get_by_label('Входящий интерфейс',exact=True)).to_have_value('')
  await page.set_viewport_size({'width':390,'height':844})
  await page.screenshot(path='output/playwright/firewall-form-mobile.png',full_page=True)
  assert await form.evaluate('e=>e.scrollWidth<=e.clientWidth+1'), 'form overflows mobile width'
  assert not errors,errors
  await browser.close();print('firewall form PASS')
asyncio.run(main())
