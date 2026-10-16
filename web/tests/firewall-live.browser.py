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
  cfg['interfaces'][2]['label']='WAN'
  cfg['firewall']['nat']=[{'id':'old-nat','name':'Old NAT','system':True,'enabled':False,'direction':'source','interface':'eth0'}]
  live={'captured_at':'2026-10-15T10:00:00Z','sources':{},'comments':{'-A LAN-FWD -s 192.0.2.0/24 -j REJECT':'intersegment default'},'families':[{'family':'IPv4','tables':[{'name':'filter','chains':[{'name':'WAN-IN','policy':'-','counters':'[0:0]','rules':['-A WAN-IN -i eth0 -p udp --dport 51820 -j ACCEPT']},{'name':'LAN-FWD','policy':'-','counters':'[0:0]','rules':['-A LAN-FWD -s 192.0.2.0/24 -j REJECT']},{'name':'FOREIGN','policy':'-','counters':'[0:0]','rules':[]}]}]},{'family':'IPv6','tables':[],'error':'fixture IPv6 unavailable'}]}
  state={"cfg":cfg};errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
  live['comments']['-A WAN-IN -i eth0 -p udp --dport 51820 -j ACCEPT']='VPN-сервер «QA»'
  isolation='-A LAN-FWD -s 192.0.2.0/24 -d 198.51.100.0/24 -j REJECT'
  live['families'][0]['tables'][0]['chains'][1]['rules'].append(isolation)
  live['comments'][isolation]='изоляция «QA»: QA → VPN'
  cfg['firewall']['rules'].append({**cfg['firewall']['rules'][0],'id':'disabled','enabled':False})
  command='-A LAN-FWD -i br-lan -d 192.168.20.0/24 -j ACCEPT'
  live['rule_ids']={command:['rule']}
  live['families'][0]['tables'][0]['chains'][1]['rules'][:0]=['-A LAN-FWD -m comment --comment "Before saved" -j ACCEPT',command]
  for family in live['families']:
   for table in family['tables']:
    for chain in table['chains']:
     chain['rules']=[line.replace(' -j ', ' -m comment --comment "'+live['comments'][line]+'" -j ') if line in live['comments'] else line for line in chain['rules']]
  async def route(r):
   path=urlparse(r.request.url).path
   if not path.startswith('/api/'):
    file=DIST/('index.html' if path=='/' else path.lstrip('/'));await r.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
   body={}
   if path=='/api/config':
    if r.request.method=='PUT':state['cfg']=r.request.post_data_json
    body={'config':state['cfg'],'dirty':False,'draft_version':1,'problems':[]}
   elif path=='/api/firewall/preview':
    if state.get('fail_preview'):await r.fulfill(status=500,json={'error':'preview failed'});return
    body=live
   elif path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'qa'}
   elif path=='/api/status':body={'interfaces':[],'channels':[],'uptime_seconds':1}
   elif path.endswith('/clients'):body=[]
   await r.fulfill(json=body)
  await page.route('**/*',route)
  await page.goto('https://netos-ui.test/#firewall')
  # Same-name disabled row must remain, no name-based matching.
  checkbox=page.get_by_role('checkbox',name='Показать автоматические правила',exact=True)
  saved=page.locator('tr[data-rule-index="0"]')
  await expect(saved).to_be_visible()
  await saved.evaluate('(e)=>e.dataset.preserved="yes"')
  before=await saved.locator('td').evaluate_all('(cells)=>cells.map(e=>e.getBoundingClientRect().width)')
  await checkbox.check()
  await expect(page.get_by_text('WAN-IN',exact=True)).to_be_visible()
  await expect(saved).to_have_attribute('data-preserved','yes')
  await expect(page.get_by_text('Allow s1 to s2',exact=True)).to_have_count(2)
  await expect(page.get_by_role('button',name='Создать правило',exact=True)).to_be_visible()
  await expect(saved.get_by_role('button',name='Изменить',exact=True)).to_be_enabled()
  for grip in await page.locator('.grip').all():await expect(grip).to_be_disabled()
  for toggle in await page.locator('.automatic-rule input').all():
   await expect(toggle).to_be_checked();await expect(toggle).to_be_disabled()
  assert await saved.locator('td').evaluate_all('(cells)=>cells.map(e=>e.getBoundingClientRect().width)')==before
  chain=saved.locator('xpath=ancestor::tbody')
  names=await chain.locator('tr td:nth-child(3)>div:first-child').all_text_contents()
  assert names==['Before saved','Allow s1 to s2','Allow s1 to s2','Запрет между локальными сегментами','изоляция «QA»: QA → VPN'],names
  assert await page.locator('.firewall-live').count()==0
  await expect(page.get_by_text('Зоны и политики',exact=True)).to_be_visible()
  await expect(page.get_by_text('Трансляция адресов',exact=True)).to_be_visible()
  await saved.get_by_role('button',name='Изменить',exact=True).click()
  await expect(page.get_by_role('textbox',name='Название',exact=True)).to_have_value('Allow s1 to s2')
  await page.get_by_role('button',name='Отмена',exact=True).click()
  await checkbox.uncheck()
  await expect(page.locator('.automatic-rule')).to_have_count(0)
  await expect(saved).to_have_attribute('data-preserved','yes')
  await expect(saved.locator('.grip')).to_be_enabled()
  await checkbox.check()
  await expect(page.locator('.automatic-rule')).not_to_have_count(0)
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.evaluate("document.documentElement.dataset.theme='dark'")
  await checkbox.scroll_into_view_if_needed()
  await page.screenshot(path='output/playwright/firewall-inline.png',full_page=True)
  await page.set_viewport_size({'width':390,'height':900})
  await page.screenshot(path='output/playwright/firewall-inline-mobile.png',full_page=True)
  await page.set_viewport_size({'width':1440,'height':1000})
  await checkbox.uncheck()
  state['fail_preview']=True
  await checkbox.check()
  await expect(page.get_by_text('preview failed',exact=True)).to_be_visible()
  await expect(saved).to_be_visible()
  state['fail_preview']=False
  await checkbox.uncheck();await checkbox.check()
  await expect(page.get_by_text('preview failed',exact=True)).to_have_count(0)
  await checkbox.uncheck()
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
