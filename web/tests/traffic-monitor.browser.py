"""Production-build UI regression for history ranges and optional collection."""
import asyncio,json,mimetypes,os,time
from pathlib import Path
from urllib.parse import urlparse,parse_qs
from playwright.async_api import async_playwright,expect
DIST=Path(__file__).resolve().parents[2]/'backend/internal/api/webdist'
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(headless=True,executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE') or ('C:/Program Files/Google/Chrome/Application/chrome.exe' if os.name=='nt' else None))
  page=await browser.new_page(viewport={'width':1440,'height':1000});errors=[];calls=[];writes=[]
  page.on('pageerror',lambda e:errors.append(str(e)))
  cfg={'system':{'hostname':'router'},'interfaces':[{'id':'wan','name':'eth0','enabled':True}],'wans':[{'id':'wan','interface':'wan','enabled':True}],'networks':[],'channels':[],'vpn_servers':[],'traffic_monitor':{'enabled':True}}
  async def route(r):
   u=urlparse(r.request.url);path=u.path;q=parse_qs(u.query);body={};calls.append((path,q))
   if not path.startswith('/api/'):
    f=DIST/('index.html' if path=='/' else path.lstrip('/'));await r.fulfill(body=f.read_bytes(),content_type=mimetypes.guess_type(str(f))[0] or 'application/octet-stream');return
   now=int(time.time());start=now-int(q.get('minutes',['1440'])[0])*60
   if path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'test'}
   elif path=='/api/config':
    if r.request.method=='PUT':cfg.update(r.request.post_data_json);writes.append(cfg['traffic_monitor']['enabled'])
    body={'config':cfg,'draft_version':1,'dirty':bool(writes),'problems':[]}
   elif path=='/api/status':body={'interfaces':[],'wans':[],'channels':[],'uptime_seconds':100}
   elif path=='/api/statistics':body={'points':[{'at':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime(now-n)),'interfaces':{'eth0':{'rx_bps':10000+n,'tx_bps':1000}}} for n in [60,30,0]]}
   elif path=='/api/statistics/clients/live':body={'enabled':cfg['traffic_monitor']['enabled'],'at':now,'clients':[{'id':'a','name':'Speaker','rx':100,'tx':50}],'points':[{'id':'a','at':now,'rx_bps':(now%60+1)*100000,'tx_bps':10000}]}
   elif path=='/api/statistics/clients':body={'enabled':True,'from':start,'to':now,'clients':[{'id':'a','name':'Speaker','rx':25000,'tx':180000,'queries':3,'connections':5},{'id':'b','name':'Laptop','rx':80000,'tx':1000,'queries':1},{'id':'zero','name':'Never used','rx':0,'tx':0,'queries':0},{'id':'short','name':'Short sessions','rx':0,'tx':0,'queries':0,'connections':4 if q.get('details')==['1'] else 0}],'points':[{'id':id,'at':now-n,'rx_bps':20000,'tx_bps':10000} for id in ['a','b'] for n in [60,30,0]],'domains':[{'client':'a','domain':'example.com','count':3,'first':now-30,'last':now},{'client':'a','domain':'xray.example','source':'xray-domain','count':2,'first':now-30,'last':now},{'client':'a','domain':'inferred.example','source':'xray-dns','count':2,'first':now-30,'last':now},{'client':'a','domain':'192.0.2.5','source':'xray-ip','count':1,'first':now-30,'last':now}] if q.get('details')==['1'] else []}
   await r.fulfill(json=body,content_type='application/json')
  await page.route('**/*',route);await page.goto('http://netos-ui.test/#dashboard')
  await expect(page.get_by_text('Трафик клиентов',exact=True)).to_be_visible()
  await page.get_by_label('Период статистики').select_option('5')
  await expect(page.get_by_role('img',name='График скорости за выбранный период')).to_have_count(2)
  assert any(path=='/api/statistics' and q.get('minutes')==['5'] for path,q in calls)
  await expect(page.locator('.monitor-clients').get_by_text('Never used',exact=True)).to_have_count(0)
  boxes=[await node.bounding_box() for node in await page.locator('.monitor-clients label').all()]
  assert boxes[1]['x']-boxes[0]['x']<=280,boxes
  chart=page.get_by_role('img',name='График скорости за выбранный период').last
  await chart.scroll_into_view_if_needed()
  before=await chart.locator('path').first.get_attribute('d')
  await expect(chart.locator('path').first).not_to_have_attribute('d',before,timeout=10000)
  box=await chart.bounding_box()
  await page.mouse.move(box['x']+box['width']*.9,box['y']+100)
  await expect(page.locator('[role="tooltip"]')).to_be_visible()
  await expect(chart.locator('.monitor-crosshair line')).to_have_count(1)
  assert await chart.locator('.monitor-crosshair circle').count()>0
  await page.mouse.move(box['x']+box['width']*.99,box['y']+100)
  tooltip=await page.locator('[role="tooltip"]').bounding_box()
  assert tooltip['width']>=120 and tooltip['x']>=box['x'] and tooltip['x']+tooltip['width']<=box['x']+box['width'],tooltip
  stroke=await chart.locator('.monitor-crosshair line').evaluate('(e)=>getComputedStyle(e).stroke')
  assert stroke!='none',stroke
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.screenshot(path='output/playwright/traffic-live-hover.png',full_page=True)
  await page.mouse.move(0,0)
  await expect(page.locator('[role="tooltip"]')).to_have_count(0)
  await page.get_by_role('button',name='Подробнее',exact=True).click();await expect(page.get_by_role('cell',name='example.com',exact=True)).to_be_visible()
  for label in ['Xray · домен','Xray · по DNS','Xray · IP']:
   await expect(page.get_by_role('cell',name=label,exact=True)).to_be_visible()
  await expect(page.locator('th').filter(has_text='Соединений Xray')).to_be_visible()
  await expect(page.locator('.monitor-clients label').filter(has_text='Short sessions')).to_be_visible()
  await expect(page.get_by_text('Есть обращения · нет замера трафика',exact=True)).to_be_visible()
  await page.get_by_label('Направление трафика клиентов').select_option('up')
  await page.get_by_role('button',name='Скрыть подробности',exact=True).click();await expect(page.get_by_role('cell',name='example.com',exact=True)).to_have_count(0)
  await page.get_by_text('Собирать историю',exact=True).click();await page.wait_for_timeout(700);assert writes==[False],writes
  await page.get_by_label('Период статистики').select_option('0')
  await page.get_by_label('Начало периода').fill('2020-01-01T00:00');await page.get_by_role('button',name='Показать',exact=True).click();await expect(page.get_by_text('Выберите начало и конец в пределах последних 7 дней',exact=True)).to_be_visible()
  dates=await page.evaluate("()=>[Date.now()-300000,Date.now()].map(t=>{const d=new Date(t);return new Date(t-d.getTimezoneOffset()*60000).toISOString().slice(0,16)})")
  await page.get_by_label('Начало периода').fill(dates[0]);await page.get_by_label('Конец периода').fill(dates[1])
  await page.get_by_role('button',name='Показать',exact=True).click()
  live_calls=sum(path=='/api/statistics/clients/live' for path,q in calls)
  await page.wait_for_timeout(5500)
  assert sum(path=='/api/statistics/clients/live' for path,q in calls)==live_calls
  await page.set_viewport_size({'width':390,'height':844})
  assert await page.evaluate('document.documentElement.scrollWidth<=innerWidth')
  assert not errors,errors
  await browser.close();print('traffic monitor browser PASS')
asyncio.run(main())
