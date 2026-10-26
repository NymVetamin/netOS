"""Production-build UI regression for history ranges and optional collection."""
import asyncio,json,mimetypes,os,time
from pathlib import Path
from urllib.parse import urlparse,parse_qs
from playwright.async_api import async_playwright,expect
DIST=Path(__file__).resolve().parents[2]/'backend/internal/api/webdist'
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(headless=True,executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE') or ('C:/Program Files/Google/Chrome/Application/chrome.exe' if os.name=='nt' else None))
  page=await browser.new_page(viewport={'width':1440,'height':1000});errors=[];calls=[];writes=[];aborted=[]
  page.on('pageerror',lambda e:errors.append(str(e)))
  page.on('requestfailed',lambda r:aborted.append(r.url))
  cfg={'system':{'hostname':'router'},'interfaces':[{'id':'wan','name':'eth0','enabled':True}],'wans':[{'id':'wan','interface':'wan','enabled':True}],'networks':[],'channels':[],'vpn_servers':[],'traffic_monitor':{'enabled':True}}
  extra_domains=[]
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
   elif path in ['/api/statistics/realtime','/api/statistics/realtime/history']:
    def frame(at):
     return {'at':at,'sequence':at,'problems':[],'values':[{'id':id,'name':name,'at':at,'rx_bps':(at%60+1)*10000,'tx_bps':1000} for id,name in [('if:eth0','eth0'),('a','Speaker'),('b','Laptop')]]}
    if path.endswith('/history'):
     finish=int(float(q.get('to',[now])[0]));begin=int(float(q.get('from',[start])[0]))
     step=max(1,(finish-begin)//1200)
     body={'points':[frame(at) for at in range(begin,finish+1,step)],'interval_seconds':step}
    else:
     await asyncio.sleep(1);body=frame(int(time.time()))
   elif path=='/api/statistics/clients/live':body={'enabled':cfg['traffic_monitor']['enabled'],'at':now,'clients':[{'id':'a','name':'Speaker','rx':100,'tx':50}],'points':[{'id':'a','at':now,'rx_bps':(now%60+1)*100000,'tx_bps':10000}]}
   elif path=='/api/statistics/clients':body={'enabled':True,'from':start,'to':now,'clients':[{'id':'a','name':'Speaker','rx':25000,'tx':180000,'queries':3,'connections':5},{'id':'b','name':'Laptop','rx':80000,'tx':1000,'queries':1},{'id':'zero','name':'Never used','rx':0,'tx':0,'queries':0},{'id':'short','name':'Short sessions','rx':0,'tx':0,'queries':0,'connections':4 if q.get('details')==['1'] else 0}],'points':[{'id':id,'at':now-n,'rx_bps':20000,'tx_bps':10000} for id in ['a','b'] for n in [60,30,0]],'domains':[{'client':'a','domain':'example.com','count':3,'first':now-30,'last':now},{'client':'a','domain':'deep.www.example.com','source':'xray-domain','count':2,'first':now-30,'last':now},{'client':'a','domain':'api.news.bbc.co.uk','source':'xray-dns','count':2,'first':now-30,'last':now},{'client':'a','domain':'192.0.2.5','source':'xray-ip','count':1,'first':now-30,'last':now}] if q.get('details')==['1'] else []}
   if path=='/api/statistics/clients' and q.get('details')==['1']:body['domains']+=extra_domains
   if path in ['/api/statistics/realtime/history','/api/statistics/clients'] and q.get('minutes')==['120']:
    await asyncio.sleep(1)
   await r.fulfill(json=body,content_type='application/json')
  await page.route('**/*',route);await page.goto('http://netos-ui.test/#dashboard')
  await expect(page.get_by_text('Трафик клиентов',exact=True)).to_be_visible()
  await page.get_by_label('Период статистики').select_option('5')
  await expect(page.get_by_role('img',name='График скорости в реальном времени')).to_have_count(2)
  assert any(path=='/api/statistics/realtime/history' and q.get('minutes')==['5'] for path,q in calls)
  await expect(page.locator('.monitor-clients').get_by_text('Never used',exact=True)).to_have_count(0)
  # Hold freezes the curves, stops unused live/history requests, but keeps
  # domain detail/selection requests. Resume reloads the seconds missed on hold.
  await page.get_by_role('button',name='Пауза',exact=True).click()
  await page.wait_for_timeout(200)
  held_paths=await page.locator('.rt-moving path').evaluate_all('(els)=>els.map(e=>e.getAttribute("d"))')
  hold_start=len(calls)
  await page.wait_for_timeout(31000)
  assert not any(path in ['/api/statistics/realtime','/api/statistics/realtime/history'] for path,q in calls[hold_start:]),calls[hold_start:]
  assert any(path=='/api/statistics/clients' for path,q in calls[hold_start:])
  assert held_paths==await page.locator('.rt-moving path').evaluate_all('(els)=>els.map(e=>e.getAttribute("d"))')
  await page.get_by_role('button',name='Подробнее',exact=True).click()
  await expect(page.locator('.domain-legend li').filter(has_text='example.com')).to_have_text('example.com571.4%')
  await page.get_by_label('Направление трафика клиентов').select_option('up')
  laptop=page.locator('.monitor-clients label').filter(has_text='Laptop').get_by_role('checkbox')
  await laptop.uncheck();await expect(laptop).not_to_be_checked()
  await laptop.check();await expect(laptop).to_be_checked()
  await page.get_by_label('Направление трафика клиентов').select_option('sum')
  assert not any(path in ['/api/statistics/realtime','/api/statistics/realtime/history'] for path,q in calls[hold_start:])
  await page.get_by_role('button',name='Скрыть подробности',exact=True).click()
  resume_start=len(calls)
  await page.get_by_role('button',name='Продолжить',exact=True).click()
  await page.wait_for_timeout(2000)
  assert any(path=='/api/statistics/realtime/history' and q.get('minutes')==['5'] for path,q in calls[resume_start:])
  assert any(path=='/api/statistics/realtime' for path,q in calls[resume_start:])
  # Both WAN lines contain all 300 one-second samples after catch-up.
  for path in await page.locator('.rt-moving').first.locator('path').all():
   d=await path.get_attribute('d');assert d.count('L')>=295,d[:120]
  await page.get_by_role('button',name='Пауза',exact=True).click()
  await page.get_by_label('Период статистики').select_option('10')
  await expect(page.get_by_role('button',name='Пауза',exact=True)).to_be_visible()
  await page.get_by_label('Период статистики').select_option('5')
  boxes=[await node.bounding_box() for node in await page.locator('.monitor-clients label').all()]
  assert boxes[1]['x']-boxes[0]['x']<=280,boxes
  chart=page.get_by_role('img',name='График скорости в реальном времени').last
  await chart.scroll_into_view_if_needed()
  before=await chart.locator('path').first.get_attribute('d')
  await expect(chart.locator('path').first).not_to_have_attribute('d',before,timeout=10000)
  box=await chart.bounding_box()
  await page.mouse.move(box['x']+box['width']*.9,box['y']+100)
  await expect(page.locator('[role="tooltip"]')).to_be_visible()
  await expect(chart.locator('.rt-cursor')).to_have_count(1)
  assert await chart.locator('..').locator('.monitor-point').count()>0
  await page.mouse.move(box['x']+box['width']*.99,box['y']+100)
  tooltip=await page.locator('[role="tooltip"]').bounding_box()
  assert tooltip['width']>=120 and tooltip['x']>=box['x'] and tooltip['x']+tooltip['width']<=box['x']+box['width'],tooltip
  await expect(chart.locator('.rt-cursor')).to_be_visible()
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.screenshot(path='output/playwright/traffic-live-hover.png',full_page=True)
  await page.mouse.move(0,0)
  await expect(page.locator('[role="tooltip"]')).to_have_count(0)
  # The marker must stay round in screen pixels, even when the SVG is stretched.
  for width in [390,1440,1920]:
   await page.set_viewport_size({'width':width,'height':1000})
   for graph in await page.get_by_role('img',name='График скорости в реальном времени').all():
    await graph.scroll_into_view_if_needed()
    bounds=await graph.bounding_box()
    await page.mouse.move(bounds['x']+bounds['width']*.988,bounds['y']+100)
    markers=graph.locator('..').locator('.monitor-point')
    await expect(markers.first).to_be_visible()
    cursor=await graph.locator('.rt-cursor').bounding_box()
    for marker in await markers.all():
     point=await marker.bounding_box()
     # The panel's global 1.05 zoom applies equally to both axes.
     assert abs(point['width']-point['height'])<.1 and 8<=point['width']<=11,point
     assert abs(point['x']+point['width']/2-cursor['x'])<2,(point,cursor)
    if width==390:
     await graph.locator('..').screenshot(path='output/playwright/traffic-round-marker-mobile.png')
    await page.mouse.move(0,0)
    await expect(markers).to_have_count(0)
  await page.set_viewport_size({'width':1440,'height':1000})
  await page.get_by_role('button',name='Подробнее',exact=True).click()
  await expect(page.locator('.domain-legend li').filter(has_text='example.com')).to_have_text('example.com571.4%')
  await expect(page.locator('.domain-legend li').filter(has_text='bbc.co.uk')).to_have_text('bbc.co.uk228.6%')
  await expect(page.get_by_text('192.0.2.5',exact=True)).to_have_count(0)
  await expect(page.get_by_text('deep.www.example.com',exact=True)).to_have_count(0)
  await expect(page.locator('.monitor-details table')).to_have_count(1)
  await expect(page.get_by_role('img',name='Обращения к доменам: 7')).to_be_visible()
  await page.locator('.domain-chart').screenshot(path='output/playwright/domain-chart.png')
  domain_button=page.locator('.domain-legend').get_by_role('button',name='example.com',exact=True)
  await domain_button.focus();await page.keyboard.press('Enter')
  dialog=page.get_by_role('dialog',name='example.com',exact=True)
  await expect(dialog.get_by_role('cell',name='deep.www.example.com',exact=True)).to_be_visible()
  await expect(dialog.locator('tbody tr')).to_have_count(2)
  await page.keyboard.press('Escape');await expect(dialog).to_have_count(0);await expect(domain_button).to_be_focused()
  extra_domains.extend({'client':'a','domain':f'api.domain{i:02d}.com','count':1,'source':'dns'} for i in range(12))
  await page.get_by_label('Период статистики').select_option('10')
  others=page.locator('.domain-legend').get_by_role('button',name='Остальные',exact=True)
  await others.click()
  dialog=page.get_by_role('dialog',name='Остальные домены',exact=True)
  await expect(dialog.locator('tbody tr')).to_have_count(4)
  await expect(dialog.get_by_role('button',name='domain07.com',exact=True)).to_have_count(0)
  await dialog.get_by_role('button',name='domain11.com',exact=True).click()
  dialog=page.get_by_role('dialog',name='domain11.com',exact=True)
  await expect(dialog.get_by_role('cell',name='api.domain11.com',exact=True)).to_be_visible()
  await page.set_viewport_size({'width':390,'height':844})
  bounds=await dialog.bounding_box();assert bounds['x']>=0 and bounds['x']+bounds['width']<=390,bounds
  assert await dialog.evaluate('(e)=>e.scrollWidth<=e.clientWidth')
  await dialog.screenshot(path='output/playwright/domain-details-mobile.png')
  await page.set_viewport_size({'width':1440,'height':1000})
  await page.emulate_media(color_scheme='dark')
  await dialog.screenshot(path='output/playwright/domain-details-dark.png')
  await page.emulate_media(color_scheme='light')
  await dialog.get_by_role('button',name='← Остальные домены',exact=True).click()
  await expect(page.get_by_role('dialog').locator('tbody tr')).to_have_count(4)
  await page.get_by_role('dialog').get_by_role('button',name='Закрыть',exact=True).click()
  await expect(others).to_be_focused()
  extra_domains.clear()
  await page.get_by_label('Период статистики').select_option('5')
  await expect(page.get_by_role('img',name='Обращения к доменам: 7')).to_be_visible()

  await page.set_viewport_size({'width':390,'height':844})
  await page.locator('.domain-chart').screenshot(path='output/playwright/domain-chart-mobile.png')
  assert await page.evaluate('document.documentElement.scrollWidth<=innerWidth')
  await page.set_viewport_size({'width':1440,'height':1000})
  await expect(page.locator('th').filter(has_text='Соединений Xray')).to_be_visible()
  await expect(page.locator('.monitor-clients label').filter(has_text='Short sessions')).to_be_visible()
  await expect(page.get_by_text('Есть обращения · нет замера трафика',exact=True)).to_be_visible()
  await page.get_by_label('Направление трафика клиентов').select_option('up')
  await page.get_by_role('button',name='Скрыть подробности',exact=True).click();await expect(page.get_by_role('cell',name='example.com',exact=True)).to_have_count(0)
  # Changing the range must cancel both obsolete requests, not just ignore
  # their eventual result while the router continues aggregating history.
  async with page.expect_request('**/api/statistics/clients?minutes=120&*'):
   await page.get_by_label('Период статистики').select_option('120')
  await page.get_by_label('Период статистики').select_option('360')
  await page.wait_for_timeout(1300)
  cancelled={urlparse(u).path for u in aborted if parse_qs(urlparse(u).query).get('minutes')==['120']}
  assert cancelled=={'/api/statistics/realtime/history','/api/statistics/clients'},cancelled
  await expect(page.get_by_label('Период статистики')).to_have_value('360')
  await expect(page.get_by_role('img',name='График скорости за выбранный период')).to_have_count(2)
  await expect(page.get_by_text('Не удалось обновить историю клиентов',exact=True)).to_have_count(0)
  await page.get_by_text('Собирать историю',exact=True).click();await page.wait_for_timeout(700);assert writes==[False],writes
  await page.get_by_label('Период статистики').select_option('0')
  await page.get_by_label('Начало периода').fill('2020-01-01T00:00');await page.get_by_role('button',name='Показать',exact=True).click();await expect(page.get_by_text('Выберите начало и конец в пределах последних 7 дней',exact=True)).to_be_visible()
  dates=await page.evaluate("()=>[Date.now()-300000,Date.now()].map(t=>{const d=new Date(t);return new Date(t-d.getTimezoneOffset()*60000).toISOString().slice(0,16)})")
  await page.get_by_label('Начало периода').fill(dates[0]);await page.get_by_label('Конец периода').fill(dates[1])
  await page.get_by_role('button',name='Показать',exact=True).click()
  live_calls=sum(path=='/api/statistics/realtime' for path,q in calls)
  await page.wait_for_timeout(5500)
  assert sum(path=='/api/statistics/realtime' for path,q in calls)==live_calls
  await page.set_viewport_size({'width':390,'height':844})
  assert await page.evaluate('document.documentElement.scrollWidth<=innerWidth')
  assert not errors,errors
  await browser.close();print('traffic monitor browser PASS')
asyncio.run(main())
