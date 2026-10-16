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
   elif path=='/api/statistics/clients':body={'enabled':True,'from':start,'to':now,'clients':[{'id':'a','name':'Speaker','rx':25000,'tx':180000,'queries':3},{'id':'b','name':'Laptop','rx':80000,'tx':1000,'queries':1}],'points':[{'id':id,'at':now-n,'rx_bps':20000,'tx_bps':10000} for id in ['a','b'] for n in [60,30,0]],'domains':[{'client':'a','domain':'example.com','count':3,'first':now-30,'last':now}] if q.get('details')==['1'] else []}
   await r.fulfill(json=body,content_type='application/json')
  await page.route('**/*',route);await page.goto('http://netos-ui.test/#dashboard')
  await expect(page.get_by_text('Трафик клиентов',exact=True)).to_be_visible()
  await page.get_by_label('Период статистики').select_option('5')
  await expect(page.get_by_role('img',name='График скорости за выбранный период')).to_have_count(2)
  assert any(path=='/api/statistics' and q.get('minutes')==['5'] for path,q in calls)
  await page.get_by_role('button',name='Подробнее',exact=True).click();await expect(page.get_by_role('cell',name='example.com',exact=True)).to_be_visible()
  await page.get_by_label('Направление трафика клиентов').select_option('up')
  await page.get_by_role('button',name='Скрыть подробности',exact=True).click();await expect(page.get_by_role('cell',name='example.com',exact=True)).to_have_count(0)
  await page.get_by_text('Собирать историю',exact=True).click();await page.wait_for_timeout(700);assert writes==[False],writes
  await page.get_by_label('Период статистики').select_option('0')
  await page.get_by_label('Начало периода').fill('2020-01-01T00:00');await page.get_by_role('button',name='Показать',exact=True).click();await expect(page.get_by_text('Выберите начало и конец в пределах последних 7 дней',exact=True)).to_be_visible()
  assert not errors,errors
  await browser.close();print('traffic monitor browser PASS')
asyncio.run(main())
