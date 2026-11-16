"""Live logs page in production UI, mocked API only: python web/tests/logs.browser.py"""
import asyncio, mimetypes
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from playwright.async_api import async_playwright, expect
DIST=Path(__file__).resolve().parents[2]/"backend/internal/api/webdist"
XSS=' <script>safe</script>'
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch()
  page=await browser.new_page(viewport={"width":1440,"height":1000})
  cfg={"system":{"hostname":"qa"},"interfaces":[],"networks":[],"wans":[],"channels":[],"policies":[],"firewall":{"enabled":True,"zones":[],"nat":[],"rules":[]},"dns":{"query_log":True}}
  state={'events':[],'epoch':'e1','fail':False,'topics':[]}
  def add(topic,level,source,message):
   seq=len(state['events'])+1
   state['events'].append({'seq':seq,'time':1794816000000+seq*1000,'topic':topic,'level':level,'source':source,'message':message})
  add('services','info','netos-dnsmasq','запущена'+XSS)
  add('access','warning','SSH','неудачный вход root с 198.51.100.9')
  add('firewall','info','drop-ssh','TCP 203.0.113.5:1 → 192.0.2.1:22, вход eth0')
  errors=[];page.on("pageerror",lambda e:errors.append(str(e)))
  async def route(r):
   url=urlparse(r.request.url);path=url.path
   if not path.startswith('/api/'):
    file=DIST/('index.html' if path=='/' else path.lstrip('/'));await r.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
   body={}
   if path=='/api/config':body={'config':cfg,'dirty':False,'draft_version':1,'problems':[]}
   elif path=='/api/logs':
    if state['fail']:
     await r.fulfill(status=503,json={'error':'fixture unavailable'});return
    q=parse_qs(url.query);topic=q.get('topic',['all'])[0];after=int(q.get('after',['0'])[0]);epoch=q.get('epoch',[''])[0]
    state['topics'].append(topic)
    def snapshot():  # one consistent view, as eventlog.Since under its lock
     a=after if epoch==state['epoch'] else 0
     ev=[e for e in reversed(state['events']) if e['seq']>a and (topic=='all' or e['topic']==topic)]
     return {'epoch':state['epoch'],'latest':len(state['events']),'reset':a==0,'events':ev}
    body=snapshot()
    if not body['events'] and not body['reset']:
     await asyncio.sleep(0.3)  # long poll stand-in
     body=snapshot()
   elif path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'qa'}
   elif path=='/api/status':body={'interfaces':[],'channels':[],'uptime_seconds':1}
   elif path.endswith('/clients'):body=[]
   await r.fulfill(json=body)
  await page.route('**/*',route)
  rows=page.locator('.logs-content tbody tr')
  await page.goto('https://netos-ui.test/#diagnostics?tab=logs&log=all')
  await expect(rows).to_have_count(3)
  await expect(rows.first).to_contain_text('drop-ssh')
  await expect(page.locator('.logs-content').get_by_role('tab',name='DNS',exact=True)).to_be_visible()
  await expect(page.get_by_text('запущена'+XSS,exact=True)).to_be_visible()
  await expect(page.locator('.logs-content').get_by_text('Обновить журнал')).to_have_count(0)
  # A new event appears on top without any button.
  add('services','error','netos-unbound','сбой: процесс завершился с ошибкой (код 1)')
  await expect(rows).to_have_count(4)
  await expect(rows.first).to_contain_text('netos-unbound')
  await expect(rows.first.locator('.badge.danger')).to_have_text('ошибка')
  # Topic tab shows only its own events and follows the hash.
  await page.get_by_role('tab',name='Службы',exact=True).click()
  await expect(rows).to_have_count(2)
  assert state['topics'][-1]=='services',state['topics']
  await page.get_by_role('tab',name='Общий',exact=True).click()
  await page.get_by_label('Поиск в журнале',exact=True).fill('ssh')
  await expect(rows).to_have_count(2)
  async with page.expect_download() as pending:
   await page.get_by_role('button',name='Скачать журнал',exact=True).click()
  text=Path(await (await pending.value).path()).read_text(encoding='utf-8')
  assert 'drop-ssh' in text and 'неудачный вход' in text and 'netos-dnsmasq' not in text,text
  await page.get_by_label('Поиск в журнале',exact=True).fill('')
  # Lost connection: notice, rows kept, automatic reconnect continues the list.
  state['fail']=True
  await expect(page.get_by_text('Нет связи с роутером, переподключение…')).to_be_visible()
  add('access','info','SSH','вход root с 198.51.100.7 (ключ)')
  await expect(rows).to_have_count(4)
  state['fail']=False
  await expect(rows).to_have_count(5)
  await expect(rows.first).to_contain_text('вход root')
  await expect(page.get_by_text('Нет связи с роутером, переподключение…')).to_have_count(0)
  # netosd restart (new epoch): the list is replaced, not mixed.
  state['epoch']='e2';state['events']=[];add('services','info','netosd','запущена')
  add('services','info','netosd','после перезапуска')
  await expect(rows).to_have_count(2)
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.screenshot(path='output/playwright/logs.png')
  # Leaving the page stops polling.
  await page.goto('https://netos-ui.test/#dashboard')
  await page.wait_for_timeout(500);n=len(state['topics']);await page.wait_for_timeout(1500)
  assert len(state['topics'])==n,(n,len(state['topics']))
  assert not errors,errors
  await browser.close();print('live logs: tabs, live append, search, export, reconnect, reset, stop on leave PASS')
asyncio.run(main())
