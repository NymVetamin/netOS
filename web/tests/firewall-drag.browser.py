"""Firewall ordering through real mouse gestures; mocked API, no router changes."""
import asyncio, copy, mimetypes, os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / 'backend/internal/api/webdist'
async def main():
 async with async_playwright() as p:
  browser = await p.chromium.launch(headless=True, executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE', str(Path(os.environ['ProgramFiles']) / 'Google/Chrome/Application/chrome.exe')))
  page = await browser.new_page()
  await page.add_init_script("new MutationObserver(()=>document.querySelectorAll('details.xd').forEach(e=>e.open=true)).observe(document,{childList:true,subtree:true})")
  cfg={'system':{'hostname':'router'}, 'interfaces':[], 'networks':[], 'policies':[], 'wans':[], 'channels':[],
    'firewall':{'enabled':True,'zones':[], 'nat':[], 'rules':[{'id':f'r{i}','name':f'Rule {i}','enabled':True,'zone':'global','flow':'forward','action':'accept'} for i in range(3)]}}
  state = {'cfg': cfg, 'puts': []}
  errors = []
  page.on('pageerror', lambda e: errors.append(str(e)))
  async def route(r):
   path = urlparse(r.request.url).path
   if not path.startswith('/api/'):
    f = DIST / ('index.html' if path == '/' else path.lstrip('/'))
    assert f.parent == DIST and f.is_file()
    await r.fulfill(body=f.read_bytes(), content_type=mimetypes.guess_type(str(f))[0] or 'application/octet-stream'); return
   body = {}
   if path == '/api/session': body = {'username': 'admin', 'role': 'admin', 'csrf_token': 'test'}
   elif path == '/api/config':
    if r.request.method == 'PUT':
     value = r.request.post_data_json
     state['puts'].append(copy.deepcopy(value))
     state['cfg'] = value
    body = {'config': copy.deepcopy(state['cfg']), 'dirty': False, 'draft_version': len(state['puts']) + 1, 'problems': []}
   elif path == '/api/status': body = {'interfaces': [], 'channels': [], 'uptime_seconds': 1}
   elif path.endswith('/clients'): body = []
   await r.fulfill(json=body)
  await page.route('**/*', route)
  await page.goto('https://netos-ui.test/#firewall')
  await expect(page.locator('.grip')).to_have_count(3)
  async def gesture(source, target, delay, cancel=False, outside=False):
   await page.locator('.grip').nth(source).scroll_into_view_if_needed()
   first=await page.locator('.grip').nth(source).bounding_box()
   last=await page.locator('.grip').nth(target).bounding_box()
   await page.mouse.move(first['x']+first['width']/2,first['y']+first['height']/2)
   await page.mouse.down()
   await page.wait_for_timeout(delay)
   await page.mouse.move(last['x']+last['width']/2,last['y']+last['height']/2,steps=12)
   if cancel: await page.keyboard.press('Escape')
   if outside: await page.mouse.move(50,80)
   await page.mouse.up()
  for delay in (0,1200,2200):
   before=[r['id'] for r in state['cfg']['firewall']['rules']]
   async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
    await gesture(0,2,delay)
   assert [r['id'] for r in state['cfg']['firewall']['rules']]==before[1:]+before[:1]
   await page.reload()
   await expect(page.locator('.rules tr').first).to_contain_text(state['cfg']['firewall']['rules'][0]['name'])
  before=[r['id'] for r in state['cfg']['firewall']['rules']]
  async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
   await gesture(2,0,1200)
  assert [r['id'] for r in state['cfg']['firewall']['rules']]==before[-1:]+before[:-1]
  writes=len(state['puts'])
  await gesture(0,2,1000,cancel=True)
  await gesture(0,2,0,outside=True)
  await gesture(0,0,1100)
  await page.wait_for_timeout(700)
  assert len(state['puts'])==writes,'cancel/outside/click changed rules'
  await expect(page.locator('tr.dragging')).to_have_count(0)
  await page.locator('.grip').first.focus()
  async with page.expect_response(lambda r:r.request.method=='PUT' and r.url.endswith('/api/config')):
   await page.keyboard.press('ArrowDown')
  assert len(state['puts'])==writes+1
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.screenshot(path='output/playwright/firewall-drag.png')
  assert not errors,errors
  print('PASS: quick drag, hold 1.2/2.2s, reverse, reload, Escape, outside, stationary hold, keyboard')
  await browser.close()
asyncio.run(main())

