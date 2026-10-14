"""Saved Reality credentials stay redacted; profile export reads after draft flush."""
import asyncio, copy, mimetypes, os
from pathlib import Path
from urllib.parse import urlparse, urlencode
from playwright.async_api import async_playwright, expect

DIST=Path(__file__).resolve().parents[2]/'backend/internal/api/webdist'
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(headless=True,executable_path=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE',str(Path(os.environ['ProgramFiles'])/'Google/Chrome/Application/chrome.exe')))
  page=await browser.new_page()
  await page.add_init_script("new MutationObserver(()=>document.querySelectorAll('details.xd').forEach(e=>e.open=true)).observe(document,{childList:true,subtree:true})")
  cfg={'system':{'hostname':'test'},'interfaces':[],'networks':[],'policies':[],'components':[{'id':'xray','installed':True}],'channels':[{'id':'direct','enabled':True,'name':'Напрямую','type':'direct'}],'vpn_servers':[{'id':'srv','name':'Reality','type':'xray','index':1,'enabled':True,'port':443,'subnet':'10.9.0.1/24','reality_key_set':True,'config':{'protocol':'reality','private_key':'','public_endpoint':'vpn.example:443','server_names':['example.com'],'short_ids':['abcd'],'flow':'xtls-rprx-vision'},'peers':[{'id':'phone','name':'Телефон','enabled':True,'credentials':{'uuid':''}}]}]}
  state={'cfg':cfg,'reads':0,'link':''};errors=[]
  page.on('pageerror',lambda e:errors.append(str(e)))
  async def route(r):
   path=urlparse(r.request.url).path
   if not path.startswith('/api/'):
    f=DIST/('index.html' if path=='/' else path.lstrip('/'));assert f.parent==DIST and f.is_file()
    await r.fulfill(body=f.read_bytes(),content_type=mimetypes.guess_type(str(f))[0] or 'application/octet-stream');return
   body={}
   if path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'test'}
   elif path=='/api/config':
    if r.request.method=='PUT':state['cfg']=r.request.post_data_json
    body={'config':copy.deepcopy(state['cfg']),'dirty':False,'draft_version':1,'problems':[]}
   elif path=='/api/status':body={'interfaces':[],'channels':[],'uptime_seconds':1}
   elif path.endswith('/clients'):body=[]
   elif path.endswith('/reality-profile'):
    state['reads']+=1
    sid=state['cfg']['vpn_servers'][0]['config']['short_ids'][0]
    state['link']='vless://12345678-1234-1234-1234-123456789abc@vpn.example:443?'+urlencode({'security':'reality','pbk':'public','sid':sid,'sni':'example.com'})+'#phone'
    body={'link':state['link']}
   elif path=='/api/xray/keypair':raise AssertionError('export requested private key derivation in browser')
   await r.fulfill(json=body)
  await page.route('**/*',route)
  await page.goto('https://netos-ui.test/#vpn-servers')
  await expect(page.get_by_placeholder('••••••••')).to_be_visible()
  assert await page.get_by_placeholder('••••••••').input_value()==''
  await page.get_by_role('button',name='Открыть QR-код',exact=True).click()
  await expect(page.locator('.qr-card svg')).to_be_visible()
  first_svg=await page.locator('.qr-card svg').inner_html()
  async with page.expect_download() as event:await page.get_by_role('button',name='Скачать VLESS-ссылку',exact=True).click()
  assert Path(await (await event.value).path()).read_text().strip()==state['link']
  await page.reload()
  await page.get_by_role('button',name='Открыть QR-код',exact=True).click()
  await expect(page.locator('.qr-card svg')).to_be_visible()
  page.on('dialog', lambda d: errors.append('Unexpected browser dialog: '+d.message))
  await page.get_by_role('button',name='Перегенерировать Short ID').click()
  dialog=page.get_by_role('dialog')
  await expect(dialog).to_be_visible()
  await expect(dialog.get_by_role('button',name='Отмена',exact=True)).to_be_focused()
  await dialog.get_by_role('button',name='Отмена',exact=True).click()
  await expect(dialog).to_have_count(0)
  await expect(page.get_by_role('button',name='Перегенерировать Short ID')).to_be_focused()
  assert state['cfg']['vpn_servers'][0]['config']['short_ids']==['abcd']
  await page.get_by_role('button',name='Перегенерировать Short ID').click()
  await page.keyboard.press('Escape')
  await expect(dialog).to_have_count(0)
  assert state['cfg']['vpn_servers'][0]['config']['short_ids']==['abcd']
  await page.get_by_role('button',name='Перегенерировать Short ID').click()
  await expect(dialog).to_be_visible()
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  for width in (1280,390):
   await page.set_viewport_size({'width':width,'height':900})
   await page.screenshot(path=f'output/playwright/confirm-{width}.png')
   assert await dialog.evaluate('e => e.getBoundingClientRect().right <= innerWidth')
  await dialog.get_by_role('button',name='Заменить Short ID',exact=True).click()
  await expect(page.locator('.qr-card svg')).to_have_count(0)
  await page.get_by_role('button',name='Открыть QR-код',exact=True).click()
  await expect(page.locator('.qr-card svg')).to_be_visible()
  assert state['cfg']['vpn_servers'][0]['config']['short_ids']!=['abcd']
  assert await page.locator('.qr-card svg').inner_html()!=first_svg
  assert not errors,errors
  print('Reality saved export / reload / QR / Short ID rotation / draft flush: PASS')
  await browser.close()
asyncio.run(main())
