"""Production UI lifecycle checks; APIs intercepted, no router access."""
import asyncio,copy,importlib.util,json
from pathlib import Path
from playwright.async_api import async_playwright, expect
spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('ui-review-regressions.browser.py'));m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
async def main():
 results=[]
 async with async_playwright() as p:
  browser=await p.chromium.launch(channel='chrome',headless=True)
  for stage in ['save','profile','profile-error','edit','normal','retry']:
   cfg=copy.deepcopy(m.CONFIG)
   cfg['vpn_servers']=[{'id':'x','type':'xray','name':'Xray','index':1,'enabled':True,'port':443,'subnet':'10.9.0.1/24','config':{'protocol':'vless','public_endpoint':'vpn.example.test:443','tls':{'mode':'acme'}},'peers':[{'id':'p','name':'Client','enabled':True,'address':'10.9.0.2','credentials':{'uuid':'00000000-0000-0000-0000-000000000001'}}]}]
   page,state=await m.fixture(browser,{'role':'admin'},cfg)
   started=asyncio.Event();release=asyncio.Event();calls=[];downloads=[]
   page.on('download',lambda d:downloads.append(d.suggested_filename))
   async def save(route):
    if route.request.method!='PUT':await route.fallback();return
    calls.append('save')
    if stage in ['save','normal']:started.set();await release.wait()
    cfg.update(route.request.post_data_json)
    await route.fulfill(json={'config':cfg,'dirty':True,'draft_version':2,'problems':[]})
   async def profile(route):
    calls.append('profile')
    if stage.startswith('profile') or stage=='edit':started.set();await release.wait()
    if stage=='profile-error' or (stage=='retry' and calls.count('profile')==1):
     await route.fulfill(status=503,json={'error':'stale profile error'});return
    await route.fulfill(json={'link':'vless://test@vpn.example.test:443','config':{'outbounds':[]}})
   await page.route('**/api/config',save);await page.route('**/xray-profile',profile)
   await page.goto('http://netos.test/#vpn-servers')
   await page.locator('[data-vpn-client="p"]').wait_for(state='attached')
   await page.evaluate("document.querySelectorAll('details').forEach(d=>d.open=true)")
   row=page.locator('[data-vpn-client="p"]')
   if stage in ['save','normal']:await row.locator('input:not([type=checkbox])').first.fill('Changed')
   await row.get_by_role('button',name='Скачать JSON Xray',exact=True).click()
   if stage=='retry':
    await expect(page.get_by_text('stale profile error',exact=True)).to_be_visible()
    await expect(row.get_by_role('button',name='Скачать JSON Xray',exact=True)).to_be_enabled()
    async with page.expect_download():
     await row.get_by_role('button',name='Скачать JSON Xray',exact=True).click()
    assert len(downloads)==1
   else:
    await asyncio.wait_for(started.wait(),10)
    if stage=='edit':
     await row.locator('input:not([type=checkbox])').first.fill('New name')
    elif stage!='normal':
     await page.evaluate("location.hash='#network'")
     await row.wait_for(state='detached')
    release.set()
    if stage=='normal':
     await expect(row.get_by_role('button',name='Скачать JSON Xray',exact=True)).to_be_enabled()
     await page.wait_for_timeout(300)
     assert downloads==['Changed.json'],downloads
     assert calls==['save','profile'],calls
     await page.evaluate("Object.defineProperty(navigator,'clipboard',{value:{writeText:async s=>window.copied=s},configurable:true})")
     await row.get_by_role('button',name='Скопировать ссылку',exact=True).click()
     await expect(row.get_by_role('button',name='Ссылка скопирована',exact=True)).to_be_visible()
     assert await page.evaluate('window.copied')=='vless://test@vpn.example.test:443'
     await row.get_by_role('button',name='Открыть QR-код',exact=True).click()
     await expect(row.locator('.qr-card svg')).to_be_visible()
    else:
     await page.wait_for_timeout(500)
     assert not downloads,(stage,downloads)
     if stage=='save':assert calls==['save'],calls
     if stage=='edit':
      await expect(row.get_by_role('button',name='Скачать JSON Xray',exact=True)).to_be_enabled()
      async with page.expect_download():
       await row.get_by_role('button',name='Скачать JSON Xray',exact=True).click()
      assert downloads==['New name.json'],downloads
     else:
      await page.goto('http://netos.test/#vpn-servers')
     assert await page.get_by_text('stale profile error',exact=True).count()==0
   assert not state['errors'],state['errors']
   results.append({'stage':stage,'calls':calls,'downloads':downloads,'errors':state['errors']})
   await page.close()
  await browser.close()
 print(json.dumps(results))
asyncio.run(main())

