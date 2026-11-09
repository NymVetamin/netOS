"""Wake-on-LAN production UI with intercepted API; no router access."""
import asyncio,copy,importlib.util
from pathlib import Path
from playwright.async_api import async_playwright,expect
spec=importlib.util.spec_from_file_location('fixture',Path(__file__).with_name('ui-review-regressions.browser.py'));f=importlib.util.module_from_spec(spec);spec.loader.exec_module(f)
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(channel='chrome',headless=True)
  for role,level in [('admin','manage'),('limited','manage'),('limited','view'),('viewer','view')]:
   cfg=copy.deepcopy(f.CONFIG);cfg['policies']=[];cfg['vpn_servers']=[]
   cfg['dhcp']['reservations']=[{'id':'sleep','mac':'02:11:22:33:44:55','hostname':'Sleeping PC','ip':'192.0.2.10','network':'lan','enabled':True}]
   page,state=await f.fixture(browser,{'role':role,'permissions':{'clients':level}},cfg)
   calls=[];control={'fail':False,'hold':None}
   async def wake(route):
    calls.append(route.request.post_data_json)
    assert route.request.method=='POST'
    if control['hold'] is not None:await control['hold'].wait()
    await route.fulfill(status=500 if control['fail'] else 200,json={'error':'test send failure'} if control['fail'] else {'interface':'br-lan'})
   await page.route('**/api/clients/wake',wake)
   await page.goto('http://netos.test/#clients')
   await page.get_by_text('Sleeping PC',exact=True).click()
   button=page.get_by_role('button',name='Разбудить (Wake-on-LAN)',exact=True)
   if level!='manage':
    await expect(button).to_have_count(0);assert not calls;await page.close();continue
   await expect(page.get_by_label('Сегмент Wake-on-LAN')).to_have_value('lan')
   await asyncio.sleep(.4);assert not calls
   control['hold']=asyncio.Event();await button.click()
   await expect(page.get_by_role('button',name='Отправка…',exact=True)).to_be_disabled()
   await asyncio.sleep(.3);assert len(calls)==1
   control['hold'].set();control['hold']=None
   await expect(page.get_by_role('status')).to_contain_text('Пакет отправлен через br-lan')
   assert calls==[{'mac':'02:11:22:33:44:55','network':'lan'}]
   control['fail']=True;await button.click();await expect(page.get_by_role('status')).to_contain_text('test send failure')
   control['fail']=False;await button.click();await expect(page.get_by_role('status')).to_contain_text('Это не подтверждает пробуждение')
   control['hold']=asyncio.Event();await button.click();await page.evaluate("location.hash='network'");control['hold'].set()
   await asyncio.sleep(.4)
   assert not state['writes'],state['writes'];assert not state['errors'],state['errors']
   await page.close()
  cfg=copy.deepcopy(f.CONFIG);cfg['networks'].append({'id':'guest','name':'Guest','enabled':True,'interface':'guest'})
  page,state=await f.fixture(browser,{'role':'admin'},cfg)
  await page.route('**/api/clients',lambda r:r.fulfill(json={'clients':[{'mac':'02:11:22:33:44:55','hostname':'Unknown PC','online':False}]}))
  await page.goto('http://netos.test/#clients');await page.get_by_text('Unknown PC',exact=True).click()
  button=page.get_by_role('button',name='Разбудить (Wake-on-LAN)',exact=True)
  await expect(button).to_be_disabled();await page.get_by_label('Сегмент Wake-on-LAN').select_option('guest');await expect(button).to_be_enabled()
  await page.set_viewport_size({'width':390,'height':844})
  await page.screenshot(path=str(Path(__file__).resolve().parents[2]/'.codex/wol-mobile.png'),full_page=True)
  assert not state['writes'] and not state['errors']
  await browser.close();print('offline client, permissions, segment selection, busy, success/error/retry, navigation, no config writes PASS')
asyncio.run(main())
