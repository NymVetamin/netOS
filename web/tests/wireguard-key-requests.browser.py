import asyncio,copy,importlib.util,json,base64
from pathlib import Path
from playwright.async_api import async_playwright,expect
root=Path(__file__).resolve().parents[2]
s=importlib.util.spec_from_file_location('fixture',root/'web/tests/ui-review-regressions.browser.py');f=importlib.util.module_from_spec(s);s.loader.exec_module(f)
async def main():
 async with async_playwright() as p:
  browser=await p.chromium.launch(channel='chrome',headless=True)
  results=[]
  for n in [1,25]:
   cfg=copy.deepcopy(f.CONFIG);cfg['policies']=[]
   cfg['channels']=[{'id':f'wg{i}','index':i+1,'name':f'WG test {i}','enabled':False,'type':'wireguard','mode':'tun','secrets_set':{'private_key':True},'config':{'private_key':'','endpoint':'old.example:51820','allowed_ips':['0.0.0.0/0']},'probe':{'enabled':False}} for i in range(n)]
   page,state=await f.fixture(browser,{'role':'admin'},cfg);calls=[]
   async def keys(route):
    calls.append(route.request.post_data_json)
    await route.fulfill(json={'public_key':base64.b64encode(bytes([8])*32).decode()})
   await page.route('**/api/wireguard/keypair',keys)
   await page.goto('http://netos.test/#channels')
   await page.get_by_text('WG test 0',exact=True).click()
   await expect(page.get_by_label('Ваш публичный ключ WireGuard',exact=True).first).not_to_have_value('')
   await asyncio.sleep(.6);initial=len(calls)
   endpoint=page.locator('input[placeholder="vpn.example.com:51820"]').first
   for i in range(3):
    await endpoint.fill(f'changed{i}.example:51820');await asyncio.sleep(.7)
   assert len(calls)==initial, calls
   results.append({'channels':n,'initial_key_requests':initial,'additional_requests_after_3_endpoint_edits':len(calls)-initial,'errors':state['errors']})
   await page.close()
  await lifecycle(browser)
  await browser.close()
  print(json.dumps(results));print('key retry, change, stale response, reload and discard PASS')
async def lifecycle(browser):
 cfg=copy.deepcopy(f.CONFIG);cfg['policies']=[]
 cfg['channels']=[{'id':'wg','index':1,'name':'WG test','enabled':False,'type':'wireguard','mode':'tun','secrets_set':{'private_key':True},'config':{'private_key':'','endpoint':'old.example:51820'},'probe':{'enabled':False}}]
 page,state=await f.fixture(browser,{'role':'admin'},cfg)
 key=lambda n:base64.b64encode(bytes([n])*32).decode()
 control={'fail':True,'saved':key(8),'calls':0,'hold':None}
 async def keys(route):
  control['calls']+=1
  body=route.request.post_data_json or {}
  if control['fail']:
   await route.fulfill(status=503,json={'error':'key service unavailable'});return
  value=key(9) if body.get('private_key') else control['saved']
  if control['hold'] is not None:
   event=control['hold'];control['hold']=None
   await event.wait()
  await route.fulfill(json={'public_key':value})
 async def configs(route):
  if route.request.method=='PUT':
   state['config']=route.request.post_data_json;state['dirty']=True
  if route.request.url.endswith('/discard'):
   state['config']=copy.deepcopy(cfg);state['dirty']=False
  await route.fulfill(json={'config':state['config'],'dirty':state.get('dirty',False),'draft_version':1,'problems':[]})
 await page.route('**/api/config',configs)
 await page.route('**/api/config/discard',configs)
 await page.route('**/api/wireguard/keypair',keys)
 await page.goto('http://netos.test/#channels')
 await page.get_by_text('WG test',exact=True).click()
 public=page.get_by_label('Ваш публичный ключ WireGuard',exact=True)
 private=page.get_by_label('Приватный ключ WireGuard',exact=True)
 endpoint=page.locator('input[placeholder="vpn.example.com:51820"]')
 await expect(page.get_by_text('key service unavailable',exact=False)).to_be_visible()
 control['fail']=False
 await endpoint.fill('retry.example:51820')
 await expect(public).to_have_value(key(8))
 assert control['calls']==2
 await private.fill(key(7));await expect(public).to_have_value(key(9))
 await private.fill('');await expect(public).to_have_value(key(8))
 # An old saved-key response cannot overwrite a newly entered private key.
 await private.fill(key(7));await expect(public).to_have_value(key(9))
 event=asyncio.Event();control['hold']=event;calls=control['calls']
 await private.fill('')
 for _ in range(40):
  if control['calls']>calls:break
  await asyncio.sleep(.05)
 assert control['calls']>calls
 await private.fill(key(7));await expect(public).to_have_value(key(9))
 event.set();await asyncio.sleep(.5);await expect(public).to_have_value(key(9))
 # Authoritative reload remounts editors and reads the current stored key.
 state['config']=copy.deepcopy(cfg);control['saved']=key(10)
 await page.reload();await page.get_by_text('WG test',exact=True).click()
 await expect(public).to_have_value(key(10))
 await endpoint.fill('discard.example:51820')
 await expect(page.get_by_role('button',name='Отменить',exact=True)).to_be_visible()
 control['saved']=key(11)
 await page.get_by_role('button',name='Отменить',exact=True).click()
 await expect(public).to_have_value(key(11))
 await expect(endpoint).to_have_value('old.example:51820')
 assert not state['errors'],state['errors']
 await page.close()

asyncio.run(main())
