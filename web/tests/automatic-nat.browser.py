"""Automatic NAT visibility with mocked API; no router is modified."""
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
  cfg={'system':{'hostname':'router'}, 'interfaces':[{'id':'uplink','name':'enp8s0'}], 'networks':[], 'policies':[],
    'firewall':{'zones':[], 'rules':[], 'nat':[{'id':'manual','name':'Explicit WAN','enabled':True,'direction':'source','interface':'enp8s0'}]},
    'wans':[{'id':'wan','name':'Uplink','enabled':True,'interface':'uplink'}],
    'channels':[{'id':'direct','type':'direct','enabled':True}]+[{'id':f'ch{i}','index':i,'name':name,'enabled':True,'type':kind} for i,name,kind in [(1,'Riga','xray'),(2,'Poland','xray'),(3,'WG','wireguard'),(4,'OC','openconnect'),(5,'L2TP','l2tp'),(6,'IKE','ikev2')]],
    'ddns':{}, 'vpn_servers':[]}
  state = {'cfg': cfg, 'puts': []}
  tunnel_names = [('Riga','tun-ch1'),('Poland','tun-ch2'),('WG','wg-ch3'),
                  ('OC','tun-ch4'),('L2TP','ppp-ch5'),('IKE','xfrm-ch6')]
  preview = {'families':[{'family':'IPv4','tables':[{'name':'nat','chains':[
    {'name':'POSTROUTING','rules':[
      f'-A POSTROUTING -o {iface} -m comment --comment "NAT канала «{name}»" -j MASQUERADE'
      for name,iface in tunnel_names
    ] + ['-A POSTROUTING -o ppp-wan -m comment --comment "NAT аплинка «PPP»" -j MASQUERADE']}
  ]}]}]}
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
   elif path == '/api/firewall/preview': body = preview
   elif path.endswith('/clients'): body = []
   await r.fulfill(json=body)
  await page.route('**/*', route)
  await page.goto('https://netos-ui.test/#firewall')
  checkbox = page.get_by_role('checkbox',name='Показать автоматические правила',exact=True)
  await expect(page.locator('.automatic-nat')).to_have_count(0)
  await checkbox.check()
  await expect(page.locator('.automatic-nat')).to_have_count(7)
  for name in ('Riga','Poland','WG','OC','L2TP','IKE'):
   await expect(page.get_by_text(f'NAT канала «{name}»',exact=True)).to_be_visible()
  for iface in ('tun-ch1','tun-ch2','wg-ch3','tun-ch4','ppp-ch5','xfrm-ch6'):
   await expect(page.get_by_text(iface,exact=True)).to_be_visible()
  await expect(page.get_by_text('NAT аплинка «Uplink»',exact=True)).to_have_count(0)
  Path('output/playwright').mkdir(parents=True,exist_ok=True)
  await page.get_by_text('NAT канала «Riga»',exact=True).scroll_into_view_if_needed()
  await page.screenshot(path='output/playwright/automatic-nat.png')
  for toggle in await page.locator('.automatic-nat input').all():
   await expect(toggle).to_be_disabled()
   await expect(toggle).to_be_checked()
  await checkbox.uncheck()
  await expect(page.locator('.automatic-nat')).to_have_count(0)
  await expect(page.get_by_text('Explicit WAN',exact=True)).to_be_visible()
  await checkbox.check()
  await expect(page.locator('.automatic-nat')).to_have_count(7)
  await expect(page.get_by_text('ppp-wan',exact=True)).to_be_visible()
  await expect(page.get_by_text('Правил подмены адреса отправителя в настройках нет',exact=True)).to_have_count(0)
  await page.set_viewport_size({'width':390,'height':844})
  assert await page.evaluate('document.documentElement.scrollWidth <= innerWidth')
  assert not state['puts'], 'read-only rows must not write config'
  assert not errors, errors
  print('PASS: preview NAT visibility, all tunnel names, PPP, disabled toggles, mobile, no config writes')
  await browser.close()
asyncio.run(main())
