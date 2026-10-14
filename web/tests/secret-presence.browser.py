"""UI regression with a simulated redacted API; no router is modified."""
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
  cfg = {'system': {'hostname': 'test'}, 'interfaces': [], 'networks': [], 'wans': [], 'policies': [],
   'components': [{'id': 'ocserv', 'installed': True}, {'id': 'wireguard-tools', 'installed': True}],
   'channels': [{'id': 'direct', 'enabled': True, 'name': 'Напрямую', 'type': 'direct'}],
   'ddns': {'enabled': True, 'provider': 'noip', 'username': 'test', 'password': '', 'secrets_set': {'password': True}, 'hostname': 'router.example.org', 'address_source': 'web', 'interval': 300},
   'vpn_servers': [{'id': 'oc', 'name': 'OpenConnect', 'type': 'ocserv', 'index': 1, 'enabled': True, 'port': 443, 'subnet': '10.30.0.1/24',
    'config': {'dns': ['9.9.9.9'], 'public_endpoint': 'vpn.example.org:443'},
    'peers': [{'id': 'phone', 'name': 'Телефон', 'enabled': True, 'address': '10.30.0.2', 'credentials': {'username': 'test', 'password': ''}, 'secrets_set': {'password': True}},
              {'id': 'empty', 'name': 'Новый', 'enabled': False, 'address': '10.30.0.3', 'credentials': {'username': 'new', 'password': ''}}]},
    {'id': 'wg', 'name': 'WireGuard', 'type': 'wireguard', 'index': 2, 'enabled': False, 'subnet': '10.9.0.1/24', 'port': 51820, 'config': {'private_key': ''}, 'secrets_set': {'private_key': True}, 'peers': []}]}
  state = {'cfg': cfg, 'puts': [], 'password': 'original'}
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
     assert '••••' not in str(value), 'mask submitted as credential'
     if value['ddns'].get('password'): state['password'] = value['ddns']['password']
     value['ddns']['password'] = ''
     value['ddns']['secrets_set'] = {'password': bool(state['password'])}
     state['cfg'] = value
    body = {'config': copy.deepcopy(state['cfg']), 'dirty': False, 'draft_version': len(state['puts']) + 1, 'problems': []}
   elif path == '/api/ddns/status': body = {'success': True, 'address': '203.0.113.10', 'last_run': 1791972000, 'next_run': 1791972300}
   elif path == '/api/status': body = {'interfaces': [], 'channels': [], 'uptime_seconds': 1}
   elif path.endswith('/clients'): body = []
   await r.fulfill(json=body)
  await page.route('**/*', route)
  await page.goto('https://netos-ui.test/#services')
  await expect(page.get_by_label('Провайдер DDNS')).to_be_visible()
  for width in (1440, 1043, 390):
   await page.set_viewport_size({'width': width, 'height': 1000})
   await page.locator('.ddns-grid').scroll_into_view_if_needed()
   assert await page.locator('.ddns-grid').evaluate("""e => [...e.querySelectorAll('input,select')].every(x => {
    const r=x.getBoundingClientRect(); return r.width >= 240 && r.right <= innerWidth && r.left >= 0;
   })"""), f'DDNS fields clipped at {width}'
   Path('output/playwright').mkdir(parents=True, exist_ok=True)
   await page.screenshot(path=f'output/playwright/ddns-{width}.png')
  await page.set_viewport_size({'width': 1280, 'height': 900})
  await page.goto('https://netos-ui.test/#traffic')
  await expect(page.get_by_role('heading', name='Скорость и QoS', exact=True)).to_be_visible()
  await expect(page.get_by_label('Провайдер DDNS')).to_have_count(0)
  await page.goto('https://netos-ui.test/#services')
  password = page.get_by_label('Пароль No-IP', exact=True)
  await expect(password).to_have_attribute('placeholder', '••••••••')
  await expect(password).to_have_value('')
  async with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'PUT'):
   await page.get_by_label('Доменное имя DDNS').fill('changed.example.org')
  assert state['password'] == 'original'
  assert state['puts'][-1]['ddns']['password'] == ''
  async with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'PUT'):
   await password.fill('replacement-password')
  await page.reload()
  await expect(password).to_have_value('')
  await expect(password).to_have_attribute('placeholder', '••••••••')
  assert state['password'] == 'replacement-password'
  async with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'PUT'):
   await page.get_by_label('Провайдер DDNS').select_option('duckdns')
  await expect(page.get_by_label('API-токен DDNS')).to_have_attribute('placeholder', 'Не задан')
  async with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'PUT'):
   await page.get_by_label('Провайдер DDNS').select_option('cloudflare')
  await expect(page.get_by_label('Cloudflare Zone ID')).to_be_visible()
  await expect(page.get_by_label('Cloudflare Record ID')).to_be_visible()
  async with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'PUT'):
   await page.get_by_label('Источник адреса DDNS').select_option('interface')
  await expect(page.get_by_label('Интернет-канал DDNS', exact=True)).to_be_visible()
  async with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'PUT'):
   await page.get_by_label('Источник адреса DDNS').select_option('web')
  await expect(page.get_by_label('Интернет-канал DDNS', exact=True)).to_have_count(0)
  await page.goto('https://netos-ui.test/#vpn-servers')
  await expect(page.get_by_label('Закрытый ключ сервера')).to_have_attribute('placeholder', '••••••••')
  peers = page.locator('[data-peers-of="oc"]')
  await expect(peers.locator('input[type=password]').nth(0)).to_have_attribute('placeholder', '••••••••')
  await expect(peers.locator('input[type=password]').nth(1)).to_have_attribute('placeholder', 'Не задан')
  dns = page.get_by_label('DNS OpenConnect', exact=True)
  await expect(dns).to_have_value('9.9.9.9')
  switch = page.get_by_role('checkbox', name='Использовать DNS роутера', exact=True)
  async with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'PUT'):
   await switch.locator('..').click()
  await expect(dns).to_have_count(0)
  assert state['cfg']['vpn_servers'][0]['config']['use_router_dns'] is True
  assert state['cfg']['vpn_servers'][0]['config']['dns'] == ['9.9.9.9']
  await page.reload()
  await expect(switch).to_be_checked()
  async with page.expect_response(lambda r: r.url.endswith('/api/config') and r.request.method == 'PUT'):
   await switch.locator('..').click()
  await expect(dns).to_have_value('9.9.9.9')
  assert not errors, errors
  print('Saved/empty secrets, DDNS replacement/reload, unchanged password, WG key, OpenConnect DNS toggle/reload: PASS')
  await browser.close()
asyncio.run(main())
