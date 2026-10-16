"""Local production UI regression; all API calls are mocked, no router access."""
import asyncio
import mimetypes
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def main():
    cfg = {"system": {"hostname": "test", "ntp": {"enabled": True,
           "servers": ["0.debian.pool.ntp.org", "1.debian.pool.ntp.org"]}},
           "interfaces": [], "policies": [], "channels": [], "networks": []}
    errors=[]
    async with async_playwright() as p:
      browser=await p.chromium.launch()
      page=await browser.new_page()
      page.on('pageerror', lambda e: errors.append(str(e)))
      async def route_request(route):
        nonlocal cfg
        req=route.request; path=urlparse(req.url).path
        if not path.startswith('/api/'):
          file=DIST/('index.html' if path=='/' else path.lstrip('/'))
          await route.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream'); return
        body={}
        if path=='/api/session': body={'username':'admin','role':'admin','csrf_token':'test'}
        elif path=='/api/config':
          if req.method=='PUT': cfg=req.post_data_json
          body={'config':cfg,'dirty':False,'draft_version':1,'problems':[]}
        elif path=='/api/status': body={'interfaces':[],'channels':[]}
        await route.fulfill(json=body)
      await page.route('**/*',route_request)
      await page.goto('https://netos-ui.test/#system')
      field=page.get_by_role('combobox',name='Часовой пояс',exact=True)
      options=page.locator('.timezone-options').get_by_role('option')
      await field.fill('')
      await expect(options).to_have_count(0)
      await field.fill('a')
      await expect(options).to_have_count(10)
      await field.press('ArrowDown')
      first=await options.first.inner_text()
      await field.press('Enter')
      await expect(field).to_have_value(first)
      await expect(options).to_have_count(0)
      await field.fill('mos')
      await expect(options).to_have_count(1)
      await page.get_by_role('option',name='Europe/Moscow',exact=True).click()
      await expect(field).to_have_value('Europe/Moscow')
      await page.wait_for_timeout(800)
      assert cfg['system']['timezone']=='Europe/Moscow'
      await page.reload()
      await expect(field).to_have_value('Europe/Moscow')
      await field.fill('EuRoPe/')
      await expect(options).to_have_count(10)
      await field.press('Escape')
      await expect(options).to_have_count(0)
      await field.fill('unknown-zone')
      await expect(options).to_have_count(0)
      await field.fill('uTc')
      await field.press('ArrowUp')
      await field.press('Enter')
      await expect(field).to_have_value('UTC')
      await page.set_viewport_size({'width':390,'height':900})
      await field.fill('a')
      await expect(options).to_have_count(10)
      box=await page.get_by_role('listbox').bounding_box()
      assert box['x']>=0 and box['x']+box['width']<=390
      await page.screenshot(path='output/playwright/timezone-mobile.png')
      await field.press('Tab')
      await expect(options).to_have_count(0)
      assert not errors, errors
      await browser.close()
      print('PASS: timezone suggestions, limit, keyboard/mouse, persistence, mobile')
asyncio.run(main())
