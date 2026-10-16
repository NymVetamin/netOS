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
        elif path=='/api/panel-users': body=[]
        elif path=='/api/status': body={'interfaces':[],'channels':[]}
        await route.fulfill(json=body,content_type="application/json")
      await page.route('**/*',route_request)
      await page.goto('https://netos-ui.test/#system')
      block=page.locator('.ntp-servers')
      await expect(block).to_be_visible()
      await expect(block.locator('input')).to_have_count(2)
      await expect(block.locator('input').first).not_to_be_visible()
      await block.locator('summary').click()
      await expect(page.get_by_label('Сервер времени 1',exact=True)).to_have_value('0.debian.pool.ntp.org')
      add=page.get_by_role('button',name='+ Добавить сервер',exact=True)
      for index in range(2,8):
        await add.click()
        await page.get_by_label(f'Сервер времени {index+1}',exact=True).fill(f'{index}.pool.ntp.org')
      await expect(add).to_be_disabled()
      await expect(block.locator('input')).to_have_count(8)
      await page.get_by_role('button',name='Удалить сервер времени 2',exact=True).click()
      await expect(add).to_be_enabled()
      await expect(page.get_by_label('Сервер времени 2',exact=True)).to_have_value('2.pool.ntp.org')
      await page.wait_for_timeout(800)
      assert len(cfg['system']['ntp']['servers'])==7
      await page.reload()
      await block.locator('summary').click()
      await expect(block.locator('input')).to_have_count(7)
      for width in [1440,390]:
        await page.set_viewport_size({'width':width,'height':1000})
        await block.screenshot(path=f'output/playwright/ntp-{width}.png')
        assert await block.evaluate('(el)=>el.scrollWidth<=el.clientWidth')
      await page.get_by_role('checkbox',name='Синхронизировать время автоматически',exact=True).locator('..').click()
      await expect(add).to_be_disabled()
      await expect(block.locator('input').first).to_be_disabled()
      await expect(block.get_by_role('button').first).to_be_disabled()
      assert not errors, errors
      await browser.close()
      print('PASS: NTP rows, limit, deletion, reload, disabled state, desktop/mobile')
asyncio.run(main())
