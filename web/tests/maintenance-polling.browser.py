"""Production UI, intercepted API only: restore polling must survive daemon restart."""
import asyncio,mimetypes,os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright,expect

DIST=Path(__file__).resolve().parents[2]/'backend/internal/api/webdist'

async def scenario(browser,restart):
 page=await browser.new_page()
 state={'hostname':'before','operation':'idle','offline':False,'restores':0,'config_reads':0}
 errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 async def route_request(route):
  req=route.request;path=urlparse(req.url).path
  if not path.startswith('/api/'):
   file=DIST/('index.html' if path=='/' else path.lstrip('/'))
   assert file.parent==DIST and file.is_file(),path
   await route.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or 'application/octet-stream');return
  if state['offline'] and path in ['/api/status','/api/maintenance/status']:
   await route.abort();return
  body={}
  if path=='/api/session':body={'username':'admin','role':'admin','csrf_token':'test'}
  elif path=='/api/panel-users':body=[]
  elif path=='/api/config':
   state['config_reads']+=1
   body={'config':{'system':{'hostname':state['hostname']},'interfaces':[],'networks':[],'policies':[],'channels':[]},'dirty':False,'draft_version':1,'problems':[],'pending_confirmation':False}
  elif path=='/api/status':body={'interfaces':[],'channels':[],'version':'v0.22','uptime_seconds':1}
  elif path=='/api/backups':body={'backups':[{'name':'saved.tar.gz','size':1024,'modified':'2026-10-26T00:00:00Z'}]}
  elif path=='/api/maintenance/status':body={'state':state['operation'],'failed':False}
  elif path=='/api/maintenance/restore':
   assert req.post_data_json=={'name':'saved.tar.gz','confirm':'RESTORE'}
   state['restores']+=1;state['operation']='idle' if restart else 'active';body={'scheduled':True}
  await route.fulfill(json=body,content_type='application/json')
 await page.route('**/*',route_request);await page.goto('https://netos-ui.test/#system')
 await page.get_by_role('button',name='Восстановить',exact=True).click()
 confirm=page.locator('.btn.danger').filter(has_text='Восстановить')
 await expect(confirm).to_be_disabled();await page.get_by_label('Подтверждение восстановления').fill('RESTORE');await confirm.click()
 await expect(page.get_by_text('Восстановление запланировано',exact=True)).to_be_visible()
 if restart:state['offline']=True
 await page.wait_for_timeout(2600)
 reads=state['config_reads'];state['offline']=False;state['operation']='idle';state['hostname']='restored'
 await expect(page.get_by_text('Восстановление запланировано',exact=True)).to_have_count(0,timeout=7000)
 assert state['config_reads']>reads,'restored configuration was not reloaded'
 await expect(page.get_by_label('Подтверждение восстановления')).to_have_count(0)
 assert state['restores']==1 and not errors,(state,errors)
 await page.close();print('restore restart' if restart else 'restore active/idle','PASS')

async def main():
 async with async_playwright() as p:
  executable=os.environ.get('PLAYWRIGHT_CHROMIUM_EXECUTABLE')
  if not executable and os.name=='nt':executable=str(Path(os.environ['ProgramFiles'])/'Google/Chrome/Application/chrome.exe')
  browser=await p.chromium.launch(headless=True,executable_path=executable)
  for restart in [False,True]:await scenario(browser,restart)
  await browser.close()
asyncio.run(main())
