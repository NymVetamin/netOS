// Run in an authenticated panel: playwright-cli -s=NAME run-code --filename=web/tests/logs-refresh.browser.js
// Only the browser's GET /api/logs responses are replaced; router configuration is untouched.
async page => {
 const check=(ok,message)=>{if(!ok)throw new Error(message)};
 let release, pending=false, fail=false, serial=0;
 const handler=async route=>{
  const kind=new URL(route.request().url()).searchParams.get('kind');
  if(pending)await new Promise(resolve=>{release=resolve});
  await route.fulfill({status:fail?500:200,contentType:'application/json',body:JSON.stringify(fail?{error:'test failure'}:{captured_at:'2026-01-01T00:00:00Z',entries:Array.from({length:30},(_,i)=>({time:'2026-01-01T00:00:00Z',source:kind,unit:'test',message:`${kind} snapshot ${serial} row ${i}`}))})});
 };
 await page.route('**/api/logs?*',handler);
 try {
  await page.getByRole('navigation').getByRole('button',{name:'Диагностика',exact:true}).click();
  const details=page.locator('.logs-section');
  if(!await details.evaluate(e=>e.open))await details.locator('summary').click();
  await page.locator('.logs-content table').waitFor();
  await page.locator('.logs-content table').evaluate(e=>{e.dataset.testIdentity='retained';e.parentElement.parentElement.scrollTop=200});
  const height=(await page.locator('.logs-content').boundingBox()).height;
  pending=true;serial++;
  await page.getByRole('button',{name:'Обновить журнал',exact:true}).click();
  await page.locator('.logs-content[aria-busy="true"]').waitFor();
  check(await page.locator('.logs-content table').count()===1,'refresh removed table');
  check(Math.abs((await page.locator('.logs-content').boundingBox()).height-height)<1,'refresh changed height');
  while(!release)await new Promise(r=>setTimeout(r,10));release();release=null;pending=false;
  await page.locator('.logs-content[aria-busy="false"]').waitFor();
  const retained=await page.locator('.logs-content table').evaluate(e=>e.dataset.testIdentity==='retained'&&e.parentElement.parentElement.scrollTop>190);
  check(retained,'refresh lost table/scroll');
  fail=true;
  await page.getByRole('button',{name:'Обновить журнал',exact:true}).click();
  await page.getByText('Не удалось загрузить журнал',{exact:true}).waitFor();
  check(await page.locator('.logs-content table').count()===1,'failure lost last snapshot');
  check(await page.getByRole('button',{name:'Скачать журнал',exact:true}).isDisabled(),'failed snapshot can be exported');
  fail=false;
  await page.getByRole('button',{name:'Обновить журнал',exact:true}).click();
  await page.getByText('Не удалось загрузить журнал',{exact:true}).waitFor({state:'hidden'});
  await page.locator('.logs-content[aria-busy="false"]').waitFor();
  const current=await page.getByRole('tab',{selected:true}).innerText();
  const target=current==='Firewall'?'Службы':'Firewall';
  pending=true;
  await page.getByRole('tab',{name:target,exact:true}).click();
  await page.locator('.logs-content[aria-busy="true"]').waitFor();
  check(await page.locator('.logs-content table').count()===0,'previous source shown under new tab');
  while(!release)await new Promise(r=>setTimeout(r,10));release();release=null;pending=false;
  await page.locator('.logs-content[aria-busy="false"]').waitFor();
  await page.getByRole('textbox',{name:'Поиск в журнале'}).fill('row 29');
  check(await page.locator('.logs-content tbody tr').count()===1,'filter stopped working');
  return {refreshHeightDelta:0,scrollRetained:true,failureRecovery:true,sourceIsolation:true,filter:true};
 } finally {if(release)release();await page.unroute('**/api/logs?*',handler);}
}
