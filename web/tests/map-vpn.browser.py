"""Local production UI regression; all API calls are mocked, no router access."""
import asyncio
import re
import mimetypes
import os
from pathlib import Path
from urllib.parse import urlparse
from playwright.async_api import async_playwright, expect

DIST = Path(__file__).resolve().parents[2] / "backend/internal/api/webdist"


async def scenario(browser, mode):
    page = await browser.new_page(viewport={"width":1600,"height":1000})
    errors, writes = [], []
    page.on("pageerror",lambda e:errors.append(str(e)))
    cfg={"system":{"hostname":"router"},"interfaces":[{"id":"lan","name":"br-lan","type":"bridge"}],"wans":[],"channels":[],"policies":[],
         "networks":[{"id":"lan","name":"LAN","enabled":True,"interface":"lan","router_address":"192.168.10.1/24"}],"vpn_servers":[]}
    if mode!="no-vpn":
        cfg["vpn_servers"]=[{"id":"wg1","name":"VPN server","type":"wireguard","enabled":True,"subnet":"10.9.0.1/24",
           "peers":[{"id":"phone","name":"Phone","address":"10.9.0.2","enabled":True},
                    {"id":"tablet","name":"Tablet","address":"10.9.0.3","enabled":True},
                    {"id":"denied","name":"Denied","address":"10.9.0.4","enabled":False}]}]
    if mode=="many":
        cfg["vpn_servers"].append({"id":"wg2","name":"Other server","type":"wireguard","enabled":False,"peers":[{"id":"phone","name":"Other phone","enabled":True}]})
    cfg['channels']=[{'id':f'ch{i}','name':f'Exit {i}','type':'xray','enabled':True} for i in range(5 if mode=='many' else 2)]
    telemetry_error=mode=="error"
    async def route_request(route):
        req,path=route.request,urlparse(route.request.url).path
        if not path.startswith("/api/"):
            file=DIST/("index.html" if path=="/" else path.lstrip("/"))
            await route.fulfill(body=file.read_bytes(),content_type=mimetypes.guess_type(str(file))[0] or "application/octet-stream");return
        body,status={},200
        if req.method!="GET":writes.append(path)
        if path=="/api/session":body={"username":"admin","role":"admin","csrf_token":"test"}
        elif path=="/api/config":body={"config":cfg,"dirty":False,"draft_version":1,"problems":[],"pending_confirmation":False}
        elif path=="/api/status":body={"interfaces":[],"wans":[],"channels":[],"uptime_seconds":100}
        elif path=="/api/clients":body={"clients":[]}
        elif path.endswith("/clients") and path.startswith("/api/vpn-servers/"):
            body=[{"id":"phone","state":"recent","endpoint":"192.0.2.10:4567","last_handshake":1700000000,"received":1234,"sent":5678},
                  {"id":"tablet","state":"never"}]
            if telemetry_error:status,body=503,{"error":"unavailable"}
        await route.fulfill(status=status,json=body)
    await page.route("**/*",route_request)
    await page.goto("http://netos-ui.test/#map")
    graph=page.get_by_role("group",name="Схема сети")
    await expect(graph.get_by_role("button",name="LAN:",exact=False)).to_be_visible()
    await expect(graph.get_by_role('button',name='Exit 0:',exact=False)).to_be_visible()
    await expect(graph.get_by_role('button',name='Exit 1:',exact=False)).to_be_visible()
    if mode!='no-vpn':
        await expect(graph.get_by_role('button',name='VPN server:',exact=False).locator('circle')).to_have_class('nd ok')
    box=await graph.bounding_box()
    assert box['y']+box['height']<1000
    live=graph.locator('.edge.live').first
    await expect(live).to_have_css('animation-name','flow')
    offset=await live.evaluate('(e)=>getComputedStyle(e).strokeDashoffset')
    await page.wait_for_timeout(180)
    assert await live.evaluate('(e)=>getComputedStyle(e).strokeDashoffset')!=offset
    for edge in await graph.locator('.edge.idle, .edge.dead').all():
        await expect(edge).to_have_css('animation-name','none')
    await page.emulate_media(reduced_motion='reduce')
    await expect(live).to_have_css('animation-name','none')
    await page.emulate_media(reduced_motion='no-preference')
    await expect(live).to_have_css('animation-name','flow')
    if mode=='many':
        await expect(graph.get_by_role('button',name='Other server:',exact=False).locator('circle')).to_have_class('nd idle')
        nodes=await graph.get_by_role('button',name=re.compile(r'^Exit ')).all()
        boxes=[await n.bounding_box() for n in nodes]
        for i,a in enumerate(boxes):
            for b in boxes[i+1:]:
                assert a['x']+a['width']<=b['x'] or b['x']+b['width']<=a['x'] or a['y']+a['height']<=b['y'] or b['y']+b['height']<=a['y']
    if mode=="healthy":
        # Navigation must preserve selection, cursor anchor and live polling.
        canvas=graph.locator(":scope > g")
        before=await canvas.get_attribute("transform")
        box=await graph.bounding_box()
        x,y=round(box["x"]+box["width"]*.5),round(box["y"]+box["height"]*.5)
        await page.mouse.move(x,y)
        scroll=await page.evaluate("window.scrollY")
        anchor=await canvas.evaluate("(e,p)=>{const q=new DOMPoint(...p).matrixTransform(e.getScreenCTM().inverse());return [q.x,q.y]}",[x,y])
        await page.mouse.wheel(0,-250)
        await expect(canvas).not_to_have_attribute("transform",before)
        assert await page.evaluate("window.scrollY")==scroll
        matrix=await canvas.evaluate("e=>{const m=e.getCTM();return [m.a,m.d,m.e,m.f]}")
        assert matrix[0]>1
        after_anchor=await canvas.evaluate("(e,p)=>{const q=new DOMPoint(...p).matrixTransform(e.getScreenCTM().inverse());return [q.x,q.y]}",[x,y])
        assert all(abs(a-b)<0.1 for a,b in zip(anchor,after_anchor)),(anchor,after_anchor)
        zoomed=await canvas.get_attribute("transform")
        await page.wait_for_timeout(5500)
        await expect(canvas).to_have_attribute("transform",zoomed)
        await page.get_by_role("button",name="Показать всю карту",exact=True).click()
        await expect(canvas).to_have_attribute("transform",before)
        node=graph.get_by_role("button",name="LAN:",exact=False)
        nb=await node.bounding_box()
        await page.mouse.move(nb["x"]+20,nb["y"]+20)
        await page.mouse.down()
        await page.wait_for_timeout(1100)
        await page.mouse.move(nb["x"]+100,nb["y"]+50,steps=10)
        await page.mouse.up()
        await expect(canvas).not_to_have_attribute("transform",before)
        await expect(node).to_have_attribute("aria-pressed","false")
        await page.get_by_role("button",name="Показать всю карту",exact=True).click()
        await node.click()
        await expect(node).to_have_attribute("aria-pressed","true")
        await graph.get_by_role("button",name="Роутер router",exact=True).focus()
        await page.keyboard.press("Enter")
        await expect(node).to_have_attribute("aria-pressed","false")
        for percent in [125,156,195,244,305,381,400]:
            await page.get_by_role("button",name="Увеличить карту",exact=True).click()
            await expect(page.get_by_label("Масштаб карты",exact=True)).to_have_text(f'{percent}%')
        await expect(page.get_by_role("button",name="Увеличить карту",exact=True)).to_be_disabled()
        await page.get_by_role("button",name="Показать всю карту",exact=True).click()
    if mode=="no-vpn":
        await expect(graph.get_by_role("button",name=re.compile(r"^Phone:"))).to_have_count(0)
    else:
        phone=graph.get_by_role("button",name=re.compile(r"^Phone:"))
        await expect(phone).to_be_visible()
        await expect(graph.get_by_role("button",name="Tablet:",exact=False)).to_be_visible()
        await expect(graph.get_by_role("button",name="Denied:",exact=False)).to_be_visible()
        await phone.click()
        await expect(page.get_by_text("10.9.0.2",exact=True)).to_be_visible()
        if mode=="error":
            await expect(page.get_by_text("Состояние VPN-клиентов недоступно",exact=True)).to_be_visible()
            await expect(page.get_by_text("состояние неизвестно",exact=True)).to_be_visible()
        else:
            await expect(page.get_by_text("192.0.2.10:4567",exact=True)).to_be_visible()
            if mode=="many":
                await graph.get_by_role("button",name="Other phone:",exact=False).click()
                await expect(page.get_by_text("сервер выключен",exact=True)).to_be_visible()
            else:
                artifact=Path("output/playwright/map-vpn.png");artifact.parent.mkdir(parents=True,exist_ok=True)
                await page.screenshot(path=str(artifact),full_page=True)
                card=page.locator('.map-layout > .card').last
                for width in [1920,1366,1110,1024,768,390,320]:
                    await page.set_viewport_size({'width':width,'height':1000})
                    for text in ['10.9.0.2','192.0.2.10:4567','10.9.0.1/24']:
                        value=card.get_by_text(text,exact=True)
                        await expect(value).to_be_visible()
                        assert await value.evaluate("e=>{const r=document.createRange();r.selectNodeContents(e);return r.getClientRects().length===1}"), (width,text)
                    assert await card.evaluate('e=>e.scrollWidth<=e.clientWidth'), width
                await card.screenshot(path='output/playwright/map-node-mobile.png')
                await page.set_viewport_size({'width':1366,'height':1000})
                await card.screenshot(path='output/playwright/map-node-desktop.png')
                telemetry_error=True
                await expect(page.get_by_text("Состояние VPN-клиентов недоступно",exact=True)).to_be_visible(timeout=10000)
                await expect(page.get_by_text("состояние неизвестно",exact=True)).to_be_visible()
                await expect(page.get_by_text("192.0.2.10:4567",exact=True)).to_have_count(0)
    assert not errors,errors
    assert not writes,writes
    await page.close();print(mode,"PASS")

async def main():
    async with async_playwright() as p:
        executable = os.environ.get("PLAYWRIGHT_CHROMIUM_EXECUTABLE")
        if not executable and os.name == "nt":
            executable = str(Path(os.environ["ProgramFiles"]) / "Google/Chrome/Application/chrome.exe")
        browser = await p.chromium.launch(headless=True, executable_path=executable)
        for mode in ("healthy", "error", "many", "no-vpn"):
            await scenario(browser, mode)
        await browser.close()

asyncio.run(main())
