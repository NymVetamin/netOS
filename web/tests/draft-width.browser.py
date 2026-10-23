"""Real browser layout regression using the production stylesheet."""
import asyncio, os
from pathlib import Path
from playwright.async_api import async_playwright

async def main():
    css=(Path(__file__).resolve().parents[1]/'src/styles.css').read_text(encoding='utf8')
    async with async_playwright() as p:
        browser=await p.chromium.launch(executable_path=str(Path(os.environ['ProgramFiles'])/'Google/Chrome/Application/chrome.exe'),headless=True,ignore_default_args=["--hide-scrollbars"])
        for width in [1280,1920,390]:
            page=await browser.new_page(viewport={'width':width,'height':900})
            await page.set_content('<div id="root"><div class="app"><header class="topbar">netOS</header><div class="shell"><aside class="sidebar"></aside><main class="main"><div class="page"><div id="content">Content</div></div></main></div></div></div>')
            await page.add_style_tag(content=css)
            await page.evaluate('''() => {
              const main=document.querySelector('.main'), content=document.querySelector('#content');
              const mobile=innerWidth<=860;
              const available=mobile ? (innerHeight-main.getBoundingClientRect().top)/parseFloat(getComputedStyle(document.documentElement).getPropertyValue("--zoom")) : main.clientHeight;
              const style=getComputedStyle(document.querySelector('.page'));
              content.style.height=(available-parseFloat(style.paddingTop)-parseFloat(style.paddingBottom)-5)+'px';
            }''')
            measure='''() => {const e=document.querySelector('#content').getBoundingClientRect();return {x:e.x,width:e.width}}'''
            before=await page.evaluate(measure)
            await page.evaluate("document.documentElement.style.setProperty('--applybar-height','100px')")
            after=await page.evaluate(measure)
            assert before==after,(width,before,after)
            await page.evaluate("document.documentElement.style.removeProperty('--applybar-height')")
            assert await page.evaluate(measure)==before
            print(width,'stable width PASS')
            await page.close()
        await browser.close()

asyncio.run(main())
