import asyncio
import os
from playwright.async_api import async_playwright

FLAG = os.environ.get('FLAG')
URL_TEMPLATE = "http://web:5000/view/{}"

async def visit(fortune_id):
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context()
        await context.add_cookies([{
            'name': 'flag',
            'value': FLAG,
            'domain': 'web',
            'path': '/'
        }])
        page = await context.new_page()

        url = URL_TEMPLATE.format(fortune_id)
        try:
            print(f"[QC BOT] 🥠 Quality Control reviewing fortune: {url}")
            await page.goto(url, timeout=5000)
            await asyncio.sleep(5)
            print(f"[QC BOT] ✅ Fortune review complete")
        except Exception as e:
            print(f"[QC BOT] ❌ Error during review: {e}")
        finally:
            await browser.close()

async def main():
    queue_file = '/shared/queue.txt'
    if not os.path.exists(queue_file):
        open(queue_file, 'w').close()
        print("[QC BOT] Created queue file")
    
    last_pos = 0
    print("[QC BOT] 🥠 Fortune Cookie Quality Control Bot Started")
    print("[QC BOT] Monitoring for fortune submissions...")
    
    while True:
        try:
            with open(queue_file, 'r') as f:
                f.seek(last_pos)
                lines = f.readlines()
                last_pos = f.tell()
            for line in lines:
                fortune_id = line.strip()
                if fortune_id:
                    print(f"[QC BOT] 📋 New fortune submission in queue: {fortune_id}")
                    await visit(fortune_id)
        except Exception as e:
            print(f"[QC BOT] Error reading queue: {e}")
        await asyncio.sleep(5)

if __name__ == '__main__':
    asyncio.run(main())
