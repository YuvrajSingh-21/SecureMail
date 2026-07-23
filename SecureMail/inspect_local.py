import asyncio
from playwright.async_api import async_playwright
import os

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        
        # Load local HTML file directly
        # First create a test html that includes the css and the header
        html_content = """
        <!DOCTYPE html>
        <html lang="en" data-theme="dark" class="dark">
        <head>
            <style>
            :root {
                --bg: #0a0e1a;
                --surface: #1f2937;
                --surface-alt: #111827;
                --text: #f9fafb;
                --text-secondary: #94a3b8;
                --border: #374151;
                --header-bg: #1f2937;
            }
            </style>
            <link rel="stylesheet" href="file:///home/lonewolf/Email_Phisher/Email_Phisher/SecureMail/static/SecureMail/css/global.css">
            <script src="https://cdn.tailwindcss.com"></script>
        </head>
        <body class="bg-gray-900">
            <main class="flex-1 overflow-y-auto p-6 md:p-10 transition-all duration-300">
                <div id="dashboard-content" class="max-w-7xl mx-auto">
                    <header class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-12 animate-slide-up">
                        <div>
                            <h1 class="text-4xl font-black text-gray-900 dark:text-white tracking-tight">Security Center</h1>
                        </div>
                    </header>
                </div>
            </main>
        </body>
        </html>
        """
        
        with open('test.html', 'w') as f:
            f.write(html_content)
            
        await page.goto(f"file://{os.path.abspath('test.html')}")
        await page.wait_for_timeout(1000)
        
        # Helper to get computed styles
        async def get_styles(selector):
            element = await page.query_selector(selector)
            if not element:
                return None
            return await page.evaluate("""(el) => {
                const styles = window.getComputedStyle(el);
                return {
                    backgroundColor: styles.backgroundColor,
                    borderTopWidth: styles.borderTopWidth,
                    borderBottomWidth: styles.borderBottomWidth,
                    borderStyle: styles.borderBottomStyle,
                    borderColor: styles.borderBottomColor,
                    outlineStyle: styles.outlineStyle,
                    boxShadow: styles.boxShadow
                };
            }""", element)
        
        elements = ["h1", "header", "#dashboard-content", "main", "body"]
        for sel in elements:
            print(f"--- {sel} ---")
            styles = await get_styles(sel)
            if styles:
                print(styles)
        
        await browser.close()

asyncio.run(main())
