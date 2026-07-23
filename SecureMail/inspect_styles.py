import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        context = await browser.new_context()
        page = await context.new_page()
        
        # Go to dashboard
        await page.goto("http://localhost:8000/dashboard/")
        
        # Set dark mode
        await page.evaluate("""() => {
            localStorage.setItem('theme', 'dark');
            document.documentElement.setAttribute('data-theme', 'dark');
            document.documentElement.classList.add('dark');
            document.body.className = 'h-full transition-colors duration-300 dark-mode bg-gray-900';
        }""")
        
        # Wait a bit for transition
        await page.wait_for_timeout(500)
        
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
                    borderLeftWidth: styles.borderLeftWidth,
                    borderRightWidth: styles.borderRightWidth,
                    borderColor: styles.borderColor,
                    outlineStyle: styles.outlineStyle,
                    outlineWidth: styles.outlineWidth,
                    boxShadow: styles.boxShadow,
                    backdropFilter: styles.backdropFilter
                };
            }""", element)
        
        # Check elements
        elements = [
            "h1",
            "header",
            "#dashboard-content",
            "main",
            "body"
        ]
        
        for sel in elements:
            print(f"--- Styles for {sel} ---")
            styles = await get_styles(sel)
            if styles:
                for k, v in styles.items():
                    print(f"{k}: {v}")
            else:
                print("Element not found")
        
        # Also check pseudo elements on h1
        print("--- Pseudo elements on h1 ---")
        h1_pseudo = await page.evaluate("""() => {
            const el = document.querySelector('h1');
            const before = window.getComputedStyle(el, '::before');
            const after = window.getComputedStyle(el, '::after');
            return {
                before: before.content !== 'none' ? before.backgroundColor + ' ' + before.borderStyle : 'none',
                after: after.content !== 'none' ? after.backgroundColor + ' ' + after.borderStyle : 'none'
            };
        }""")
        print(h1_pseudo)
        
        await browser.close()

asyncio.run(main())
