import asyncio
from playwright.async_api import async_playwright
import json

async def run():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={"width": 1920, "height": 1080})
        page = await context.new_page()

        # 1. Login
        await page.goto("http://localhost:8000/login/")
        # We need to register a user if not exists or create one via manage.py. 
        # Let's just create one via shell first.
        # Actually, we will execute manage.py in bash before running this script.
        
        await page.fill("input[name='username']", "testuser_trace")
        await page.fill("input[name='password']", "testpass_trace123")
        await page.click("button[type='submit']")
        await page.wait_for_load_state("networkidle")

        # 2. Intelligence Report Trace
        await page.goto("http://localhost:8000/dashboard/")
        await page.wait_for_load_state("networkidle")
        
        # Inject interceptor
        await page.evaluate("""
            window.dashboardTrace = {};
            
            // Override html2pdf
            const origHtml2Pdf = window.html2pdf;
            window.html2pdf = function() {
                const instance = origHtml2Pdf.apply(this, arguments);
                
                const origSet = instance.set;
                instance.set = function(opt) {
                    window.dashboardTrace.options = opt;
                    return origSet.apply(this, arguments);
                };
                
                const origFrom = instance.from;
                instance.from = function(element) {
                    window.dashboardTrace.sourceElement = {
                        id: element.id,
                        tag: element.tagName,
                        exists: document.body.contains(element),
                        childCount: element.childNodes.length,
                        innerHTML_len: element.innerHTML.length,
                        outerHTML_len: element.outerHTML.length,
                        containsCards: element.innerHTML.includes('Total Analyzed') || element.innerHTML.includes('bg-white dark:bg-gray-800')
                    };
                    
                    // Intercept cloneNode on this element
                    const origClone = element.cloneNode;
                    element.cloneNode = function(deep) {
                        const clone = origClone.apply(this, arguments);
                        window.dashboardTrace.cloneNodeInfo = {
                            wasCloned: true,
                            containsCards: clone.innerHTML.includes('Total Analyzed') || clone.innerHTML.includes('bg-white dark:bg-gray-800')
                        };
                        return clone;
                    };

                    return origFrom.apply(this, arguments);
                };
                return instance;
            };
        """)

        # Trigger Export
        await page.evaluate("if(typeof exportDashboardPDF === 'function') exportDashboardPDF();")
        await asyncio.sleep(2) # Wait for it to trigger
        
        dashboard_trace = await page.evaluate("window.dashboardTrace")
        print("--- INTELLIGENCE REPORT TRACE ---")
        print(json.dumps(dashboard_trace, indent=2))
        
        # 3. Forensic Report Trace
        # We need to go to an email view. But since it's a test user, they have no emails!
        # We can just inject the HTML or trigger it on a fake page.
        # Let's create an email via django shell first.
        
        await browser.close()

if __name__ == "__main__":
    asyncio.run(run())
