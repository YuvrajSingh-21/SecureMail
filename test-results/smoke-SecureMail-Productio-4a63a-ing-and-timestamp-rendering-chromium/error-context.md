# Instructions

- Following Playwright test failed.
- Explain why, be concise, respect Playwright best practices.
- Provide a snippet of code with the fix, if possible.

# Test info

- Name: smoke.spec.js >> SecureMail Production Smoke Tests >> Inbox loading and timestamp rendering
- Location: tests/e2e/smoke.spec.js:74:3

# Error details

```
Error: expect(locator).toBeVisible() failed

Locator: locator('#email-list, .inbox-container, main')
Expected: visible
Timeout: 5000ms
Error: element(s) not found

Call log:
  - Expect "toBeVisible" with timeout 5000ms
  - waiting for locator('#email-list, .inbox-container, main')

```

```yaml
- link "Securamail":
  - /url: /
  - img "Securamail"
- heading "Securamail" [level=1]
- paragraph: Intelligent Email Security & Threat Intelligence
- link "Continue with Google":
  - /url: /auth/google/login/
  - img
  - text: Continue with Google
- paragraph:
  - text: By continuing, you agree to Securamail's
  - link "Terms":
    - /url: /terms/
  - text: and
  - link "Privacy Policy":
    - /url: /privacy/
  - text: .
```

# Test source

```ts
  1   | const { test, expect } = require('@playwright/test');
  2   | 
  3   | test.describe.serial('SecureMail Production Smoke Tests', () => {
  4   |   let page;
  5   | 
  6   |   test.beforeAll(async ({ browser }) => {
  7   |     // We use a single context and page for all serial tests
  8   |     const context = await browser.newContext();
  9   |     page = await context.newPage();
  10  |   });
  11  | 
  12  |   test.afterAll(async () => {
  13  |     if (page) {
  14  |       await page.close();
  15  |     }
  16  |   });
  17  | 
  18  |   test('Production availability and login page load', async () => {
  19  |     // 7. Lightweight performance measurement for initial load
  20  |     const startTime = Date.now();
  21  |     await page.goto('/');
  22  |     const loadTime = Date.now() - startTime;
  23  |     console.log(`Initial page load time: ${loadTime}ms`);
  24  | 
  25  |     // Verify it didn't throw a 500 error
  26  |     const title = await page.title();
  27  |     expect(title).toContain('Securamail');
  28  |     
  29  |     // Navigate to Login if not already there
  30  |     if (!page.url().includes('/login')) {
  31  |         await page.goto('/login/');
  32  |     }
  33  |     
  34  |     // Check for Google OAuth button
  35  |     await expect(page.locator('a[href="/auth/google/login/"]')).toBeVisible();
  36  |   });
  37  | 
  38  |   test('Authentication via Google OAuth', async () => {
  39  |     // We will simulate clicking the Google OAuth button and completing the flow.
  40  |     // If the test doesn't have credentials in environment, we skip gracefully or fail.
  41  |     const testEmail = process.env.E2E_TEST_EMAIL;
  42  |     const testPassword = process.env.E2E_TEST_PASSWORD;
  43  |     
  44  |     if (!testEmail || !testPassword) {
  45  |       console.warn('Skipping Google Auth test: E2E_TEST_EMAIL or E2E_TEST_PASSWORD not set.');
  46  |       test.skip();
  47  |     }
  48  | 
  49  |     // Click Continue with Google
  50  |     await page.click('a[href="/auth/google/login/"]');
  51  | 
  52  |     // Wait for redirect to Google accounts
  53  |     await page.waitForURL(/accounts\.google\.com/);
  54  | 
  55  |     // Fill Email
  56  |     await page.fill('input[type="email"]', testEmail);
  57  |     await page.click('#identifierNext');
  58  | 
  59  |     // Fill Password
  60  |     await page.waitForSelector('input[type="password"]', { state: 'visible', timeout: 10000 });
  61  |     // Small delay to let Google animations finish
  62  |     await page.waitForTimeout(1000); 
  63  |     await page.fill('input[type="password"]', testPassword);
  64  |     await page.click('#passwordNext');
  65  | 
  66  |     // Wait for redirect back to our app (Inbox)
  67  |     // We measure time until Inbox becomes usable
  68  |     const startTime = Date.now();
  69  |     await page.waitForURL('**/inbox/', { timeout: 30000 });
  70  |     const authTime = Date.now() - startTime;
  71  |     console.log(`Time from login to Inbox: ${authTime}ms`);
  72  |   });
  73  | 
  74  |   test('Inbox loading and timestamp rendering', async () => {
  75  |     // Verify Inbox UI
  76  |     await expect(page.locator('h1').filter({ hasText: /Inbox|Securamail/i })).toBeVisible();
  77  |     
  78  |     // Verify Email list is rendered
  79  |     // Assuming emails are loaded in a list or table
  80  |     const emailRows = page.locator('.email-row, .email-item, tr.email').first();
  81  |     // We do not strict assert count > 0 because test account might be empty, 
  82  |     // but we can check the container exists.
> 83  |     await expect(page.locator('#email-list, .inbox-container, main')).toBeVisible();
      |                                                                       ^ Error: expect(locator).toBeVisible() failed
  84  | 
  85  |     // Verify timestamps are not invalid
  86  |     // Assuming timestamps have a specific class or we can just check there's no "Invalid Date" text
  87  |     const pageText = await page.content();
  88  |     expect(pageText).not.toContain('Invalid Date');
  89  |     expect(pageText).not.toContain('NaN');
  90  |   });
  91  | 
  92  |   test('Gmail synchronization API', async () => {
  93  |     // Verify sync UI or endpoint responds
  94  |     // Instead of clicking sync and causing traffic, we just verify the inbox_status endpoint is healthy
  95  |     const response = await page.request.get('/inbox_status/');
  96  |     expect(response.ok()).toBeTruthy();
  97  |     const data = await response.json();
  98  |     expect(data).toHaveProperty('total');
  99  |   });
  100 | 
  101 |   test('Sidebar toggle functionality', async () => {
  102 |     // Hamburger button toggle
  103 |     const hamburger = page.locator('button.mobile-menu-button, [data-lucide="menu"], .hamburger').first();
  104 |     
  105 |     if (await hamburger.isVisible()) {
  106 |       await hamburger.click();
  107 |       // Verify sidebar becomes visible
  108 |       const sidebar = page.locator('aside, .sidebar, #sidebar-menu');
  109 |       await expect(sidebar).toBeVisible();
  110 |     }
  111 |   });
  112 | 
  113 |   test('Compose modal/page rendering', async () => {
  114 |     // Do not send real emails. Just verify the UI.
  115 |     const composeBtn = page.locator('a[href="/compose/"], button:has-text("Compose")').first();
  116 |     await composeBtn.click();
  117 |     
  118 |     // Verify UI renders recipient/subject
  119 |     await expect(page.locator('input[name="recipient"], input[name="to"]')).toBeVisible();
  120 |     await expect(page.locator('input[name="subject"]')).toBeVisible();
  121 |     await expect(page.locator('textarea[name="body"], div.editor')).toBeVisible();
  122 |     
  123 |     // Navigate back to inbox safely
  124 |     await page.goto('/inbox/');
  125 |   });
  126 | 
  127 |   test('Sent folder navigation', async () => {
  128 |     const sentLink = page.locator('a[href="/inbox/SENT/"], a:has-text("Sent")').first();
  129 |     await sentLink.click();
  130 |     
  131 |     await page.waitForURL('**/inbox/SENT/');
  132 |     await expect(page.locator('body')).toBeVisible();
  133 |     
  134 |     // Basic check that it doesn't 500 error
  135 |     const pageText = await page.content();
  136 |     expect(pageText).not.toContain('Server Error');
  137 |   });
  138 | 
  139 | });
  140 | 
```