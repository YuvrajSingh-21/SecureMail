const { test, expect } = require('@playwright/test');

test.describe.serial('SecureMail Production Smoke Tests', () => {
  let page;

  test.beforeAll(async ({ browser }) => {
    // We use a single context and page for all serial tests
    const context = await browser.newContext();
    page = await context.newPage();
  });

  test.afterAll(async () => {
    if (page) {
      await page.close();
    }
  });

  test('Production availability and login page load', async () => {
    // 7. Lightweight performance measurement for initial load
    const startTime = Date.now();
    await page.goto('/');
    const loadTime = Date.now() - startTime;
    console.log(`Initial page load time: ${loadTime}ms`);

    // Verify it didn't throw a 500 error
    const title = await page.title();
    expect(title).toContain('Securamail');
    
    // Navigate to Login if not already there
    if (!page.url().includes('/login')) {
        await page.goto('/login/');
    }
    
    // Check for Google OAuth button
    await expect(page.locator('a[href="/auth/google/login/"]')).toBeVisible();
  });

  test('Authentication via Google OAuth', async () => {
    // We will simulate clicking the Google OAuth button and completing the flow.
    // If the test doesn't have credentials in environment, we skip gracefully or fail.
    const testEmail = process.env.E2E_TEST_EMAIL;
    const testPassword = process.env.E2E_TEST_PASSWORD;
    
    if (!testEmail || !testPassword) {
      console.warn('Skipping Google Auth test: E2E_TEST_EMAIL or E2E_TEST_PASSWORD not set.');
      test.skip();
    }

    // Click Continue with Google
    await page.click('a[href="/auth/google/login/"]');

    // Wait for redirect to Google accounts
    await page.waitForURL(/accounts\.google\.com/);

    // Fill Email
    await page.fill('input[type="email"]', testEmail);
    await page.click('#identifierNext');

    // Fill Password
    await page.waitForSelector('input[type="password"]', { state: 'visible', timeout: 10000 });
    // Small delay to let Google animations finish
    await page.waitForTimeout(1000); 
    await page.fill('input[type="password"]', testPassword);
    await page.click('#passwordNext');

    // Wait for redirect back to our app (Inbox)
    // We measure time until Inbox becomes usable
    const startTime = Date.now();
    await page.waitForURL('**/inbox/', { timeout: 30000 });
    const authTime = Date.now() - startTime;
    console.log(`Time from login to Inbox: ${authTime}ms`);
  });

  test('Inbox loading and timestamp rendering', async () => {
    // Verify Inbox UI
    await expect(page.locator('h1').filter({ hasText: /Inbox|Securamail/i })).toBeVisible();
    
    // Verify Email list is rendered
    // Assuming emails are loaded in a list or table
    const emailRows = page.locator('.email-row, .email-item, tr.email').first();
    // We do not strict assert count > 0 because test account might be empty, 
    // but we can check the container exists.
    await expect(page.locator('#email-list, .inbox-container, main')).toBeVisible();

    // Verify timestamps are not invalid
    // Assuming timestamps have a specific class or we can just check there's no "Invalid Date" text
    const pageText = await page.content();
    expect(pageText).not.toContain('Invalid Date');
    expect(pageText).not.toContain('NaN');
  });

  test('Gmail synchronization API', async () => {
    // Verify sync UI or endpoint responds
    // Instead of clicking sync and causing traffic, we just verify the inbox_status endpoint is healthy
    const response = await page.request.get('/inbox_status/');
    expect(response.ok()).toBeTruthy();
    const data = await response.json();
    expect(data).toHaveProperty('total');
  });

  test('Sidebar toggle functionality', async () => {
    // Hamburger button toggle
    const hamburger = page.locator('button.mobile-menu-button, [data-lucide="menu"], .hamburger').first();
    
    if (await hamburger.isVisible()) {
      await hamburger.click();
      // Verify sidebar becomes visible
      const sidebar = page.locator('aside, .sidebar, #sidebar-menu');
      await expect(sidebar).toBeVisible();
    }
  });

  test('Compose modal/page rendering', async () => {
    // Do not send real emails. Just verify the UI.
    const composeBtn = page.locator('a[href="/compose/"], button:has-text("Compose")').first();
    await composeBtn.click();
    
    // Verify UI renders recipient/subject
    await expect(page.locator('input[name="recipient"], input[name="to"]')).toBeVisible();
    await expect(page.locator('input[name="subject"]')).toBeVisible();
    await expect(page.locator('textarea[name="body"], div.editor')).toBeVisible();
    
    // Navigate back to inbox safely
    await page.goto('/inbox/');
  });

  test('Sent folder navigation', async () => {
    const sentLink = page.locator('a[href="/inbox/SENT/"], a:has-text("Sent")').first();
    await sentLink.click();
    
    await page.waitForURL('**/inbox/SENT/');
    await expect(page.locator('body')).toBeVisible();
    
    // Basic check that it doesn't 500 error
    const pageText = await page.content();
    expect(pageText).not.toContain('Server Error');
  });

});
