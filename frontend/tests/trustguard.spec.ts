import { test, expect } from '@playwright/test';

const API = 'http://localhost:8000';

// ── API contract tests ──────────────────────────────────────────────────────

test('GET /health returns ok', async ({ request }) => {
  const res = await request.get(`${API}/health`);
  expect(res.ok()).toBeTruthy();
  expect(await res.json()).toMatchObject({ status: 'ok' });
});

test('POST /scan returns expected shape', async ({ request }) => {
  const res = await request.post(`${API}/scan`, {
    data: { url: 'https://google.com' }
  });
  expect(res.ok()).toBeTruthy();
  const body = await res.json();
  expect(body).toHaveProperty('url');
  expect(body).toHaveProperty('risk_score');
  expect(body).toHaveProperty('prediction');
  expect(body).toHaveProperty('reasons');
  expect(typeof body.risk_score).toBe('number');
});

test('GET /history returns array', async ({ request }) => {
  const res = await request.get(`${API}/history?limit=5`);
  expect(res.ok()).toBeTruthy();
  expect(Array.isArray(await res.json())).toBeTruthy();
});

test('POST /report returns success', async ({ request }) => {
  const res = await request.post(`${API}/report`, {
    data: { url: 'https://google.com', is_phishing: false, comments: 'test' }
  });
  expect(res.ok()).toBeTruthy();
  expect(await res.json()).toMatchObject({ status: 'success' });
});

// ── UI tests ────────────────────────────────────────────────────────────────

test('page loads with TrustGuard title and 3 tabs', async ({ page }) => {
  await page.goto('/');
  await expect(page).toHaveTitle('TrustGuard');
  await expect(page.getByRole('button', { name: /scan url/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /history/i })).toBeVisible();
  await expect(page.getByRole('button', { name: /dashboard/i })).toBeVisible();
});

test('scan tab: analyze button disabled when input empty', async ({ page }) => {
  await page.goto('/');
  await expect(page.getByRole('button', { name: /analyze/i })).toBeDisabled();
});

test('scan tab: submitting a URL shows result card', async ({ page }) => {
  await page.goto('/');
  await page.fill('.search-input', 'https://google.com');
  await expect(page.getByRole('button', { name: /analyze/i })).toBeEnabled();
  await page.click('button[type="submit"]');
  await expect(page.locator('.card').first()).toBeVisible({ timeout: 15000 });
  await expect(page.getByText(/analysis complete/i)).toBeVisible();
});

test('scan tab: result shows risk score ring', async ({ page }) => {
  await page.goto('/');
  await page.fill('.search-input', 'https://google.com');
  await page.click('button[type="submit"]');
  await expect(page.locator('.circular-chart')).toBeVisible({ timeout: 15000 });
  await expect(page.locator('.score-label')).toContainText(/risk score/i);
});

test('scan tab: report form appears after scan', async ({ page }) => {
  await page.goto('/');
  await page.fill('.search-input', 'https://google.com');
  await page.click('button[type="submit"]');
  await expect(page.getByRole('button', { name: /phishing/i })).toBeVisible({ timeout: 15000 });
  await expect(page.getByRole('button', { name: /legitimate/i })).toBeVisible();
});

test('scan tab: submitting report shows confirmation', async ({ page }) => {
  await page.goto('/');
  await page.fill('.search-input', 'https://google.com');
  await page.click('button[type="submit"]');
  await expect(page.getByRole('button', { name: /legitimate/i })).toBeVisible({ timeout: 15000 });
  await page.click('button:has-text("Legitimate")');
  await expect(page.getByText(/report submitted/i)).toBeVisible({ timeout: 5000 });
});

test('history tab: renders table with headers', async ({ page }) => {
  await page.goto('/');
  await page.click('button:has-text("History")');
  await expect(page.locator('.history-table')).toBeVisible();
  await expect(page.locator('th', { hasText: /url/i })).toBeVisible();
  await expect(page.locator('th', { hasText: /score/i })).toBeVisible();
  await expect(page.locator('th', { hasText: /status/i })).toBeVisible();
});

test('dashboard tab: renders stat cards', async ({ page }) => {
  await page.goto('/');
  await page.click('button:has-text("Dashboard")');
  await expect(page.locator('.stat-card').first()).toBeVisible();
  await expect(page.getByText(/total scans/i)).toBeVisible();
  await expect(page.locator('.stat-label', { hasText: /phishing/i }).first()).toBeVisible();
  await expect(page.locator('.stat-label', { hasText: /safe/i })).toBeVisible();
});

test('dashboard tab: threat breakdown bars visible', async ({ page }) => {
  await page.goto('/');
  await page.click('button:has-text("Dashboard")');
  await expect(page.getByText(/threat breakdown/i)).toBeVisible();
});
