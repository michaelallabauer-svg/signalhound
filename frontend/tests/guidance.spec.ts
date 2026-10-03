import { test, expect, type Page } from '@playwright/test';
const asset = { id: 1, organization_id: 1, scope_id: 1, asset_type: 'IP', value: '192.168.1.1', active: true, source: 'nmap', known_asset: true, first_seen: '2026-10-01T10:00:00Z', last_seen: '2026-10-03T10:00:00Z' };
const service = { id: 1, asset_id: 1, protocol: 'TCP', port: 443, name: 'https', active: true, source: 'nmap' };
const run = { id: 1, status: 'COMPLETED', profile_name: 'internal_quick', target: asset.value, summary: {}, jobs: [] };
async function fixture(page: Page, observations: unknown[] = [], status = 'COMPLETED') {
  await page.route('**/health', route => route.fulfill({ json: { status: 'ok' } }));
  await page.route('**/api/v1/**', route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
    const data: Record<string, unknown> = {
      '/organizations': [{ id: 1, name: 'Test LAN' }],
      '/scopes': [{ id: 1, name: 'LAN', target: asset.value, active: true, scan_zone: 'INTERNAL_IT' }],
      '/assets': [asset], '/services': [service],
      '/assets/1/detail': { ...asset, services: [service], observations: [], service_observations: observations, findings: [] },
      '/assessments': [{ ...run, status }], '/assessments/1/detail': { ...run, status },
      '/scan-profiles': [{ name: 'internal_quick', display_name: 'Internal quick', scan_zone: 'INTERNAL_IT', adapter_sequence: ['nmap'] }],
    };
    return route.fulfill({ json: data[path] ?? [] });
  });
  await page.goto('/');
}
const observation = (id: number, date: string, metadata: Record<string, unknown>, source = 'web_fingerprint') => ({ id, observed_at: date, metadata, source, service_id: 1 });

test('latest fingerprint survives later discovery; metadata is text, errors and missing values are explicit', async ({ page }) => {
  await fixture(page, [
    observation(3, '2026-10-03T10:00:00Z', { title: '<img src=x onerror=alert(1)>', server: 'Router Server', redirect_location: 'javascript:alert(1)', error: 'TLS unavailable' }),
    observation(1, '2026-10-01T10:00:00Z', { title: 'Old title' }),
    observation(4, '2026-10-04T10:00:00Z', {}, 'nmap'),
  ]);
  await page.getByRole('button', { name: 'Inventory', exact: true }).click();
  const card = page.locator('.fingerprint-card');
  await expect(card).toHaveCount(1);
  await expect(card).toContainText('<img src=x onerror=alert(1)>');
  await expect(card).not.toContainText('Old title');
  await expect(card).toContainText('Collection incomplete: TLS unavailable');
  await expect(card).toContainText('Not available');
  await expect(card.locator('img, a')).toHaveCount(0);
  await page.getByRole('button', { name: 'About HTTP status', exact: true }).hover();
  await expect(page.getByRole('tooltip')).toContainText('None of these alone is a vulnerability');
});

test('empty fingerprints explain next action; help works on keyboard and mobile tap', async ({ page }) => {
  await fixture(page);
  await page.getByRole('button', { name: 'Inventory', exact: true }).click();
  await expect(page.getByText('No web fingerprints yet.', { exact: false })).toBeVisible();
  const help = page.getByRole('button', { name: 'Help for Type', exact: true });
  await help.focus();
  await expect(page.getByRole('tooltip')).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(page.getByRole('tooltip')).toHaveCount(0);
  await page.setViewportSize({ width: 390, height: 844 });
  await help.click();
  await expect(page.getByRole('tooltip')).toBeVisible();
  const bounds = await page.getByRole('tooltip').boundingBox();
  expect(bounds!.x).toBeGreaterThanOrEqual(0);
  expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(390);
});

test('workflow distinguishes preparation from execution and explains disabled follow-ups', async ({ page }) => {
  await fixture(page, [], 'FAILED');
  await page.getByRole('button', { name: 'Scanners', exact: true }).click();
  await expect(page.getByRole('list', { name: 'Assessment workflow' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Prepare web fingerprinting', exact: true })).toBeDisabled();
  await expect(page.getByText('Follow-up preparation becomes available', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'About preparing follow-ups' }).focus();
  await expect(page.getByRole('tooltip')).toContainText('They do not run scans');
});

test('large inventories bound concurrent service requests', async ({ page }) => {
  await fixture(page);
  await page.route('**/api/v1/assets?*', route => route.fulfill({ json: Array.from({ length: 24 }, (_, i) => ({ ...asset, id: i + 1 })) }));
  let active = 0;
  let peak = 0;
  let finished = 0;
  await page.route('**/api/v1/services?*', async route => {
    active += 1;
    peak = Math.max(peak, active);
    await new Promise(resolve => setTimeout(resolve, 30));
    await route.fulfill({ json: [] });
    active -= 1;
    finished += 1;
  });
  await page.reload();
  // React StrictMode deliberately mounts twice in the development test server.
  await expect.poll(() => finished).toBe(48);
  expect(peak).toBeLessThanOrEqual(8);
});
