import { test, expect, type Page } from '@playwright/test';
const input = { key: 'observation:7:cpe', reference: 'cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*', kind: 'CPE', service_id: 1, observation_id: 7, source: 'nmap', observed_at: '2026-10-03T10:00:00Z' };
const snapshot = {
  id: 1, asset_id: 1, created_at: '2026-10-03T11:00:00Z', status: 'PARTIAL', evidence: input,
  result: { notice: 'No confirmed findings are created.', total: 1, truncated: false,
    sources: [{ provider: 'NVD', status: 'OK', cached: true, fetched_at: '2026-10-03T10:30:00Z' }, { provider: 'CISA KEV', status: 'ERROR', error: 'Unavailable; retry later' }],
    candidates: [{ cve_id: 'CVE-2021-44228', description: '<img src=x onerror=alert(1)>', assessment: 'MAY_BE_AFFECTED', status: 'Analyzed', modified: null,
      confidence: 'MODERATE', match_reason: 'Version observed; patch level not verified.', cvss: { score: 10, version: '3.1', source: 'NVD', vector: 'CVSS:3.1/AV:N' }, epss: null, kev: null, kev_detail: null }]
  }
};
async function setup(page: Page, enabled = true, inputs = [input], runs: unknown[] = []) {
  let posts = 0;
  const errors: string[] = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.route('**/health', r => r.fulfill({ json: { status: 'ok' } }));
  await page.route('**/api/v1/**', route => {
    const path = new URL(route.request().url()).pathname.replace('/api/v1', '');
    const asset = { id: 1, organization_id: 1, value: '192.0.2.10', asset_type: 'IP', active: true, known_asset: false, source: 'nmap', first_seen: input.observed_at, last_seen: input.observed_at };
    if (path === '/assets/1/intelligence') {
      if (route.request().method() === 'POST') {
        posts++;
        expect(route.request().postDataJSON()).toEqual({ organization_id: 1, evidence_key: input.key });
        runs = [snapshot];
        return route.fulfill({ status: 201, json: snapshot });
      }
      return route.fulfill({ json: { enabled, inputs, software: [], runs } });
    }
    const data: Record<string, unknown> = {
      '/assets/1/risk': { algorithm_version: 'exposure-v1.0', snapshots: [] },
      '/organizations': [{ id: 1, name: 'Intelligence test' }], '/assets': [asset],
      '/assets/1/detail': { ...asset, services: [], observations: [], service_observations: [], findings: [] },
    };
    return route.fulfill({ json: data[path] ?? [] });
  });
  await page.goto('/');
  await page.getByRole('button', { name: 'Inventory', exact: true }).click();
  await expect(page.getByRole('region', { name: 'Vulnerability intelligence' })).toBeVisible();
  return { posts: () => posts, errors };
}

test('explicit lookup preserves distinction, unknown values, provenance and safe rendering', async ({ page }) => {
  const state = await setup(page);
  expect(state.posts()).toBe(0);
  await page.getByRole('button', { name: 'Look up intelligence', exact: true }).click();
  const region = page.getByRole('region', { name: 'Vulnerability intelligence' });
  await expect(region).toContainText('May be affected — unconfirmed');
  await expect(region).toContainText('Unknown — catalog unavailable');
  await expect(region).toContainText('Unknown / not supplied');
  await expect(region).toContainText('NVD: Cached');
  await expect(region).toContainText('<img src=x onerror=alert(1)>');
  await expect(region.locator('img')).toHaveCount(0);
  await page.getByRole('button', { name: 'About CVSS CVE-2021-44228' }).focus();
  await expect(page.getByRole('tooltip')).toContainText('not your organization’s risk score');
  await page.keyboard.press('Escape');
  await expect(page.getByRole('tooltip')).toHaveCount(0);
  expect(state.posts()).toBe(1);
  expect(state.errors).toEqual([]);
});

test('disabled lookups retain readable history and work on narrow screens', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const state = await setup(page, false, [input], [snapshot]);
  await expect(page.getByRole('button', { name: 'Look up intelligence', exact: true })).toBeDisabled();
  await expect(page.getByText('Public lookups are disabled.', { exact: false })).toBeVisible();
  await expect(page.getByText('May be affected — unconfirmed', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'About KEV CVE-2021-44228' }).click();
  await expect(page.getByRole('tooltip')).toContainText('does not mean this asset was attacked');
  expect(state.posts()).toBe(0);
  expect(state.errors).toEqual([]);
});

test('missing evidence and failed lookup are actionable, not a clean bill of health', async ({ page }) => {
  await setup(page, true, [], [{ ...snapshot, status: 'ERROR', result: { ...snapshot.result, candidates: [], total: null } }]);
  await expect(page.getByText('No lookup-ready evidence.', { exact: false })).toBeVisible();
  await expect(page.getByText('Lookup failed. Retry later;', { exact: false })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Look up intelligence', exact: true })).toHaveCount(0);
});
