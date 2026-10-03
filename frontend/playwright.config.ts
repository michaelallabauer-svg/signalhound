import { defineConfig } from '@playwright/test';
export default defineConfig({
  testDir: './tests',
  use: { baseURL: 'http://127.0.0.1:18011', viewport: { width: 1280, height: 900 } },
  webServer: { command: 'npm run dev -- --port 18011', url: 'http://127.0.0.1:18011', reuseExistingServer: false },
});
