import { test, expect } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';

const fixture = JSON.parse(fs.readFileSync(path.join(process.env.SHOUGT_UI_WORK!, 'fixture.json'), 'utf8'));

test('stored Markdown cannot execute HTML payloads in a visitors browser', async ({ page, context }) => {
  await context.route('**/*', route => {
    const url = new URL(route.request().url());
    return ['localhost', '127.0.0.1', 'privileged.localhost'].includes(url.hostname) && Number(url.port) >= 10000
      ? route.continue() : route.abort();
  });
  await page.addInitScript(() => { (window as any).__shouAuditExecuted = false; });
  await page.goto(`/article/${fixture.audit_post.id}/`);
  const preview = page.locator('.md-editor-preview');
  await expect(preview).toContainText('审计中的正常内容');
  await expect(preview.locator('strong')).toContainText('正常加粗');
  await page.evaluate(() => Promise.all([...document.images].map(image => image.decode().catch(() => {}))));
  expect(await page.evaluate(() => (window as any).__shouAuditExecuted)).toBe(false);
  await expect(preview.locator('[onerror], [onload], iframe, script, a[href^="javascript:"]')).toHaveCount(0);
});

test('ordinary account cannot forge identities or use management endpoints over HTTP', async ({ request }) => {
  const login = await request.post('/api/security/password-login/', { data: fixture.normal });
  expect(login.status()).toBe(200);
  const auth = (await login.json()).authorization;
  const token = (payload: object) => 'Bearer ' + Buffer.from(JSON.stringify(payload)).toString('base64url') + '.' + auth.signature;
  const headers = { Authorization: token(auth.payload) };
  for (const url of ['/api/admin/user/', '/api/security/console-begin/', '/api/security/django-admin/']) {
    const response = url.includes('/admin/user/') ? await request.get(url, { headers }) : await request.post(url, { headers, data: {} });
    expect(response.status(), url).toBe(403);
  }
  const promoted = await request.put(`/api/admin/user/${fixture.normal.user_id}/?type=permission`, {
    headers, data: { super_admin: true, is_superuser: true },
  });
  expect(promoted.status()).toBe(403);
  for (const payload of [{ ...auth.payload, user_id: fixture.root.user_id },
                         { ...auth.payload, role_id: fixture.root.primary_role_id },
                         { ...auth.payload, source: 'server' }]) {
    const response = await request.get('/api/user/info/', { headers: { Authorization: token(payload) } });
    expect(response.status()).toBe(401);
  }
  const unchanged = await request.get('/api/user/info/', { headers });
  expect(unchanged.status()).toBe(200);
  expect((await unchanged.json()).permission.super_admin).toBe(false);
  const nested = '['.repeat(5000) + '0' + ']'.repeat(5000);
  const nestedToken = Buffer.from(nested).toString('base64url') + '.invalid';
  expect((await request.get('/api/user/info/', {
    headers: { Authorization: 'Bearer ' + nestedToken },
  })).status()).toBe(401);
  for (const url of ['/api/security/key-login-begin/', '/api/image/']) {
    expect((await request.post(url, {
      headers: { ...headers, 'Content-Type': 'application/json' },
      data: Buffer.from(nested),
    })).status(), url).toBe(400);
  }
});

test('mTLS console rejects missing certificates forged tickets cross-site requests and traversal', async ({ browser }) => {
  const origin = 'https://privileged.localhost:18443';
  const anonymous = await browser.newContext({ ignoreHTTPSErrors: true });
  try {
    await expect(anonymous.request.get(origin + '/', { headers: { 'X-Client-Cert': 'forged', 'X-SSL-Client-Verify': 'SUCCESS' } })).rejects.toThrow();
  } finally { await anonymous.close(); }
  const context = await browser.newContext({ ignoreHTTPSErrors: true, clientCertificates: [{
    origin, certPath: fixture.client_certificate, keyPath: fixture.client_key,
  }] });
  try {
    const page = await context.request.get(origin + '/');
    expect(page.status()).toBe(200);
    expect(page.headers()['content-security-policy']).toContain("frame-ancestors 'none'");
    expect(page.headers()['cache-control']).toContain('no-store');
    const sameOrigin = { Origin: origin };
    expect((await context.request.post(origin + '/api/login', { headers: sameOrigin, data: { ticket: 'forged-ticket' } })).status()).toBe(401);
    expect((await context.request.post(origin + '/api/prepare', { headers: sameOrigin, data: { action: 'list_logs', payload: {} } })).status()).toBe(401);
    expect((await context.request.post(origin + '/api/login', { headers: { Origin: 'https://untrusted.invalid' }, data: { ticket: 'forged-ticket' } })).status()).toBe(403);
    expect((await context.request.post(origin + '/api/login', { headers: sameOrigin, data: [] })).status()).toBe(400);
    expect((await context.request.post(origin + '/api/login', { headers: sameOrigin, data: { ticket: 'x'.repeat(70000) } })).status()).toBe(413);
    for (const path of ['/config.json', '/.env', '/%2e%2e/config.json', '/api/password_hash']) {
      expect((await context.request.get(origin + path)).status(), path).toBe(404);
    }
  } finally { await context.close(); }
});
