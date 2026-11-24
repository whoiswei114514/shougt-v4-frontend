const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function isValidUuid(value: unknown): value is string {
  return typeof value === 'string' && UUID_RE.test(value);
}

export function getTrustedConsoleOrigin(rawUrl: unknown): string | null {
  if (typeof rawUrl !== 'string' || !rawUrl.trim()) return null;
  try {
    const parsed = new URL(rawUrl.trim());
    if (parsed.origin === 'null') return null;
    if (parsed.protocol === 'https:') return parsed.origin;
    if (parsed.protocol === 'http:' && LOOPBACK_HOSTS.has(parsed.hostname)) {
      return parsed.origin;
    }
  } catch {
    return null;
  }
  return null;
}

export function validateConsoleHandoffUrl(handoffUrl: unknown, expectedConsoleUrl: unknown): string {
  const expectedOrigin = getTrustedConsoleOrigin(expectedConsoleUrl);
  if (!expectedOrigin) {
    throw new Error('特权管理站配置地址无效');
  }
  if (typeof handoffUrl !== 'string' || !handoffUrl.trim()) {
    throw new Error('特权管理站跳转地址无效');
  }
  if (/[\u0000-\u001f\u007f]/.test(handoffUrl)) {
    throw new Error('特权管理站跳转地址包含非法字符');
  }
  const parsed = new URL(handoffUrl);
  if (parsed.origin !== expectedOrigin) {
    throw new Error('特权管理站跳转来源校验失败');
  }
  return parsed.href;
}

export function validateRelativeRedirectUrl(rawUrl: unknown): string {
  if (typeof rawUrl !== 'string') {
    throw new Error('跳转地址无效');
  }
  const trimmed = rawUrl.trim();
  if (
    !trimmed ||
    /[\u0000-\u001f\u007f\\]/.test(trimmed) ||
    !trimmed.startsWith('/') ||
    trimmed.startsWith('//')
  ) {
    throw new Error('不安全的跳转地址');
  }
  if (typeof window !== 'undefined') {
    const parsed = new URL(trimmed, window.location.origin);
    if (parsed.origin !== window.location.origin) {
      throw new Error('跳转地址超出当前站点范围');
    }
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  }
  return trimmed;
}

export function sanitizeSafeNextPath(rawNext: unknown, baseOrigin = 'https://localhost'): string {
  if (typeof rawNext !== 'string') return '/';
  const trimmed = rawNext.trim();
  if (
    !trimmed ||
    /[\u0000-\u001f\u007f\\]/.test(trimmed) ||
    !trimmed.startsWith('/') ||
    trimmed.startsWith('//')
  ) {
    return '/';
  }
  try {
    const parsed = new URL(trimmed, baseOrigin);
    if (parsed.origin !== baseOrigin) return '/';
    const pathAndQuery = `${parsed.pathname}${parsed.search}`;
    return pathAndQuery.startsWith('/') && !pathAndQuery.startsWith('//') ? pathAndQuery : '/';
  } catch {
    return '/';
  }
}
