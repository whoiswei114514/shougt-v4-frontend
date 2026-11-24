import { FilterXSS, escapeAttrValue, friendlyAttrValue } from 'xss';

function isSafeXssHref(raw: string): boolean {
  const trimmed = friendlyAttrValue(raw).trim();
  if (!trimmed || /[\u0000-\u001f\u007f\\]/.test(trimmed)) return false;
  if (trimmed.startsWith('/') && !trimmed.startsWith('//')) return true;
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:';
  } catch {
    return false;
  }
}

const filterXss = new FilterXSS({
  whiteList: {
    a: ['href', 'title', 'target', 'rel', 'class'],
  },
  allowCommentTag: false,
  stripBlankChar: true,
  stripIgnoreTagBody: ['script', 'style'],
  css: false,
  onTagAttr(tag, name, value, isWhiteAttr) {
    if (tag === 'a' && isWhiteAttr) {
      if (name === 'target') {
        if (value === '_blank') {
          return 'target="_blank" rel="noopener noreferrer"';
        }
        return '';
      }
      if (name === 'rel') {
        return '';
      }
    }
    return undefined;
  },
  safeAttrValue(tag, name, value) {
    if (tag === 'a' && name === 'href') {
      if (!isSafeXssHref(value)) return '';
      return escapeAttrValue(friendlyAttrValue(value).trim());
    }
    return escapeAttrValue(value);
  },
});

export const xss = (str: string) => filterXss.process(str);

const filterXssAll = new FilterXSS({
  whiteList: {},
  allowCommentTag: false,
  stripBlankChar: true,
  stripIgnoreTagBody: ['script', 'style'],
  css: false,
});

export const xssAll = (str: string) => filterXssAll.process(str);
