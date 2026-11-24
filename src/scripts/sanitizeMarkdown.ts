import createDOMPurify from 'dompurify';

const SAFE_URI_REGEXP = /^(?:(?:https?|mailto):|\/(?![/\\])|#|\.\.?\/)/i;
const SAFE_FRAGMENT_URL_RE = /url\(\s*(?:'#[A-Za-z0-9_.:-]+'|"#[A-Za-z0-9_.:-]+"|#[A-Za-z0-9_.:-]+)\s*\)/gi;
const DANGEROUS_CSS_RE =
  /@(?:import|charset|namespace)\b|expression\s*\(|-moz-binding\b|behavior\s*:|(?:-[a-z]+-)?image-set\s*\(|\burl\s*\(|\b(?:javascript|vbscript|data)\s*:|\bposition\s*:\s*fixed\b|\\|<|[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/i;
const URI_ATTRS = ['href', 'src', 'xlink:href', 'action', 'formaction', 'cite'] as const;

function stripCssComments(css: string): string | null {
  let current = css;
  while (true) {
    const next = current.replace(/\/\*[\s\S]*?\*\//g, '');
    if (next === current) break;
    current = next;
  }
  if (current.includes('/*')) return null;
  return current;
}

export function isSafeAttrUri(raw: string, requireFragment = false): boolean {
  const trimmed = raw.trim();
  if (!trimmed || /[\u0000-\u001f\u007f\\]/.test(trimmed)) return false;
  if (requireFragment) {
    return /^#[A-Za-z0-9_.:-]+$/.test(trimmed);
  }
  if (trimmed.startsWith('#')) {
    return trimmed === '#' || /^#[A-Za-z0-9_.:-]+$/.test(trimmed);
  }
  if ((trimmed.startsWith('/') && !trimmed.startsWith('//')) || trimmed.startsWith('./') || trimmed.startsWith('../')) {
    return true;
  }
  try {
    const parsed = new URL(trimmed);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' || parsed.protocol === 'mailto:';
  } catch {
    return false;
  }
}

export function sanitizeCssText(raw: string, allowChildCombinator = false): string | null {
  const withoutComments = stripCssComments(raw);
  if (withoutComments === null) return null;
  if (!allowChildCombinator && withoutComments.includes('>')) return null;
  const safeUrlNormalized = withoutComments.replace(SAFE_FRAGMENT_URL_RE, 'var(--safe-svg-ref)');
  if (DANGEROUS_CSS_RE.test(safeUrlNormalized)) return null;
  return withoutComments;
}

function getPurifier() {
  if (typeof window === 'undefined') return null;
  const instance = createDOMPurify(window);
  instance.addHook('afterSanitizeAttributes', node => {
    const tag = node.tagName?.toUpperCase() ?? '';
    if (tag === 'A') {
      const target = node.getAttribute('target');
      if (target === '_blank') {
        node.setAttribute('rel', 'noopener noreferrer');
      } else if (target !== null) {
        node.removeAttribute('target');
      }
    }
    const requireFragment = tag === 'USE';
    for (const attr of URI_ATTRS) {
      if (node.hasAttribute(attr)) {
        const value = node.getAttribute(attr) ?? '';
        if (!isSafeAttrUri(value, requireFragment)) {
          node.removeAttribute(attr);
        }
      }
    }
    if (node.hasAttribute('style')) {
      const sanitizedStyle = sanitizeCssText(node.getAttribute('style') ?? '', false);
      if (!sanitizedStyle) {
        node.removeAttribute('style');
      } else {
        node.setAttribute('style', sanitizedStyle);
      }
    }
  });
  instance.addHook('afterSanitizeElements', node => {
    if (node.nodeType === 1 && (node as Element).tagName?.toUpperCase() === 'STYLE') {
      const sanitizedCss = sanitizeCssText(node.textContent ?? '', true);
      if (sanitizedCss === null) {
        node.parentNode?.removeChild(node);
      } else {
        node.textContent = sanitizedCss;
      }
    }
  });
  return instance;
}

const purifier = getPurifier();

const MARKDOWN_FORBID_TAGS = [
  'svg',
  'iframe',
  'object',
  'embed',
  'form',
  'style',
  'script',
  'base',
  'meta',
  'link',
  'noscript',
  'template',
];

const MERMAID_FORBID_TAGS = [
  'iframe',
  'object',
  'embed',
  'form',
  'script',
  'base',
  'meta',
  'link',
  'noscript',
  'template',
  'set',
  'animate',
  'handler',
  'listener',
];

const COMMON_FORBID_ATTR = [
  'autofocus',
  'srcdoc',
  'formaction',
  'action',
  'background',
  'poster',
  'ping',
  'attributionsrc',
];

export const sanitizeMarkdown = (html: string): string => {
  if (!purifier) return '';
  return purifier.sanitize(html, {
    USE_PROFILES: { html: true, mathMl: true },
    FORBID_TAGS: MARKDOWN_FORBID_TAGS,
    FORBID_ATTR: COMMON_FORBID_ATTR,
    ADD_ATTR: ['target'],
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    ALLOWED_URI_REGEXP: SAFE_URI_REGEXP,
  });
};

export const sanitizeMermaid = async (svg: string): Promise<string> => {
  if (!purifier) return '';
  return purifier.sanitize(svg, {
    USE_PROFILES: { html: true, svg: true, svgFilters: true },
    FORBID_TAGS: MERMAID_FORBID_TAGS,
    FORBID_ATTR: COMMON_FORBID_ATTR,
    ADD_ATTR: ['target'],
    ALLOW_DATA_ATTR: false,
    ALLOW_UNKNOWN_PROTOCOLS: false,
    ALLOWED_URI_REGEXP: SAFE_URI_REGEXP,
  });
};
