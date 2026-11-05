import createDOMPurify from 'dompurify';

const purifier = createDOMPurify(window);
purifier.addHook('afterSanitizeAttributes', node => {
  if (node.tagName === 'A' && node.getAttribute('target') === '_blank') {
    node.setAttribute('rel', 'noopener noreferrer');
  }
});

export const sanitizeMarkdown = (html: string): string => purifier.sanitize(html, {
  USE_PROFILES: { html: true, mathMl: true },
  FORBID_TAGS: ['iframe', 'object', 'embed', 'form', 'style'],
  FORBID_ATTR: ['autofocus', 'srcdoc'],
  ADD_ATTR: ['target'],
  ALLOW_DATA_ATTR: false,
});

export const sanitizeMermaid = async (svg: string): Promise<string> => purifier.sanitize(svg, {
  USE_PROFILES: { html: true, svg: true, svgFilters: true },
  FORBID_TAGS: ['iframe', 'object', 'embed', 'form'],
  FORBID_ATTR: ['autofocus', 'srcdoc'],
});
