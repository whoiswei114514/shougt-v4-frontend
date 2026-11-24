<script setup lang="ts">
import { computed } from 'vue';

const props = defineProps<{
  content: string;
}>();

interface Segment {
  text: string;
  href?: string;
}

const URL_REGEX = /https?:\/\/[-A-Za-z0-9]+(?:\.[-A-Za-z0-9]+)+(?::\d+)?(?:\/[-A-Za-z0-9+&@#/%?=~_|!:,.]*)?/g;

function toSafeHttpHref(raw: string): string | undefined {
  try {
    const parsed = new URL(raw);
    if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
      return parsed.href;
    }
  } catch {
    return undefined;
  }
  return undefined;
}

const segments = computed<Segment[]>(() => {
  const text = props.content ?? '';
  const result: Segment[] = [];
  let lastIndex = 0;
  for (const match of text.matchAll(URL_REGEX)) {
    const index = match.index ?? 0;
    const rawUrl = match[0];
    if (index > lastIndex) {
      result.push({ text: text.slice(lastIndex, index) });
    }
    const safeHref = toSafeHttpHref(rawUrl);
    result.push(safeHref ? { text: rawUrl, href: safeHref } : { text: rawUrl });
    lastIndex = index + rawUrl.length;
  }
  if (lastIndex < text.length) {
    result.push({ text: text.slice(lastIndex) });
  }
  return result;
});
</script>

<template>
  <pre class="simple-rich-text"><template v-for="(seg, idx) in segments" :key="idx"><a v-if="seg.href" :href="seg.href" target="_blank" rel="noopener noreferrer" class="link">{{ seg.text }}</a><template v-else>{{ seg.text }}</template></template></pre>
</template>

<style lang="scss">
.simple-rich-text {
  white-space: pre-wrap;
  word-wrap: break-word;
  font-family: inherit;
  margin: 0;
  .link {
    color: rgb(var(--link-6));
  }
}
</style>
