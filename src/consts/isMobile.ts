import { computed, ref } from 'vue';

const viewport = window.matchMedia('(max-width: 960px)');
const matches = ref(viewport.matches);
const update = (event: MediaQueryListEvent) => { matches.value = event.matches; };
viewport.addEventListener('change', update);

export const isMobile = computed(() => matches.value);

if (import.meta.hot) {
  import.meta.hot.dispose(() => viewport.removeEventListener('change', update));
}

export default isMobile;
