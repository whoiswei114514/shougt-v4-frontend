<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import type { KeyAssurance } from '../types';

const props = defineProps<{
  fidoAuthenticated?: boolean;
  keyAuthenticated?: boolean;
  assurance?: KeyAssurance | null;
  preview?: boolean;
}>();
const expanded = ref(false);
const certified = computed(() => Boolean(props.keyAuthenticated && props.assurance?.high_assurance));
const label = computed(() => `本次登录 · ${props.keyAuthenticated ? '安全密钥' : props.fidoAuthenticated ? '通行密钥' : '其他方式'}`);
const levels = computed(() => props.assurance?.certifications.length
  ? props.assurance.certifications : [props.assurance?.label || '标准验证']);
watch(certified, () => { expanded.value = false; });
</script>

<template>
  <a-popover
    v-if="certified"
    v-model:popup-visible="expanded"
    :trigger="['hover', 'focus']"
    position="bottom"
    content-class="security-assurance-popover"
    :content-style="{ maxWidth: 'min(320px, calc(100vw - 40px))' }"
  >
    <button
      type="button"
      class="security-status security-key-gold"
      :class="{ 'is-open': expanded }"
      :aria-label="`${label}，查看安全等级`"
      :aria-expanded="expanded"
      :aria-describedby="expanded ? 'security-key-levels' : undefined"
      @click="expanded = true"
      @keydown.esc.stop="expanded = false"
    >
      <svg class="security-key-emblem" viewBox="0 0 24 24" fill="none" aria-hidden="true">
        <path d="M12 3 20 6v6c0 4.2-4.1 7.6-8 9-3.9-1.4-8-4.8-8-9V6l8-3Z" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" />
        <path d="m8.5 12 2.4 2.4 4.6-4.8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
      </svg>
      <span>{{ label }}</span>
    </button>
    <template #content>
      <div id="security-key-levels" class="security-assurance-details" role="tooltip">
        <p>{{ preview ? '安全等级 · 效果预览' : '已核验的安全等级' }}</p>
        <div class="security-assurance-levels">
          <span v-for="level in levels" :key="level">{{ level }}</span>
        </div>
      </div>
    </template>
  </a-popover>
  <span v-else class="security-status" :class="{ complete: fidoAuthenticated }">{{ label }}</span>
</template>

<style scoped lang="scss">
.security-status.security-key-gold {
  position: relative;
  display: inline-flex;
  align-items: center;
  gap: 6px;
  overflow: hidden;
  padding: 6px 11px;
  border: 1px solid rgba(186, 142, 57, .26);
  background: linear-gradient(115deg, #fff8e2, #f5e5b7);
  color: #825917;
  font: inherit;
  font-size: 12px;
  line-height: inherit;
  cursor: pointer;
  box-shadow: inset 0 1px 0 #ffffffbd;
  transition: transform .18s ease, box-shadow .2s ease;

  &::after {
    content: '';
    position: absolute;
    inset: -50% -30%;
    background: linear-gradient(115deg, transparent 36%, #fff9 48%, transparent 60%);
    transform: translateX(-100%);
    pointer-events: none;
  }

  &:hover, &:focus-visible, &.is-open {
    transform: translateY(-1px);
    box-shadow: inset 0 1px 0 #fff, 0 4px 13px #b28a3224;
    &::after { animation: security-gold-shine .65s ease-out; }
  }

  &:focus-visible { outline: 2px solid #b48b38; outline-offset: 3px; }
}

.security-key-emblem { width: 15px; height: 15px; flex-shrink: 0; }
.security-assurance-details {
  padding: 3px 1px;
  p { margin: 0 0 10px; color: var(--color-text-3); font-size: 12px; }
}
.security-assurance-levels {
  display: flex;
  gap: 7px;
  flex-wrap: wrap;
  span {
    padding: 5px 9px;
    border-radius: 6px;
    background: #b9903612;
    color: #825917;
    font: 12px/1.5 Consolas, monospace;
  }
}
:global(.security-assurance-popover) {
  border-color: #b9903640;
  border-radius: 12px;
  box-shadow: 0 9px 30px #43351c12;
}
:global(body[arco-theme='dark'] .security-status.security-key-gold) {
  background: linear-gradient(115deg, #3a321f, #4b3b20);
  color: #f0d18a;
  border-color: #b9903659;
  box-shadow: inset 0 1px 0 #ffffff0d;
}
:global(body[arco-theme='dark'] .security-status.security-key-gold::after) { opacity: .25; }
:global(body[arco-theme='dark'] .security-assurance-levels span) { color: #f0d18a; background: #b990361a; }
@keyframes security-gold-shine {
  to { transform: translateX(100%); }
}
@media (prefers-reduced-motion: reduce) {
  .security-status.security-key-gold {
    transition: none;
    &:hover, &:focus-visible, &.is-open { transform: none; }
    &::after { display: none; animation: none; }
  }
}
</style>
