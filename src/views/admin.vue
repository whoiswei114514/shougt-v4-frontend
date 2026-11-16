<script setup lang="ts">
import SecurityWatermark from '../components/SecurityWatermark.vue';
import { isMobile } from '../consts/isMobile';
import { useRoute } from 'vue-router';
import { useStore } from '../stores';
import '../styles/admin-components.scss';
import { ref } from 'vue';
import { Camera } from '@vicons/tabler';
import { Message } from '@arco-design/web-vue';

const route = useRoute();
const store = useStore();
const watermark = ref<InstanceType<typeof SecurityWatermark>>();
const capturing = ref(false);
async function capture() {
  capturing.value = true;
  try { await watermark.value?.capture(); }
  catch (error) { Message.error(error instanceof Error ? error.message : '截图生成失败'); }
  finally { capturing.value = false; }
}
</script>

<template>
    <a-layout class="admin-layout">
      <div class="admin-heading">
      <a-typography-title :heading="3" v-if="!isMobile && route.meta.title">
        {{ route.meta.title }}
      </a-typography-title>
      <a-tooltip content="下载带溯源的截图">
        <a-button shape="circle" aria-label="下载带溯源的截图" :loading="capturing" @click="capture">
          <template #icon><Camera /></template>
        </a-button>
      </a-tooltip>
      </div>

      <a-alert v-if="store.permission.global_reader" class="mb-2">全局读者 · 可查看所有管理数据，业务修改操作已禁用。</a-alert>
      <RouterView />
    </a-layout>
  <SecurityWatermark ref="watermark" :marker="store.watermark_id" :actor="`${store.user?.real_name || ''} · ${store.user?.username || ''}`" />
</template>

<style lang="scss" scoped>
.admin-layout {
  padding: 2vh 5vw;
  max-width: max(800px, 60vw);
  min-height: 50vh;
  margin: 0 auto;

  h3 {
    margin: 0 0 3vh 0.2em;
  }
}
.admin-heading {
  display: flex;
  align-items: start;
  justify-content: space-between;
  gap: 12px;
  margin-bottom: 16px;
  :deep(svg) { width: 18px; height: 18px; }
}

.pane-wrapper {
  width: 100%;
  justify-content: center;
  align-items: center;
  height: 22rem;
}

:deep(.arco-tabs-content) {
  max-width: min(max(1100px, 50vw), 90vw);
  margin: -1em auto 0 auto;
}
</style>
