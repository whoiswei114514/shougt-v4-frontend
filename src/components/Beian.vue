<script setup lang="ts">
const icp = import.meta.env.VITE_ICP_NUMBER || '';
const policeNumber = import.meta.env.VITE_POLICE_NUMBER || '';
const policeLabel = import.meta.env.VITE_POLICE_LABEL || '';
const year = new Date().getFullYear();
</script>

<template>
  <a-space direction="vertical" class="beian" size="mini">
    <RouterLink :to="{ name: 'about' }">
      <a-link> 版权所有 © {{ year }} shou瓜田 </a-link>
    </RouterLink>
    <a-link v-if="icp" href="https://beian.miit.gov.cn/" target="_blank">
      {{ icp }}
    </a-link>
    <a-link
      v-if="policeNumber && policeLabel"
      :href="`https://beian.mps.gov.cn/#/query/webSearch?code=${encodeURIComponent(policeNumber)}`"
      target="_blank"
    >
      <template #icon>
        <div style="margin-top: 0.18em">
          <img src="../assets/gaba.png" style="width: auto; height: 1em" />
        </div>
      </template>
      {{ policeLabel }}
    </a-link>
  </a-space>
</template>

<style scoped lang="scss">
.beian {
  display: flex;
  align-items: center;
  color: var(--color-text-3);
  margin: 1.5em 0;
  .arco-link {
    color: var(--color-text-3);
    font-size: 0.9em;
  }
}
</style>
