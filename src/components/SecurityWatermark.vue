<script setup lang="ts">
import { onMounted, onBeforeUnmount, watch } from 'vue';
import { installAdminWatermark } from '../scripts/adminWatermark';
import Axios from '../axios';
import type { WatermarkController } from '../scripts/adminWatermark';
const props = defineProps<{marker: string; actor: string}>();
let stop: WatermarkController | undefined;
const refresh = () => {
  stop?.();
  stop = installAdminWatermark(props.marker, props.actor, document.body, {
    loadFrame: async () => (await Axios.get('/security/watermark/')).data,
  });
};
onMounted(refresh);
watch(() => [props.marker, props.actor], refresh, {flush:'post'});
onBeforeUnmount(() => stop?.());
defineExpose({capture: () => stop?.capture()});
</script>
<template></template>
