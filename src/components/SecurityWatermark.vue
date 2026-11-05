<script setup lang="ts">
import { onMounted, onBeforeUnmount, watch } from 'vue';
import { installAdminWatermark } from '../scripts/adminWatermark';
const props = defineProps<{marker: string; actor: string}>();
let stop = () => {};
const refresh = () => { stop(); stop = installAdminWatermark(props.marker, props.actor); };
onMounted(refresh);
watch(() => [props.marker, props.actor], refresh, {flush:'post'});
onBeforeUnmount(() => stop());
</script>
<template></template>
