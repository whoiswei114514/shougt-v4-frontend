<script setup lang="ts">
import type { RoleBrief } from '../types';
defineProps<{ role?: RoleBrief | null }>();
</script>
<template><span class="role-certifications" v-if="role?.badges?.length"><a-tooltip v-for="badge in role.badges" :key="badge.role" :content="badge.label"><span class="role-certification">{{ badge.label }}</span></a-tooltip></span></template>
<style scoped>.role-certifications{display:inline-flex;gap:4px;flex-wrap:wrap;vertical-align:middle;margin-left:6px}.role-certification{font-size:10px;line-height:18px;padding:0 6px;border-radius:4px;background:rgba(var(--green-6),.12);color:rgb(var(--green-6));white-space:nowrap}</style>
