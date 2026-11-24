<script setup lang="ts">
import { onMounted, ref } from 'vue';
import Axios from '../../axios';
import { markImpersonationIsolated, saveUserInfo } from '../../scripts/userInfo';
import { consumeImpersonationTicket } from '../../scripts/impersonationTicket';
import { securityError } from '../../scripts/webauthn';
import router from '../../router';
const error = ref('');
const ticket = consumeImpersonationTicket();
onMounted(async () => {
  const token = ticket || consumeImpersonationTicket();
  try {
    if (!token) throw new Error('缺少代登录授权');
    const { data } = await Axios.post('/security/impersonation-exchange/', { ticket: token });
    if (data?.security?.session_scope !== 'impersonation') {
      throw new Error('无效的代登录会话状态');
    }
    markImpersonationIsolated();
    saveUserInfo(data, true, false);
    await router.replace('/');
  } catch (reason) {
    error.value = securityError(reason);
  }
});
</script>
<template><div class="card-container"><a-card><a-result v-if="error" status="error" title="无法进入代登录会话" :subtitle="error"/><a-spin v-else tip="正在验证超级管理员的代登录授权…"/></a-card></div></template>
