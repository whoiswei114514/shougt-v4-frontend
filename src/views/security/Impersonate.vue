<script setup lang="ts">
import { onMounted, ref } from 'vue';
import Axios from '../../axios';
import { saveUserInfo } from '../../scripts/userInfo';
import { securityError } from '../../scripts/webauthn';
import router from '../../router';
const error=ref('');
onMounted(async()=>{const ticket=new URLSearchParams(location.hash.slice(1)).get('ticket');history.replaceState(null,'',location.pathname);try{if(!ticket)throw new Error('缺少代登录授权');const {data}=await Axios.post('/security/impersonation-exchange/',{ticket});saveUserInfo(data,true,false);await router.replace('/');}catch(reason){error.value=securityError(reason);}});
</script>
<template><div class="card-container"><a-card><a-result v-if="error" status="error" title="无法进入代登录会话" :subtitle="error"/><a-spin v-else tip="正在验证超级管理员的代登录授权…"/></a-card></div></template>
