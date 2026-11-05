<script setup lang="ts">
import { reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import Axios from '../../axios';
import { useStore } from '../../stores';
import { saveUserInfo } from '../../scripts/userInfo';
import { reauthenticate, securityError } from '../../scripts/webauthn';
import '../../styles/auth.scss';
const store=useStore(),busy=ref(false),step=ref(1),form=reactive({email:'',password:'',code:'',challenge_id:''});
async function send(){busy.value=true;try{if(store.security?.fido_authenticated)await reauthenticate();const {data}=await Axios.post('/user/email_sendcode/',{email:form.email,password:form.password});form.challenge_id=data.challenge_id;step.value=2;Message.success('验证码已发送');}catch(error){Message.error(securityError(error));}finally{busy.value=false;}}
async function verify(){busy.value=true;try{const {data}=await Axios.post('/user/email_verifycode/',form);saveUserInfo(data,false);step.value=3;}catch(error){Message.error(securityError(error));}finally{busy.value=false;}}
</script>
<template><div class="auth-layout"><section class="auth-art"><div><div class="brand-mini"><img src="/logo.svg" alt="">shou瓜田</div><h2>一封邮件，<br>确认你的校园身份。</h2><p>学生邮箱对应海大学生，其他海大邮箱对应教师，其他教育邮箱对应外校人士。</p></div></section><section class="auth-panel"><p class="auth-step">EDUCATION EMAIL / {{step.toString().padStart(2,'0')}}</p><h1>验证教育邮箱</h1><p class="auth-subtitle">更换邮箱会重新计算校园身份；管理员需要重新完成进阶认证。</p><a-form v-if="step===1" :model="form" layout="vertical" @submit="send"><a-form-item label="教育邮箱"><a-input v-model="form.email" inputmode="email" autocomplete="email" placeholder="name@st.shou.edu.cn" /></a-form-item><a-form-item v-if="!store.security?.fido_authenticated" label="当前密码"><a-input-password v-model="form.password" autocomplete="current-password" /></a-form-item><a-button class="auth-primary" type="primary" html-type="submit" :loading="busy">发送验证码</a-button></a-form><a-form v-else-if="step===2" :model="form" layout="vertical" @submit="verify"><p class="auth-subtitle">验证码已发送至 {{form.email}}，10 分钟内有效。</p><a-form-item label="六位验证码"><a-input v-model="form.code" :max-length="6" autocomplete="one-time-code" placeholder="000000" /></a-form-item><a-button class="auth-primary" type="primary" html-type="submit" :loading="busy">确认邮箱</a-button><div class="auth-footer"><a-link @click="step=1">重新填写或获取验证码</a-link></div></a-form><a-result v-else status="success" title="教育邮箱已验证"><template #extra><RouterLink to="/settings/?tab=security"><a-button type="primary">返回安全中心</a-button></RouterLink></template></a-result></section></div></template>
