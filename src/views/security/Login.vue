<script setup lang="ts">
import { reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { useRoute, useRouter } from 'vue-router';
import Axios from '../../axios';
import { saveUserInfo } from '../../scripts/userInfo';
import { getAssertion, securityError } from '../../scripts/webauthn';
import Hccaptcha from '../../components/Hccaptcha.vue';
import '../../styles/auth.scss';

const router = useRouter(), route = useRoute();
const form = reactive({username:'', password:'', remember_me:false, captcha_token:''});
const mode = ref('key'), busy = ref(false), captchaRequired = ref(true), contact = ref('renzheng@shouguatian.com');
const factor = ref<any>(null), factorMethod = ref('password'), factorCode = ref(''), factorEmail = ref(''), factorPassword = ref(''), emailChallenge = ref('');
const countdown = ref(0);
Axios.get('/security/config/').then(({data}) => { captchaRequired.value=data.captcha_required; contact.value=data.material_review_contact; }).catch(() => {});
async function receive(data: any) {
  if (data.factor_required) { factor.value=data; factorMethod.value=data.methods[0]; return; }
  saveUserInfo(data, true, form.remember_me);
  Message.success(data.security?.session_scope === 'enrollment' ? '请完成账号安全配置' : '登录成功');
  const next = typeof route.query.next === 'string' && route.query.next.startsWith('/') && !route.query.next.startsWith('//') ? route.query.next : '/';
  await router.replace(data.security?.session_scope === 'enrollment' ? '/settings/?tab=security' : next);
}
async function loginKey() {
  busy.value=true;
  try { const {data}=await Axios.post('/security/key-login-begin/',{username:form.username,remember_me:form.remember_me}); await receive((await Axios.post('/security/key-login-finish/',await getAssertion(data))).data); }
  catch(error) { Message.error(securityError(error)); } finally {busy.value=false;}
}
async function loginPassword() {
  if (!form.username || !form.password) return Message.warning('请填写账号和密码');
  if (captchaRequired.value && !form.captcha_token) return Message.warning('请先完成人机验证');
  busy.value=true;
  try { await receive((await Axios.post('/security/password-login/',form)).data); }
  catch(error: any) { if(error.response?.data?.security_key_required) mode.value='key'; Message.error(securityError(error)); form.captcha_token=''; } finally {busy.value=false;}
}
async function sendFactorEmail() {
  busy.value=true;
  try { const {data}=await Axios.post('/security/factor-email/',{ticket:factor.value.ticket,email:factorEmail.value}); emailChallenge.value=data.challenge_id; countdown.value=60; const timer=setInterval(()=>{countdown.value--;if(!countdown.value) clearInterval(timer);},1000); Message.success('验证码已发送至教育邮箱'); }
  catch(error) {Message.error(securityError(error));} finally {busy.value=false;}
}
async function finishFactor() {
  busy.value=true;
  try {
    const payload:any={ticket:factor.value.ticket,method:factorMethod.value,password:factorPassword.value,code:factorCode.value,email_challenge_id:emailChallenge.value};
    if (factorMethod.value==='security_key') {
      const {data}=await Axios.post('/security/factor-key-begin/',{ticket:factor.value.ticket});
      Object.assign(payload,await getAssertion(data));
    }
    await receive((await Axios.post('/security/factor-finish/',payload)).data);
  }
  catch(error) {Message.error(securityError(error));} finally {busy.value=false;}
}
</script>
<template>
  <div class="auth-layout auth-login">
    <section class="auth-panel" v-if="!factor"><h1>登录</h1><p class="auth-subtitle">选择安全密钥、通行密钥或密码登录。</p><a-radio-group v-model="mode" type="button" class="auth-tabs"><a-radio value="key">安全密钥 / 通行密钥</a-radio><a-radio value="password">密码</a-radio></a-radio-group>
      <a-form :model="form" layout="vertical" @submit="mode === 'key' ? loginKey() : loginPassword()"><a-form-item :label="mode === 'key' ? '账号（可选）' : '账号'"><a-input v-model="form.username" autocomplete="username webauthn" placeholder="你的瓜田账号" /></a-form-item><a-form-item v-if="mode === 'password'" label="密码"><a-input-password v-model="form.password" autocomplete="current-password" placeholder="请输入密码" /></a-form-item><Hccaptcha v-if="mode === 'password' && captchaRequired" v-model:token="form.captcha_token"/><a-form-item><a-checkbox v-model="form.remember_me">记住这次登录</a-checkbox></a-form-item><a-button class="auth-primary" type="primary" html-type="submit" :loading="busy">{{ mode === 'key' ? '使用安全密钥或通行密钥登录' : '登录' }}</a-button></a-form>
      <div class="auth-footer"><span>还没有账号？<RouterLink to="/register/">教育邮箱注册</RouterLink></span><a-tooltip :content="`账号协助：${contact}`"><a-link>登录帮助</a-link></a-tooltip></div>
    </section>
    <section class="auth-panel" v-else><p class="auth-step">VERIFY YOUR IDENTITY / 02</p><h1>{{factor.enrollment ? '配置管理员安全性' : '再确认一次，是你本人'}}</h1><p class="auth-subtitle">{{factor.enrollment ? '先通过教育邮箱确认本人，再绑定安全密钥与完成进阶认证。' : '此账号需要另一项独立验证。'}}</p><a-form :model="{}" layout="vertical" @submit="finishFactor"><a-form-item label="验证方式"><a-select v-model="factorMethod"><a-option v-for="item in factor.methods" :key="item" :value="item">{{item === 'security_key' ? '另一把安全密钥' : item === 'totp' ? '二次验证器' : item === 'email' ? '教育邮箱验证码' : '账号密码'}}</a-option></a-select></a-form-item><a-form-item v-if="factorMethod === 'password'" label="账号密码"><a-input-password v-model="factorPassword" autocomplete="current-password" /></a-form-item><p v-else-if="factorMethod === 'security_key'" class="auth-subtitle">请连接或轻触另一把已绑定的安全密钥。重复验证第一把密钥无法完成登录。</p><template v-else><a-form-item v-if="factorMethod === 'email' && factor.needs_email" label="教育邮箱"><a-input v-model="factorEmail" placeholder="name@st.shou.edu.cn" inputmode="email" /></a-form-item><a-form-item label="六位验证码"><a-input v-model="factorCode" :max-length="6" autocomplete="one-time-code" placeholder="000000" /></a-form-item><a-button v-if="factorMethod === 'email'" :disabled="countdown>0 || busy" @click="sendFactorEmail" class="mb-1">{{countdown ? `${countdown} 秒后重发` : '发送邮箱验证码'}}</a-button></template><a-button class="auth-primary" type="primary" html-type="submit" :loading="busy">确认并继续</a-button></a-form><div class="auth-footer"><a-link @click="factor=null">重新选择登录方式</a-link></div></section>
  </div>
</template>
<style scoped>
.auth-login { grid-template-columns: 1fr; max-width: 480px; margin: 7vh auto; }
@media (max-width: 780px) { .auth-login { margin: 25px auto; } }
</style>
