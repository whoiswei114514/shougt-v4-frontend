<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { useRoute, useRouter } from 'vue-router';
import Axios from '../../axios';
import { saveUserInfo } from '../../scripts/userInfo';
import { getAssertion, securityError } from '../../scripts/webauthn';
import { sanitizeSafeNextPath } from '../../scripts/securityUrls';
import { sharedFunctions } from '../../stores';
import Hccaptcha from '../../components/Hccaptcha.vue';
import '../../styles/auth.scss';

const router = useRouter(), route = useRoute();
const showPcsc = computed(() => route.query.pcsc === '1');
const form = reactive({username:'', password:'', remember_me:false, captcha_token:''});
const mode = ref('key'), busy = ref(false), captchaRequired = ref(true), contact = ref('renzheng@shouguatian.com');
const factor = ref<any>(null), factorMethod = ref('password'), factorCode = ref(''), factorEmail = ref(''), factorPassword = ref(''), emailChallenge = ref('');
const secondKeyConnection = ref<'browser'|'smartcard'>('browser');
const countdown = ref(0);
Axios.get('/security/config/').then(({data}) => { captchaRequired.value=data.captcha_required; contact.value=data.material_review_contact; }).catch(() => {});
async function receive(data: any) {
  if (data.factor_required) { factor.value=data; factorMethod.value=data.methods[0]; return; }
  saveUserInfo(data, true, form.remember_me);
  const next = sanitizeSafeNextPath(route.query.next, window.location.origin);
  const needsOnboarding = Boolean(
    data.security?.session_scope === 'enrollment' ||
    data.security?.admin_onboarding_required ||
    (data.security?.is_management && !data.security?.admin_setup_ready) ||
    (data.security?.is_admin_candidate && !data.security?.advanced_verified)
  );
  if (needsOnboarding) {
    const destination = next.startsWith('/admin/') || next.startsWith('/zero-width/') ? '/' : next;
    await router.replace(destination);
    sharedFunctions.openAdminOnboardingModal();
    return;
  }
  if ((data.security?.signed_issuance_ready_count || 0) > 0) {
    Message.success(`您的 ${data.security.signed_issuance_ready_count} 份离线证书申请已签署完成，请点击页面顶部提醒完成导入激活`);
  } else if ((data.security?.pending_sign_requests_count || 0) > 0) {
    Message.info(`有 ${data.security.pending_sign_requests_count} 份管理员硬件证书公钥等待签署，请点击页面顶部提醒协助签署`);
  } else if (data.security?.needs_certificate_issuance) {
    Message.info('登录成功；首次进入独立特权管理站时将自动弹出硬件证书签发窗口');
  } else {
    Message.success('登录成功');
  }
  await router.replace(next);
}
async function loginKey(connection:'browser'|'smartcard'='browser') {
  busy.value=true;
  secondKeyConnection.value = 'browser';
  try { const {data}=await Axios.post('/security/key-login-begin/',{username:form.username,remember_me:form.remember_me}); await receive((await Axios.post('/security/key-login-finish/',await getAssertion(data,connection))).data); }
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
      Object.assign(payload,await getAssertion(data, showPcsc.value ? secondKeyConnection.value : 'browser', false));
    }
    await receive((await Axios.post('/security/factor-finish/',payload)).data);
  }
  catch(error) {Message.error(securityError(error));} finally {busy.value=false;}
}
</script>
<template>
  <div class="card-container">
    <a-card v-if="!factor" class="auth-panel">
      <a-typography-title :heading="2">登录</a-typography-title>
      <a-divider class="divider-30" />
      <p class="auth-subtitle">选择安全密钥、通行密钥或密码登录。</p>
      <a-radio-group v-model="mode" type="button" class="auth-tabs">
        <a-radio value="key">安全密钥 / 通行密钥</a-radio>
        <a-radio value="password">密码</a-radio>
      </a-radio-group>
      <a-form :model="form" layout="vertical" @submit="mode === 'key' ? loginKey() : loginPassword()">
        <a-form-item :label="mode === 'key' ? '账号（可选）' : '账号'">
          <a-input v-model="form.username" autocomplete="username webauthn" placeholder="你的瓜田账号" />
        </a-form-item>
        <a-form-item v-if="mode === 'password'" label="密码">
          <a-input-password v-model="form.password" autocomplete="current-password" placeholder="请输入密码" />
        </a-form-item>
        <Hccaptcha v-if="mode === 'password' && captchaRequired" v-model:token="form.captcha_token" />
        <a-form-item>
          <a-checkbox v-model="form.remember_me">记住这次登录</a-checkbox>
        </a-form-item>
        <a-form-item>
          <a-button type="primary" long html-type="submit" :loading="busy">
            {{ mode === 'key' ? '使用安全密钥或通行密钥登录' : '登录' }}
          </a-button>
        </a-form-item>
      </a-form>
      <a-button v-if="mode === 'key' && showPcsc" long :disabled="busy" @click="loginKey('smartcard')">
        使用接触式智能卡登录
      </a-button>
      <div class="auth-footer">
        <span>还没有账号？<RouterLink to="/register/"><a-link>教育邮箱注册</a-link></RouterLink></span>
        <a-tooltip :content="`账号协助：${contact}`"><a-link>登录帮助</a-link></a-tooltip>
      </div>
    </a-card>

    <a-card v-else class="auth-panel">
      <a-typography-title :heading="2">{{ factor.enrollment ? '配置管理员安全性' : '再确认一次，是你本人' }}</a-typography-title>
      <a-divider class="divider-30" />
      <p class="auth-subtitle">
        {{ factor.enrollment ? '先通过教育邮箱确认本人，再绑定安全密钥与完成进阶认证。' : '此账号需要另一项独立验证。' }}
      </p>
      <a-form :model="{}" layout="vertical" @submit="finishFactor">
        <a-form-item label="验证方式">
          <a-select v-model="factorMethod">
            <a-option v-for="item in factor.methods" :key="item" :value="item">
              {{ item === 'security_key' ? '另一把安全密钥' : item === 'totp' ? '二次验证器' : item === 'email' ? '教育邮箱验证码' : '账号密码' }}
            </a-option>
          </a-select>
        </a-form-item>
        <a-form-item v-if="factorMethod === 'password'" label="账号密码">
          <a-input-password v-model="factorPassword" autocomplete="current-password" />
        </a-form-item>
        <template v-else-if="factorMethod === 'security_key'">
          <a-form-item v-if="showPcsc" label="第二把密钥连接方式">
            <a-select v-model="secondKeyConnection" :disabled="busy" aria-label="第二把密钥连接方式">
              <a-option value="browser">USB / NFC 安全密钥（浏览器）</a-option>
              <a-option value="smartcard">接触式智能卡（PC/SC）</a-option>
            </a-select>
          </a-form-item>
          <p class="auth-subtitle">请连接或轻触另一把已绑定的安全密钥。重复验证第一把密钥无法完成登录。</p>
        </template>
        <template v-else>
          <a-form-item v-if="factorMethod === 'email' && factor.needs_email" label="教育邮箱">
            <a-input v-model="factorEmail" placeholder="name@st.shou.edu.cn" inputmode="email" />
          </a-form-item>
          <a-form-item label="六位验证码">
            <a-input v-model="factorCode" :max-length="6" autocomplete="one-time-code" placeholder="000000" />
          </a-form-item>
          <a-button v-if="factorMethod === 'email'" :disabled="countdown > 0 || busy" @click="sendFactorEmail" class="mb-1">
            {{ countdown ? `${countdown} 秒后重发` : '发送邮箱验证码' }}
          </a-button>
        </template>
        <a-button type="primary" long html-type="submit" :loading="busy">确认并继续</a-button>
      </a-form>
      <div class="auth-footer">
        <a-link @click="factor = null">重新选择登录方式</a-link>
      </div>
    </a-card>
  </div>
</template>
