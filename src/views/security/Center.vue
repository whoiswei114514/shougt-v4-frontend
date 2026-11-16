<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute } from 'vue-router';
import { Message, Modal } from '@arco-design/web-vue';
import VueQr from 'vue-qr/src/packages/vue-qr.vue';
import Axios from '../../axios';
import { useStore, sharedFunctions } from '../../stores';
import { createCredential, getAssertion, reauthenticate, securityError } from '../../scripts/webauthn';
import { saveUserInfo } from '../../scripts/userInfo';
import { formatDatetime } from '../../scripts/time';
import type { KeyAssurance, SecurityState } from '../../types';
import SecurityKeyStatus from '../../components/SecurityKeyStatus.vue';
import router from '../../router';
import { isMobile } from '../../consts/isMobile';
import '../../styles/security-settings.scss';

type KeyInfo={id:number;name:string;is_security_key:boolean;trusted_hardware:boolean;local_preview_trusted:boolean;assurance:KeyAssurance;created_at:string;last_used_at:string|null};
const store=useStore(), status=ref<(SecurityState & {keys:KeyInfo[]}) | null>(null), busy=ref(false);
const route=useRoute();
const previewKeyLevel=computed(()=>import.meta.env.DEV &&
  ['localhost','127.0.0.1','[::1]'].includes(window.location.hostname) &&
  route.query.key_preview==='fips140-3-level4' && Boolean(status.value?.key_authenticated));
const displayedKeyAssurance=computed<KeyAssurance|null>(()=>previewKeyLevel.value
  ? {level:'fips140-3-level4',label:'FIPS 140-3 L4',high_assurance:true,certifications:['FIPS 140-3 L4']}
  : status.value?.session_key_assurance || null);
const form=reactive({password:'',name:'我的安全密钥',kind:'security_key',totpCode:''});
const totpSetup=ref<{secret:string;uri:string}|null>(null), mail=ref<any>(null), advanced=ref<any>({status:'not_started'}), contact=ref('renzheng@shouguatian.com');
const manager=computed(()=>status.value?.is_management || status.value?.is_admin_candidate);
const onboarding=computed(()=>Boolean(status.value?.admin_onboarding_required));
const hasTrustedKey=computed(()=>Boolean(status.value?.keys.some(key=>key.trusted_hardware)));
function showSetupSection(id:string){document.getElementById(id)?.scrollIntoView({behavior:'smooth',block:'start'});}
const advancedLabel=computed(()=>advanced.value.status==='approved'?'认证通过':['rejected','expired'].includes(advanced.value.status)?'认证错误':'等待认证');
async function refresh(){const [security, info, verification]=await Promise.all([Axios.get('/security/status/'),Axios.get('/user/info/'),Axios.get('/security/advanced/status/')]);status.value=security.data;saveUserInfo(info.data,false);advanced.value=verification.data;}
async function run(action:()=>Promise<void>){busy.value=true;try{await action();}catch(error){Message.error(securityError(error));}finally{busy.value=false;}}
async function accountProof(){if(status.value?.fido_authenticated)await reauthenticate();}
const bindKey=()=>run(async()=>{await accountProof();const {data}=await Axios.post('/security/key-register-begin/',form);await Axios.post('/security/key-register-finish/',{...await createCredential(data),password:form.password});form.password='';Message.success('凭据已绑定');await refresh();});
function removeKey(key:KeyInfo){Modal.confirm({title:`撤销「${key.name}」`,content:'撤销后，这个凭据将无法用于登录。管理员需保留至少一把安全密钥。',onOk:()=>run(async()=>{await accountProof();await Axios.post('/security/key-remove/',{key_id:key.id,password:form.password});if(status.value?.session_key_id===key.id){sharedFunctions.logout();await router.replace('/login/');}else await refresh();Message.success('凭据已撤销');})});}
const startTotp=()=>run(async()=>{await accountProof();totpSetup.value=(await Axios.post('/security/totp-begin/',{password:form.password})).data;});
const confirmTotp=()=>run(async()=>{await Axios.post('/security/totp-confirm/',{code:form.totpCode,password:form.password});totpSetup.value=null;form.totpCode='';form.password='';await refresh();Message.success('二次验证器已启用');});
const removeTotp=()=>run(async()=>{await accountProof();await Axios.post('/security/totp-remove/',{code:form.totpCode,password:form.password});form.totpCode='';await refresh();Message.success('二次验证器已移除');});
const signAdvanced=()=>run(async()=>{if(!status.value?.key_authenticated)await reauthenticate();const {data}=await Axios.post('/security/advanced/begin/',{});mail.value=(await Axios.post('/security/advanced/finish/',await getAssertion(data))).data;await refresh();});
const copyMail=()=>run(async()=>{await navigator.clipboard.writeText(mail.value.body);Message.success('认证邮件正文已复制');});
function downloadMail(){const url=URL.createObjectURL(new Blob([mail.value.body],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='shou-verification.txt';link.click();URL.revokeObjectURL(url);}
const openConsole=()=>run(async()=>{const target=window.open('about:blank','shou-privileged');try{const {data}=await Axios.post('/security/console-begin/');const result=await Axios.post('/security/console-finish/',await getAssertion(data));if(target)target.location.href=result.data.url;else window.location.assign(result.data.url);}catch(error){target?.close();throw error;}});
const openDjango=()=>run(async()=>{await reauthenticate();const {data}=await Axios.post('/security/django-admin/');window.open(data.url,'_blank','noopener,noreferrer');});
const showRealName=(value:boolean)=>run(async()=>{await Axios.post('/security/privacy/',{show_real_name:value});await refresh();Message.success('实名展示设置已保存');});
const completeAdminSetup=()=>run(async()=>{
  const {data}=await Axios.post('/security/admin-setup-begin/');
  const result=await Axios.post('/security/admin-setup-finish/',await getAssertion(data));
  saveUserInfo(result.data,true);await refresh();Message.success('管理员安全配置已完成');
});
onMounted(()=>run(async()=>{await refresh();contact.value=(await Axios.get('/security/config/')).data.material_review_contact;}));
</script>
<template>
  <div class="security-settings">
    <section v-if="onboarding" class="admin-welcome" aria-labelledby="admin-welcome-title">
      <p class="admin-welcome-eyebrow">SECURITY / FIRST LOGIN</p>
      <h2 id="admin-welcome-title">欢迎加入管理团队</h2>
      <p class="security-muted">先为管理身份配置安全密钥。完成以下步骤后，就可以开始使用获授的管理功能。</p>
      <ol class="admin-welcome-steps">
        <li :class="{complete:hasTrustedKey}"><span class="admin-step-number">01</span><div><strong>配置 FIDO2 安全密钥</strong><p>{{hasTrustedKey?'已找到可信安全密钥，可继续使用或添加备用密钥。':'连接支持 PIN 或生物识别的 USB / NFC 安全密钥，完成绑定。'}}</p></div></li>
        <li :class="{complete:status?.admin_setup_ready}"><span class="admin-step-number">02</span><div><strong>确认管理身份</strong><p>{{status?.admin_setup_ready?'邮箱、实名与进阶认证已就绪。':'完成教育邮箱与身份认证，等待材料审核通过。'}}</p></div></li>
        <li><span class="admin-step-number">03</span><div><strong>验证密钥，完成配置</strong><p>使用本人的安全密钥确认。配置完成前，仅开放安全配置功能。</p></div></li>
      </ol>
      <a-space wrap>
        <a-button v-if="!hasTrustedKey" type="primary" @click="showSetupSection('security-key-setup')">绑定我的安全密钥</a-button>
        <a-button v-else-if="!status?.admin_setup_ready" type="primary" @click="showSetupSection('security-identity-setup')">继续身份认证</a-button>
        <a-button v-else type="primary" :loading="busy" @click="completeAdminSetup">验证安全密钥并完成配置</a-button>
        <a-button v-if="hasTrustedKey" @click="showSetupSection('security-key-setup')">管理或添加备用密钥</a-button>
      </a-space>
    </section>
    <a-alert v-if="status?.session_scope === 'enrollment' && !onboarding" type="info" class="security-notice">
      当前为安全配置会话。完成邮箱、密钥、实名与进阶认证后，请重新使用安全密钥登录。
    </a-alert>
    <a-alert v-if="status?.admin_suspended_until && new Date(status.admin_suspended_until).getTime() > Date.now()" type="warning" class="security-notice">
      管理权限冻结至 {{ formatDatetime(status.admin_suspended_until) }}。
    </a-alert>

    <section>
      <a-typography-title :heading="5">账号安全中心</a-typography-title>
      <p class="security-muted">管理登录凭据、校园身份与认证展示。</p>
      <div class="security-statuses">
        <span class="security-status" :class="{ complete: status?.email_verified }">教育邮箱 · {{ status?.email_verified ? '已验证' : '待验证' }}</span>
        <SecurityKeyStatus :fido-authenticated="status?.fido_authenticated" :key-authenticated="status?.key_authenticated" :assurance="displayedKeyAssurance" :preview="previewKeyLevel" />
        <span class="security-status" :class="{ complete: status?.totp_enabled }">二次验证器 · {{ status?.totp_enabled ? '已启用' : '未启用' }}</span>
        <template v-if="manager">
          <span class="security-status" :class="{ complete: status?.real_name_verified }">实名 · {{ status?.real_name_verified ? '已认证' : '待认证' }}</span>
          <span class="security-status" :class="{ complete: status?.advanced_verified }">进阶认证 · {{ status?.advanced_verified ? '已认证' : '待认证' }}</span>
        </template>
      </div>
    </section>

    <a-divider />

    <section id="security-key-setup">
      <a-typography-title :heading="5">安全密钥与通行密钥</a-typography-title>
      <p class="security-muted">每个账号可绑定 1–3 把安全密钥，支持 USB 与 NFC。普通账号验证任意一把即可；管理员可选安全密钥加密码、二次验证器，或验证两把不同的安全密钥。</p>
      <div v-for="key in status?.keys" :key="key.id" class="key-row">
        <div class="key-info">
          <span class="key-name">{{ key.name }}</span>
          <span class="key-detail">{{ key.local_preview_trusted ? '本机测试已允许的安全密钥' : key.trusted_hardware ? '已验证的外置安全密钥' : key.is_security_key ? '外置凭据 · 硬件证明待验证' : '通行密钥' }} · {{ key.assurance?.label || '标准验证' }}</span>
          <span class="key-detail">最近使用：{{ key.last_used_at ? formatDatetime(key.last_used_at) : '尚未使用' }}</span>
        </div>
        <a-button type="text" status="danger" :disabled="busy" @click="removeKey(key)">撤销</a-button>
      </div>
      <a-empty v-if="status && !status.keys.length" description="还没有绑定登录凭据" class="key-empty" />
      <a-form :model="form" auto-label-width :layout="isMobile ? 'vertical' : 'horizontal'" class="security-form" @submit="bindKey">
        <a-form-item v-if="!status?.fido_authenticated" label="当前密码">
          <a-input-password v-model="form.password" autocomplete="current-password" placeholder="用于确认此次安全设置" />
        </a-form-item>
        <a-form-item label="凭据名称">
          <a-input v-model="form.name" :max-length="80" placeholder="例如：随身安全密钥" />
        </a-form-item>
        <a-form-item label="凭据类型">
          <a-radio-group v-model="form.kind" type="button">
            <a-radio value="security_key">外置安全密钥</a-radio>
            <a-radio v-if="!status?.is_management" value="passkey">设备通行密钥</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item>
          <a-button type="primary" html-type="submit" :loading="busy" :disabled="form.kind === 'security_key' && (status?.keys.filter((key:any) => key.is_security_key).length || 0) >= 3">绑定新凭据</a-button>
        </a-form-item>
      </a-form>
    </section>

    <a-divider />

    <section>
      <a-typography-title :heading="5">教育邮箱</a-typography-title>
      <p class="security-email">{{ store.user?.email || '尚未绑定' }}</p>
      <p class="security-muted">{{ store.user?.school === 'shou' ? '上海海洋大学' : '其他院校' }} · {{ store.user?.identity }}</p>
      <RouterLink to="/email/"><a-button>验证或更换教育邮箱</a-button></RouterLink>
    </section>

    <a-divider />

    <section>
      <a-typography-title :heading="5">二次验证器</a-typography-title>
      <p class="security-muted">使用验证器生成六位动态验证码，为管理账号增加一项独立验证。</p>
      <a-button v-if="!status?.totp_enabled && !totpSetup" :loading="busy" @click="startTotp">设置二次验证器</a-button>
      <div v-if="totpSetup" class="totp-setup">
        <VueQr :text="totpSetup.uri" :size="172" :margin="8" />
        <p class="totp-secret">{{ totpSetup.secret }}</p>
        <p>用验证器扫描，或手动输入上方密钥。</p>
      </div>
      <a-form v-if="totpSetup || status?.totp_enabled" :model="form" auto-label-width :layout="isMobile ? 'vertical' : 'horizontal'" class="security-form" @submit="totpSetup ? confirmTotp() : removeTotp()">
        <a-form-item label="动态验证码">
          <a-input v-model="form.totpCode" :max-length="6" inputmode="numeric" autocomplete="one-time-code" placeholder="六位动态验证码" />
        </a-form-item>
        <a-form-item>
          <a-button v-if="totpSetup" type="primary" html-type="submit" :loading="busy">确认启用</a-button>
          <a-button v-else status="danger" html-type="submit" :loading="busy">验证并移除</a-button>
        </a-form-item>
      </a-form>
    </section>

    <template v-if="manager">
      <a-divider />
      <section id="security-identity-setup">
        <a-typography-title :heading="5">管理员进阶认证</a-typography-title>
        <p class="security-muted">使用本次登录的安全密钥，对随机挑战与签发时间进行签名。请在 24 小时内，使用已验证的教育邮箱，将完整认证邮件发送至 <strong>renzheng@shouguatian.com</strong>。</p>
        <a-tag role="status">{{ advancedLabel }}</a-tag>
        <a-form :model="form" class="security-form" @submit="signAdvanced">
          <p v-if="advanced.real_name || store.user?.real_name" class="advanced-details">实名：{{ advanced.real_name || store.user?.real_name }}<span v-if="advanced.student_id || store.user?.student_id"> · 学号：{{ advanced.student_id || store.user?.student_id }}</span></p>
          <a-space wrap>
            <a-button type="primary" html-type="submit" :loading="busy">生成并签署认证挑战</a-button>
            <a-button :disabled="busy" @click="run(refresh)">刷新审核状态</a-button>
          </a-space>
        </a-form>
        <div v-if="mail">
          <p class="security-muted">发件邮箱：{{ mail.from_email }} · 截止：{{ formatDatetime(mail.expires_at) }}</p>
          <pre class="challenge-mail">{{ mail.body }}</pre>
          <div class="security-actions">
            <a-button @click="copyMail">复制认证邮件</a-button>
            <a-button @click="downloadMail">下载认证文本</a-button>
            <a :href="`mailto:${mail.recipient}?subject=${encodeURIComponent(mail.subject)}&body=${encodeURIComponent(mail.body)}`"><a-button>打开邮件客户端</a-button></a>
          </div>
        </div>
        <p class="security-muted security-contact">实名材料审核联系方式：{{ contact }}</p>
      </section>
    </template>

    <template v-if="status?.is_management">
      <a-divider />
      <section>
        <a-typography-title :heading="5">认证展示</a-typography-title>
        <p class="security-muted">管理认证始终显示在注册主角色。你可以选择是否公开该角色的姓名、学号等实名信息。</p>
        <a-space wrap :size="18">
          <label class="privacy-toggle">
            <a-switch :model-value="!status.show_real_name" :disabled="busy" aria-label="隐藏公开的实名信息" @change="value => showRealName(!Boolean(value))" />
            <span>隐藏公开的实名信息</span>
          </label>
          <RouterLink v-if="status.primary_role_id" :to="`/role/${status.primary_role_id}/`">查看主角色</RouterLink>
        </a-space>
        <p v-if="status.key_exempt_until" class="security-muted security-contact">非密钥登录许可截止：{{ formatDatetime(status.key_exempt_until) }}</p>
      </section>
    </template>

    <template v-if="status?.admin_access && status?.is_privileged || store.permission.super_admin">
      <a-divider />
      <section>
        <a-typography-title :heading="5">管理入口</a-typography-title>
        <a-space wrap>
          <a-button v-if="status?.admin_access && status?.is_privileged" :loading="busy" @click="openConsole">进入独立特权管理站</a-button>
          <a-button v-if="store.permission.super_admin" :loading="busy" @click="openDjango">Django 管理</a-button>
        </a-space>
      </section>
    </template>
  </div>
</template>
