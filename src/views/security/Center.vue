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
import { preferredSmartCard } from '../../scripts/smartcard';
import { validateConsoleHandoffUrl, validateRelativeRedirectUrl } from '../../scripts/securityUrls';
import '../../styles/security-settings.scss';

type KeyInfo={id:number;name:string;is_security_key:boolean;trusted_hardware:boolean;local_preview_trusted:boolean;assurance:KeyAssurance;created_at:string;last_used_at:string|null};
const store=useStore(), status=ref<(SecurityState & {keys:KeyInfo[]}) | null>(null), busy=ref(false);
const fidoFreshUntil=ref(0);
const secondKeyGuide=ref(false);
const route=useRoute();
const showPcsc=computed(()=>route.query.pcsc==='1'||preferredSmartCard());
const credentialConnection=ref<'browser'|'smartcard'>(showPcsc.value?'smartcard':'browser');
const sessionKeyName=computed(()=>{
  const id=status.value?.session_key_id;
  return status.value?.keys.find((key)=>key.id===id)?.name || '本次登录使用的安全密钥';
});
const previewKeyLevel=computed(()=>import.meta.env.DEV &&
  ['localhost','127.0.0.1','[::1]'].includes(window.location.hostname) &&
  route.query.key_preview==='fips140-3-level4' && Boolean(status.value?.key_authenticated));
const displayedKeyAssurance=computed<KeyAssurance|null>(()=>previewKeyLevel.value
  ? {level:'fips140-3-level4',label:'FIPS 140-3 L4',high_assurance:true,certifications:['FIPS 140-3 L4']}
  : status.value?.session_key_assurance || null);
const isAndroid = /Android/i.test(navigator.userAgent || '');
const form=reactive({password:'',name:'我的安全密钥',kind:'security_key',resident_key:(isAndroid?'discouraged':'preferred') as 'preferred'|'discouraged'|'required',totpCode:''});
const totpSetup=ref<{secret:string;uri:string}|null>(null), mail=ref<any>(null), advanced=ref<any>({status:'not_started'}), contact=ref('renzheng@shouguatian.com');
const pendingJobCount=ref(0);
const manager=computed(()=>status.value?.is_management || status.value?.is_admin_candidate);
const onboarding=computed(()=>Boolean(status.value?.admin_onboarding_required));
const adminKeysReady=computed(()=>Boolean(status.value?.admin_keys_satisfied));
const needsSecondOrdinaryKey=computed(()=>Boolean(status.value?.is_management && !status.value?.admin_keys_satisfied && (status.value?.external_key_count || 0) === 1 && !status.value?.has_high_assurance_key));
const adminKeyGuideVisible=ref(false);
const adminKeyGuideShown=ref(false);
function showSetupSection(id:string){document.getElementById(id)?.scrollIntoView({behavior:'smooth',block:'start'});}
function openKeySetupFromGuide(){adminKeyGuideVisible.value=false;showSetupSection('security-key-setup');}
const advancedLabel=computed(()=>advanced.value.status==='approved'?'认证通过':['rejected','expired'].includes(advanced.value.status)?'认证错误':'等待认证');
async function refresh(){
  const [security, info, verification]=await Promise.all([Axios.get('/security/status/'),Axios.get('/user/info/'),Axios.get('/security/advanced/status/')]);
  status.value=security.data;
  const freshSeconds=Number(security.data?.fido_fresh_seconds || 0);
  fidoFreshUntil.value=freshSeconds > 0 ? Date.now() + freshSeconds * 1000 : 0;
  saveUserInfo(info.data,false);advanced.value=verification.data;
  if(onboarding.value && !adminKeysReady.value && !adminKeyGuideShown.value){
    adminKeyGuideVisible.value=true;
    adminKeyGuideShown.value=true;
  }
  if(status.value?.key_authenticated && status.value?.email_verified && status.value?.real_name_verified && status.value?.advanced_verified && !status.value?.admin_onboarding_required){
    try{
      const pendingRes=await Axios.get('/security/issuance-pending/');
      pendingJobCount.value=Array.isArray(pendingRes.data?.jobs)?pendingRes.data.jobs.length:0;
    }catch{
      pendingJobCount.value=0;
    }
  }else{
    pendingJobCount.value=0;
  }
}
async function run(action:()=>Promise<void>){busy.value=true;try{await action();}catch(error){Message.error(securityError(error));}finally{busy.value=false;}}
function hasFreshFido(bufferSeconds=60){
  return Boolean(status.value?.fido_authenticated && fidoFreshUntil.value - Date.now() > bufferSeconds * 1000);
}
async function performReauth(){
  const res=await reauthenticate(showPcsc.value ? credentialConnection.value : 'browser');
  const freshSeconds=Number(res?.fido_fresh_seconds || 300);
  fidoFreshUntil.value=Date.now() + freshSeconds * 1000;
}
async function accountProof(bufferSeconds=30){
  if(status.value?.fido_authenticated && !hasFreshFido(bufferSeconds)){
    await performReauth();
  }
}
function promptReauthForBind(){
  Modal.confirm({
    title:'请先验证当前登录的安全密钥',
    content:`当前安全验证已超过有效期。请先连接或轻触本次登录使用的安全密钥「${sessionKeyName.value}」确认身份；确认通过后再更换为要绑定的新密钥。`,
    okText:'验证当前密钥',
    cancelText:'取消',
    onOk:()=>run(async()=>{
      await performReauth();
      Message.success('身份已确认（5 分钟内有效）。请插入或轻触要绑定的新密钥，再点击「绑定新凭据」。');
    }),
  });
}
const bindKey=()=>{
  if(status.value?.fido_authenticated && !hasFreshFido(60)){
    promptReauthForBind();
    return;
  }
  return run(async()=>{
    const payload={kind:form.kind,name:form.name,resident_key:form.kind==='security_key'?form.resident_key:'preferred',password:form.password};
    let data:any;
    try{
      ({data}=await Axios.post('/security/key-register-begin/',payload));
    }catch(error:any){
      if(status.value?.fido_authenticated && error?.response?.status===403 && String(error?.response?.data?.msg || '').includes('重新验证')){
        fidoFreshUntil.value=0;
        promptReauthForBind();
        return;
      }
      throw error;
    }
    const {data:finishData}=await Axios.post('/security/key-register-finish/',{...await createCredential(data,form.kind==='passkey'||!showPcsc.value?'browser':credentialConnection.value),password:form.password});
    form.password='';await refresh();
    const count=status.value?.external_key_count ?? finishData?.external_key_count ?? 0;
    if(status.value?.is_management && !finishData?.high_assurance && !status.value?.admin_keys_satisfied && count===1){
      secondKeyGuide.value=true;
      adminKeyGuideVisible.value=true;
      form.kind='security_key';
      form.name='备用安全密钥（第 2 把）';
      Message.info('第 1 把普通安全密钥已绑定。管理员需绑定 2 把普通安全密钥（或 1 把高认证密钥），请插入或轻触第 2 把不同的安全密钥并继续绑定。');
      showSetupSection('security-key-setup');
    }else{
      secondKeyGuide.value=false;
      form.name='我的安全密钥';
      Message.success('凭据已绑定');
    }
  });
};
function removeKey(key:KeyInfo){Modal.confirm({title:`撤销「${key.name}」`,content:'撤销后，这个凭据将无法用于登录。管理员需保留至少一把安全密钥。',onOk:()=>run(async()=>{await accountProof();await Axios.post('/security/key-remove/',{key_id:key.id,password:form.password});if(status.value?.session_key_id===key.id){sharedFunctions.logout();await router.replace('/login/');}else await refresh();Message.success('凭据已撤销');})});}
const startTotp=()=>run(async()=>{await accountProof();totpSetup.value=(await Axios.post('/security/totp-begin/',{password:form.password})).data;});
const confirmTotp=()=>run(async()=>{await Axios.post('/security/totp-confirm/',{code:form.totpCode,password:form.password});totpSetup.value=null;form.totpCode='';form.password='';await refresh();Message.success('二次验证器已启用');});
const removeTotp=()=>run(async()=>{await accountProof();await Axios.post('/security/totp-remove/',{code:form.totpCode,password:form.password});form.totpCode='';await refresh();Message.success('二次验证器已移除');});
const signAdvanced=()=>run(async()=>{if(!status.value?.key_authenticated)await reauthenticate();const {data}=await Axios.post('/security/advanced/begin/',{});mail.value=(await Axios.post('/security/advanced/finish/',await getAssertion(data))).data;await refresh();});
const copyMail=()=>run(async()=>{await navigator.clipboard.writeText(mail.value.body);Message.success('认证邮件正文已复制');});
function downloadMail(){const url=URL.createObjectURL(new Blob([mail.value.body],{type:'text/plain;charset=utf-8'}));const link=document.createElement('a');link.href=url;link.download='shou-verification.txt';link.click();URL.revokeObjectURL(url);}
const openConsole=()=>run(async()=>{
  if(status.value?.needs_certificate_issuance||store.security?.needs_certificate_issuance){
    Message.info(status.value?.certificate_status==='expired'?'你的特权管理证书已过期，请先在弹窗中重新签发硬件证书':'首次进入独立特权管理站前，请先在弹窗中完成硬件证书签发');
    sharedFunctions.openIssuanceModal();
    return;
  }
  const target=window.open('about:blank','shou-privileged');
  try{
    const [{data},configRes]=await Promise.all([Axios.post('/security/console-begin/'),Axios.get('/security/config/')]);
    const result=await Axios.post('/security/console-finish/',await getAssertion(data));
    const consoleUrl=validateConsoleHandoffUrl(result.data?.url,configRes.data?.console_url);
    if(target)target.location.href=consoleUrl;
    else window.location.assign(consoleUrl);
  }catch(error){
    target?.close();
    throw error;
  }
});
const openDjango=()=>run(async()=>{
  await reauthenticate();
  const {data}=await Axios.post('/security/django-admin/');
  const targetUrl=validateRelativeRedirectUrl(data?.url);
  window.open(targetUrl,'_blank','noopener,noreferrer');
});
const showRealName=(value:boolean)=>run(async()=>{await Axios.post('/security/privacy/',{show_real_name:value});await refresh();Message.success('实名展示设置已保存');});
const completeAdminSetup=()=>run(async()=>{
  const {data}=await Axios.post('/security/admin-setup-begin/');
  const result=await Axios.post('/security/admin-setup-finish/',await getAssertion(data,showPcsc.value?credentialConnection.value:'browser'));
  saveUserInfo(result.data,true);
  await refresh();
  if(result.data?.security?.needs_certificate_issuance){
    Message.success('管理员安全配置已完成；首次进入独立特权管理站时将自动弹出硬件证书签发窗口');
    return;
  }
  Message.success('管理员安全配置已完成');
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
        <li :class="{complete:adminKeysReady}"><span class="admin-step-number">01</span><div><strong>配置 FIDO2 安全密钥</strong><p>{{adminKeysReady?'安全密钥配置已达标，可继续完成身份认证或添加备用密钥。':needsSecondOrdinaryKey?'已绑定第 1 把普通安全密钥，请再绑定第 2 把不同的安全密钥（或改为绑定 FIPS 140-2 L2 / CC EAL4+ 以上高认证密钥）。':'管理员需绑定 2 把不同的普通外置安全密钥，或 1 把 FIPS 140-2 L2 / CC EAL4+ 以上高认证安全密钥。'}}</p></div></li>
        <li :class="{complete:status?.admin_setup_ready}"><span class="admin-step-number">02</span><div><strong>确认管理身份</strong><p>{{status?.admin_setup_ready?'邮箱、实名与进阶认证已就绪。':'完成教育邮箱与身份认证，等待材料审核通过。'}}</p></div></li>
        <li><span class="admin-step-number">03</span><div><strong>验证密钥，完成配置</strong><p>使用本人的安全密钥确认。配置完成前，仅开放安全配置功能。</p></div></li>
      </ol>
      <a-space wrap>
        <a-button v-if="!adminKeysReady" type="primary" @click="showSetupSection('security-key-setup')">{{ needsSecondOrdinaryKey ? '继续绑定第 2 把安全密钥' : '绑定我的安全密钥' }}</a-button>
        <a-button v-else-if="!status?.admin_setup_ready" type="primary" @click="showSetupSection('security-identity-setup')">继续身份认证</a-button>
        <a-button v-else type="primary" :loading="busy" @click="completeAdminSetup">验证安全密钥并完成配置</a-button>
        <a-button v-if="adminKeysReady" @click="showSetupSection('security-key-setup')">管理或添加备用密钥</a-button>
        <a-button type="text" @click="adminKeyGuideVisible = true">查看密钥要求</a-button>
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
      <p class="security-muted">每个账号可绑定 1–3 把安全密钥，支持 USB 与 NFC。</p>
      <div v-for="key in status?.keys" :key="key.id" class="key-row">
        <div class="key-info">
          <span class="key-name">{{ key.name }}</span>
          <span class="key-detail">{{ key.local_preview_trusted ? '本机测试已允许的安全密钥' : key.assurance?.high_assurance ? '高认证外置安全密钥' : key.trusted_hardware ? '已验证的外置安全密钥' : key.is_security_key ? '普通外置安全密钥' : '通行密钥' }} · {{ key.assurance?.label || '标准验证' }}</span>
          <span class="key-detail">最近使用：{{ key.last_used_at ? formatDatetime(key.last_used_at) : '尚未使用' }}</span>
        </div>
        <a-button type="text" status="danger" :disabled="busy" @click="removeKey(key)">撤销</a-button>
      </div>
      <a-empty v-if="status && !status.keys.length" description="还没有绑定登录凭据" class="key-empty" />
      <a-alert v-if="needsSecondOrdinaryKey || secondKeyGuide" type="warning" class="security-notice">
        已绑定 1 把普通安全密钥。管理员至少需要 2 把不同的普通外置安全密钥（或 1 把 FIPS 140-2 L2 / CC EAL4+ 以上高认证密钥）；请插入或轻触第 2 把安全密钥，然后点击下方按钮完成第 2 把密钥绑定。
      </a-alert>
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
        <a-form-item v-if="form.kind==='security_key' && showPcsc" label="连接方式">
          <a-select v-model="credentialConnection"><a-option value="browser">USB / NFC 安全密钥</a-option><a-option value="smartcard">接触式智能卡（PC/SC）</a-option></a-select>
        </a-form-item>
        <a-form-item v-if="form.kind==='security_key'" label="凭据模式" :extra="isAndroid ? '安卓 NFC 建议保持兼容模式；若系统弹窗仍提示失败，请在系统设置中将通行密钥服务切换为 Google 密码管理工具。' : undefined">
          <a-select v-model="form.resident_key" aria-label="凭据模式">
            <a-option value="preferred">标准模式（支持免账号登录，占 1 个空位）</a-option>
            <a-option value="discouraged">兼容模式（非可发现凭据，兼容移动 NFC）</a-option>
          </a-select>
        </a-form-item>
        <a-form-item>
          <a-button type="primary" html-type="submit" :loading="busy" :disabled="form.kind === 'security_key' && (status?.keys.filter((key:any) => key.is_security_key).length || 0) >= 3">{{ needsSecondOrdinaryKey ? '继续绑定第 2 把安全密钥' : '绑定新凭据' }}</a-button>
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

    <template v-if="pendingJobCount > 0 || (status?.signed_issuance_ready_count || 0) > 0 || (status?.pending_sign_requests_count || 0) > 0">
      <a-divider />
      <section id="security-browser-issuance">
        <a-typography-title :heading="5">智能卡 / TPM 证书签发与待签署提醒</a-typography-title>
        <a-alert v-if="(status?.pending_sign_requests_count || 0) > 0" type="info" class="security-notice">
          当前有 {{ status?.pending_sign_requests_count }} 份其他管理员提交的硬件证书公钥等待签署（CA 卡 / 超管卡 / 超级特权卡），请前往协助签署。
        </a-alert>
        <a-alert v-if="(status?.signed_issuance_ready_count || 0) > 0" type="success" class="security-notice">
          您有 {{ status?.signed_issuance_ready_count }} 份离线硬件证书申请已由管理员签署完成，请前往导入证书链到原智能卡 / TPM 并激活。
        </a-alert>
        <a-alert v-if="pendingJobCount > 0 && !(status?.signed_issuance_ready_count || 0)" type="info" class="security-notice">
          当前共有 {{ pendingJobCount }} 项进行中的特权证书签发任务。为确保私钥不可导出，证书仅可在实体智能卡或本机 Windows TPM 2.0 安全芯片内生成，请前往证书签发页查看进度或完成操作。
        </a-alert>
        <a-button type="primary" @click="sharedFunctions.openIssuanceModal()">打开证书签发弹窗</a-button>
      </section>
    </template>

    <template v-if="status?.admin_access && status?.is_privileged || store.permission.super_admin">
      <a-divider />
      <section>
        <a-typography-title :heading="5">管理入口</a-typography-title>
        <a-alert v-if="status?.needs_certificate_issuance" type="warning" class="security-notice">
          {{ status.certificate_status === 'expired' ? '你的特权管理证书已过期，点击下方「进入独立特权管理站」将自动弹出重新签发窗口。' : '首次访问独立特权管理站前需先签发硬件证书，点击下方「进入独立特权管理站」将自动弹出签发窗口。' }}
        </a-alert>
        <a-space wrap>
          <a-button v-if="status?.admin_access && status?.is_privileged" :loading="busy" @click="openConsole">进入独立特权管理站</a-button>
          <a-button v-if="store.permission.super_admin" :loading="busy" @click="openDjango">Django 管理</a-button>
        </a-space>
      </section>
    </template>

    <a-modal
      v-model:visible="adminKeyGuideVisible"
      :title="needsSecondOrdinaryKey ? '请继续绑定第 2 把安全密钥' : '管理员安全密钥要求'"
      :footer="false"
      :width="isMobile ? '92vw' : 520"
    >
      <p v-if="needsSecondOrdinaryKey" class="security-muted" style="margin-top: 0">
        你已绑定第 1 把普通安全密钥，还需再绑定第 2 把不同的外置安全密钥，方可完成管理员安全配置。
      </p>
      <ul style="margin: 0; padding-left: 20px; line-height: 1.75">
        <li>管理员需绑定 <strong>2 把不同的普通外置安全密钥</strong>，或 <strong>1 把 FIPS 140-2 L2 / CC EAL4+ 以上高认证安全密钥</strong>（须跨平台外置、不可备份同步且支持 PIN 或生物识别）。</li>
        <li>普通密钥登录需搭配第 2 把密钥、密码、二次验证器或邮箱验证码；高认证密钥支持单因素登录（超级／特权管理使用本站认证智能卡时仍需额外密钥或密码／二次验证器／邮箱验证）。</li>
      </ul>
      <a-button type="primary" long style="margin-top: 16px" @click="openKeySetupFromGuide">
        {{ needsSecondOrdinaryKey ? '我知道了，继续绑定第 2 把密钥' : '我知道了，去绑定密钥' }}
      </a-button>
    </a-modal>
  </div>
</template>
