<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { useRoute, useRouter } from 'vue-router';
import { Message, Modal } from '@arco-design/web-vue';
import Axios from '../../axios';
import { useStore } from '../../stores';
import { createCredential, getAssertion, reauthenticate, securityError } from '../../scripts/webauthn';
import { saveUserInfo } from '../../scripts/userInfo';
import { formatDatetime } from '../../scripts/time';
import { preferredSmartCard } from '../../scripts/smartcard';
import type { KeyAssurance, SecurityState } from '../../types';
import '../../styles/security-settings.scss';

type KeyInfo = {
  id: number;
  name: string;
  is_security_key: boolean;
  trusted_hardware: boolean;
  local_preview_trusted: boolean;
  assurance: KeyAssurance;
  created_at: string;
  last_used_at: string | null;
};

const emit = defineEmits<{
  (e: 'close'): void;
  (e: 'completed'): void;
}>();

const store = useStore();
const route = useRoute();
const router = useRouter();

const status = ref<(SecurityState & { keys: KeyInfo[] }) | null>(null);
const busy = ref(false);
const fidoFreshUntil = ref(0);
const mail = ref<any>(null);
const advanced = ref<any>({ status: 'not_started' });
const contact = ref('renzheng@shouguatian.com');

const showPcsc = computed(() => route.query.pcsc === '1' || preferredSmartCard());
const credentialConnection = ref<'browser' | 'smartcard'>(showPcsc.value ? 'smartcard' : 'browser');
const isAndroid = /Android/i.test(navigator.userAgent || '');

const keyForm = reactive({
  password: '',
  name: '我的安全密钥',
  resident_key: (isAndroid ? 'discouraged' : 'preferred') as 'preferred' | 'discouraged' | 'required',
});

const isManagement = computed(() => Boolean(status.value?.is_management ?? store.security?.is_management));
const adminKeysReady = computed(() => Boolean(status.value?.admin_keys_satisfied));
const identityVerified = computed(() =>
  Boolean(status.value?.email_verified && status.value?.real_name_verified && status.value?.advanced_verified)
);
const externalKeys = computed(() => (status.value?.keys || []).filter(key => key.is_security_key));
const hasAnyExternalKey = computed(() => externalKeys.value.length > 0);
const needsSecondOrdinaryKey = computed(() =>
  Boolean(
    isManagement.value &&
    !status.value?.admin_keys_satisfied &&
    (status.value?.external_key_count || 0) === 1 &&
    !status.value?.has_high_assurance_key
  )
);
const badgeLabels = computed(() => (store.user?.badges || []).map(item => item.label).filter(Boolean));
const sessionKeyName = computed(() => {
  const id = status.value?.session_key_id;
  return status.value?.keys.find(key => key.id === id)?.name || '本次登录使用的安全密钥';
});
const advancedLabel = computed(() => {
  if (identityVerified.value || advanced.value.status === 'approved') return '认证通过';
  if (['rejected', 'expired'].includes(advanced.value.status)) return '认证错误';
  return '等待认证';
});

async function refresh() {
  const [securityRes, infoRes, verificationRes] = await Promise.all([
    Axios.get('/security/status/'),
    Axios.get('/user/info/'),
    Axios.get('/security/advanced/status/'),
  ]);
  status.value = securityRes.data;
  const freshSeconds = Number(securityRes.data?.fido_fresh_seconds || 0);
  fidoFreshUntil.value = freshSeconds > 0 ? Date.now() + freshSeconds * 1000 : 0;
  saveUserInfo(infoRes.data, false);
  advanced.value = verificationRes.data;
  if (needsSecondOrdinaryKey.value && keyForm.name === '我的安全密钥') {
    keyForm.name = '备用安全密钥（第 2 把）';
  }
}

async function run(action: () => Promise<void>) {
  busy.value = true;
  try {
    await action();
  } catch (error) {
    Message.error(securityError(error));
  } finally {
    busy.value = false;
  }
}

function hasFreshFido(bufferSeconds = 60) {
  return Boolean(status.value?.fido_authenticated && fidoFreshUntil.value - Date.now() > bufferSeconds * 1000);
}

async function performReauth() {
  const res = await reauthenticate(showPcsc.value ? credentialConnection.value : 'browser');
  const freshSeconds = Number(res?.fido_fresh_seconds || 300);
  fidoFreshUntil.value = Date.now() + freshSeconds * 1000;
}

function promptReauthForBind() {
  Modal.confirm({
    title: '请先验证已绑定的安全密钥',
    content: `当前安全验证需要重新确认。请先连接或轻触已绑定的「${sessionKeyName.value}」确认身份，验证通过后再绑定新密钥。`,
    okText: '验证已绑定密钥',
    cancelText: '取消',
    onOk: () => run(async () => {
      await performReauth();
      await refresh();
      Message.success('身份已确认（5 分钟内有效）。请接入新安全密钥并再次点击绑定。');
    }),
  });
}

const bindKey = () => {
  if (status.value?.fido_authenticated && !hasFreshFido(60)) {
    promptReauthForBind();
    return;
  }
  return run(async () => {
    const payload = {
      kind: 'security_key',
      name: keyForm.name,
      resident_key: keyForm.resident_key,
      password: keyForm.password,
    };
    let data: any;
    try {
      ({ data } = await Axios.post('/security/key-register-begin/', payload));
    } catch (error: any) {
      const msg = String(error?.response?.data?.msg || '');
      if (
        error?.response?.status === 403 &&
        (hasAnyExternalKey.value || status.value?.fido_authenticated) &&
        (msg.includes('重新验证') || msg.includes('外置安全密钥'))
      ) {
        fidoFreshUntil.value = 0;
        promptReauthForBind();
        return;
      }
      throw error;
    }
    const connection = showPcsc.value ? credentialConnection.value : 'browser';
    const { data: finishData } = await Axios.post('/security/key-register-finish/', {
      ...(await createCredential(data, connection)),
      password: keyForm.password,
    });
    keyForm.password = '';
    await refresh();
    const count = status.value?.external_key_count ?? finishData?.external_key_count ?? 0;
    if (isManagement.value && !finishData?.high_assurance && !status.value?.admin_keys_satisfied && count === 1) {
      keyForm.name = '备用安全密钥（第 2 把）';
      Message.info('第 1 把普通安全密钥已绑定，请再插入第 2 把不同的外置安全密钥完成绑定。');
    } else {
      keyForm.name = '我的安全密钥';
      Message.success('外置安全密钥已绑定');
    }
  });
};

const signAdvanced = () => run(async () => {
  const connection = showPcsc.value ? credentialConnection.value : 'browser';
  if (!status.value?.key_authenticated) {
    await performReauth();
  }
  const { data } = await Axios.post('/security/advanced/begin/', {});
  mail.value = (await Axios.post('/security/advanced/finish/', await getAssertion(data, connection))).data;
  await refresh();
});

const copyMail = () => run(async () => {
  await navigator.clipboard.writeText(mail.value.body);
  Message.success('认证邮件正文已复制');
});

function downloadMail() {
  const url = URL.createObjectURL(new Blob([mail.value.body], { type: 'text/plain;charset=utf-8' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = 'shou-verification.txt';
  link.click();
  URL.revokeObjectURL(url);
}

function goToEmail() {
  emit('close');
  void router.push('/email/');
}

const completeAdminSetup = () => run(async () => {
  const connection = showPcsc.value ? credentialConnection.value : 'browser';
  const { data } = await Axios.post('/security/admin-setup-begin/');
  const result = await Axios.post('/security/admin-setup-finish/', await getAssertion(data, connection));
  saveUserInfo(result.data, true);
  await refresh();
  emit('completed');
  if (result.data?.security?.needs_certificate_issuance) {
    Message.success('管理员安全配置已完成；首次进入独立特权管理站时将自动弹出硬件证书签发窗口');
    return;
  }
  Message.success('管理员安全配置已完成，管理权限已启用');
});

onMounted(() => run(async () => {
  const [configRes] = await Promise.all([
    Axios.get('/security/config/').catch(() => null),
    refresh(),
  ]);
  if (configRes?.data?.material_review_contact) {
    contact.value = configRes.data.material_review_contact;
  }
}));
</script>

<template>
  <div class="admin-onboarding-modal">
    <section class="admin-welcome" aria-labelledby="admin-welcome-title">
      <div class="admin-welcome-top">
        <h2 id="admin-welcome-title" style="margin: 0">{{ isManagement ? '欢迎加入管理团队' : '管理员实名与安全认证' }}</h2>
        <a-button type="text" size="small" aria-label="关闭引导窗口" @click="emit('close')">关闭</a-button>
      </div>
      <p v-if="isManagement && badgeLabels.length" class="security-muted" style="margin-bottom: 6px">
        当前管理身份：<strong>{{ badgeLabels.join('、') }}</strong>
      </p>

      <div class="security-statuses">
        <span class="security-status" :class="{ complete: status?.email_verified }">教育邮箱 · {{ status?.email_verified ? '已验证' : '待验证' }}</span>
        <span class="security-status" :class="{ complete: adminKeysReady }">外置密钥 · {{ adminKeysReady ? '已达标' : '待绑定' }}</span>
        <span class="security-status" :class="{ complete: status?.real_name_verified }">实名 · {{ status?.real_name_verified ? '已认证' : '待认证' }}</span>
        <span class="security-status" :class="{ complete: status?.advanced_verified }">进阶认证 · {{ status?.advanced_verified ? '已认证' : '待认证' }}</span>
      </div>

      <ol class="admin-welcome-steps">
        <li :class="{ complete: adminKeysReady }">
          <span class="admin-step-number">01</span>
          <div class="onboarding-step-body">
            <strong>绑定外置 FIDO2 安全密钥</strong>
            <div v-if="externalKeys.length" class="onboarding-bound-keys">
              <span v-for="key in externalKeys" :key="key.id" class="onboarding-key-pill">
                {{ key.name }} · {{ key.assurance?.label || '标准验证' }}
              </span>
            </div>
            <div v-if="!adminKeysReady" class="onboarding-subcard">
              <template v-if="status && !status.email_verified">
                <a-alert type="warning" class="security-notice">请先验证教育邮箱后再绑定外置安全密钥。</a-alert>
                <a-button type="primary" @click="goToEmail">前往验证教育邮箱</a-button>
              </template>
              <a-form v-else :model="keyForm" layout="vertical" class="onboarding-inline-form" @submit="bindKey">
                <a-form-item v-if="!status?.fido_authenticated && !hasAnyExternalKey" label="当前密码（刚完成邮箱登录可留空）">
                  <a-input-password v-model="keyForm.password" autocomplete="current-password" placeholder="超时重验时输入当前密码" />
                </a-form-item>
                <a-form-item label="凭据名称">
                  <a-input v-model="keyForm.name" :max-length="80" placeholder="例如：随身安全密钥" />
                </a-form-item>
                <a-form-item v-if="showPcsc" label="连接方式">
                  <a-select v-model="credentialConnection">
                    <a-option value="browser">USB / NFC 安全密钥</a-option>
                    <a-option value="smartcard">接触式智能卡（PC/SC）</a-option>
                  </a-select>
                </a-form-item>
                <a-form-item label="凭据模式" :extra="isAndroid ? '安卓 NFC 建议保持兼容模式。' : undefined">
                  <a-select v-model="keyForm.resident_key" aria-label="凭据模式">
                    <a-option value="preferred">标准模式（支持免账号登录，占 1 个空位）</a-option>
                    <a-option value="discouraged">兼容模式（非可发现凭据，兼容移动 NFC）</a-option>
                  </a-select>
                </a-form-item>
                <a-form-item>
                  <a-button
                    type="primary"
                    html-type="submit"
                    :loading="busy"
                    :disabled="externalKeys.length >= 3"
                  >
                    {{ needsSecondOrdinaryKey ? '继续绑定第 2 把安全密钥' : '绑定外置安全密钥' }}
                  </a-button>
                </a-form-item>
              </a-form>
            </div>
          </div>
        </li>

        <li :class="{ complete: identityVerified }">
          <span class="admin-step-number">02</span>
          <div id="security-identity-setup" class="onboarding-step-body onboarding-identity-panel">
            <h3 class="onboarding-step-heading">管理员进阶认证</h3>
            <div class="onboarding-status-row">
              <a-tag role="status">{{ advancedLabel }}</a-tag>
            </div>
            <template v-if="!identityVerified">
              <template v-if="status && !status.email_verified">
                <a-alert type="warning" class="security-notice">请先绑定并验证教育邮箱，再生成和签署进阶认证挑战。</a-alert>
                <a-button @click="goToEmail">前往验证教育邮箱</a-button>
              </template>
              <p v-if="advanced.real_name || store.user?.real_name" class="advanced-details">
                实名：{{ advanced.real_name || store.user?.real_name }}<span v-if="advanced.student_id || store.user?.student_id"> · 学号：{{ advanced.student_id || store.user?.student_id }}</span>
              </p>
              <a-space wrap style="margin-top: 12px">
                <a-button
                  type="primary"
                  :loading="busy"
                  :disabled="!status?.email_verified || !hasAnyExternalKey"
                  @click="signAdvanced"
                >
                  生成并签署认证挑战
                </a-button>
                <a-button :disabled="busy" @click="run(refresh)">刷新审核状态</a-button>
              </a-space>
              <p v-if="status?.email_verified && !hasAnyExternalKey" class="security-muted" style="margin-top: 8px; margin-bottom: 0">
                请先在步骤 01 绑定至少 1 把外置安全密钥，再签署认证挑战。
              </p>
              <div v-if="mail" class="onboarding-mail-box">
                <p class="security-muted">发件邮箱：{{ mail.from_email }} · 截止：{{ formatDatetime(mail.expires_at) }}</p>
                <pre class="challenge-mail">{{ mail.body }}</pre>
                <div class="security-actions">
                  <a-button @click="copyMail">复制认证邮件</a-button>
                  <a-button @click="downloadMail">下载认证文本</a-button>
                  <a :href="`mailto:${mail.recipient}?subject=${encodeURIComponent(mail.subject)}&body=${encodeURIComponent(mail.body)}`">
                    <a-button>打开邮件客户端</a-button>
                  </a>
                </div>
              </div>
              <p class="security-muted security-contact">实名材料审核联系方式：{{ contact }}</p>
            </template>
            <p v-else class="onboarding-verified-note">教育邮箱、实名与进阶认证均已通过。</p>
          </div>
        </li>

        <li v-if="isManagement" :class="{ complete: Boolean(status?.admin_access) }">
          <span class="admin-step-number">03</span>
          <div class="onboarding-step-body">
            <strong>验证密钥，启用管理权限</strong>
          </div>
        </li>
      </ol>

      <a-space wrap>
        <a-button
          v-if="isManagement"
          type="primary"
          :disabled="!status?.admin_setup_ready"
          :loading="busy"
          @click="completeAdminSetup"
        >
          验证安全密钥并完成配置
        </a-button>
        <a-button v-if="!isManagement || !status?.admin_setup_ready" @click="emit('close')">稍后继续</a-button>
      </a-space>
    </section>
  </div>
</template>
