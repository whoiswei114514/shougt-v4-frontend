<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import Axios from '../../axios';
import { formatDatetime } from '../../scripts/time';
import { saveUserInfo } from '../../scripts/userInfo';
import { getAssertion, reauthenticate, securityError } from '../../scripts/webauthn';
import { isMobile } from '../../consts/isMobile';
import type { SecurityState } from '../../types';
import {
  findAuthorityDescriptor,
  type AuthorityDescriptor,
  type BrowserPendingJob,
} from '../../scripts/webpiv/browserCeremony';
import { WebPivCeremony } from '../../scripts/webpiv/ceremony';
import { createCardRegistry, type WebUsbCardRecord } from '../../scripts/webpiv/webusb';
import { validateConsoleHandoffUrl } from '../../scripts/securityUrls';
import {
  isValidBridgePort,
  isValidBridgeToken,
  validateBridgePath,
  validateInstallBridgeResult,
  validateLoopbackBridgeUrl,
  validatePairResponse,
  validatePcscReadersPayload,
  validateSlotDecisionPayload,
  verifyGenerateBridgeResult,
  verifySignBridgeResult,
  type SanitizedPcscCard,
} from '../../scripts/bridgeValidation';
import '../../styles/auth.scss';
import '../../styles/security-settings.scss';

const props = defineProps<{ modal?: boolean }>();
const emit = defineEmits<{ (e: 'close'): void }>();

interface SelfIssuanceInfo {
  available: boolean;
  roles: string[];
  site_ca_count: number;
  super_admin_card_count: number;
  superadmin_admin_card_count: number;
  authorities_summary: AuthorityDescriptor[];
}

type PcscCard = SanitizedPcscCard;

const ROLE_TEXT: Record<string, string> = {
  super_admin: '超级管理员',
  admin_admin: '特权管理员',
  superadmin_admin: '特权超级管理员',
  global_reader: '全局读者',
};

const status = ref<SecurityState | null>(null);
const busy = ref(false);
const contact = ref('renzheng@shouguatian.com');
const pendingJobs = ref<BrowserPendingJob[]>([]);
const signQueue = ref<BrowserPendingJob[]>([]);

const selfIssuanceInfo = ref<SelfIssuanceInfo | null>(null);

const webUsbRegistry = createCardRegistry();
const webUsbSupported = computed(() => webUsbRegistry.supported());
const webUsbCards = ref<WebUsbCardRecord[]>([]);

const selfForm = reactive({
  issuanceMode: 'standard' as 'standard' | 'temporary',
  validityDays: 36,
  targetMode: 'pcsc' as 'pcsc' | 'webusb',
  caMode: 'pcsc_ca' as 'pcsc_ca' | 'webusb_ca',
  targetAlgorithm: 'auto',
  targetSlot: '9a' as '9a' | '9c' | '9e',
  targetManagementAlg: 'tdes',
  targetWebUsbId: '',
  caWebUsbId: '',
  caSlot: 'auto' as 'auto' | '9c' | '9a',
  pcscTargetReader: '',
  pcscTargetTransport: 'auto',
  pcscCaReader: '',
  pcscCaTransport: 'auto',
});

const pcsc = reactive({
  port: 18444,
  pairCode: '',
  helper: '',
  token: '',
  cards: [] as PcscCard[],
  launching: false,
  launchMessage: '',
});
let pcscPollRunId = 0;

const registerHelperCommand = 'python -m backend.piv_helper_gui --register-protocol';
const fallbackHelperCommand = computed(() => {
  const loopFlag = window.location.protocol === 'http:' ? ' --allow-loopback-http' : '';
  return `python -m backend.piv_helper_gui --origin ${window.location.origin}${loopFlag}`;
});

const selfProgress = ref('');
const selfError = ref('');
const helperDownloadHint = ref('');
const webUsbHint = ref('');
const webUsbError = ref('');
const pendingSelfSignJob = ref<BrowserPendingJob | null>(null);
const pendingSelfCarrier = ref<'pcsc' | 'webusb'>('pcsc');
const pendingSelfTargetReader = ref('');
const selfResult = ref<{
  temporary: boolean;
  isCaCert: boolean;
  validityDays?: number | null;
  expiresAt: string;
  issuerLabel: string;
  issuerKind: string;
  fingerprint: string;
  carrierLabel: string;
} | null>(null);

const webModal = reactive({
  visible: false,
  kind: 'confirm' as 'card' | 'secret' | 'confirm' | 'slot',
  title: '',
  message: '',
  secretLabel: '',
  secretValue: '',
  acknowledgeRequired: false,
  acknowledged: false,
  selectedCardId: '',
  nextSlot: '',
  error: '',
  validate: null as ((val: string) => boolean) | null,
  resolve: null as ((val: any) => void) | null,
});

const visibleAuthorities = computed(() => {
  const list = selfIssuanceInfo.value?.authorities_summary || [];
  return selfForm.issuanceMode === 'standard' ? list.filter(d => !d.temporary_only) : list;
});

const pcscReadyCards = computed(() =>
  pcsc.cards.filter(c => !['fido_only', 'unsupported', 'disconnected', 'disabled'].includes(c.state)),
);

const selectedTargetIsTpm = computed(() => {
  const card = pcsc.cards.find(c => c.id === selfForm.pcscTargetReader);
  return Boolean(card?.transport === 'tpm' || selfForm.pcscTargetReader.startsWith('tpm:'));
});

const myAsyncJobs = computed(() =>
  pendingJobs.value.filter(j => j.self_service && j.async_request),
);

const remoteAdminJobs = computed(() =>
  pendingJobs.value.filter(j => !j.self_service),
);

const usesPcscHelper = computed(() =>
  selfForm.targetMode === 'pcsc' ||
  selfForm.caMode === 'pcsc_ca' ||
  pendingJobs.value.length > 0 ||
  signQueue.value.length > 0,
);

let webCeremonyInstance: WebPivCeremony | null = null;

function openWebModal(cfg: Partial<typeof webModal>): Promise<any> {
  return new Promise(resolve => {
    webModal.kind = cfg.kind || 'confirm';
    webModal.title = cfg.title || '';
    webModal.message = cfg.message || '';
    webModal.secretLabel = cfg.secretLabel || '';
    webModal.secretValue = '';
    webModal.acknowledgeRequired = Boolean(cfg.acknowledgeRequired);
    webModal.acknowledged = false;
    webModal.selectedCardId = cfg.selectedCardId || '';
    webModal.nextSlot = cfg.nextSlot || '';
    webModal.error = '';
    webModal.validate = cfg.validate || null;
    webModal.resolve = resolve;
    webModal.visible = true;
  });
}

function submitWebModal() {
  if (webModal.kind === 'confirm' && webModal.acknowledgeRequired && !webModal.acknowledged) {
    webModal.error = '请先勾选确认项';
    return;
  }
  if (webModal.kind === 'secret') {
    if (webModal.validate && !webModal.validate(webModal.secretValue)) {
      webModal.error = '输入格式不符合要求，请核对后重试';
      return;
    }
  }
  if (webModal.kind === 'card' && !webModal.selectedCardId) {
    webModal.error = '请选择已就绪的 WebUSB 智能卡设备';
    return;
  }
  const res = webModal.resolve;
  webModal.visible = false;
  webModal.resolve = null;
  if (webModal.kind === 'secret') res?.(webModal.secretValue);
  else if (webModal.kind === 'card') res?.(webModal.selectedCardId);
  else res?.(true);
  webModal.secretValue = '';
}

function cancelWebModal() {
  const res = webModal.resolve;
  webModal.visible = false;
  webModal.resolve = null;
  webModal.secretValue = '';
  res?.(webModal.kind === 'confirm' || webModal.kind === 'slot' ? false : null);
}

async function authorizeWebUsbInModal() {
  try {
    const id = await webUsbRegistry.requestDevice();
    webUsbCards.value = await webUsbRegistry.enumerate(true);
    webModal.selectedCardId = id;
    webModal.error = '';
  } catch (error: any) {
    webModal.error = error?.name === 'NotFoundError' ? '未选择 USB 智能卡' : securityError(error);
  }
}

async function refreshWebUsbInModal() {
  try {
    webUsbCards.value = await webUsbRegistry.enumerate(true);
    if (!webUsbCards.value.some(c => c.id === webModal.selectedCardId && c.piv && c.state === 'ready')) {
      webModal.selectedCardId = webUsbCards.value.find(c => c.piv && c.state === 'ready')?.id || '';
    }
    webModal.error = '';
  } catch (error: any) {
    webModal.error = securityError(error);
  }
}

function getWebCeremony(): WebPivCeremony {
  if (webCeremonyInstance) return webCeremonyInstance;
  webCeremonyInstance = new WebPivCeremony({
    progress: msg => {
      selfProgress.value = msg;
    },
    chooseSlot: async state => Boolean(await openWebModal({
      kind: 'slot',
      title: '目标槽位已有证书',
      message: `槽位 ${state.slot} 已有证书，是否改用下一个空槽位 ${state.next_slot}？${state.next_slot === '9e' ? '\n注意：9e 槽通常不要求 PIN，请确认卡片策略支持。' : ''}`,
      nextSlot: state.next_slot,
    })),
    chooseCard: async (stage, selected) => {
      const cards = await webUsbRegistry.enumerate(true);
      webUsbCards.value = cards;
      const preferredId = selected
        || (stage === 'sign' ? selfForm.caWebUsbId : selfForm.targetWebUsbId)
        || cards.find(c => c.piv && c.state === 'ready')?.id
        || '';
      const stageLabel = stage === 'sign'
        ? '签发卡（CA 卡 / 超管卡 / 超级特权卡）'
        : stage === 'install'
          ? '原目标 USB 智能卡（回读与证明）'
          : '目标 USB 智能卡（卡内生成密钥）';
      const chosenId = await openWebModal({
        kind: 'card',
        title: `连接${stageLabel}`,
        message: `请选择用于「${stage === 'sign' ? '签发证书' : stage === 'install' ? '写入证书' : '卡内生成密钥'}」的 WebUSB 智能卡设备，也可点击下方按钮授权新卡。`,
        selectedCardId: preferredId,
      });
      if (!chosenId) throw new Error('已取消连接 USB 智能卡');
      if (stage === 'sign') selfForm.caWebUsbId = chosenId;
      else selfForm.targetWebUsbId = chosenId;
      return webUsbRegistry.channel(chosenId);
    },
    secret: async settings => {
      const isMgmt = settings.kind === 'management';
      const hexLengths: Record<string, number> = { tdes: 48, aes128: 32, aes192: 48, aes256: 64 };
      const scheme = settings.scheme || 'tdes';
      const val = await openWebModal({
        kind: 'secret',
        title: isMgmt ? '输入目标卡管理密钥' : '输入 PIV PIN',
        message: isMgmt
          ? `${settings.name} · 管理密钥仅用于当前页与智能卡双向认证，不发送给服务器。`
          : `${settings.name} · PIV PIN 错误会立即停止，不自动重试。输入内容仅用于本机签名。`,
        secretLabel: isMgmt ? `管理密钥（${scheme}，${hexLengths[scheme] || 48} 位十六进制）` : 'PIV PIN（6–8 位数字）',
        validate: value => isMgmt
          ? new RegExp(`^[0-9a-fA-F]{${hexLengths[scheme] || 48}}$`).test(value)
          : /^[0-9]{6,8}$/.test(value),
      });
      if (val === null || val === undefined) throw new Error('已取消输入智能卡密钥');
      return val;
    },
    confirm: async settings => Boolean(await openWebModal({
      kind: 'confirm',
      title: settings.stage === 'generate' ? '确认目标私钥槽位' : settings.stage === 'sign' ? '确认签发卡类型与签发信息' : '确认写入智能卡',
      message: `${settings.name} · ${settings.real_name}\n${settings.message}`,
      acknowledgeRequired: settings.stage === 'generate',
    })),
  });
  return webCeremonyInstance;
}

async function run(action: () => Promise<void>) {
  busy.value = true;
  selfError.value = '';
  try {
    await action();
  } catch (error) {
    const message = securityError(error);
    selfError.value = message;
    Message.error(message);
  } finally {
    busy.value = false;
  }
}

function roleListText(roles: string[]): string {
  return roles.map(r => ROLE_TEXT[r] || r).join(' / ');
}

function matchedAuthorityForCard(card: PcscCard): AuthorityDescriptor | null {
  if (!card.slot_9a_fingerprint) return null;
  const selfList = selfIssuanceInfo.value?.authorities_summary || [];
  const queueList = signQueue.value.flatMap(j => j.authority_descriptors || []);
  return [...selfList, ...queueList].find(item => item.fingerprint === card.slot_9a_fingerprint) || null;
}

function deviceOptionText(card: PcscCard): string {
  if (card.transport === 'tpm' || card.tpm) return `${card.name} · TPM 2.0 硬件安全芯片`;
  const medium = card.transport === 'nfc' ? 'NFC' : card.transport === 'usb' ? 'USB CCID' : '接触式 / CCID';
  const cap = card.piv ? (card.fido2 ? 'PIV + FIDO2' : 'PIV') : card.state;
  const auth = matchedAuthorityForCard(card);
  const slotHint = auth
    ? ` · 检测到【${auth.label}${auth.temporary_only ? '（仅37天内）' : ''}】`
    : card.default_slot_occupied === true
      ? ' · 9a 槽已有证书'
      : card.default_slot_occupied === false
        ? ' · 9a 槽空白（可作目标卡）'
        : '';
  return `${card.name} · ${medium} · ${cap}${slotHint}`;
}

const PCSC_HELPER_URL_KEY = 'shou_piv_helper_url';
const PCSC_HELPER_TOKEN_KEY = 'shou_piv_helper_token';
const ALLOWED_PCSC_PATHS = ['/pair', '/readers', '/start', '/status', '/choose-slot'] as const;

function savePcscSession(url: string, token: string) {
  const safeUrl = validateLoopbackBridgeUrl(url);
  if (!safeUrl || !isValidBridgeToken(token)) return;
  try {
    sessionStorage.setItem(PCSC_HELPER_URL_KEY, safeUrl);
    sessionStorage.setItem(PCSC_HELPER_TOKEN_KEY, token);
  } catch {}
}

function clearPcscSession() {
  try {
    sessionStorage.removeItem(PCSC_HELPER_URL_KEY);
    sessionStorage.removeItem(PCSC_HELPER_TOKEN_KEY);
  } catch {}
}

function syncWebUsbSelections() {
  const ready = webUsbCards.value.filter(c => c.piv && c.state === 'ready');
  const firstReadyId = ready[0]?.id || '';
  if (selfForm.targetWebUsbId && !ready.some(c => c.id === selfForm.targetWebUsbId)) {
    selfForm.targetWebUsbId = firstReadyId;
  } else if (!selfForm.targetWebUsbId && firstReadyId) {
    selfForm.targetWebUsbId = firstReadyId;
  }
  if (selfForm.caWebUsbId && !ready.some(c => c.id === selfForm.caWebUsbId)) {
    selfForm.caWebUsbId = firstReadyId;
  } else if (!selfForm.caWebUsbId && firstReadyId) {
    selfForm.caWebUsbId = firstReadyId;
  }
}

async function refresh() {
  const [securityRes, infoRes, cfgRes] = await Promise.all([
    Axios.get('/security/status/'),
    Axios.get('/user/info/'),
    Axios.get('/security/config/'),
  ]);
  status.value = securityRes.data;
  saveUserInfo(infoRes.data, false);
  contact.value = cfgRes.data?.material_review_contact || 'renzheng@shouguatian.com';

  if (webUsbSupported.value) {
    webUsbCards.value = await webUsbRegistry.enumerate(true).catch(() => []);
    syncWebUsbSelections();
    if (webUsbCards.value.length > 0) webUsbHint.value = '';
    if (webUsbCards.value.some(c => c.piv && c.state === 'ready')) webUsbError.value = '';
  }

  if (
    status.value?.key_authenticated &&
    status.value?.email_verified &&
    status.value?.real_name_verified &&
    status.value?.advanced_verified &&
    !status.value?.admin_onboarding_required
  ) {
    const [pendingResult, selfResult, queueResult] = await Promise.allSettled([
      Axios.get('/security/issuance-pending/'),
      status.value?.is_privileged && status.value?.admin_access
        ? Axios.get('/security/self-issuance-info/')
        : Promise.resolve(null),
      status.value?.can_sign_issuance_requests && status.value?.admin_access
        ? Axios.get('/security/issuance-sign-queue/')
        : Promise.resolve(null),
    ]);

    pendingJobs.value = pendingResult.status === 'fulfilled' && Array.isArray(pendingResult.value?.data?.jobs)
      ? pendingResult.value.data.jobs
      : [];
    selfIssuanceInfo.value = selfResult.status === 'fulfilled' && selfResult.value?.data
      ? selfResult.value.data
      : null;
    signQueue.value = queueResult.status === 'fulfilled' && Array.isArray(queueResult.value?.data?.jobs)
      ? queueResult.value.data.jobs
      : [];
  } else {
    pendingJobs.value = [];
    selfIssuanceInfo.value = null;
    signQueue.value = [];
  }

  if (!pcsc.token) {
    try {
      const savedUrl = validateLoopbackBridgeUrl(sessionStorage.getItem(PCSC_HELPER_URL_KEY) || '');
      const savedToken = sessionStorage.getItem(PCSC_HELPER_TOKEN_KEY) || '';
      if (savedUrl && isValidBridgeToken(savedToken)) {
        pcsc.helper = savedUrl;
        pcsc.token = savedToken;
        await refreshPcscReadersInternal();
      } else if (sessionStorage.getItem(PCSC_HELPER_URL_KEY) || sessionStorage.getItem(PCSC_HELPER_TOKEN_KEY)) {
        clearPcscSession();
      }
    } catch {
      pcsc.token = '';
      clearPcscSession();
    }
  }
}

const downloadHelperPackage = () => run(async () => {
  const res = await Axios.get('/security/helper-download/', { responseType: 'arraybuffer' });
  const bytes = new Uint8Array(res.data);
  if (bytes.byteLength < 4 || bytes[0] !== 0x50 || bytes[1] !== 0x4b) {
    throw new Error('下载的助手压缩包内容无效，请重试');
  }
  const disposition = String(res.headers?.['content-disposition'] || '');
  const match = /filename="([^"]+)"/.exec(disposition);
  const rawName = (match?.[1] || '').split(/[\\/]/).pop()?.replace(/[^A-Za-z0-9._-]/g, '_') || '';
  const filename = rawName && rawName !== '.' && rawName !== '..' ? rawName : 'shou-smartcard-helper-windows.zip';
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/zip' }));
  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  helperDownloadHint.value = '已下载 Windows 本机助手压缩包：解压到固定目录后双击运行「一键安装并注册助手.bat」，完成即可点击「一键唤起本机智能卡 / TPM 助手」。';
  Message.success('已开始下载本机智能卡 / TPM 助手');
});

async function authorizeWebUsbCard(primary: 'target' | 'ca', successText: string) {
  webUsbError.value = '';
  webUsbHint.value = '';
  try {
    const id = await webUsbRegistry.requestDevice();
    webUsbCards.value = await webUsbRegistry.enumerate(true);
    if (primary === 'target') {
      selfForm.targetWebUsbId = id;
      if (!selfForm.caWebUsbId) selfForm.caWebUsbId = id;
    } else {
      selfForm.caWebUsbId = id;
      if (!selfForm.targetWebUsbId) selfForm.targetWebUsbId = id;
    }
    syncWebUsbSelections();
    Message.success(successText);
  } catch (error) {
    webUsbError.value = securityError(error);
    throw error;
  } finally {
    webUsbCards.value = await webUsbRegistry.enumerate(false).catch(() => webUsbCards.value);
  }
}

const authorizeTargetWebUsb = () => run(() => authorizeWebUsbCard('target', '已授权 USB 智能卡'));

const authorizeCaWebUsb = () => run(() => authorizeWebUsbCard('ca', '已授权 USB 签发智能卡'));

const refreshWebUsbList = () => run(async () => {
  webUsbError.value = '';
  webUsbHint.value = '';
  webUsbCards.value = await webUsbRegistry.enumerate(true, true);
  syncWebUsbSelections();
  if (webUsbCards.value.length === 0) {
    webUsbHint.value = '浏览器尚未对当前网站授予任何 USB 智能卡权限：请先点击左侧「授权新卡」，在浏览器顶部弹出的 USB 权限窗口中选择设备；或直接切换为「Windows 读卡器 / 本机 TPM 2.0」（本机助手已识别到您的智能卡）。';
    Message.info('请先点击「授权新卡」授权浏览器访问 USB 智能卡');
    return;
  }
  const readyCount = webUsbCards.value.filter(c => c.piv && c.state === 'ready').length;
  const firstErr = webUsbCards.value.find(c => c.state !== 'ready' && c.error)?.error;
  if (readyCount === 0 && firstErr) {
    webUsbError.value = firstErr;
    Message.warning(`未检测到就绪的 WebUSB 智能卡：${firstErr}`);
  } else {
    Message.success(`已检测到 ${readyCount} 张就绪的 WebUSB 智能卡`);
  }
});

async function pcscRequest(path: string, data: Record<string, any> = {}) {
  const safeUrl = validateLoopbackBridgeUrl(pcsc.helper);
  if (!safeUrl) {
    pcsc.token = '';
    clearPcscSession();
    throw new Error('本机助手地址无效，请使用 127.0.0.1 的有效端口重新配对');
  }
  const safePath = validateBridgePath(path, ALLOWED_PCSC_PATHS);
  const authHeaders: Record<string, string> = {};
  if (pcsc.token) {
    if (!isValidBridgeToken(pcsc.token)) {
      pcsc.token = '';
      clearPcscSession();
      throw new Error('本机助手配对令牌无效，请重新配对');
    }
    authHeaders['X-Shou-Piv-Token'] = pcsc.token;
  }
  let response: Response;
  try {
    response = await fetch(safeUrl + safePath, {
      method: 'POST',
      mode: 'cors',
      credentials: 'omit',
      cache: 'no-store',
      signal: AbortSignal.timeout(15000),
      headers: { 'Content-Type': 'application/json', ...authHeaders },
      body: JSON.stringify(data),
    });
  } catch {
    throw new Error('无法连接本机智能卡 / TPM 助手，请点击「一键唤起本机智能卡 / TPM 助手」并允许连接。');
  }
  let result: any;
  try {
    result = await response.json();
  } catch {
    throw new Error('本机智能卡 / TPM 助手返回了无效响应');
  }
  if (!result || typeof result !== 'object' || Array.isArray(result)) {
    throw new Error('本机智能卡 / TPM 助手返回格式无效');
  }
  if (!response.ok) {
    if (response.status === 401) {
      pcsc.token = '';
      clearPcscSession();
    }
    const msg = typeof result.msg === 'string' ? result.msg : '';
    throw new Error(msg || '本机助手请求失败');
  }
  return result;
}

async function refreshPcscReadersInternal() {
  if (!pcsc.token) return;
  const data = await pcscRequest('/readers');
  pcsc.cards = validatePcscReadersPayload(data);
  const ready = pcscReadyCards.value;
  const readySmartcards = ready.filter(c => c.transport !== 'tpm');
  const visibleFps = new Set(visibleAuthorities.value.map(a => a.fingerprint));
  const anyAuthFps = new Set((selfIssuanceInfo.value?.authorities_summary || []).map(a => a.fingerprint));
  const firstReady = (readySmartcards[0] || ready[0])?.id || '';

  const findCaCard = (excludeId?: string) => {
    const pool = readySmartcards.filter(c => c.id !== excludeId);
    return (
      pool.find(c => c.slot_9a_fingerprint && visibleFps.has(c.slot_9a_fingerprint)) ||
      pool.find(c => c.slot_9a_fingerprint && anyAuthFps.has(c.slot_9a_fingerprint)) ||
      pool.find(c => c.default_slot_occupied === true) ||
      pool[0] ||
      readySmartcards.find(c => c.slot_9a_fingerprint && visibleFps.has(c.slot_9a_fingerprint)) ||
      ready[0]
    );
  };

  const findTargetCard = (excludeCaId?: string) => {
    const isBlankTarget = (c: PcscCard) =>
      c.default_slot_occupied === false && (!c.slot_9a_fingerprint || !anyAuthFps.has(c.slot_9a_fingerprint));
    const pool = readySmartcards.filter(c => c.id !== excludeCaId);
    return (
      pool.find(isBlankTarget) ||
      readySmartcards.find(isBlankTarget) ||
      pool[0] ||
      readySmartcards[0] ||
      ready[0]
    );
  };

  const targetValid = ready.some(c => c.id === selfForm.pcscTargetReader);
  const caValid = ready.some(c => c.id === selfForm.pcscCaReader);

  if (!targetValid) {
    const preferredCa = caValid ? selfForm.pcscCaReader : findCaCard()?.id;
    selfForm.pcscTargetReader = findTargetCard(preferredCa)?.id || firstReady;
  }
  if (!caValid) {
    selfForm.pcscCaReader = findCaCard(selfForm.pcscTargetReader)?.id || firstReady;
  } else if (selfForm.pcscCaReader === selfForm.pcscTargetReader) {
    const currentCard = ready.find(c => c.id === selfForm.pcscCaReader);
    const currentIsTrusted = Boolean(currentCard?.slot_9a_fingerprint && visibleFps.has(currentCard.slot_9a_fingerprint));
    if (!currentIsTrusted) {
      const betterCa = readySmartcards.find(
        c => c.id !== selfForm.pcscTargetReader && c.slot_9a_fingerprint && visibleFps.has(c.slot_9a_fingerprint),
      );
      if (betterCa) {
        selfForm.pcscCaReader = betterCa.id;
      }
    }
  }
}

const refreshPcscReaders = () => run(refreshPcscReadersInternal);

const connectPcscBridge = () => run(async () => {
  const port = Number(pcsc.port);
  if (!isValidBridgePort(port)) {
    throw new Error('请选择 10000–65535 范围内的本机端口');
  }
  const base = `http://127.0.0.1:${port}`;
  if (pcsc.helper !== base) {
    pcsc.helper = base;
    pcsc.token = '';
    clearPcscSession();
  }
  if (!pcsc.token) {
    if (!pcsc.pairCode.trim()) throw new Error('请输入本机智能卡助手显示的一次性配对码');
    const res = await pcscRequest('/pair', { code: pcsc.pairCode.trim() });
    const paired = validatePairResponse(res, false);
    pcsc.token = paired.token;
    pcsc.pairCode = '';
    savePcscSession(pcsc.helper, pcsc.token);
  }
  pcsc.launching = false;
  pcsc.launchMessage = '';
  await refreshPcscReadersInternal();
  Message.success(`已连接本机智能卡 / TPM 助手 · 检测到 ${pcscReadyCards.value.length} 个可用设备`);
});

function generatePairCode(): string {
  const raw = globalThis.crypto.getRandomValues(new Uint8Array(24));
  let bin = '';
  for (const byte of raw) bin += String.fromCharCode(byte);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function cancelPcscLaunch() {
  pcscPollRunId += 1;
  pcsc.launching = false;
  pcsc.launchMessage = '';
}

async function launchPcscHelper() {
  const port = Number(pcsc.port);
  if (!isValidBridgePort(port)) {
    Message.error('请选择 10000–65535 范围内的本机端口');
    return;
  }
  const code = generatePairCode();
  const base = `http://127.0.0.1:${port}`;
  pcsc.helper = base;
  pcsc.token = '';
  clearPcscSession();
  pcsc.launching = true;
  pcsc.launchMessage = '已请求唤起「本机智能卡 / TPM 助手」，请在弹出窗口点击「允许连接并自动配对」；网页将自动连接并识别 Windows 读卡器与本机 TPM…';
  const myRun = ++pcscPollRunId;

  const launchUrl = `shou-piv://start?origin=${encodeURIComponent(window.location.origin)}&port=${port}&code=${encodeURIComponent(code)}`;
  const link = document.createElement('a');
  link.href = launchUrl;
  link.style.display = 'none';
  document.body.appendChild(link);
  link.click();
  link.remove();

  let saw403 = false;
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (myRun !== pcscPollRunId) return;
    await new Promise(resolve => setTimeout(resolve, saw403 ? 1500 : (attempt === 0 ? 500 : 800)));
    if (myRun !== pcscPollRunId) return;
    try {
      const response = await fetch(`${base}/pair`, {
        method: 'POST',
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        signal: AbortSignal.timeout(3000),
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ code }),
      });
      if (myRun !== pcscPollRunId) return;
      const body = await response.json().catch(() => ({}));
      if (response.ok && body && isValidBridgeToken(body.token)) {
        const paired = validatePairResponse(body, false);
        pcsc.token = paired.token;
        savePcscSession(pcsc.helper, pcsc.token);
        pcsc.launching = false;
        pcsc.launchMessage = '';
        await refreshPcscReadersInternal();
        Message.success(`已自动连接本机智能卡 / TPM 助手 · 检测到 ${pcscReadyCards.value.length} 个可用硬件设备`);
        return;
      }
      if (response.status === 403) {
        saw403 = true;
        pcsc.launchMessage = '检测到已有运行中的助手窗口：请在新弹出的助手窗口点击「允许连接并自动配对」（将自动接管端口并完成连接），或先关闭旧助手窗口后再点击「一键唤起」；也可点击旧窗口「重新生成配对码」后在下方手动配对。';
      }
    } catch {
      // Waiting for helper startup and user confirmation in desktop window.
    }
  }
  if (myRun === pcscPollRunId) {
    pcsc.launching = false;
    pcsc.launchMessage = saw403
      ? '等待新助手接管端口超时。请先关闭旧的助手窗口后再点击「一键唤起本机智能卡 / TPM 助手」，或展开下方手动输入旧助手配对码。'
      : '等待本机智能卡 / TPM 助手超时。若浏览器未弹出打开确认，请展开下方「高级：手动输入配对码 / 首次注册本机助手协议」完成一次性注册。';
  }
}

async function runPcscStage(
  stage: 'generate' | 'sign' | 'install',
  job: BrowserPendingJob,
  readerId: string,
  transportChoice: string,
): Promise<any> {
  if (!pcsc.token) throw new Error('请先点击「一键唤起本机智能卡 / TPM 助手」完成本机连接');
  if (!readerId) throw new Error(`请选择用于「${stage}」的智能卡读卡器或 TPM 设备`);
  const cardMeta = pcsc.cards.find(c => c.id === readerId);
  const isTpm = cardMeta?.transport === 'tpm' || readerId.startsWith('tpm:');
  const transport = isTpm
    ? 'tpm'
    : (transportChoice === 'auto' ? (cardMeta?.transport || 'contact') : transportChoice);
  const operation_id = crypto.randomUUID();
  const options = {
    reader: readerId,
    transport,
    algorithm: selfForm.targetAlgorithm,
    management_algorithm: selfForm.targetManagementAlg,
    ca_slot: selfForm.caSlot,
    slot: isTpm ? '9a' : (job.card?.slot || selfForm.targetSlot),
  };
  selfProgress.value = stage === 'generate'
    ? (isTpm
      ? '请在「本机智能卡 / TPM 助手」弹窗确认在本机 TPM 2.0 内生成不可导出密钥...'
      : '请在「本机智能卡 / TPM 助手」弹窗确认目标卡槽位并输入管理密钥与 PIV PIN...')
    : stage === 'sign'
      ? '请在「本机智能卡 / TPM 助手」弹窗确认签发卡（CA 卡 / 超管卡 / 超级特权卡）并输入 PIN...'
      : (isTpm
        ? '请在「本机智能卡 / TPM 助手」弹窗确认将证书安装并绑定到 Windows TPM 密钥...'
        : '请再次连接原目标智能卡并在助手弹窗确认写入证书链与回读证明...');
  await pcscRequest('/start', { operation_id, stage, job, options });
  const parsedExpiry = Date.parse(job.expires_at);
  const maxDeadline = Math.min(
    Number.isFinite(parsedExpiry) ? parsedExpiry : Date.now() + 300_000,
    Date.now() + 300_000,
  );
  for (let polls = 0; polls < 400 && Date.now() < maxDeadline; polls += 1) {
    const state = await pcscRequest('/status', { operation_id });
    if (state.status === 'complete') {
      if (stage === 'generate') {
        return await verifyGenerateBridgeResult(state.result, job);
      }
      if (stage === 'sign') {
        return await verifySignBridgeResult(state.result, job);
      }
      return validateInstallBridgeResult(state.result, job);
    }
    if (state.status === 'waiting_for_slot') {
      const slotDecision = validateSlotDecisionPayload(state);
      const accept = Boolean(await openWebModal({
        kind: 'slot',
        title: '目标槽位已有证书',
        message: slotDecision.msg || `槽位 ${slotDecision.slot} 已有证书，是否改用空槽位 ${slotDecision.next_slot}？`,
        nextSlot: slotDecision.next_slot,
      }));
      await pcscRequest('/choose-slot', {
        operation_id,
        decision_nonce: slotDecision.decision_nonce,
        slot: slotDecision.next_slot,
        accept,
      });
    }
    if (state.status === 'failed') {
      const msg = typeof state.msg === 'string' ? state.msg : '';
      throw new Error(msg || '本机智能卡 / TPM 助手执行失败');
    }
    await new Promise(resolve => setTimeout(resolve, 800));
  }
  throw new Error('签发任务已过期或等待超时，请重新发起');
}

async function ensureFreshFido() {
  if (status.value && (status.value.fido_fresh_seconds ?? 0) <= 60) {
    selfProgress.value = '安全密钥复验窗口即将到期，请触摸本次登录的安全密钥确认操作...';
    const reauthRes = await reauthenticate();
    status.value.fido_fresh_seconds = reauthRes?.fido_fresh_seconds ?? 300;
  }
}

async function runTargetGenerate(job: BrowserPendingJob): Promise<{ issuance_id: string; csr_pem: string; card: any }> {
  if (selfForm.targetMode === 'webusb') {
    const opGen = crypto.randomUUID();
    return getWebCeremony().run('generate', job, {
      reader: selfForm.targetWebUsbId || undefined,
      slot: selfForm.targetSlot,
      algorithm: selfForm.targetAlgorithm,
      management_algorithm: selfForm.targetManagementAlg,
    }, opGen) as any;
  }
  return runPcscStage('generate', job, selfForm.pcscTargetReader, selfForm.pcscTargetTransport);
}

async function runSignStage(job: BrowserPendingJob): Promise<BrowserPendingJob & { chain_pem: string[]; issuer_descriptor?: AuthorityDescriptor | null; issuer_slot?: string }> {
  if (selfForm.caMode === 'webusb_ca') {
    if (!webUsbSupported.value) throw new Error('当前浏览器不支持 WebUSB');
    const opSign = crypto.randomUUID();
    return getWebCeremony().run('sign', job, {
      reader: selfForm.caWebUsbId || undefined,
      ca_slot: selfForm.caSlot,
    }, opSign) as any;
  }
  if (!pcsc.token || !selfForm.pcscCaReader) {
    throw new Error('请先点击「一键唤起本机智能卡 / TPM 助手」并选择签发 CA 读卡器或 TPM');
  }
  return runPcscStage('sign', job, selfForm.pcscCaReader, selfForm.pcscCaTransport);
}

async function runTargetInstall(
  job: BrowserPendingJob & { chain_pem?: string[] },
  targetCarrier: 'pcsc' | 'webusb',
  preferredTargetReader?: string,
): Promise<Record<string, any>> {
  if (targetCarrier === 'webusb') {
    const opInst = crypto.randomUUID();
    return getWebCeremony().run('install', job, {
      reader: selfForm.targetWebUsbId || undefined,
      management_algorithm: selfForm.targetManagementAlg,
    }, opInst);
  }
  const targetReader = job.card?.transport === 'tpm'
    ? (pcscReadyCards.value.find(c => c.transport === 'tpm')?.id || preferredTargetReader || selfForm.pcscTargetReader)
    : (pcscReadyCards.value.find(c => c.id === job.card?.reader)?.id || preferredTargetReader || selfForm.pcscTargetReader);
  return runPcscStage('install', job, targetReader, selfForm.pcscTargetTransport);
}

function recordSelfIssuanceSuccess(
  finishRes: any,
  job: BrowserPendingJob,
  signerLabel: string,
  validityDays: number | null,
) {
  const certMeta = finishRes.data.certificate || {};
  const isTemp = Boolean(certMeta.is_temporary);
  selfResult.value = {
    temporary: isTemp,
    isCaCert: Boolean(certMeta.is_ca),
    validityDays: isTemp ? validityDays : null,
    expiresAt: certMeta.expires_at,
    issuerLabel: certMeta.issuer_label || signerLabel,
    issuerKind: certMeta.issuer_kind || 'ca_card',
    fingerprint: certMeta.fingerprint,
    carrierLabel: job.card?.transport === 'tpm' ? '本机 Windows TPM 2.0 安全芯片' : '硬件智能卡 (PIV)',
  };
  selfProgress.value = finishRes.data.msg || '证书签发完成，客户端证书已登记';
  Message.success(selfProgress.value);
}

async function finishSelfSignAndInstall(
  job: BrowserPendingJob,
  targetCarrier: 'pcsc' | 'webusb',
  temporary: boolean,
  validityDays: number | null,
  preferredTargetReader?: string,
) {
  selfProgress.value = '正在使用所选 CA 卡 / 超管卡 / 超级特权卡签名签发证书链...';
  const signedJob = await runSignStage(job);

  const signerDesc = signedJob.issuer_descriptor || findAuthorityDescriptor(job, (signedJob as any).issuer_fingerprint || '');
  const signerLabel = signerDesc?.label || (temporary ? '超管卡 / 超级特权卡 / CA 卡' : 'CA 卡');
  selfProgress.value = `已通过【${signerLabel}】完成签名，正在写入硬件凭据并生成持钥证明...`;

  const receipt = await runTargetInstall(signedJob, targetCarrier, preferredTargetReader);

  selfProgress.value = '正在向服务器提交完整证书链与持钥证明...';
  const finishRes = await Axios.post('/security/self-issuance-finish/', {
    ...receipt,
    chain_pem: signedJob.chain_pem,
  });

  if (targetCarrier === 'webusb') {
    getWebCeremony().finish(job.issuance_id);
  }
  pendingSelfSignJob.value = null;
  pendingSelfTargetReader.value = '';

  recordSelfIssuanceSuccess(finishRes, job, signerLabel, temporary ? validityDays : null);
  await refresh();
}

const resumeSelfSign = () => run(async () => {
  const savedJob = pendingSelfSignJob.value;
  if (!savedJob) return;
  if (Date.parse(savedJob.expires_at) <= Date.now()) {
    pendingSelfSignJob.value = null;
    pendingSelfTargetReader.value = '';
    throw new Error('上一次生成的签发任务已过期，请重新生成密钥并签发');
  }
  await finishSelfSignAndInstall(
    savedJob,
    pendingSelfCarrier.value,
    Boolean(savedJob.temporary),
    savedJob.validity_days ?? null,
    pendingSelfTargetReader.value || selfForm.pcscTargetReader,
  );
});

const runSelfIssuance = () => run(async () => {
  if (!status.value || !selfIssuanceInfo.value?.available) {
    throw new Error('当前账号暂未具备现场自助签发条件');
  }
  const temporary = selfForm.issuanceMode === 'temporary';
  const validityDays = Number(selfForm.validityDays);
  if (temporary && (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 36)) {
    throw new Error('使用超管卡 / 超级特权卡或签发临时证书时，有效期必须为 1 至 36 天（严格短于 37 天）');
  }

  if (selfForm.targetMode === 'webusb') {
    if (!webUsbSupported.value) throw new Error('当前浏览器不支持 WebUSB');
  } else if (!pcsc.token || !selfForm.pcscTargetReader) {
    throw new Error('请先点击「一键唤起本机智能卡 / TPM 助手」并选择目标读卡器或 TPM');
  }

  if (selfForm.caMode === 'webusb_ca') {
    if (!webUsbSupported.value) throw new Error('当前浏览器不支持 WebUSB');
  } else if (!pcsc.token || !selfForm.pcscCaReader) {
    throw new Error('请先点击「一键唤起本机智能卡 / TPM 助手」并选择签发 CA 读卡器或 TPM');
  }

  selfResult.value = null;
  await ensureFreshFido();

  selfProgress.value = '正在创建单次硬件签发任务...';
  const beginRes = await Axios.post('/security/self-issuance-begin/', {
    temporary,
    ...(temporary ? { validity_days: validityDays } : {}),
  });
  let job: BrowserPendingJob = beginRes.data.job;

  selfProgress.value = selectedTargetIsTpm.value && selfForm.targetMode === 'pcsc'
    ? '正在本机 TPM 2.0 安全芯片内生成不可导出密钥与 CSR...'
    : '正在目标智能卡内生成密钥与 CSR...';
  const keyPayload = await runTargetGenerate(job);

  const keyRes = await Axios.post('/security/self-issuance-key/', keyPayload);
  job = keyRes.data.job;
  pendingSelfSignJob.value = job;
  pendingSelfCarrier.value = selfForm.targetMode;
  pendingSelfTargetReader.value = selfForm.pcscTargetReader;

  await finishSelfSignAndInstall(job, selfForm.targetMode, temporary, temporary ? validityDays : null, selfForm.pcscTargetReader);
});

const submitAsyncPublicKeyRequest = () => run(async () => {
  if (!status.value || !selfIssuanceInfo.value?.available) {
    throw new Error('当前账号暂未具备特权证书申请条件');
  }
  const temporary = selfForm.issuanceMode === 'temporary';
  const validityDays = Number(selfForm.validityDays);
  if (temporary && (!Number.isInteger(validityDays) || validityDays < 1 || validityDays > 36)) {
    throw new Error('临时证书有效期必须在 1 至 36 天之间（严格短于 37 天）');
  }

  if (selfForm.targetMode === 'webusb') {
    if (!webUsbSupported.value) throw new Error('当前浏览器不支持 WebUSB');
  } else if (!pcsc.token || !selfForm.pcscTargetReader) {
    throw new Error('请先点击「一键唤起本机智能卡 / TPM 助手」并选择目标读卡器或 TPM');
  }

  selfResult.value = null;
  await ensureFreshFido();

  selfProgress.value = '正在创建离线硬件公钥申请（7 天内有效）...';
  const beginRes = await Axios.post('/security/self-issuance-begin/', {
    temporary,
    async_request: true,
    ...(temporary ? { validity_days: validityDays } : {}),
  });
  const job: BrowserPendingJob = beginRes.data.job;

  selfProgress.value = selectedTargetIsTpm.value && selfForm.targetMode === 'pcsc'
    ? '正在本机 TPM 2.0 安全芯片内生成不可导出私钥与公钥请求...'
    : '正在目标智能卡内生成不可导出私钥与公钥请求...';
  const keyPayload = await runTargetGenerate(job);

  selfProgress.value = '正在上传硬件公钥并提醒其他有权限的管理员...';
  const keyRes = await Axios.post('/security/self-issuance-key/', keyPayload);
  const notified = Number(keyRes.data?.notified_signers || 0);
  selfProgress.value = notified > 0
    ? `已在硬件内生成私钥并上传公钥（已提醒 ${notified} 位有签署权限的管理员）。对方签署后，您下次登录本页即可导入证书链并激活。`
    : '已在硬件内生成私钥并上传公钥。待其他有权限的超管 / CA 管理员登录后可在本页协助签署，签署完成后您可直接导入证书链并激活。';
  Message.success('硬件公钥已上传，等待其他管理员签署');
  await refresh();
});

const signQueuedRequest = (job: BrowserPendingJob) => run(async () => {
  await ensureFreshFido();
  selfProgress.value = `正在使用您的 CA 卡 / 超管卡 / 超级特权卡为「${job.real_name}」签署证书...`;
  const signedJob = await runSignStage(job);
  selfProgress.value = '正在提交已签署证书链并通知申请人...';
  const res = await Axios.post('/security/issuance-sign-submit/', {
    issuance_id: job.issuance_id,
    chain_pem: signedJob.chain_pem,
    issuer_slot: signedJob.issuer_slot,
  });
  selfProgress.value = res.data?.msg || '已完成签署，已通知申请人导入证书链并激活';
  Message.success(selfProgress.value);
  await refresh();
});

const importAsyncSignedJob = (job: BrowserPendingJob) => run(async () => {
  const chainPem = job.signed_chain_pem || [];
  if (chainPem.length < 2) throw new Error('管理员尚未完成签名');
  await ensureFreshFido();
  selfResult.value = null;
  const installJob = { ...job, chain_pem: chainPem };
  const carrierMode = job.card?.protocol === 'WebUSB' ? 'webusb' : 'pcsc';
  if (carrierMode === 'pcsc' && (!pcsc.token || !pcscReadyCards.value.length)) {
    throw new Error('请先点击「一键唤起本机智能卡 / TPM 助手」并连接生成私钥时的原智能卡 / TPM');
  }
  selfProgress.value = '正在将已签署证书链导入原智能卡 / TPM 并生成持钥证明...';
  const receipt = await runTargetInstall(installJob, carrierMode, selfForm.pcscTargetReader);
  selfProgress.value = '正在向服务器提交持钥证明并激活特权证书...';
  const finishRes = await Axios.post('/security/self-issuance-finish/', {
    ...receipt,
    chain_pem: chainPem,
  });
  if (carrierMode === 'webusb') {
    getWebCeremony().finish(job.issuance_id);
  }
  recordSelfIssuanceSuccess(
    finishRes,
    job,
    finishRes.data?.certificate?.issuer_label || job.issuer_label || '签发管理员',
    job.temporary ? (job.validity_days ?? null) : null,
  );
  await refresh();
});

const cancelSelfAsyncJob = (job: BrowserPendingJob) => run(async () => {
  const res = await Axios.post('/security/self-issuance-cancel/', { issuance_id: job.issuance_id });
  Message.success(res.data?.msg || '已撤销离线证书申请');
  await refresh();
});

const submitRemoteCsr = (job: BrowserPendingJob) => run(async () => {
  selfProgress.value = '正在为远程任务生成硬件密钥与 CSR...';
  let keyPayload: Record<string, any>;
  if (selfForm.targetMode === 'webusb') {
    const opGen = crypto.randomUUID();
    keyPayload = await getWebCeremony().run('generate', job, {
      reader: selfForm.targetWebUsbId || undefined,
      slot: selfForm.targetSlot,
      algorithm: selfForm.targetAlgorithm,
      management_algorithm: selfForm.targetManagementAlg,
    }, opGen);
  } else {
    if (!pcsc.token || !selfForm.pcscTargetReader) {
      throw new Error('请先点击「一键唤起本机智能卡 / TPM 助手」并选择目标读卡器或 TPM');
    }
    keyPayload = await runPcscStage('generate', job, selfForm.pcscTargetReader, selfForm.pcscTargetTransport);
  }
  await Axios.post('/security/issuance-csr/', keyPayload);
  Message.success('硬件公钥请求 (CSR) 已提交，请等待签发管理员签发证书链');
  await refresh();
});

const completeRemoteInstall = (job: BrowserPendingJob) => run(async () => {
  const chainPem = job.signed_chain_pem || [];
  if (chainPem.length < 2) throw new Error('签发管理员尚未发布已签发的证书链');
  const installJob = { ...job, chain_pem: chainPem };
  let receipt: Record<string, any>;
  const useWebUsb = job.card?.protocol ? job.card.protocol === 'WebUSB' : selfForm.targetMode === 'webusb';
  if (useWebUsb) {
    const opInst = crypto.randomUUID();
    receipt = await getWebCeremony().run('install', installJob, {
      reader: selfForm.targetWebUsbId || undefined,
      management_algorithm: selfForm.targetManagementAlg,
    }, opInst);
  } else {
    if (!pcsc.token || !selfForm.pcscTargetReader) {
      throw new Error('请先点击「一键唤起本机智能卡 / TPM 助手」并选择生成密钥时的原读卡器或 TPM');
    }
    receipt = await runPcscStage('install', installJob, selfForm.pcscTargetReader, selfForm.pcscTargetTransport);
  }
  await Axios.post('/security/issuance-proof/', {
    issuance_id: receipt.issuance_id,
    proof: receipt.proof,
    card_slot: receipt.card_slot,
    ...(receipt.chain_slots ? { chain_slots: receipt.chain_slots } : {}),
  });
  Message.success('已写入证书并提交持钥证明，请联系签发管理员完成最后激活');
  await refresh();
});

const openConsole = () => run(async () => {
  const target = window.open('about:blank', 'shou-privileged');
  try {
    const [{ data }, configRes] = await Promise.all([
      Axios.post('/security/console-begin/'),
      Axios.get('/security/config/'),
    ]);
    const result = await Axios.post('/security/console-finish/', await getAssertion(data));
    const consoleUrl = validateConsoleHandoffUrl(result.data?.url, configRes.data?.console_url);
    if (target) target.location.href = consoleUrl;
    else window.location.assign(consoleUrl);
    if (props.modal) emit('close');
  } catch (error) {
    target?.close();
    throw error;
  }
});

onMounted(() => run(refresh));
onBeforeUnmount(() => {
  pcscPollRunId += 1;
});
</script>

<template>
  <div :class="props.modal ? 'security-settings' : 'card-container'">
    <a-card
      :bordered="!props.modal"
      :body-style="props.modal ? { padding: 0 } : undefined"
      :class="props.modal ? 'security-modal-card' : 'auth-card-xl security-settings'"
    >
      <template v-if="!props.modal">
        <a-typography-title :heading="2">特权管理证书签发</a-typography-title>
        <a-divider class="divider-30" />
      </template>
      <p class="security-muted">超级管理员、特权管理员与全局读者访问独立特权管理站前，需持有未撤销且在有效期内的硬件客户端证书。</p>

      <a-alert type="info" class="security-notice">
        <strong>安全要求：</strong>禁止生成或导出 <code>.p12</code> 软证书。所有特权管理证书私钥仅允许在<strong>实体智能卡（PIV）</strong>或<strong>本机 Windows TPM 2.0 安全芯片</strong>内生成，私钥不可导出。
      </a-alert>

      <template v-if="status">
        <a-alert v-if="status.certificate_status === 'missing'" type="warning" class="security-notice">
          当前特权管理账号尚未登记有效的客户端证书。可直接在下方连接本机智能卡或 TPM 完成现场自助签发（支持 CA 卡 / 其他超管卡 / 超级特权卡），或等待其他管理员发起远程签发任务。
        </a-alert>
        <a-alert v-else-if="status.certificate_status === 'expired'" type="error" class="security-notice">
          当前特权管理证书已过期（到期时间：{{ formatDatetime(status.certificate_expires_at || '') }}）。请在下方连接智能卡或 TPM 重新签发。
        </a-alert>
        <a-alert v-else-if="status.certificate_status === 'valid'" type="success" class="security-notice">
          当前客户端证书有效（到期时间：{{ formatDatetime(status.certificate_expires_at || '') }}
          <template v-if="status.certificate_is_temporary"> · 短期临时最终证书（有效期短于 37 天）</template>
          <template v-else-if="status.certificate_is_ca"> · 长期标准证书（含 CA 签发属性）</template>
          ），可直接进入独立特权管理站。
        </a-alert>
        <a-alert v-else type="info" class="security-notice">
          当前账号角色不强制要求特权管理客户端证书。
        </a-alert>

        <div v-if="status.certificate_status === 'valid' && status.admin_access" class="security-actions" style="margin-bottom: 20px">
          <a-button type="primary" :loading="busy" @click="openConsole">进入独立特权管理站</a-button>
        </div>

        <!-- 我提交的离线异步申请（等待签署 / 已签署待导入激活） -->
        <template v-if="myAsyncJobs.length">
          <a-divider />
          <section id="security-my-async-issuance">
            <a-typography-title :heading="4">我的离线证书申请（先生成私钥上传公钥 · 待他人签署后导入）</a-typography-title>
            <div v-for="job in myAsyncJobs" :key="job.issuance_id" class="key-row" style="flex-direction:column;align-items:stretch;gap:12px">
              <div class="key-info">
                <span class="key-name">
                  离线申请 #{{ job.issuance_id.slice(0, 8) }} · {{ roleListText(job.roles) }}
                </span>
                <span class="key-detail">
                  类型：{{ job.temporary ? `短期临时最终证书（${job.validity_days} 天 · 仅 37 天内）` : '长期标准证书（需 CA 卡）' }}
                  · 硬件：{{ job.card?.transport === 'tpm' ? '本机 TPM 2.0' : `智能卡（槽位 ${job.card?.slot || '9a'}）` }}
                  · 算法：{{ job.card?.algorithm || '-' }}
                  · 截止：{{ formatDatetime(job.expires_at) }}
                </span>
                <span v-if="job.public_key_sha256" class="key-detail">
                  公钥 SHA-256：<code>{{ job.public_key_sha256.slice(0, 24) }}...</code>
                </span>
              </div>
              <template v-if="!job.signed_chain_pem">
                <a-space wrap>
                  <a-tag color="arcoblue">已上传硬件公钥，等待其他有权限的超管 / CA 管理员签署</a-tag>
                  <a-button size="small" :loading="busy" @click="run(refresh)">刷新签署状态</a-button>
                  <a-button size="small" status="danger" :disabled="busy" @click="cancelSelfAsyncJob(job)">撤销此申请</a-button>
                </a-space>
              </template>
              <template v-else>
                <a-alert type="success">
                  已由 <strong>{{ job.signed_by_name || '授权管理员' }}</strong> 使用【{{ job.issuer_label || '签发卡' }}】签署完成
                  <template v-if="job.signed_at">（{{ formatDatetime(job.signed_at) }}）</template>
                  ，请连接生成私钥时的原智能卡 / TPM，点击下方按钮导入证书链并激活。
                </a-alert>
                <a-space wrap>
                  <a-button type="primary" :loading="busy" @click="importAsyncSignedJob(job)">
                    导入证书链到原智能卡 / TPM 并提交持钥签名激活
                  </a-button>
                  <a-button size="small" status="danger" :disabled="busy" @click="cancelSelfAsyncJob(job)">放弃并撤销</a-button>
                </a-space>
              </template>
            </div>
          </section>
        </template>

        <!-- 其他管理员提交、等待我协助签署的申请队列 -->
        <template v-if="signQueue.length">
          <a-divider />
          <section id="security-sign-queue">
            <a-typography-title :heading="4">待您协助签署的其他管理员证书申请（{{ signQueue.length }}）</a-typography-title>
            <a-alert type="info" style="margin-bottom: 12px">
              请先在下方选择您的「签发 CA 方式」与「签发读卡器 / TPM」（或 WebUSB 直连智能卡），并确认连接您的<strong>CA 卡 / 超管卡 / 超级特权卡</strong>，再点击下方「使用所选签发卡签署此申请」完成签名。
            </a-alert>
            <div v-for="qjob in signQueue" :key="qjob.issuance_id" class="key-row" style="flex-direction:column;align-items:stretch;gap:12px">
              <div class="key-info">
                <span class="key-name">
                  申请人：{{ qjob.real_name }}<template v-if="qjob.requester_username">（{{ qjob.requester_username }}）</template> · {{ roleListText(qjob.roles) }}
                </span>
                <span class="key-detail">
                  申请类型：{{ qjob.temporary ? `短期临时最终证书（${qjob.validity_days} 天 · 可用 CA 卡 / 超管卡 / 超级特权卡）` : '长期标准证书（仅限站点 CA 卡）' }}
                  · 目标硬件：{{ qjob.card?.transport === 'tpm' ? 'Windows TPM 2.0' : `智能卡（槽位 ${qjob.card?.slot || '9a'}）` }}
                  · 算法：{{ qjob.card?.algorithm || '-' }}
                </span>
                <span class="key-detail">
                  公钥 SHA-256：<code>{{ qjob.public_key_sha256 }}</code>
                  · 截止：{{ formatDatetime(qjob.expires_at) }}
                </span>
              </div>
              <a-space wrap>
                <a-button type="primary" :loading="busy" @click="signQueuedRequest(qjob)">
                  使用所选签发卡签署此申请
                </a-button>
              </a-space>
            </div>
          </section>
        </template>

        <!-- 现场自助签发与离线申请 / 助手区块 -->
        <template v-if="selfIssuanceInfo?.available || myAsyncJobs.length || remoteAdminJobs.length || signQueue.length">
          <a-divider />
          <section id="security-self-issuance">
            <template v-if="selfIssuanceInfo?.available">
              <a-typography-title :heading="4">现场自助签发 / 离线申请（CA 卡 / 超管卡 / 超级特权卡）</a-typography-title>
              <p class="security-muted">
                当前账号角色：<strong>{{ roleListText(selfIssuanceInfo.roles) }}</strong>。现场持有 <strong>CA 卡 / 超管卡 / 超级特权卡</strong> 时可直接一次完成签发；若签发人不在现场，也可先在您的硬件内生成私钥并上传公钥，待有权限的管理员登录后为您签署，再导入证书链激活。
              </p>

              <a-space wrap style="margin-bottom: 14px">
                <a-tag color="arcoblue">CA 卡（站点签发 CA）：{{ selfIssuanceInfo.site_ca_count }} 张</a-tag>
                <a-tag color="orange">超管卡：{{ selfIssuanceInfo.super_admin_card_count }} 张（有效期仅 37 天内）</a-tag>
                <a-tag color="gold">超级特权卡：{{ selfIssuanceInfo.superadmin_admin_card_count }} 张（有效期仅 37 天内）</a-tag>
              </a-space>
            </template>

            <a-form :model="selfForm" auto-label-width :layout="isMobile ? 'vertical' : 'horizontal'" class="security-form" @submit="runSelfIssuance">
              <template v-if="selfIssuanceInfo?.available">
                <a-form-item label="签发类型">
                  <a-radio-group v-model="selfForm.issuanceMode" direction="vertical">
                    <a-radio value="standard">
                      <strong>CA 卡签发 · 标准长期证书</strong>
                      <span class="security-muted">（仅限 CA 卡；超管 / 超级特权角色自动附带 CA 签发属性）</span>
                    </a-radio>
                    <a-radio value="temporary">
                      <strong>超管卡 / 超级特权卡 / CA 卡 · 短期临时最终证书</strong>
                      <span class="security-muted">（有效期仅限 37 天内，到期自动失效，不可用于再次签发）</span>
                    </a-radio>
                  </a-radio-group>
                </a-form-item>

                <a-alert v-if="selfForm.issuanceMode === 'temporary'" type="warning" style="margin-bottom: 14px">
                  <strong>有效期限制提示：</strong>「超管卡」与「超级特权卡」签发的证书有效期<strong>仅限 37 天内（1–36 天）</strong>，且属于不可再签发下级的临时最终证书（<code>CA:FALSE</code>）；请核对签发时显示的卡类型标签（<code>CA 卡</code> / <code>超管卡</code> / <code>超级特权卡</code>）。
                </a-alert>

                <a-form-item v-if="selfForm.issuanceMode === 'temporary'" label="临时有效期（天）">
                  <a-input-number v-model="selfForm.validityDays" :min="1" :max="36" style="width: 160px" />
                  <span class="security-muted" style="margin-left: 10px">1–36 天（严格短于 37 天）</span>
                </a-form-item>

                <a-form-item v-if="visibleAuthorities.length" label="可用签发证书">
                  <a-space wrap>
                    <a-tag
                      v-for="item in visibleAuthorities"
                      :key="item.fingerprint"
                      :color="item.temporary_only ? 'orange' : 'arcoblue'"
                    >
                      {{ item.label }}<template v-if="item.owner_name"> · {{ item.owner_name }}</template> · {{ item.cn }}<template v-if="item.algorithm"> ({{ item.algorithm }})</template><template v-if="item.temporary_only"> · 仅37天内</template>
                    </a-tag>
                  </a-space>
                </a-form-item>

                <a-divider style="margin: 12px 0" />
              </template>

              <a-form-item label="目标证书载体">
                <a-select v-model="selfForm.targetMode">
                  <a-option value="pcsc">Windows 智能卡读卡器 / 本机 TPM 2.0 安全芯片（通用 USB CCID 读卡器或 TPM）</a-option>
                  <a-option value="webusb" :disabled="!webUsbSupported">浏览器 WebUSB 直连智能卡（仅支持 WebUSB 厂商接口，不支持普通 Windows CCID 读卡器）</a-option>
                </a-select>
              </a-form-item>

              <template v-if="selfForm.targetMode === 'webusb'">
                <a-alert type="info" style="margin-bottom: 12px">
                  浏览器禁止 WebUSB 访问 Windows 系统接管的普通 CCID 读卡器（如 <code>Microsoft Usbccid Smartcard Reader</code>）。如果您使用的是通用 USB 读卡器、接触式 / NFC 智能卡或本机 TPM 2.0，请点击：
                  <a-button size="mini" type="text" @click="selfForm.targetMode = 'pcsc'">切换到 Windows 读卡器 / TPM 助手</a-button>
                </a-alert>
                <a-form-item label="WebUSB 智能卡">
                  <a-space wrap>
                    <a-select v-model="selfForm.targetWebUsbId" placeholder="在签发弹窗中选择或先授权 USB 智能卡" style="min-width: 240px">
                      <a-option value="">在签发弹窗中选择 / 授权 USB 智能卡</a-option>
                      <a-option v-for="card in webUsbCards" :key="card.id" :value="card.id" :disabled="!card.piv || card.state !== 'ready'">
                        {{ card.name }} · {{ card.piv && card.state === 'ready' ? 'PIV 就绪' : (card.error ? `不可用：${card.error}` : '不可用') }}
                      </a-option>
                    </a-select>
                    <a-button size="small" :type="webUsbCards.some(c => c.piv && c.state === 'ready') ? 'secondary' : 'primary'" :disabled="busy" @click="authorizeTargetWebUsb">授权 USB 卡</a-button>
                    <a-button size="small" :disabled="busy" @click="refreshWebUsbList">重新检测</a-button>
                  </a-space>
                </a-form-item>
                <a-alert v-if="webUsbError" type="error" style="margin-bottom: 12px">{{ webUsbError }}</a-alert>
                <a-alert v-else-if="webUsbHint" type="warning" style="margin-bottom: 12px">{{ webUsbHint }}</a-alert>
              </template>

              <template v-else>
                <a-form-item label="目标硬件设备">
                  <a-space wrap>
                    <a-select v-model="selfForm.pcscTargetReader" placeholder="请先一键唤起本机智能卡 / TPM 助手" style="min-width: 300px">
                      <a-option v-for="card in pcscReadyCards" :key="card.id" :value="card.id">
                        {{ deviceOptionText(card) }}
                      </a-option>
                    </a-select>
                  </a-space>
                </a-form-item>
                <a-alert v-if="selectedTargetIsTpm" type="info" style="margin-bottom: 12px">
                  已选定<strong>本机 Windows TPM 2.0 安全芯片</strong>：将在硬件内部生成不可导出密钥，并将证书绑定安装到当前 Windows「个人」证书存储。
                </a-alert>
              </template>

              <a-form-item label="写入参数与算法">
                <a-space wrap>
                  <a-select v-if="selfForm.targetMode === 'webusb' || !selectedTargetIsTpm" v-model="selfForm.targetSlot" style="width: 110px">
                    <a-option value="9a">槽位 9a</a-option>
                    <a-option value="9c">槽位 9c</a-option>
                    <a-option value="9e">槽位 9e</a-option>
                  </a-select>
                  <a-select v-model="selfForm.targetAlgorithm" style="width: 165px">
                    <a-option value="auto">P-384 优先 / RSA</a-option>
                    <a-option value="P-384">ECDSA P-384</a-option>
                    <a-option value="RSA-3072">RSA-3072</a-option>
                    <a-option value="RSA-2048">RSA-2048</a-option>
                  </a-select>
                  <a-select v-if="selfForm.targetMode === 'webusb' || !selectedTargetIsTpm" v-model="selfForm.targetManagementAlg" style="width: 130px">
                    <a-option value="tdes">TDES</a-option>
                    <a-option value="aes128">AES-128</a-option>
                    <a-option value="aes192">AES-192</a-option>
                    <a-option value="aes256">AES-256</a-option>
                  </a-select>
                </a-space>
              </a-form-item>

              <template v-if="selfIssuanceInfo?.available || signQueue.length">
                <a-divider style="margin: 12px 0" />

                <a-form-item label="签发 CA 方式">
                  <a-select v-model="selfForm.caMode">
                    <a-option value="pcsc_ca">Windows 读卡器 / 本机 TPM 2.0 中的 CA 卡 / 超管卡 / 超级特权卡（通用 USB CCID / 接触式 / NFC / TPM）</a-option>
                    <a-option value="webusb_ca" :disabled="!webUsbSupported">浏览器 WebUSB 直连（CA 卡 / 超管卡 / 超级特权卡，仅支持 WebUSB 厂商接口）</a-option>
                  </a-select>
                </a-form-item>

                <template v-if="selfForm.caMode === 'webusb_ca'">
                  <a-alert v-if="selfForm.targetMode !== 'webusb'" type="info" style="margin-bottom: 12px">
                    若签发卡插在普通 Windows CCID 智能卡读卡器（如 <code>Microsoft Usbccid Smartcard Reader</code>），请
                    <a-button size="mini" type="text" @click="selfForm.caMode = 'pcsc_ca'">切换到 Windows 读卡器 / TPM 助手</a-button>
                  </a-alert>
                  <a-form-item label="WebUSB 签发卡">
                    <a-space wrap>
                      <a-select v-model="selfForm.caWebUsbId" placeholder="按步骤弹窗选择签发 USB 卡" style="min-width: 240px">
                        <a-option value="">在签发弹窗中选择 / 授权 USB 智能卡</a-option>
                        <a-option v-for="card in webUsbCards" :key="card.id" :value="card.id" :disabled="!card.piv || card.state !== 'ready'">
                          {{ card.name }} · {{ card.piv && card.state === 'ready' ? 'PIV 就绪' : (card.error ? `不可用：${card.error}` : '不可用') }}
                        </a-option>
                      </a-select>
                      <a-select v-model="selfForm.caSlot" style="width: 140px">
                        <a-option value="auto">CA 槽位：自动</a-option>
                        <a-option value="9c">槽位 9c</a-option>
                        <a-option value="9a">槽位 9a</a-option>
                      </a-select>
                      <a-button size="small" :type="webUsbCards.some(c => c.piv && c.state === 'ready') ? 'secondary' : 'primary'" :disabled="busy" @click="authorizeCaWebUsb">授权新卡</a-button>
                      <a-button size="small" :disabled="busy" @click="refreshWebUsbList">重新检测</a-button>
                    </a-space>
                  </a-form-item>
                  <a-alert v-if="webUsbError" type="error" style="margin-bottom: 12px">{{ webUsbError }}</a-alert>
                  <a-alert v-else-if="webUsbHint" type="warning" style="margin-bottom: 12px">{{ webUsbHint }}</a-alert>
                </template>

                <template v-else>
                  <a-form-item label="签发读卡器 / TPM">
                    <a-space wrap>
                      <a-select v-model="selfForm.pcscCaReader" placeholder="请先一键唤起本机智能卡 / TPM 助手" style="min-width: 300px">
                        <a-option v-for="card in pcscReadyCards" :key="card.id" :value="card.id">
                          {{ deviceOptionText(card) }}
                        </a-option>
                      </a-select>
                      <a-select v-model="selfForm.caSlot" style="width: 140px">
                        <a-option value="auto">CA 槽位：自动</a-option>
                        <a-option value="9c">槽位 9c</a-option>
                        <a-option value="9a">槽位 9a</a-option>
                      </a-select>
                    </a-space>
                  </a-form-item>
                  <a-alert
                    v-if="selfForm.targetMode === 'pcsc' && selfForm.pcscTargetReader && selfForm.pcscTargetReader === selfForm.pcscCaReader && !selectedTargetIsTpm"
                    type="warning"
                    style="margin-bottom: 12px"
                  >
                    当前目标卡与签发卡共用同一读卡器：生成新卡密钥后，请按助手弹窗提示先拔出目标卡，再换插【CA 卡 / 超管卡 / 超级特权卡】继续签发。
                  </a-alert>
                </template>
              </template>

              <!-- 本机智能卡 / TPM 助手一键唤起与下载面板 -->
              <template v-if="usesPcscHelper">
                <a-alert type="info" style="margin-bottom: 12px">
                  <template #title>Windows 智能卡读卡器与本机 TPM 2.0 助手</template>
                  <a-space wrap style="margin-top: 4px">
                    <a-button type="primary" :loading="pcsc.launching" :disabled="busy" @click="launchPcscHelper">
                      {{ pcsc.token ? '重新唤起 / 配对本机助手' : '一键唤起本机智能卡 / TPM 助手' }}
                    </a-button>
                    <a-button :disabled="busy" @click="downloadHelperPackage">
                      下载本机助手（Windows 中间件）
                    </a-button>
                    <a-button v-if="pcsc.launching" size="small" @click="cancelPcscLaunch">取消等待</a-button>
                    <a-button v-if="pcsc.token" size="small" :loading="busy" @click="refreshPcscReaders">重新扫描设备</a-button>
                    <a-tag v-if="pcsc.token" color="green">
                      已连接 · 检测到 {{ pcscReadyCards.length }} 个可用硬件设备
                    </a-tag>
                    <a-tag v-else color="gray">未连接</a-tag>
                  </a-space>
                  <div v-if="helperDownloadHint" style="margin-top: 8px">
                    {{ helperDownloadHint }}
                    <a-link style="margin-left: 8px" @click="downloadHelperPackage">若浏览器未自动保存，点此重新下载</a-link>
                  </div>
                  <div v-if="pcsc.launchMessage" style="margin-top: 8px">{{ pcsc.launchMessage }}</div>
                  <div v-if="pcsc.token && pcscReadyCards.length" style="margin-top: 8px">
                    <a-space wrap>
                      <a-tag v-for="card in pcscReadyCards" :key="card.id" color="arcoblue">
                        {{ deviceOptionText(card) }}
                      </a-tag>
                    </a-space>
                  </div>
                  <a-collapse :bordered="false" style="margin-top: 8px; background: transparent">
                    <a-collapse-item header="高级：手动输入配对码 / 首次注册本机助手协议" key="manual">
                      <div style="margin-bottom: 6px">首次在当前电脑使用「一键唤起」，请先运行一次注册命令（或手动启动图形助手）：</div>
                      <pre class="security-code" style="margin: 6px 0; user-select: all">{{ registerHelperCommand }}</pre>
                      <pre class="security-code" style="margin: 6px 0; user-select: all">{{ fallbackHelperCommand }}</pre>
                      <a-space wrap style="margin-top: 8px">
                        <a-input-number v-model="pcsc.port" :min="10000" :max="65535" style="width: 110px" />
                        <a-input v-model="pcsc.pairCode" placeholder="输入助手窗口显示的配对码" style="width: 220px" />
                        <a-button type="outline" size="small" :loading="busy" @click="connectPcscBridge">手动配对连接</a-button>
                      </a-space>
                    </a-collapse-item>
                  </a-collapse>
                </a-alert>
              </template>

              <a-alert v-if="selfIssuanceInfo?.available && pendingSelfSignJob" type="warning" style="margin-bottom: 12px">
                <template #title>目标卡公钥已生成并提交，可直接换插签发卡继续签名，无需重新生成密钥</template>
                <div style="margin-bottom: 8px">
                  任务 #{{ pendingSelfSignJob.issuance_id.slice(0, 8) }} · 槽位 {{ pendingSelfSignJob.card?.slot || '9a' }} · 算法 {{ pendingSelfSignJob.card?.algorithm || '-' }}
                </div>
                <a-space wrap>
                  <a-button type="primary" size="small" :loading="busy" @click="resumeSelfSign">继续使用已生成公钥重试签发</a-button>
                  <a-button size="small" :disabled="busy" @click="pendingSelfSignJob = null; selfError = ''">放弃并重新生成</a-button>
                </a-space>
              </a-alert>

              <a-form-item v-if="selfIssuanceInfo?.available">
                <a-space wrap>
                  <a-button type="primary" html-type="submit" :loading="busy">
                    开始现场签发{{ selfForm.issuanceMode === 'temporary' ? `（${selfForm.validityDays} 天临时证书）` : '（长期标准证书）' }}
                  </a-button>
                  <a-button type="outline" :loading="busy" @click="submitAsyncPublicKeyRequest">
                    仅生成私钥并上传公钥（离线申请，等其他管理员签署）
                  </a-button>
                </a-space>
              </a-form-item>
            </a-form>

            <a-alert v-if="selfProgress" type="info" style="margin-top: 10px">{{ selfProgress }}</a-alert>
            <a-alert v-if="selfError" type="error" style="margin-top: 10px">{{ selfError }}</a-alert>

            <a-alert v-if="selfResult" type="success" style="margin-top: 12px">
              <template #title>
                证书签发完成 · 使用【{{ selfResult.issuerLabel }}】签发
              </template>
              <div>
                目标载体：<strong>{{ selfResult.carrierLabel }}</strong>
                <br>证书类型：<strong>{{ selfResult.temporary ? `短期临时最终证书（有效期 ${selfResult.validityDays} 天 · 短于 37 天，不可再次签发）` : (selfResult.isCaCert ? '长期标准证书（含 CA 签发属性）' : '长期客户端证书') }}</strong>
                <br>到期时间：{{ formatDatetime(selfResult.expiresAt) }}
              </div>
              <div v-if="status.admin_access" style="margin-top: 10px">
                <a-button type="primary" size="small" :loading="busy" @click="openConsole">立即进入独立特权管理站</a-button>
              </div>
            </a-alert>
          </section>
        </template>

        <!-- 管理员发起的待办远程签发任务（仅硬件智能卡 / TPM） -->
        <template v-if="remoteAdminJobs.length">
          <a-divider />
          <section id="security-remote-issuance">
            <a-typography-title :heading="5">管理员发起的待办远程签发任务（使用上方所选智能卡 / TPM）</a-typography-title>
            <div v-for="job in remoteAdminJobs" :key="job.issuance_id" class="key-row" style="flex-direction:column;align-items:stretch;gap:12px">
              <div class="key-info">
                <span class="key-name">任务 #{{ job.issuance_id.slice(0, 8) }} · {{ job.roles.join(' / ') }}</span>
                <span class="key-detail">
                  类型：{{ job.temporary ? `短期临时最终证书（${job.validity_days} 天 · 仅 37 天内）` : (job.delegated_ca ? '长期 CA 签发证书' : '长期客户端证书') }}
                  · 截止：{{ formatDatetime(job.expires_at) }}
                </span>
              </div>
              <template v-if="job.state === 'requested' && !job.has_target_csr">
                <a-button type="primary" :loading="busy" @click="submitRemoteCsr(job)">
                  在所选智能卡 / TPM 内生成密钥并提交 CSR
                </a-button>
              </template>
              <template v-else-if="job.state === 'requested' || !job.signed_chain_pem">
                <a-space wrap>
                  <a-tag color="arcoblue">已提交硬件公钥，等待管理员签发证书链</a-tag>
                  <a-button size="small" :loading="busy" @click="run(refresh)">刷新签名状态</a-button>
                </a-space>
              </template>
              <template v-else-if="job.has_target_proof">
                <a-tag color="green">持钥证明已提交，等待签发管理员完成最后激活</a-tag>
              </template>
              <template v-else>
                <a-button type="primary" :loading="busy" @click="completeRemoteInstall(job)">
                  写入智能卡 / TPM 证书库并提交持钥证明
                </a-button>
              </template>
            </div>
          </section>
        </template>

        <template v-else-if="status.needs_certificate_issuance && !selfIssuanceInfo?.available && !myAsyncJobs.length">
          <ol class="admin-welcome-steps">
            <li><span class="admin-step-number">01</span><div><strong>联系签发管理员发起任务</strong><p>请持有 CA 签发权限的超级管理员或特权超级管理员，在独立特权管理站为你的账号发起证书签发或续期任务（联系邮箱：{{ contact }}）。</p></div></li>
            <li><span class="admin-step-number">02</span><div><strong>唤起本机助手并生成硬件密钥</strong><p>任务发起后，点击下方「刷新签发状态」，唤起本机智能卡 / TPM 助手或连接支持 WebUSB 直连的智能卡生成不可导出硬件密钥。</p></div></li>
            <li><span class="admin-step-number">03</span><div><strong>写入硬件并激活入口</strong><p>签发管理员签名后，在本页面完成证书写卡 / TPM 绑定与持钥证明，即可进入独立特权管理站。</p></div></li>
          </ol>
        </template>

        <div class="security-actions">
          <a-button :loading="busy" @click="run(refresh)">刷新签发状态</a-button>
          <a-button v-if="props.modal" @click="emit('close')">关闭</a-button>
          <template v-else>
            <RouterLink to="/settings/?tab=security"><a-button>返回安全中心</a-button></RouterLink>
            <RouterLink to="/"><a-button type="text">返回首页</a-button></RouterLink>
          </template>
        </div>
      </template>
      <a-spin v-else />
    </a-card>

    <!-- WebUSB / 槽位交互弹窗 -->
    <a-modal
      v-model:visible="webModal.visible"
      :title="webModal.title"
      :mask-closable="false"
      @ok="submitWebModal"
      @cancel="cancelWebModal"
    >
      <p style="white-space: pre-line; margin-top: 0">{{ webModal.message }}</p>
      <div v-if="webModal.kind === 'card'" style="margin-top: 12px">
        <a-select v-model="webModal.selectedCardId" placeholder="选择 WebUSB 智能卡设备" style="width: 100%; margin-bottom: 10px">
          <a-option v-for="(c, idx) in webUsbCards" :key="c.id" :value="c.id" :disabled="!c.piv || c.state !== 'ready'">
            {{ c.name }} · USB {{ idx + 1 }} · {{ c.piv && c.state === 'ready' ? 'PIV 就绪' : '不可用' }}
          </a-option>
        </a-select>
        <a-space>
          <a-button size="small" type="primary" @click="authorizeWebUsbInModal">授权另一张 USB 智能卡</a-button>
          <a-button size="small" @click="refreshWebUsbInModal">重新检测</a-button>
        </a-space>
      </div>
      <div v-else-if="webModal.kind === 'secret'" style="margin-top: 12px">
        <div style="margin-bottom: 6px; font-weight: 500">{{ webModal.secretLabel }}</div>
        <a-input-password v-model="webModal.secretValue" @keyup.enter="submitWebModal" />
      </div>
      <div v-else-if="webModal.kind === 'confirm' && webModal.acknowledgeRequired" style="margin-top: 12px">
        <a-checkbox v-model="webModal.acknowledged">我已核对目标私钥槽，确认可用于本次签发与写卡</a-checkbox>
      </div>
      <a-alert v-if="webModal.error" type="error" style="margin-top: 10px">{{ webModal.error }}</a-alert>
      <template #footer>
        <a-button @click="cancelWebModal">{{ webModal.kind === 'slot' ? '停止本次签发' : '取消' }}</a-button>
        <a-button type="primary" @click="submitWebModal">{{ webModal.kind === 'slot' ? `改用槽位 ${webModal.nextSlot}` : '确认继续' }}</a-button>
      </template>
    </a-modal>
  </div>
</template>
