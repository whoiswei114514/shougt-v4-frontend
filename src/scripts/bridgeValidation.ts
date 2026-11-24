import * as asn1 from 'asn1js';
import { CertificationRequest } from 'pkijs';
import type { AuthorityDescriptor, BrowserCardDescriptor, BrowserPendingJob } from './webpiv/browserCeremony';
import { hex, unpem } from './webpiv/bytes.js';
import { encoded, sha, validateInstallation, validatedCsr } from './webpiv/crypto.js';

const TOKEN_RE = /^[A-Za-z0-9._~-]{8,128}$/;
const BASE64_PROOF_RE = /^[A-Za-z0-9+/=]{16,8192}$/;
const WEB_SAFE_B64_RE = /^[A-Za-z0-9+/_-]{1,2048}=*$/;
const LOOPBACK_URL_RE = /^http:\/\/127\.0\.0\.1:(\d{5})$/;
const CLIENT_SLOTS = new Set(['9a', '9c', '9e']);
const PIV_SLOT_RE = /^(?:9[acde]|8[2-9]|9[0-5])$/i;
const ALLOWED_TRANSPORTS = new Set(['usb', 'contact', 'nfc', 'tpm']);
const CONTROL_CHAR_RE = /[\u0000-\u001f\u007f]/;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/i;

function isPlainObject(value: unknown): value is Record<string, any> {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function cleanBoundedString(value: unknown, maxLen: number): string | null {
  if (typeof value !== 'string') return null;
  if (!value || value.length > maxLen || CONTROL_CHAR_RE.test(value)) return null;
  return value;
}

export function isValidBridgePort(port: unknown): port is number {
  return Number.isInteger(port) && (port as number) >= 10000 && (port as number) <= 65535;
}

export function validateLoopbackBridgeUrl(rawUrl: unknown): string | null {
  if (typeof rawUrl !== 'string') return null;
  const trimmed = rawUrl.trim();
  const match = LOOPBACK_URL_RE.exec(trimmed);
  if (!match) return null;
  const port = Number(match[1]);
  return isValidBridgePort(port) ? `http://127.0.0.1:${port}` : null;
}

export function isValidBridgeToken(token: unknown): token is string {
  return typeof token === 'string' && TOKEN_RE.test(token);
}

export function validateBridgePath(path: string, allowedPaths: readonly string[]): string {
  if (!allowedPaths.includes(path)) {
    throw new Error(`不允许访问本机助手路径: ${path}`);
  }
  return path;
}

export function validatePairResponse(
  data: unknown,
  requireExpiresIn = false,
): { token: string; expiresIn: number } {
  if (!isPlainObject(data) || !isValidBridgeToken(data.token)) {
    throw new Error('本机助手配对响应无效');
  }
  if (requireExpiresIn && (typeof data.expires_in !== 'number' || !Number.isFinite(data.expires_in) || data.expires_in <= 0)) {
    throw new Error('本机助手会话有效期无效');
  }
  const expiresIn =
    typeof data.expires_in === 'number' && Number.isFinite(data.expires_in) && data.expires_in > 0
      ? Math.min(1800, data.expires_in)
      : 900;
  return { token: data.token, expiresIn };
}

export interface SharedSessionPayload {
  token: string;
  deadline: number;
  port: number;
  reader: string;
}

export function validateSmartcardSessionShare(
  data: unknown,
  expectedNonce: string,
  nowMs = Date.now(),
): SharedSessionPayload | null {
  if (!isPlainObject(data)) return null;
  if (data.type !== 'session' || data.nonce !== expectedNonce) return null;
  if (!isValidBridgeToken(data.token)) return null;
  if (!isValidBridgePort(data.port)) return null;
  if (typeof data.deadline !== 'number' || !Number.isFinite(data.deadline)) return null;
  if (data.deadline <= nowMs || data.deadline > nowMs + 1800_000) return null;
  if (typeof data.reader !== 'string' || data.reader.length > 300 || CONTROL_CHAR_RE.test(data.reader)) {
    return null;
  }
  return {
    token: data.token,
    deadline: data.deadline,
    port: data.port,
    reader: data.reader,
  };
}

export interface SanitizedPcscCard {
  id: string;
  name: string;
  transport: string;
  state: string;
  piv?: boolean;
  fido2?: boolean;
  tpm?: boolean;
  default_slot_occupied?: boolean;
  slot_9a_fingerprint?: string;
}

export function validatePcscReadersPayload(data: unknown): SanitizedPcscCard[] {
  if (!isPlainObject(data)) {
    throw new Error('本机助手返回的设备列表格式无效');
  }
  const rawList = Array.isArray(data.cards)
    ? data.cards
    : Array.isArray(data.readers)
      ? data.readers.map(name => ({ id: name, name, transport: 'contact', state: 'ready', piv: true }))
      : null;
  if (!rawList || rawList.length > 64) {
    throw new Error('本机助手返回的设备列表无效');
  }
  const cards: SanitizedPcscCard[] = [];
  for (const item of rawList) {
    if (!isPlainObject(item)) continue;
    const id = cleanBoundedString(item.id, 300);
    const name = cleanBoundedString(item.name, 300);
    const state = cleanBoundedString(item.state, 64);
    const transport = cleanBoundedString(item.transport ?? 'contact', 32);
    if (!id || !name || !state || !transport) continue;
    const card: SanitizedPcscCard = {
      id,
      name,
      transport,
      state,
      ...(typeof item.piv === 'boolean' ? { piv: item.piv } : {}),
      ...(typeof item.fido2 === 'boolean' ? { fido2: item.fido2 } : {}),
      ...(typeof item.tpm === 'boolean' ? { tpm: item.tpm } : {}),
      ...(typeof item.default_slot_occupied === 'boolean'
        ? { default_slot_occupied: item.default_slot_occupied }
        : {}),
      ...(typeof item.slot_9a_fingerprint === 'string' && SHA256_HEX_RE.test(item.slot_9a_fingerprint)
        ? { slot_9a_fingerprint: item.slot_9a_fingerprint.toLowerCase() }
        : {}),
    };
    cards.push(card);
  }
  return cards;
}

export interface SanitizedFidoCard {
  id: string;
  name: string;
  fido2: boolean;
  piv?: boolean;
  fido2_pin_set?: boolean;
  fido2_access_denied?: boolean;
  state: string;
}

export function validateFidoReadersPayload(data: unknown): SanitizedFidoCard[] {
  if (!isPlainObject(data) || !Array.isArray(data.cards) || data.cards.length > 64) {
    throw new Error('接触式智能卡工具返回的读卡器列表无效');
  }
  const cards: SanitizedFidoCard[] = [];
  for (const item of data.cards) {
    if (!isPlainObject(item)) continue;
    const id = cleanBoundedString(item.id, 300);
    const name = cleanBoundedString(item.name, 300);
    const state = cleanBoundedString(item.state, 64);
    if (!id || !name || !state) continue;
    cards.push({
      id,
      name,
      state,
      fido2: Boolean(item.fido2),
      ...(typeof item.piv === 'boolean' ? { piv: item.piv } : {}),
      ...(typeof item.fido2_pin_set === 'boolean' ? { fido2_pin_set: item.fido2_pin_set } : {}),
      ...(typeof item.fido2_access_denied === 'boolean'
        ? { fido2_access_denied: item.fido2_access_denied }
        : {}),
    });
  }
  return cards;
}

export function validateFidoAssertionResult(
  result: unknown,
  operation: 'create' | 'get',
): Record<string, any> {
  if (!isPlainObject(result)) {
    throw new Error('智能卡返回的 WebAuthn 凭据格式无效');
  }
  const id = cleanBoundedString(result.id, 1024);
  const rawId = cleanBoundedString(result.rawId, 1024);
  if (!id || !rawId || !WEB_SAFE_B64_RE.test(rawId) || result.type !== 'public-key') {
    throw new Error('智能卡返回的凭据标识无效');
  }
  if (!isPlainObject(result.response)) {
    throw new Error('智能卡返回的凭据响应缺失');
  }
  const clientDataJSON = cleanBoundedString(result.response.clientDataJSON, 8192);
  if (!clientDataJSON || !WEB_SAFE_B64_RE.test(clientDataJSON)) {
    throw new Error('智能卡返回的 clientDataJSON 无效');
  }
  const sanitizedResponse: Record<string, any> = { clientDataJSON };
  if (operation === 'create') {
    const attestationObject = cleanBoundedString(result.response.attestationObject, 65536);
    if (!attestationObject || !WEB_SAFE_B64_RE.test(attestationObject)) {
      throw new Error('智能卡返回的 attestationObject 无效');
    }
    sanitizedResponse.attestationObject = attestationObject;
    if (Array.isArray(result.response.transports)) {
      sanitizedResponse.transports = result.response.transports
        .filter((t): t is string => typeof t === 'string' && t.length > 0 && t.length <= 32)
        .slice(0, 8);
    }
  } else {
    const authenticatorData = cleanBoundedString(result.response.authenticatorData, 8192);
    const signature = cleanBoundedString(result.response.signature, 4096);
    if (!authenticatorData || !WEB_SAFE_B64_RE.test(authenticatorData) || !signature || !WEB_SAFE_B64_RE.test(signature)) {
      throw new Error('智能卡返回的签名数据无效');
    }
    sanitizedResponse.authenticatorData = authenticatorData;
    sanitizedResponse.signature = signature;
    if (typeof result.response.userHandle === 'string' && result.response.userHandle.length <= 1024) {
      sanitizedResponse.userHandle = result.response.userHandle;
    } else if (result.response.userHandle === null) {
      sanitizedResponse.userHandle = null;
    }
  }
  return {
    id,
    rawId,
    type: 'public-key',
    response: sanitizedResponse,
    ...(typeof result.authenticatorAttachment === 'string' && result.authenticatorAttachment.length <= 32
      ? { authenticatorAttachment: result.authenticatorAttachment }
      : {}),
    ...(isPlainObject(result.clientExtensionResults)
      ? { clientExtensionResults: result.clientExtensionResults }
      : {}),
  };
}

export function validateSlotDecisionPayload(state: unknown): {
  slot: string;
  next_slot: string;
  decision_nonce: string;
  msg?: string;
} {
  if (!isPlainObject(state)) {
    throw new Error('槽位确认请求格式无效');
  }
  const nextSlot = cleanBoundedString(state.next_slot, 8);
  const decisionNonce = cleanBoundedString(state.decision_nonce, 128);
  const slot = typeof state.slot === 'string' && PIV_SLOT_RE.test(state.slot) ? state.slot.toLowerCase() : '9a';
  if (!nextSlot || !PIV_SLOT_RE.test(nextSlot) || !decisionNonce || !TOKEN_RE.test(decisionNonce)) {
    throw new Error('槽位确认参数无效');
  }
  const msg = typeof state.msg === 'string' && !CONTROL_CHAR_RE.test(state.msg)
    ? state.msg.slice(0, 300)
    : undefined;
  return {
    slot,
    next_slot: nextSlot.toLowerCase(),
    decision_nonce: decisionNonce,
    ...(msg ? { msg } : {}),
  };
}

export async function verifyGenerateBridgeResult(
  raw: unknown,
  job: BrowserPendingJob,
): Promise<{ issuance_id: string; csr_pem: string; card: BrowserCardDescriptor }> {
  if (!isPlainObject(raw)) {
    throw new Error('本机助手返回的密钥生成结果格式无效');
  }
  if (raw.issuance_id !== job.issuance_id) {
    throw new Error('密钥生成结果与当前签发任务编号不匹配');
  }
  if (typeof raw.csr_pem !== 'string') {
    throw new Error('密钥生成结果缺少有效 CSR');
  }
  const csrDer = unpem('CERTIFICATE REQUEST', raw.csr_pem);
  if (!isPlainObject(raw.card)) {
    throw new Error('密钥生成结果缺少硬件凭据描述');
  }
  if (raw.card.on_card_generation !== true || raw.card.browser_keystore === true) {
    throw new Error('拒绝非硬件生成的密钥结果');
  }
  const slot = cleanBoundedString(raw.card.slot, 8)?.toLowerCase() ?? '';
  const transport = cleanBoundedString(raw.card.transport, 32) ?? '';
  const algorithm = cleanBoundedString(raw.card.algorithm, 32) ?? '';
  const protocol = cleanBoundedString(raw.card.protocol, 64) ?? '';
  if (!CLIENT_SLOTS.has(slot) || !ALLOWED_TRANSPORTS.has(transport) || !algorithm || !protocol || protocol === 'browser') {
    throw new Error('硬件凭据属性不符合安全策略');
  }
  if (Array.isArray(job.algorithms) && job.algorithms.length > 0 && !job.algorithms.includes(algorithm)) {
    throw new Error('硬件生成的密钥算法不在任务允许范围内');
  }
  const reader = typeof raw.card.reader === 'string' && !CONTROL_CHAR_RE.test(raw.card.reader)
    ? raw.card.reader.slice(0, 300)
    : '';
  const platform = typeof raw.card.platform === 'string' && !CONTROL_CHAR_RE.test(raw.card.platform)
    ? raw.card.platform.slice(0, 64)
    : '';

  const asnResult = asn1.fromBER(csrDer);
  if (asnResult.offset !== csrDer.length || asnResult.offset < 0) {
    throw new Error('CSR 的 ASN.1 格式不正确');
  }
  const csrParsed = new CertificationRequest({ schema: asnResult.result });
  const spkiDer = encoded(csrParsed.subjectPublicKeyInfo.toSchema());
  const publicKeySha256 = hex(await sha(spkiDer));

  const card: BrowserCardDescriptor = {
    reader,
    slot,
    algorithm,
    transport,
    protocol,
    platform,
    on_card_generation: true,
    browser_keystore: false,
  };
  await validatedCsr({
    ...job,
    csr_pem: raw.csr_pem,
    card,
    public_key_sha256: publicKeySha256,
  });

  return {
    issuance_id: job.issuance_id,
    csr_pem: raw.csr_pem,
    card,
  };
}

export async function verifySignBridgeResult(
  raw: unknown,
  job: BrowserPendingJob,
): Promise<BrowserPendingJob & {
  chain_pem: string[];
  issuer_slot?: string;
  issuer_fingerprint?: string;
  issuer_descriptor?: AuthorityDescriptor | null;
}> {
  if (!isPlainObject(raw) || !Array.isArray(raw.chain_pem) || raw.chain_pem.length < 2 || raw.chain_pem.length > 8) {
    throw new Error('本机助手返回的签名证书链无效');
  }
  const chainPem: string[] = [];
  for (const certPem of raw.chain_pem) {
    if (typeof certPem !== 'string') {
      throw new Error('签名证书链条目格式无效');
    }
    unpem('CERTIFICATE', certPem);
    chainPem.push(certPem);
  }
  await validateInstallation({ ...job, chain_pem: chainPem });

  const issuerSlot = typeof raw.issuer_slot === 'string' && PIV_SLOT_RE.test(raw.issuer_slot)
    ? raw.issuer_slot.toLowerCase()
    : undefined;
  const issuerFingerprint = typeof raw.issuer_fingerprint === 'string' && SHA256_HEX_RE.test(raw.issuer_fingerprint)
    ? raw.issuer_fingerprint.toLowerCase()
    : undefined;
  const issuerDescriptor = issuerFingerprint && Array.isArray(job.authority_descriptors)
    ? job.authority_descriptors.find(d => d.fingerprint === issuerFingerprint) ?? null
    : undefined;

  return {
    ...job,
    chain_pem: chainPem,
    ...(issuerSlot ? { issuer_slot: issuerSlot } : {}),
    ...(issuerFingerprint ? { issuer_fingerprint: issuerFingerprint } : {}),
    ...(issuerDescriptor !== undefined ? { issuer_descriptor: issuerDescriptor } : {}),
  };
}

export function validateInstallBridgeResult(
  raw: unknown,
  job: BrowserPendingJob & { chain_pem?: string[] },
): Record<string, any> {
  if (!isPlainObject(raw)) {
    throw new Error('本机助手返回的持钥证明格式无效');
  }
  if (raw.issuance_id !== job.issuance_id) {
    throw new Error('持钥证明任务编号与当前任务不匹配');
  }
  if (raw.readback_verified !== true || raw.onsite_confirmed !== true) {
    throw new Error('硬件写入未通过回读及现场校验');
  }
  if (typeof raw.proof !== 'string' || !BASE64_PROOF_RE.test(raw.proof)) {
    throw new Error('硬件持钥签名格式无效');
  }
  const cardSlot = cleanBoundedString(raw.card_slot, 8)?.toLowerCase() ?? '';
  if (!CLIENT_SLOTS.has(cardSlot)) {
    throw new Error('持钥证明报告的槽位无效');
  }
  if (job.card?.slot && cardSlot !== job.card.slot.toLowerCase()) {
    throw new Error('持钥证明槽位与目标密钥槽位不一致');
  }
  let chainSlots: string[] | undefined;
  if (raw.chain_slots !== undefined) {
    if (!Array.isArray(raw.chain_slots) || raw.chain_slots.length > 16) {
      throw new Error('证书链槽位列表格式无效');
    }
    chainSlots = [];
    for (const s of raw.chain_slots) {
      if (typeof s !== 'string' || !PIV_SLOT_RE.test(s)) {
        throw new Error('证书链槽位编号无效');
      }
      chainSlots.push(s.toLowerCase());
    }
  }
  const expectedChain = job.chain_pem || job.signed_chain_pem;
  let validatedChain = expectedChain;
  if (raw.chain_pem !== undefined) {
    if (!Array.isArray(raw.chain_pem) || raw.chain_pem.length < 2 || raw.chain_pem.length > 8) {
      throw new Error('安装回执中的证书链格式无效');
    }
    for (const c of raw.chain_pem) {
      if (typeof c !== 'string') throw new Error('安装回执证书链条目无效');
      unpem('CERTIFICATE', c);
    }
    if (
      Array.isArray(expectedChain) &&
      expectedChain.length > 0 &&
      (raw.chain_pem.length !== expectedChain.length ||
        raw.chain_pem.some((cert, idx) => cert !== expectedChain[idx]))
    ) {
      throw new Error('安装回执中的证书链与已签发证书链不一致');
    }
    validatedChain = [...raw.chain_pem];
  }
  return {
    issuance_id: job.issuance_id,
    ...(validatedChain ? { chain_pem: validatedChain } : {}),
    proof: raw.proof,
    readback_verified: true,
    onsite_confirmed: true,
    card_slot: cardSlot,
    ...(chainSlots ? { chain_slots: chainSlots } : {}),
  };
}
