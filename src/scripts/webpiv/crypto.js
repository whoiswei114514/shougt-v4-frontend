import * as asn1 from 'asn1js';
import {
  AlgorithmIdentifier, Attribute, AttributeTypeAndValue, AuthorityKeyIdentifier, BasicConstraints,
  Certificate, CertificationRequest, CryptoEngine, Extension, ExtKeyUsage, PublicKeyInfo,
  RelativeDistinguishedNames, Time, setEngine,
} from 'pkijs';
import CryptoJS from 'crypto-js/core.js';
import 'crypto-js/aes.js';
import 'crypto-js/tripledes.js';
import 'crypto-js/mode-ecb.js';
import 'crypto-js/pad-nopadding.js';
import {bytes, concat, equal, hex, utf8, canonical, pem, unpem, unhex, tlv, valueOf} from './bytes.js';

export const BINDING_OID = '2.25.193227676215671796411912755825224731624';
export const ALGORITHMS = ['P-384', 'RSA-3072', 'RSA-2048'];
export const CLIENT_SLOTS = ['9a', '9c', '9e'];
export const CERT_SLOTS = ['9a', '9c', '9d', '9e', ...Array.from({length: 20}, (_, index) => (0x82 + index).toString(16))];
const keyUsageOID = '2.5.29.15', constraintsOID = '2.5.29.19', ekuOID = '2.5.29.37';
const extensionRequestOID = '1.2.840.113549.1.9.14';
const cnOID = '2.5.4.3';
// ASN1js renders very large OID arcs as base-128 hex. Normalize our exact wire OID.
const bindingWireOID = asn1.fromBER(new asn1.ObjectIdentifier({value: BINDING_OID}).toBER(false)).result.valueBlock.toString();
function normalizeExtension(item) {
  if (item.extnID === bindingWireOID) item.extnID = BINDING_OID;
  return item;
}
let engineReady = false;
function engine() {
  if (!globalThis.crypto?.subtle) throw new Error('此浏览器没有可用的安全密码接口，请使用 HTTPS');
  if (!engineReady) {
    setEngine('shou-browser', globalThis.crypto, new CryptoEngine({name: 'shou-browser', crypto: globalThis.crypto}));
    engineReady = true;
  }
  return globalThis.crypto.subtle;
}
function schema(value) {
  const data = bytes(value), result = asn1.fromBER(data);
  if (result.offset !== data.length || result.offset < 0) throw new Error('证书或 CSR 的 ASN.1 格式不正确');
  return result.result;
}
export const encoded = object => new Uint8Array(object.toBER(false));
export const sha = async (value, name = 'SHA-256') => new Uint8Array(await engine().digest(name, value));
export const fingerprint = async certificate => hex(await sha(certificate.der));
export function cardBinding(job) {
  const data = {
    issuance_id: job.issuance_id,
    nonce: job.nonce,
    user_id: job.user_id,
    user_version: job.user_version,
    real_name: job.real_name,
    roles: job.roles,
    card_slot: job.card?.slot || '9a',
  };
  if (job.temporary) {
    data.temporary = true;
    data.validity_days = job.validity_days;
    data.final_certificate = true;
  } else if (Array.isArray(job.roles) && (job.roles.includes('super_admin') || job.roles.includes('superadmin_admin'))) {
    data.delegated_ca = true;
  }
  return data;
}
export function requireActive(job) {
  if (!Number.isFinite(Date.parse(job.expires_at)) || Date.parse(job.expires_at) <= Date.now())
    throw new Error('签发任务已过期，请核对卡片状态后重新发起');
}
export function blockCipher(scheme, secret, input, decrypt = false) {
  const keySize = {tdes: 24, aes128: 16, aes192: 24, aes256: 32}[scheme];
  const blockSize = scheme === 'tdes' ? 8 : 16;
  if (!keySize || secret.length !== keySize || input.length !== blockSize) throw new Error('管理密钥或挑战长度与算法不匹配');
  const words = value => {
    const result = [];
    for (let index = 0; index < value.length; index++) result[index >>> 2] = (result[index >>> 2] || 0) | value[index] << (24 - (index % 4) * 8);
    return CryptoJS.lib.WordArray.create(result, value.length);
  };
  const key = words(secret), message = words(input);
  const cipher = scheme === 'tdes' ? CryptoJS.TripleDES : CryptoJS.AES;
  let output;
  try {
    const options = {mode: CryptoJS.mode.ECB, padding: CryptoJS.pad.NoPadding};
    output = decrypt ? cipher.decrypt({ciphertext: message}, key, options) : cipher.encrypt(message, key, options).ciphertext;
    return Uint8Array.from({length: output.sigBytes}, (_, index) => (output.words[index >>> 2] >>> (24 - (index % 4) * 8)) & 255);
  } finally {
    key.words.fill(0); message.words.fill(0); output?.words.fill(0);
  }
}
export async function publicKeyInfo(der) {
  const parsed = new PublicKeyInfo({schema: schema(der)});
  const oid = parsed.algorithm.algorithmId;
  let key;
  if (oid === '1.2.840.10045.2.1' && parsed.algorithm.algorithmParams?.valueBlock.toString() === '1.3.132.0.34') {
    key = await engine().importKey('spki', der, {name: 'ECDSA', namedCurve: 'P-384'}, false, ['verify']);
    return {parsed, der: bytes(der), key, name: 'P-384', size: 384};
  }
  if (oid === '1.2.840.113549.1.1.1') {
    key = await engine().importKey('spki', der, {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384'}, false, ['verify']);
    const size = key.algorithm.modulusLength;
    if (![2048, 3072, 4096].includes(size)) throw new Error('卡片的 RSA 密钥长度不受支持');
    return {parsed, der: bytes(der), key, name: `RSA-${size}`, size};
  }
  throw new Error('卡片必须支持 P-384 或 RSA');
}
function integer(value) {
  let data = bytes(value);
  while (data.length > 1 && data[0] === 0) data = data.slice(1);
  return tlv(0x02, data[0] & 0x80 ? concat(new Uint8Array([0]), data) : data);
}
export async function generatedPublicKey(name, response) {
  const data = valueOf(response, 0x7f49);
  const algorithm = name === 'P-384' ? unhex('301006072a8648ce3d020106052b81040022') : unhex('300d06092a864886f70d0101010500');
  const key = name === 'P-384' ? valueOf(data, 0x86) : tlv(0x30, concat(integer(valueOf(data, 0x81)), integer(valueOf(data, 0x82))));
  const result = await publicKeyInfo(tlv(0x30, concat(algorithm, tlv(0x03, concat(new Uint8Array([0]), key)))));
  if (result.name !== name) throw new Error('卡片返回了不同的密钥算法');
  return result;
}
function rawEcdsa(signature, size) {
  const sequence = schema(signature), integers = sequence.valueBlock.value;
  if (!(sequence instanceof asn1.Sequence) || sequence.lenBlock.isIndefiniteForm || sequence.lenBlock.isLongForm || integers.length !== 2)
    throw new Error('卡片 ECDSA 签名格式不正确');
  return concat(...integers.map(integer => {
    if (!(integer instanceof asn1.Integer)) throw new Error('卡片 ECDSA 签名格式不正确');
    let value = integer.valueBlock.valueHexView;
    if (!value.length || integer.lenBlock.isLongForm || value[0] & 0x80 ||
        (value.length > 1 && value[0] === 0 && !(value[1] & 0x80)))
      throw new Error('卡片 ECDSA 签名不是规范 DER 编码');
    while (value.length > 1 && value[0] === 0) value = value.subarray(1);
    if (value.length > size) throw new Error('卡片 ECDSA 签名长度不正确');
    const padded = new Uint8Array(size); padded.set(value, size - value.length); return padded;
  }));
}
export function derEcdsa(raw, size = 48) {
  const data = bytes(raw);
  if (data.length !== size * 2) throw new Error('ECDSA 签名长度不正确');
  const encodeInt = part => {
    let slice = part;
    while (slice.length > 1 && slice[0] === 0) slice = slice.slice(1);
    return tlv(0x02, slice[0] & 0x80 ? concat(new Uint8Array([0]), slice) : slice);
  };
  return tlv(0x30, concat(encodeInt(data.slice(0, size)), encodeInt(data.slice(size))));
}
export async function verifySignature(key, signature, message) {
  const algorithm = key.name === 'P-384' ? {name: 'ECDSA', hash: 'SHA-384'} : {name: 'RSASSA-PKCS1-v1_5'};
  const encodedSignature = key.name === 'P-384' ? rawEcdsa(signature, 48) : signature;
  if (!await engine().verify(algorithm, key.key, encodedSignature, message)) throw new Error('卡片签名验证失败');
}
export function parseCertificate(der) {
  const parsed = new Certificate({schema: schema(der)});
  parsed.extensions?.forEach(normalizeExtension);
  return {der: bytes(der), parsed};
}
export const certificateFromPem = value => parseCertificate(unpem('CERTIFICATE', value));
export const certificateKey = certificate => publicKeyInfo(encoded(certificate.parsed.subjectPublicKeyInfo.toSchema()));
function signingIdentifier(key) {
  return key.name === 'P-384'
    ? new AlgorithmIdentifier({algorithmId: '1.2.840.10045.4.3.3'})
    : new AlgorithmIdentifier({algorithmId: '1.2.840.113549.1.1.12', algorithmParams: new asn1.Null()});
}
function extension(certificate, oid) {
  const matches = (certificate.parsed.extensions || []).filter(item => item.extnID === oid);
  if (matches.length !== 1) throw new Error('证书扩展缺失或重复');
  return matches[0];
}
function extensionValue(certificate, oid) {
  return schema(extension(certificate, oid).extnValue.valueBlock.valueHexView);
}
function caConstraints(certificate) {
  return new BasicConstraints({schema: extensionValue(certificate, constraintsOID)});
}
function usage(certificate, mask) {
  const value = extensionValue(certificate, keyUsageOID);
  return value instanceof asn1.BitString && !!(value.valueBlock.valueHexView[0] & mask);
}
function validNow(certificate) {
  const now = Date.now();
  if (!(certificate.parsed.notBefore.value.getTime() <= now && now <= certificate.parsed.notAfter.value.getTime()))
    throw new Error('证书链已过期或尚未生效');
}
export function issuerMatches(key, issuer) {
  return key.name === 'P-384' ? issuer.name === 'P-384' : key.name.startsWith('RSA-') && issuer.name.startsWith('RSA-');
}
export async function buildChain(ca, job) {
  engine();
  const pool = [...job.authorities, ...job.roots].map(certificateFromPem);
  const roots = new Set(await Promise.all(job.roots.map(async value => fingerprint(certificateFromPem(value)))));
  const chain = [ca], visited = new Set([await fingerprint(ca)]);
  while (!roots.has(await fingerprint(chain.at(-1)))) {
    let issuer;
    for (const candidate of pool) {
      const digest = await fingerprint(candidate);
      if (visited.has(digest) || !caConstraints(candidate).cA || !usage(candidate, 0x04)) continue;
      if (chain.at(-1).parsed.issuer.isEqual(candidate.parsed.subject) && await chain.at(-1).parsed.verify(candidate.parsed)) {
        issuer = candidate; visited.add(digest); break;
      }
    }
    if (!issuer) throw new Error('CA 未连接到任务指定的信任根');
    chain.push(issuer);
    if (chain.length > 7) throw new Error('CA 链过长');
  }
  for (let index = 0; index < chain.length; index++) {
    const certificate = chain[index], constraints = caConstraints(certificate);
    validNow(certificate);
    if (!constraints.cA || !usage(certificate, 0x04) || (constraints.pathLenConstraint !== undefined && constraints.pathLenConstraint < index))
      throw new Error('CA 证书不允许签发此证书链');
  }
  return chain;
}
export async function makeCsr(job, key, sign) {
  engine();
  const request = new CertificationRequest({
    version: 0,
    subject: new RelativeDistinguishedNames({typesAndValues: [new AttributeTypeAndValue({type: cnOID, value: new asn1.Utf8String({value: job.real_name})})]}),
    subjectPublicKeyInfo: key.parsed,
    attributes: [new Attribute({type: extensionRequestOID, values: [new asn1.Sequence({value: [
      new Extension({extnID: BINDING_OID, critical: false, extnValue: utf8(canonical(cardBinding(job)))}).toSchema(),
    ]})]})],
  });
  const toSign = encoded(request.encodeTBS());
  request.tbs = toSign.buffer;
  request.signatureAlgorithm = signingIdentifier(key);
  const signature = await sign(toSign);
  await verifySignature(key, signature, toSign);
  request.signatureValue = new asn1.BitString({valueHex: signature});
  const der = encoded(request.toSchema());
  return {parsed: request, der, pem: pem('CERTIFICATE REQUEST', der)};
}
export async function validatedCsr(job) {
  engine();
  requireActive(job);
  const der = unpem('CERTIFICATE REQUEST', job.csr_pem), request = new CertificationRequest({schema: schema(der)});
  const requests = (request.attributes || []).filter(attribute => attribute.type === extensionRequestOID);
  if (requests.length !== 1 || requests[0].values.length !== 1 || !(requests[0].values[0] instanceof asn1.Sequence))
    throw new Error('CSR 扩展不正确');
  const bindings = requests[0].values[0].valueBlock.value.map(value => normalizeExtension(new Extension({schema: value}))).filter(value => value.extnID === BINDING_OID);
  const subject = request.subject.typesAndValues;
  if (bindings.length !== 1 || !equal(bindings[0].extnValue.valueBlock.valueHexView, utf8(canonical(cardBinding(job)))) ||
      subject.length !== 1 || subject[0].type !== cnOID || subject[0].value.valueBlock.value !== job.real_name || !await request.verify())
    throw new Error('CSR 身份、任务绑定或签名不匹配');
  const key = await publicKeyInfo(encoded(request.subjectPublicKeyInfo.toSchema()));
  if (hex(await sha(key.der)) !== job.public_key_sha256 || key.name !== job.card.algorithm || !CLIENT_SLOTS.includes(job.card.slot))
    throw new Error('CSR 公钥摘要、算法或槽位不匹配');
  return {parsed: request, der, key};
}
export async function selectCa(card, job, requested = 'auto') {
  const {key} = await validatedCsr(job);
  const trusted = new Set(await Promise.all(job.authorities.map(async value => fingerprint(certificateFromPem(value)))));
  const slots = requested === 'auto' ? ['9c', '9a', ...CERT_SLOTS.filter(slot => !['9a', '9c'].includes(slot))] : [requested];
  for (const slot of slots) {
    if (!CERT_SLOTS.includes(slot)) throw new Error('无效的 CA 槽位');
    const ca = await card.certificate(slot);
    if (!ca || !trusted.has(await fingerprint(ca))) continue;
    try {
      if (!issuerMatches(key, await certificateKey(ca)) || !caConstraints(ca).cA || !usage(ca, 0x04)) continue;
      return {slot, ca, chain: await buildChain(ca, job)};
    } catch (_) { /* Try another trusted CA without asking for any PIN. */ }
  }
  throw new Error('CA 卡内没有受信任且与目标算法对应的签发证书；尚未请求 CA PIN');
}
export async function makeCertificate(job, ca, chain, sign) {
  const request = await validatedCsr(job), issuerKey = await certificateKey(ca);
  const caBc = caConstraints(ca);
  if (!issuerMatches(request.key, issuerKey) || !caBc.cA || !usage(ca, 0x04)) throw new Error('CA 算法或签发用途不匹配');
  const temporary = Boolean(job.temporary);
  const delegatedCa = Boolean(!temporary && Array.isArray(job.roles) && (job.roles.includes('super_admin') || job.roles.includes('superadmin_admin')));
  if (delegatedCa && caBc.pathLenConstraint === 0) {
    throw new Error('个人超管 CA 仅可签发短于 37 天的临时最终证书，不能签发 CA 证书');
  }
  let validDays = 365;
  if (temporary) {
    if (!Number.isInteger(job.validity_days) || job.validity_days < 1 || job.validity_days > 36) {
      throw new Error('临时证书有效期必须为 1 至 36 天');
    }
    validDays = job.validity_days;
  }
  const now = Date.now(), serial = globalThis.crypto.getRandomValues(new Uint8Array(20));
  serial[0] &= 0x7f;
  if (!serial.some(Boolean)) serial[19] = 1;
  const ext = (oid, value, critical = false) => new Extension({extnID: oid, critical, extnValue: value});
  const bcExt = delegatedCa ? new BasicConstraints({cA: true, pathLenConstraint: 0}) : new BasicConstraints({cA: false});
  const kuExt = delegatedCa
    ? new asn1.BitString({valueHex: new Uint8Array([0x84]), unusedBits: 2})
    : new asn1.BitString({valueHex: new Uint8Array([0x80]), unusedBits: 7});
  const certificate = new Certificate({
    version: 2, serialNumber: new asn1.Integer({valueHex: serial}),
    signature: signingIdentifier(issuerKey), signatureAlgorithm: signingIdentifier(issuerKey),
    subject: request.parsed.subject, issuer: ca.parsed.subject, subjectPublicKeyInfo: request.key.parsed,
    notBefore: new Time({type: 0, value: new Date(now - 60000)}),
    notAfter: new Time({type: 0, value: new Date(Math.min(now + validDays * 86400000, ...chain.map(certificate => certificate.parsed.notAfter.value.getTime())))}),
    extensions: [
      ext(constraintsOID, encoded(bcExt.toSchema()), true),
      ext(keyUsageOID, encoded(kuExt), true),
      ext(ekuOID, encoded(new ExtKeyUsage({keyPurposes: ['1.3.6.1.5.5.7.3.2']}).toSchema())),
      ext('2.5.29.14', encoded(new asn1.OctetString({valueHex: await sha(request.key.parsed.subjectPublicKey.valueBlock.valueHexView, 'SHA-1')}))),
      ext('2.5.29.35', encoded(new AuthorityKeyIdentifier({
        keyIdentifier: new asn1.OctetString({valueHex: await sha(issuerKey.parsed.subjectPublicKey.valueBlock.valueHexView, 'SHA-1')}),
      }).toSchema())),
      ext(BINDING_OID, utf8(canonical({...cardBinding(job), write_nonce: job.write_nonce}))),
    ],
  });
  const toSign = encoded(certificate.encodeTBS());
  certificate.tbs = toSign.buffer;
  const signature = await sign(toSign);
  await verifySignature(issuerKey, signature, toSign);
  certificate.signatureValue = new asn1.BitString({valueHex: signature});
  const result = parseCertificate(encoded(certificate.toSchema()));
  if (!await result.parsed.verify(ca.parsed)) throw new Error('CA 签名验证失败');
  return result;
}
export async function validateInstallation(job) {
  const request = await validatedCsr(job);
  if (!Array.isArray(job.chain_pem) || job.chain_pem.length < 2 || job.chain_pem.length > 8) throw new Error('证书链长度不正确');
  const certificates = job.chain_pem.map(certificateFromPem), [leaf, ...chain] = certificates;
  const trusted = await Promise.all(job.authorities.map(async value => fingerprint(certificateFromPem(value))));
  if (!trusted.includes(await fingerprint(chain[0])) || !issuerMatches(request.key, await certificateKey(chain[0])))
    throw new Error('签发 CA 或签发算法不匹配');
  for (let index = 0; index < certificates.length - 1; index++)
    if (!certificates[index].parsed.issuer.isEqual(certificates[index + 1].parsed.subject) || !await certificates[index].parsed.verify(certificates[index + 1].parsed))
      throw new Error('证书链签名不正确');
  const expected = await buildChain(chain[0], job);
  if (canonical(await Promise.all(chain.map(fingerprint))) !== canonical(await Promise.all(expected.map(fingerprint))))
    throw new Error('完整证书链未连接到指定信任根');
  const key = await certificateKey(leaf);
  const eku = new ExtKeyUsage({schema: extensionValue(leaf, ekuOID)});
  validNow(leaf);
  const temporary = Boolean(job.temporary);
  const delegatedCa = Boolean(!temporary && Array.isArray(job.roles) && (job.roles.includes('super_admin') || job.roles.includes('superadmin_admin')));
  const bc = caConstraints(leaf);
  if (bc.cA !== delegatedCa || (delegatedCa && bc.pathLenConstraint !== 0) ||
      !usage(leaf, 0x80) || (delegatedCa ? !usage(leaf, 0x04) : usage(leaf, 0x04)) ||
      !eku.keyPurposes.includes('1.3.6.1.5.5.7.3.2') ||
      (temporary && (leaf.parsed.notAfter.value.getTime() - leaf.parsed.notBefore.value.getTime()) >= 37 * 86400000) ||
      leaf.parsed.notAfter.value.getTime() > Math.min(...chain.map(certificate => certificate.parsed.notAfter.value.getTime())) ||
      !equal(key.der, request.key.der) || !leaf.parsed.subject.isEqual(request.parsed.subject) ||
      !equal(extension(leaf, BINDING_OID).extnValue.valueBlock.valueHexView, utf8(canonical({...cardBinding(job), write_nonce: job.write_nonce}))))
    throw new Error('客户端证书身份、用途、公钥或任务绑定不匹配');
  return {certificates, leaf, chain, key};
}
export async function writeProof(job, leaf, chain) {
  return utf8(canonical({
    purpose: 'shou-piv-installed-v1', issuance_id: job.issuance_id, write_nonce: job.write_nonce,
    certificate: await fingerprint(leaf), chain: await Promise.all(chain.map(fingerprint)), card_slot: job.card.slot,
  }));
}
