import {test} from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {createCipheriv, generateKeyPairSync, randomUUID, sign as nodeSign} from 'node:crypto';
import * as asn1 from 'asn1js';
import {
  AttributeTypeAndValue, BasicConstraints, Certificate, CertificationRequest, Extension,
} from 'pkijs';
import {appletRPC} from './webpiv-rpc.mjs';
import {concat, hex, pem, tlv, unhex, unpem} from '../src/scripts/webpiv/bytes.js';
import {
  blockCipher, certificateFromPem, derEcdsa, makeCertificate, makeCsr, sha, publicKeyInfo, validateInstallation, verifySignature,
} from '../src/scripts/webpiv/crypto.js';
import * as browserCeremony from '../src/scripts/webpiv/browserCeremony.js';
import {isSafeAttrUri, sanitizeCssText} from '../src/scripts/sanitizeMarkdown.ts';
import {getTrustedConsoleOrigin, isValidUuid, sanitizeSafeNextPath, validateConsoleHandoffUrl, validateRelativeRedirectUrl} from '../src/scripts/securityUrls.ts';
import {
  validateFidoAssertionResult,
  validateInstallBridgeResult,
  validateLoopbackBridgeUrl,
  validatePcscReadersPayload,
  validateSlotDecisionPayload,
  verifyGenerateBridgeResult,
  verifySignBridgeResult,
} from '../src/scripts/bridgeValidation.ts';
import {CanoKeyChannel, PivCard} from '../src/scripts/webpiv/transport.js';
import {WebPivCeremony} from '../src/scripts/webpiv/ceremony.js';

const work = path.resolve(process.env.SHOUGT_WEBPIV_WORK || '.test-work/webpiv');
fs.mkdirSync(work, {recursive: true});
const management = '00112233445566778899aabbccddeeff0123456789abcdef';
const storage = () => {
  const values = new Map();
  return {getItem: key => values.get(key) || null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key)};
};
async function fixture(t, {supported, acceptSlot = true} = {}) {
  const rpc = appletRPC(); t.after(() => rpc.close());
  const directory = fs.mkdtempSync(path.join(work, 'fixture-'));
  const {job} = await rpc.send({action: 'init', work: directory, ...(supported ? {supported} : {})});
  const persistence = storage(), prompts = [];
  const callbacks = {
    storage: persistence,
    chooseCard: async stage => {
      const device = stage === 'sign' ? 'ca' : 'target';
      return {id: device, name: `Software ${device}`, channel: {
        open: async () => {}, close: async () => {},
        transmit: async apdu => unhex(await rpc.send({action: 'apdu', device, apdu: hex(apdu)})),
      }};
    },
    secret: async settings => { prompts.push(settings); return settings.kind === 'management' ? management : '654321'; },
    confirm: async () => true, chooseSlot: async () => acceptSlot,
  };
  const ceremony = new WebPivCeremony(callbacks);
  const options = {reader: 'software', transport: 'usb', algorithm: 'auto', management_algorithm: 'tdes', ca_slot: 'auto', slot: '9a'};
  return {rpc, job, directory, prompts, callbacks, ceremony, options};
}
async function generate(value) {
  const keyResult = await value.ceremony.run('generate', value.job, value.options, 'generate');
  const csr = new CertificationRequest({schema: asn1.fromBER(unpem('CERTIFICATE REQUEST', keyResult.csr_pem)).result});
  const job = {...value.job, state: 'key_ready', card: keyResult.card, csr_pem: keyResult.csr_pem,
    public_key_sha256: hex(await sha(csr.subjectPublicKeyInfo.toSchema().toBER(false))), write_nonce: 'web-write-nonce'};
  return {keyResult, job};
}

test('occupied default slot stops before any management authentication or PIN', async t => {
  const value = await fixture(t, {acceptSlot: false});
  await assert.rejects(value.ceremony.run('generate', value.job, value.options, 'generate'), /已停止签发/);
  const stats = await value.rpc.send({action: 'stats'});
  assert.equal(stats.generations, 0); assert.equal(stats.management_attempts, 0);
  assert.equal(stats.pin_attempts, 0); assert.equal(value.prompts.length, 0);
  assert.equal(stats.old_default_preserved, true); assert.deepEqual(stats.writes, []);
});

test('certificate added during confirmation stops before key generation', async t => {
  const value = await fixture(t), choices = [];
  await value.rpc.send({action: 'configure', options: {occupy_after_management: true}});
  value.ceremony.chooseSlot = async choice => { choices.push(choice); return choices.length === 1; };
  await assert.rejects(value.ceremony.run('generate', value.job, value.options, 'generate'), /已停止签发/);
  assert.deepEqual(choices.map(choice => choice.slot), ['9a', '9c']);
  const stats = await value.rpc.send({action: 'stats'});
  assert.equal(stats.generations, 0); assert.equal(stats.pin_attempts, 0); assert.deepEqual(stats.writes, []);
});

for (const [name, supported, attempts, issuerSlot] of [
  ['P-384', ['P-384', 'RSA-3072', 'RSA-2048'], ['P-384'], '9a'],
  ['RSA-3072', ['RSA-3072', 'RSA-2048'], ['P-384', 'RSA-3072'], '9c'],
  ['RSA-2048', ['RSA-2048'], ['P-384', 'RSA-3072', 'RSA-2048'], '9c'],
]) test(`browser ${name} CSR, CA selection, chain and proof interoperate with Python`, async t => {
  const value = await fixture(t, {supported}), {job, keyResult} = await generate(value);
  assert.equal(keyResult.card.algorithm, name); assert.equal(keyResult.card.slot, '9c');
  const signed = await value.ceremony.run('sign', job, value.options, 'sign');
  assert.equal(signed.issuer_slot, issuerSlot);
  const receipt = await value.ceremony.run('install', signed, value.options, 'install');
  const result = {job: signed, key_result: keyResult, receipt};
  fs.writeFileSync(path.join(work, name.replace('-', '').toLowerCase() + '-interop.json'), JSON.stringify({result}, null, 2));
  const verified = await value.rpc.send({action: 'verify', result});
  assert.equal(verified.csr_verified, true); assert.equal(verified.certificate_verified, true); assert.equal(verified.proof_verified, true);
  assert.equal(verified.generations, 1); assert.deepEqual(verified.algorithms, attempts);
  assert.deepEqual(verified.writes, ['9c', '83', '84']);
  assert.deepEqual(verified.discovery_objects, ['5fc102', '5fc107']);
  assert.equal(verified.old_default_preserved, true); assert.equal(verified.old_chain_preserved, true);
  fs.writeFileSync(path.join(work, name.replace('-', '').toLowerCase() + '-interop.json'), JSON.stringify({result, verified}, null, 2));
});

test('wrong PIN consumes one VERIFY; retry completes the CSR without another GENERATE', async t => {
  const value = await fixture(t);
  await value.rpc.send({action: 'configure', options: {fail_pin_once: true}});
  await assert.rejects(value.ceremony.run('generate', value.job, value.options, 'generate'), /63c2/);
  const first = await value.rpc.send({action: 'stats'});
  assert.equal(first.generations, 1); assert.equal(first.pin_attempts, 1);
  await generate(value);
  const retry = await value.rpc.send({action: 'stats'});
  assert.equal(retry.generations, 1); assert.equal(retry.pin_attempts, 2);
  assert.equal(retry.management_attempts, 1);
});

for (const error of ['fail_after_generate', 'malformed_generate']) test(`${error} stops fallback and blocks generation after reload`, async t => {
  const value = await fixture(t);
  await value.rpc.send({action: 'configure', options: {[error]: true}});
  await assert.rejects(value.ceremony.run('generate', value.job, value.options, 'generate'));
  await assert.rejects(value.ceremony.run('generate', value.job, value.options, 'generate'), /禁止重复生成/);
  const reloaded = new WebPivCeremony(value.callbacks);
  await assert.rejects(reloaded.run('generate', value.job, value.options, 'new-operation'), /禁止自动再次生成/);
  const stats = await value.rpc.send({action: 'stats'});
  assert.equal(stats.generations, 1); assert.deepEqual(stats.algorithms, ['P-384']); assert.equal(stats.pin_attempts, 0);
});

test('missing matching CA and tampered CSR stop before requesting a CA PIN', async t => {
  const value = await fixture(t), {job} = await generate(value);
  await assert.rejects(value.ceremony.run('sign', {...job, authorities: [job.authorities[1]]}, value.options, 'no-ca'), /尚未请求 CA PIN/);
  const other = new WebPivCeremony(value.callbacks);
  await assert.rejects(other.run('sign', {...job, public_key_sha256: '0'.repeat(64)}, value.options, 'bad-csr'), /公钥摘要/);
  assert.equal((await value.rpc.send({action: 'stats', device: 'ca'})).pin_attempts, 0);
});

test('partial writes recover with identical certificates and preserve occupied chain slots', async t => {
  const value = await fixture(t), {job} = await generate(value);
  const signed = await value.ceremony.run('sign', job, value.options, 'sign');
  await value.rpc.send({action: 'configure', options: {bad_readback: true}});
  await assert.rejects(value.ceremony.run('install', signed, value.options, 'install'));
  assert.deepEqual((await value.rpc.send({action: 'stats'})).writes, ['9c']);
  await value.rpc.send({action: 'configure', options: {bad_readback: false}});
  const receipt = await value.ceremony.run('install', signed, value.options, 'install');
  assert.deepEqual(receipt.chain_slots, ['9c', '83', '84']);
  assert.deepEqual((await value.rpc.send({action: 'stats'})).writes, ['9c', '83', '84']);
});

test('another target card cannot pass the private key proof before writes', async t => {
  const value = await fixture(t), {job} = await generate(value);
  const signed = await value.ceremony.run('sign', job, value.options, 'sign');
  const other = await fixture(t);
  const wrong = new WebPivCeremony({...value.callbacks, chooseCard: other.callbacks.chooseCard});
  await assert.rejects(wrong.run('install', signed, value.options, 'wrong-target'));
  const stats = await other.rpc.send({action: 'stats'});
  assert.deepEqual(stats.writes, []); assert.equal(stats.management_attempts, 0);
});

test('a WebUSB descriptor with CCID class is rejected before claiming its interface', async () => {
  let claims = 0;
  const channel = new CanoKeyChannel({vendorId: 0x20a0, productId: 0x42d4, open: async () => {},
    configuration: {interfaces: [{interfaceNumber: 1, alternates: [{interfaceClass: 0x0b}]}]},
    claimInterface: async () => { claims++; }});
  await assert.rejects(channel.open(), /没有提供受支持的 WebUSB/); assert.equal(claims, 0);
});

test('CanoKey vendor transport uses bounded status polling and does not retry a stalled command', async () => {
  const requests = [], view = data => new DataView(Uint8Array.from(data).buffer);
  let polls = 0;
  const device = {
    vendorId: 0x20a0, productId: 0x42d4, open: async () => {}, close: async () => {},
    claimInterface: async () => {}, releaseInterface: async () => {},
    configuration: {interfaces: [{interfaceNumber: 1, alternates: [{interfaceClass: 0xff}]}]},
    controlTransferOut: async (setup, data) => { requests.push(setup); return {status: 'ok', bytesWritten: data.length}; },
    controlTransferIn: async setup => { requests.push(setup); return {status: 'ok', data: setup.request === 2 ? view([polls++ < 2 ? 1 : 0]) : view([0x90, 0])}; },
  };
  const channel = new CanoKeyChannel(device, {timeout: 100, pollInterval: 1});
  await channel.open();
  assert.deepEqual(await channel.transmit(new Uint8Array([0, 0xa4, 0, 0, 0])), new Uint8Array([0x90, 0]));
  assert.deepEqual(requests.map(request => request.request), [0, 2, 2, 2, 1]);
  assert.equal(requests.every(request => request.index === 1 && request.requestType === 'vendor' && request.recipient === 'interface'), true);
  let commands = 0;
  device.controlTransferOut = async () => { commands++; return {status: 'stalled', bytesWritten: 0}; };
  await assert.rejects(channel.transmit(new Uint8Array([0, 0x20, 0, 0x80, 0])), /发送失败/);
  assert.equal(commands, 1);
  device.controlTransferOut = async (_, data) => ({status: 'ok', bytesWritten: data.length});
  device.controlTransferIn = async () => ({status: 'ok', data: view([1])});
  await assert.rejects(channel.transmit(new Uint8Array([0, 0x47, 0, 0x9a, 0])), /超时/);
  await assert.rejects(channel.transmit(new Uint8Array([0, 0x47, 0, 0x9a, 0])), /连接不可用/);
  await channel.close();
});

test('TDES and AES management block operations match Node OpenSSL ECB', () => {
  for (const [scheme, size, name, blockSize] of [['tdes', 24, 'des-ede3', 8], ['aes128', 16, 'aes-128-ecb', 16], ['aes192', 24, 'aes-192-ecb', 16], ['aes256', 32, 'aes-256-ecb', 16]]) {
    const key = Uint8Array.from({length: size}, (_, index) => index + 1), block = Uint8Array.from({length: blockSize}, (_, index) => index * 13);
    const cipher = createCipheriv(name, key, null); cipher.setAutoPadding(false);
    const expected = Buffer.concat([cipher.update(block), cipher.final()]);
    assert.equal(hex(blockCipher(scheme, key, block)), hex(expected), scheme);
    assert.equal(hex(blockCipher(scheme, key, expected, true)), hex(block), scheme);
  }
});

test('a mathematically valid ECDSA signature with noncanonical DER is rejected before use', async () => {
  const {publicKey, privateKey} = generateKeyPairSync('ec', {namedCurve: 'secp384r1'});
  const key = await publicKeyInfo(publicKey.export({type: 'spki', format: 'der'}));
  const message = new TextEncoder().encode('Malformed PIV signature regression');
  const signature = nodeSign('sha384', message, privateKey);
  await verifySignature(key, signature, message);
  const decoded = asn1.fromBER(signature).result;
  decoded.valueBlock.value[0] = new asn1.Integer({valueHex: concat(new Uint8Array([0]), decoded.valueBlock.value[0].valueBlock.valueHexView)});
  await assert.rejects(verifySignature(key, new Uint8Array(decoded.toBER(false)), message), /规范 DER/);
});

test('endless APDU continuation responses are stopped at the bound', async () => {
  let count = 0;
  const card = new PivCard({transmit: async () => { count++; return new Uint8Array([0x61, 0]); }});
  await assert.rejects(card.command(0xcb, 0x3f, 0xff), /续取次数限制/);
  assert.equal(count, 257);
});

async function makeTestPkiCa(cn, pathLenConstraint, issuerCert = null, issuerPrivateKey = null) {
  const keyPair = await globalThis.crypto.subtle.generateKey(
    {name: 'ECDSA', namedCurve: 'P-384'}, true, ['sign', 'verify'],
  );
  const cert = new Certificate();
  cert.version = 2;
  cert.serialNumber = new asn1.Integer({valueHex: globalThis.crypto.getRandomValues(new Uint8Array(8))});
  cert.subject.typesAndValues.push(new AttributeTypeAndValue({type: '2.5.4.3', value: new asn1.Utf8String({value: cn})}));
  cert.issuer.typesAndValues.push(...(issuerCert ? issuerCert.subject.typesAndValues : cert.subject.typesAndValues));
  cert.notBefore.value = new Date(Date.now() - 3600000);
  cert.notAfter.value = new Date(Date.now() + 365 * 86400000);
  await cert.subjectPublicKeyInfo.importKey(keyPair.publicKey);
  const keyUsageBits = new ArrayBuffer(1);
  new Uint8Array(keyUsageBits)[0] = 0x84;
  const bc = new BasicConstraints({cA: true, pathLenConstraint});
  cert.extensions = [
    new Extension({extnID: '2.5.29.19', critical: true, extnValue: bc.toSchema().toBER(false)}),
    new Extension({extnID: '2.5.29.15', critical: true, extnValue: new asn1.BitString({valueHex: keyUsageBits, unusedBits: 2}).toBER(false)}),
  ];
  await cert.sign(issuerPrivateKey || keyPair.privateKey, 'SHA-384');
  const b64 = Buffer.from(cert.toSchema().toBER(false)).toString('base64').match(/.{1,64}/g).join('\n');
  const pemText = `-----BEGIN CERTIFICATE-----\n${b64}\n-----END CERTIFICATE-----\n`;
  const pkcs8Der = new Uint8Array(await globalThis.crypto.subtle.exportKey('pkcs8', keyPair.privateKey));
  return {cert, pemText, pkcs8Der, privateKey: keyPair.privateKey};
}

test('no software .p12 export or browser key vault path exists and delegated CA / <37d limits hold', async () => {
  assert.equal(fs.existsSync(path.resolve('src/scripts/webpiv/pkcs12.js')), false);
  assert.equal(fs.existsSync(path.resolve('src/scripts/webpiv/vault.js')), false);
  assert.deepEqual(Object.keys(browserCeremony), ['findAuthorityDescriptor']);

  const signEcdsa = privateKey => async tbs =>
    derEcdsa(new Uint8Array(await globalThis.crypto.subtle.sign({name: 'ECDSA', hash: 'SHA-384'}, privateKey, tbs)), 48);

  const rootCa = await makeTestPkiCa('Test Root CA', 2);
  const subCa = await makeTestPkiCa('Test Sub CA', 1, rootCa.cert, rootCa.privateKey);

  const targetKeys = await globalThis.crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-384'}, true, ['sign', 'verify']);
  const targetSpki = new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', targetKeys.publicKey));
  const targetKeyInfo = await publicKeyInfo(targetSpki);

  const superJob = {
    issuance_id: randomUUID(),
    nonce: 'hw-super-nonce',
    write_nonce: 'hw-super-write',
    user_id: 101,
    user_version: 1,
    real_name: '超管硬件测试',
    roles: ['super_admin'],
    state: 'requested',
    expires_at: new Date(Date.now() + 300000).toISOString(),
    algorithms: ['P-384'],
    authorities: [subCa.pemText],
    roots: [rootCa.pemText],
    delegated_ca: true,
    temporary: false,
    card: {
      reader: 'fixture-usb',
      slot: '9a',
      algorithm: 'P-384',
      transport: 'usb',
      protocol: 'T=1',
      platform: 'win32',
      on_card_generation: true,
      browser_keystore: false,
    },
  };
  const superCsr = await makeCsr(superJob, targetKeyInfo, signEcdsa(targetKeys.privateKey));
  const verifiedGen = await verifyGenerateBridgeResult(
    {issuance_id: superJob.issuance_id, csr_pem: superCsr.pem, card: superJob.card},
    superJob,
  );
  assert.equal(verifiedGen.card.on_card_generation, true);
  assert.equal(verifiedGen.card.browser_keystore, false);

  await assert.rejects(
    verifyGenerateBridgeResult(
      {issuance_id: superJob.issuance_id, csr_pem: superCsr.pem, card: {...superJob.card, browser_keystore: true}},
      superJob,
    ),
    /非硬件生成/,
  );

  const superReady = {
    ...superJob,
    state: 'key_ready',
    csr_pem: superCsr.pem,
    public_key_sha256: hex(await sha(targetKeyInfo.der)),
  };
  const subWrapped = certificateFromPem(subCa.pemText);
  const rootWrapped = certificateFromPem(rootCa.pemText);
  const superLeaf = await makeCertificate(superReady, subWrapped, [subWrapped, rootWrapped], signEcdsa(subCa.privateKey));
  const superLeafPem = pem('CERTIFICATE', superLeaf.der);
  const superChainPem = [superLeafPem, subCa.pemText, rootCa.pemText];
  const verifiedSign = await verifySignBridgeResult({chain_pem: superChainPem, issuer_slot: '9a'}, superReady);
  assert.equal(verifiedSign.chain_pem.length, 3);

  const superBc = new BasicConstraints({
    schema: asn1.fromBER(superLeaf.parsed.extensions.find(e => e.extnID === '2.5.29.19').extnValue.valueBlock.valueHex).result,
  });
  assert.equal(superBc.cA, true);
  assert.equal(superBc.pathLenConstraint, 0);

  // Delegated CA (pathLen=0) cannot sign another delegated CA (only <37d final cert)
  const nestedCaJob = {...superReady, issuance_id: randomUUID(), authorities: [superLeafPem, subCa.pemText]};
  const nestedCaCsr = await makeCsr(nestedCaJob, targetKeyInfo, signEcdsa(targetKeys.privateKey));
  await assert.rejects(
    makeCertificate(
      {...nestedCaJob, csr_pem: nestedCaCsr.pem, public_key_sha256: hex(await sha(targetKeyInfo.der))},
      superLeaf,
      [superLeaf, subWrapped, rootWrapped],
      signEcdsa(targetKeys.privateKey),
    ),
    /37 天|不能签发 CA/,
  );

  // Temporary cert > 36 days rejected
  const tempKey = await globalThis.crypto.subtle.generateKey({name: 'ECDSA', namedCurve: 'P-384'}, true, ['sign', 'verify']);
  const tempKeyInfo = await publicKeyInfo(new Uint8Array(await globalThis.crypto.subtle.exportKey('spki', tempKey.publicKey)));
  const overTempJob = {
    ...superJob,
    issuance_id: randomUUID(),
    nonce: 'hw-temp-nonce',
    write_nonce: 'hw-temp-write',
    roles: ['global_reader'],
    temporary: true,
    validity_days: 37,
    delegated_ca: false,
    authorities: [superLeafPem, subCa.pemText],
  };
  const overTempCsr = await makeCsr(overTempJob, tempKeyInfo, signEcdsa(tempKey.privateKey));
  await assert.rejects(
    makeCertificate(
      {...overTempJob, state: 'key_ready', csr_pem: overTempCsr.pem, public_key_sha256: hex(await sha(tempKeyInfo.der))},
      superLeaf,
      [superLeaf, subWrapped, rootWrapped],
      signEcdsa(targetKeys.privateKey),
    ),
    /1 至 36 天/,
  );

  const validTempJob = {...overTempJob, validity_days: 7};
  const validTempCsr = await makeCsr(validTempJob, tempKeyInfo, signEcdsa(tempKey.privateKey));
  const validTempReady = {
    ...validTempJob,
    state: 'key_ready',
    csr_pem: validTempCsr.pem,
    public_key_sha256: hex(await sha(tempKeyInfo.der)),
  };
  const tempLeaf = await makeCertificate(
    validTempReady,
    superLeaf,
    [superLeaf, subWrapped, rootWrapped],
    signEcdsa(targetKeys.privateKey),
  );
  const tempLeafPem = pem('CERTIFICATE', tempLeaf.der);
  const verifiedTempSign = await verifySignBridgeResult(
    {chain_pem: [tempLeafPem, superLeafPem, subCa.pemText, rootCa.pemText]},
    validTempReady,
  );
  assert.equal(verifiedTempSign.chain_pem.length, 4);
  const receipt = validateInstallBridgeResult(
    {
      issuance_id: validTempReady.issuance_id,
      chain_pem: verifiedTempSign.chain_pem,
      proof: Buffer.from('0123456789abcdef0123456789abcdef').toString('base64'),
      readback_verified: true,
      onsite_confirmed: true,
      card_slot: '9a',
      chain_slots: ['9a', '82'],
      injected_extra: 'ignored',
    },
    verifiedTempSign,
  );
  assert.equal('injected_extra' in receipt, false);
  await validateInstallation({...verifiedTempSign, chain_pem: verifiedTempSign.chain_pem});
});

test('XSS, CSS/URI sanitization, redirect, opener origin, and localhost bridge validators reject malicious payloads', () => {
  assert.equal(isSafeAttrUri('https://shouguatian.com/p/1'), true);
  assert.equal(isSafeAttrUri('/article/1/'), true);
  assert.equal(isSafeAttrUri('javascript:alert(1)'), false);
  assert.equal(isSafeAttrUri('data:text/html,<script>alert(1)</script>'), false);
  assert.equal(isSafeAttrUri('//evil.example/phish'), false);
  assert.equal(isSafeAttrUri('#arrow', true), true);
  assert.equal(isSafeAttrUri('https://evil.example/x.svg#a', true), false);

  assert.equal(sanitizeCssText('height:1.0em;vertical-align:-0.25em;position:relative;color:#000'), 'height:1.0em;vertical-align:-0.25em;position:relative;color:#000');
  assert.equal(sanitizeCssText('fill:url(#arrowhead);', true), 'fill:url(#arrowhead);');
  assert.equal(sanitizeCssText('background:url(https://evil.example/leak)'), null);
  assert.equal(sanitizeCssText('background:u\\72l(data:text/html,1)'), null);
  assert.equal(sanitizeCssText('position:fixed;inset:0'), null);
  assert.equal(sanitizeCssText('@import url(https://evil.example);', true), null);
  assert.equal(sanitizeCssText('</style><img src=x onerror=alert(1)>', true), null);

  assert.equal(sanitizeSafeNextPath('/admin/post/', 'https://shou.example'), '/admin/post/');
  assert.equal(sanitizeSafeNextPath('//evil.example', 'https://shou.example'), '/');
  assert.equal(sanitizeSafeNextPath('/\\evil.example', 'https://shou.example'), '/');
  assert.equal(sanitizeSafeNextPath('javascript:alert(1)', 'https://shou.example'), '/');

  assert.equal(getTrustedConsoleOrigin('https://privileged.shouguatian.com/'), 'https://privileged.shouguatian.com');
  assert.equal(getTrustedConsoleOrigin('http://evil.example:8080/'), null);
  assert.equal(validateConsoleHandoffUrl('https://privileged.shouguatian.com/#ticket=abc', 'https://privileged.shouguatian.com/'), 'https://privileged.shouguatian.com/#ticket=abc');
  assert.throws(() => validateConsoleHandoffUrl('javascript:alert(1)', 'https://privileged.shouguatian.com/'));
  assert.throws(() => validateConsoleHandoffUrl('https://attacker.example/#ticket=abc', 'https://privileged.shouguatian.com/'));
  assert.throws(() => validateRelativeRedirectUrl('//evil.example/'));
  assert.equal(isValidUuid('550e8400-e29b-41d4-a716-446655440000'), true);
  assert.equal(isValidUuid('550e8400-e29b-41d4-a716-446655440000/../admin'), false);

  assert.equal(validateLoopbackBridgeUrl('http://127.0.0.1:18444'), 'http://127.0.0.1:18444');
  assert.equal(validateLoopbackBridgeUrl('https://evil.example:18444'), null);
  assert.equal(validateLoopbackBridgeUrl('http://127.0.0.1:80'), null);
  assert.throws(() => validateSlotDecisionPayload({next_slot: 'bad', decision_nonce: 'x'}));
  assert.equal(validatePcscReadersPayload({cards: [{id: 'r1', name: 'Reader', state: 'ready', transport: 'usb'}]}).length, 1);
  assert.throws(() => validateFidoAssertionResult({id: 'a', rawId: 'YQ==', type: 'wrong', response: {}}, 'get'));
});

test('PivCard.probe keeps PIV ready when FIDO2 GetInfo returns 0x6e00 or 0x6985 over WebUSB', async () => {
  for (const fidoStatus of [[0x6e, 0x00], [0x69, 0x85]]) {
    const card = new PivCard({
      transmit: async apdu => {
        const ins = apdu[1];
        if (ins === 0xa4 && apdu[4] === 8) return new Uint8Array([0x90, 0x00]); // FIDO_AID
        if (ins === 0x10) return new Uint8Array(fidoStatus); // CTAP GetInfo rejected
        if (ins === 0xa4 && apdu[4] === 11) return new Uint8Array([0x90, 0x00]); // PIV_AID
        if (ins === 0xcb) return new Uint8Array([0x6a, 0x82]); // empty 9a cert
        return new Uint8Array([0x6d, 0x00]);
      },
    });
    const probed = await card.probe();
    assert.deepEqual(probed, {piv: true, fido2: false, state: 'ready', default_slot_occupied: false});
  }
});

test('PivCard.certificate accepts PIV object without optional 0x71 compression tag', async () => {
  const sample = await makeTestPkiCa('NoCompTag', 0);
  const der = new Uint8Array(sample.cert.toSchema().toBER(false));
  const tlvNo71 = tlv(0x53, tlv(0x70, der));
  const card = new PivCard({
    transmit: async apdu => {
      if (apdu[1] === 0xcb) return concat(tlvNo71, new Uint8Array([0x90, 0x00]));
      return new Uint8Array([0x6d, 0x00]);
    },
  });
  const loaded = await card.certificate('9a');
  assert.deepEqual(loaded.der, der);
});

test('PivCard.probe keeps PIV ready when slot 9a has compressed or nonstandard certificate object', async () => {
  const sample = await makeTestPkiCa('CompressedCert', 0);
  const der = new Uint8Array(sample.cert.toSchema().toBER(false));
  const tlvCompressed = tlv(0x53, concat(tlv(0x70, der), tlv(0x71, new Uint8Array([0x01]))));
  const card = new PivCard({
    transmit: async apdu => {
      const ins = apdu[1];
      if (ins === 0xa4 && apdu[4] === 8) return new Uint8Array([0x6a, 0x82]);
      if (ins === 0xa4 && apdu[4] === 11) return new Uint8Array([0x90, 0x00]);
      if (ins === 0xcb) return concat(tlvCompressed, new Uint8Array([0x90, 0x00]));
      return new Uint8Array([0x6d, 0x00]);
    },
  });
  const probed = await card.probe();
  assert.deepEqual(probed, {piv: true, fido2: false, state: 'ready', default_slot_occupied: true});
});
