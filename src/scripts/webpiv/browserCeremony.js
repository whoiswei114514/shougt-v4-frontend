import {base64, hex, pem} from './bytes.js';
import {
  buildChain, certificateFromPem, derEcdsa, fingerprint, issuerMatches,
  makeCertificate, makeCsr, publicKeyInfo, requireActive, sha, validateInstallation, validatedCsr, writeProof,
} from './crypto.js';
import {exportPkcs12, importPkcs12} from './pkcs12.js';
import {
  deletePendingKey, hasPendingKey, listCaEntries, loadCaEntry, loadPendingKey,
  removeCaEntry, saveCaEntry, savePendingKey,
} from './vault.js';

function subtle() {
  if (!globalThis.crypto?.subtle) throw new Error('此浏览器不支持 WebCrypto，请使用 HTTPS');
  return globalThis.crypto.subtle;
}

async function generateWebCryptoPair(allowed = ['P-384', 'RSA-3072', 'RSA-2048']) {
  const order = ['P-384', 'RSA-3072', 'RSA-2048'].filter(item => allowed.includes(item));
  const preferred = order[0] || 'P-384';
  let keyPair;
  let signFn;
  if (preferred === 'P-384') {
    keyPair = await subtle().generateKey({name: 'ECDSA', namedCurve: 'P-384'}, true, ['sign', 'verify']);
    signFn = async tbs => derEcdsa(new Uint8Array(await subtle().sign({name: 'ECDSA', hash: 'SHA-384'}, keyPair.privateKey, tbs)), 48);
  } else {
    const size = Number(preferred.split('-')[1]);
    keyPair = await subtle().generateKey(
      {name: 'RSASSA-PKCS1-v1_5', modulusLength: size, publicExponent: new Uint8Array([1, 0, 1]), hash: 'SHA-384'},
      true,
      ['sign', 'verify'],
    );
    signFn = async tbs => new Uint8Array(await subtle().sign({name: 'RSASSA-PKCS1-v1_5'}, keyPair.privateKey, tbs));
  }
  const spkiDer = new Uint8Array(await subtle().exportKey('spki', keyPair.publicKey));
  const pkcs8Der = new Uint8Array(await subtle().exportKey('pkcs8', keyPair.privateKey));
  const keyInfo = await publicKeyInfo(spkiDer);
  return {keyInfo, pkcs8Der, signFn};
}

async function importPkcs8NonExtractable(pkcs8Der, algorithmName) {
  const isEc = algorithmName === 'P-384';
  const importAlg = isEc ? {name: 'ECDSA', namedCurve: 'P-384'} : {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384'};
  const privateKey = await subtle().importKey('pkcs8', pkcs8Der, importAlg, false, ['sign']);
  return async tbs => {
    const sig = new Uint8Array(await subtle().sign(isEc ? {name: 'ECDSA', hash: 'SHA-384'} : {name: 'RSASSA-PKCS1-v1_5'}, privateKey, tbs));
    return isEc ? derEcdsa(sig, 48) : sig;
  };
}

export async function generateBrowserKey({job, passphrase, algorithm = 'auto'}) {
  requireActive(job);
  if (job.state !== 'requested') throw new Error('任务阶段不允许生成密钥');
  if (typeof passphrase !== 'string' || passphrase.length < 8) {
    throw new Error('请设置至少 8 位的证书保护口令');
  }
  const allowed = algorithm === 'auto' ? (job.algorithms || ['P-384', 'RSA-3072', 'RSA-2048']) : [algorithm];
  const {keyInfo, pkcs8Der, signFn} = await generateWebCryptoPair(allowed);
  const spkiSha256 = hex(await sha(keyInfo.der));
  try {
    const csr = await makeCsr({...job, card: {slot: '9a'}}, keyInfo, signFn);
    await savePendingKey({
      issuance_id: job.issuance_id,
      pkcs8Der,
      algorithm: keyInfo.name,
      spki_sha256: spkiSha256,
      passphrase,
    });
    return {
      issuance_id: job.issuance_id,
      csr_pem: csr.pem,
      card: {
        reader: 'Browser WebCrypto',
        slot: '9a',
        algorithm: keyInfo.name,
        transport: 'browser',
        protocol: 'WebCrypto',
        platform: 'browser',
        on_card_generation: false,
        browser_keystore: true,
      },
    };
  } finally {
    pkcs8Der.fill(0);
  }
}

export async function installBrowserCert({job, passphrase, saveToCaVault = false, friendlyName}) {
  requireActive(job);
  if (job.state !== 'key_ready') throw new Error('任务尚未进入可安装阶段');
  const chainPem = job.chain_pem || job.signed_chain_pem;
  const normalizedJob = {...job, chain_pem: chainPem};
  const {leaf, chain, key} = await validateInstallation(normalizedJob);
  const {pkcs8Der, algorithm, spki_sha256} = await loadPendingKey(job.issuance_id, passphrase);
  try {
    if (hex(await sha(key.der)) !== spki_sha256) {
      throw new Error('已签发证书公钥与本浏览器暂存密钥不匹配');
    }
    const signFn = await importPkcs8NonExtractable(pkcs8Der, algorithm);
    const challenge = globalThis.crypto.getRandomValues(new Uint8Array(48));
    await signFn(challenge);
    const proofMsg = await writeProof(normalizedJob, leaf, chain);
    const proofSig = await signFn(proofMsg);
    const p12Bytes = await exportPkcs12({
      pkcs8Der,
      chainPem,
      password: passphrase,
      friendlyName: friendlyName || `shougt-${job.real_name || job.user_id}`,
    });
    const isCaCert = Boolean(!job.temporary && Array.isArray(job.roles) && (job.roles.includes('super_admin') || job.roles.includes('superadmin_admin')));
    if (saveToCaVault && isCaCert) {
      await saveCaEntry({
        fingerprint: await fingerprint(leaf),
        cn: job.real_name || String(job.user_id),
        algorithm,
        expires_at: leaf.parsed.notAfter.value.toISOString(),
        p12Bytes,
        passphrase,
      });
    }
    const filename = `shougt-${job.temporary ? 'temp-' : ''}${job.user_id}.p12`;
    return {
      p12Bytes,
      filename,
      isCaCert,
      receipt: {
        issuance_id: job.issuance_id,
        chain_pem: chainPem,
        proof: base64(proofSig),
        readback_verified: true,
        onsite_confirmed: true,
        card_slot: job.card?.slot || '9a',
      },
    };
  } finally {
    pkcs8Der.fill(0);
  }
}

export async function signWithBrowserCa({job, p12Bytes, fingerprint: caFp, passphrase}) {
  requireActive(job);
  if (job.state !== 'key_ready') throw new Error('请先确认目标公钥后再用 CA 签发');
  const raw = p12Bytes || await loadCaEntry(caFp, passphrase);
  const imported = await importPkcs12(raw, passphrase);
  const ca = imported.certificate;
  const trusted = new Set(await Promise.all((job.authorities || []).map(async item => fingerprint(certificateFromPem(item)))));
  if (!trusted.has(imported.fingerprint)) {
    throw new Error('所选 CA 证书不在本次签发任务的允许签发者列表内');
  }
  const csr = await validatedCsr(job);
  if (!issuerMatches(csr.key, imported.keyInfo)) {
    throw new Error('所选 CA 证书算法与目标公钥算法不匹配');
  }
  const chain = await buildChain(ca, job);
  const leaf = await makeCertificate(job, ca, chain, imported.sign);
  return {
    ...job,
    issuer_slot: 'p12',
    chain_pem: [leaf, ...chain].map(item => pem('CERTIFICATE', item.der)),
  };
}

export async function importCaPkcs12ToVault({p12Bytes, passphrase, label}) {
  const imported = await importPkcs12(p12Bytes, passphrase);
  const fp = imported.fingerprint;
  const cnAttr = imported.certificate.parsed.subject.typesAndValues.find(item => item.type === '2.5.4.3');
  const cn = cnAttr?.value?.valueBlock?.value || 'CA';
  await saveCaEntry({
    fingerprint: fp,
    cn,
    algorithm: imported.keyInfo.name,
    expires_at: imported.certificate.parsed.notAfter.value.toISOString(),
    label,
    p12Bytes,
    passphrase,
  });
  return {fingerprint: fp, cn, algorithm: imported.keyInfo.name, expires_at: imported.certificate.parsed.notAfter.value.toISOString()};
}

export {deletePendingKey, hasPendingKey, listCaEntries, removeCaEntry};
