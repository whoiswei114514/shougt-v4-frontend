import * as asn1 from 'asn1js';
import {
  Attribute, AuthenticatedSafe, CertBag, PFX, PKCS8ShroudedKeyBag, PrivateKeyInfo, SafeBag, SafeContents,
} from 'pkijs';
import {bytes, equal, utf8} from './bytes.js';
import {certificateFromPem, certificateKey, derEcdsa, encoded, fingerprint, verifySignature} from './crypto.js';

const SHROUDED_KEY_BAG_OID = '1.2.840.113549.1.12.10.1.2';
const KEY_BAG_OID = '1.2.840.113549.1.12.10.1.1';
const CERT_BAG_OID = '1.2.840.113549.1.12.10.1.3';
const LOCAL_KEY_ID_OID = '1.2.840.113549.1.9.21';
const FRIENDLY_NAME_OID = '1.2.840.113549.1.9.20';

function subtle() {
  if (!globalThis.crypto?.subtle) throw new Error('此浏览器不支持 WebCrypto，请使用 HTTPS');
  return globalThis.crypto.subtle;
}

export async function exportPkcs12({pkcs8Der, chainPem, password, friendlyName = 'shougt-admin'}) {
  if (typeof password !== 'string' || password.length < 8) {
    throw new Error('请设置至少 8 位的证书保护口令');
  }
  const certificates = chainPem.map(certificateFromPem);
  const keyBytes = bytes(pkcs8Der);
  const pwd = utf8(password);
  const localKeyId = globalThis.crypto.getRandomValues(new Uint8Array(8));
  try {
    const keyInfoSchema = asn1.fromBER(keyBytes);
    if (keyInfoSchema.offset !== keyBytes.length || keyInfoSchema.offset < 0) {
      throw new Error('私钥 ASN.1 格式不正确');
    }
    const keyBag = new PKCS8ShroudedKeyBag({parsedValue: new PrivateKeyInfo({schema: keyInfoSchema.result})});
    await keyBag.makeInternalValues({
      password: pwd,
      contentEncryptionAlgorithm: {name: 'AES-CBC', length: 256},
      hmacHashAlgorithm: 'SHA-256',
      iterationCount: 20000,
    });
    const keyAttrs = [
      new Attribute({type: LOCAL_KEY_ID_OID, values: [new asn1.OctetString({valueHex: localKeyId})]}),
      new Attribute({type: FRIENDLY_NAME_OID, values: [new asn1.BmpString({value: friendlyName})]}),
    ];
    const safeKey = new SafeContents({
      safeBags: [new SafeBag({bagId: SHROUDED_KEY_BAG_OID, bagValue: keyBag, bagAttributes: keyAttrs})],
    });
    const certBags = certificates.map((cert, index) => new SafeBag({
      bagId: CERT_BAG_OID,
      bagValue: new CertBag({parsedValue: cert.parsed}),
      bagAttributes: index === 0 ? keyAttrs : [],
    }));
    const safeCert = new SafeContents({safeBags: certBags});
    const pfx = new PFX({
      parsedValue: {
        integrityMode: 0,
        authenticatedSafe: new AuthenticatedSafe({
          parsedValue: {
            safeContents: [
              {privacyMode: 0, value: safeKey},
              {privacyMode: 1, value: safeCert},
            ],
          },
        }),
      },
    });
    await pfx.parsedValue.authenticatedSafe.makeInternalValues({
      safeContents: [
        {},
        {
          password: pwd,
          contentEncryptionAlgorithm: {name: 'AES-CBC', length: 256},
          hmacHashAlgorithm: 'SHA-256',
          iterationCount: 20000,
        },
      ],
    });
    await pfx.makeInternalValues({
      password: pwd,
      iterations: 20000,
      pbkdf2HashAlgorithm: 'SHA-256',
      hmacHashAlgorithm: 'SHA-256',
    });
    return new Uint8Array(pfx.toSchema().toBER(false));
  } finally {
    pwd.fill(0);
  }
}

export async function importPkcs12(p12Bytes, password) {
  if (typeof password !== 'string' || !password.length) throw new Error('请输入证书保护口令');
  const raw = bytes(p12Bytes);
  const pwd = utf8(password);
  let pkcs8Bytes = null;
  try {
    const parsedAsn1 = asn1.fromBER(raw);
    if (parsedAsn1.offset !== raw.length || parsedAsn1.offset < 0) throw new Error('PKCS#12 文件格式不正确');
    const pfx = new PFX({schema: parsedAsn1.result});
    await pfx.parseInternalValues({password: pwd, checkIntegrity: true}).catch(() => {
      throw new Error('证书保护口令错误或文件已损坏');
    });
    const rawSafeList = pfx.parsedValue?.authenticatedSafe?.safeContents;
    if (!Array.isArray(rawSafeList) || !rawSafeList.length) throw new Error('PKCS#12 文件内容为空');
    await pfx.parsedValue.authenticatedSafe.parseInternalValues({
      safeContents: rawSafeList.map(item => (item.contentType === '1.2.840.113549.1.7.6' ? {password: pwd} : {})),
    }).catch(() => {
      throw new Error('证书保护口令错误或无法解密内容');
    });
    const safeContents = pfx.parsedValue?.authenticatedSafe?.parsedValue?.safeContents || [];

    const certs = [];
    let keyInfo = null;
    for (const sc of safeContents) {
      const bags = sc.value?.safeBags || [];
      for (const bag of bags) {
        if (bag.bagId === CERT_BAG_OID && bag.bagValue?.parsedValue) {
          const der = encoded(bag.bagValue.parsedValue.toSchema());
          certs.push({der, parsed: bag.bagValue.parsedValue});
        } else if (bag.bagId === SHROUDED_KEY_BAG_OID && !keyInfo) {
          await bag.bagValue.parseInternalValues({password: pwd}).catch(() => {
            throw new Error('私钥解密失败，请核对口令');
          });
          keyInfo = bag.bagValue.parsedValue;
        } else if (bag.bagId === KEY_BAG_OID && !keyInfo) {
          keyInfo = bag.bagValue.parsedValue;
        }
      }
    }
    if (!keyInfo || !certs.length) throw new Error('PKCS#12 文件中缺少私钥或证书');
    pkcs8Bytes = new Uint8Array(keyInfo.toSchema().toBER(false));
    const algId = keyInfo.privateKeyAlgorithm.algorithmId;
    let importAlg;
    let signAlg;
    if (algId === '1.2.840.10045.2.1') {
      importAlg = {name: 'ECDSA', namedCurve: 'P-384'};
      signAlg = {name: 'ECDSA', hash: 'SHA-384'};
    } else if (algId === '1.2.840.113549.1.1.1') {
      importAlg = {name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-384'};
      signAlg = {name: 'RSASSA-PKCS1-v1_5'};
    } else {
      throw new Error('仅支持 P-384 或 RSA 私钥');
    }
    const privateKey = await subtle().importKey('pkcs8', pkcs8Bytes, importAlg, false, ['sign']);
    const sign = async message => {
      const rawSig = new Uint8Array(await subtle().sign(signAlg, privateKey, message));
      return algId === '1.2.840.10045.2.1' ? derEcdsa(rawSig, 48) : rawSig;
    };

    const probe = globalThis.crypto.getRandomValues(new Uint8Array(32));
    const probeSig = await sign(probe);
    let leaf = null;
    let leafKeyInfo = null;
    for (const cert of certs) {
      try {
        const candidateKey = await certificateKey(cert);
        await verifySignature(candidateKey, probeSig, probe);
        leaf = cert;
        leafKeyInfo = candidateKey;
        break;
      } catch (_) { /* continue */ }
    }
    if (!leaf) throw new Error('PKCS#12 中的私钥与任何证书均不匹配');
    const leafFp = await fingerprint(leaf);
    const others = [];
    for (const cert of certs) {
      if (await fingerprint(cert) !== leafFp) others.push(cert);
    }
    return {
      certificate: leaf,
      extraCertificates: others,
      keyInfo: leafKeyInfo,
      fingerprint: leafFp,
      sign,
    };
  } finally {
    pwd.fill(0);
    pkcs8Bytes?.fill(0);
  }
}
