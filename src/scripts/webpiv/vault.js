import {base64, unbase64, utf8} from './bytes.js';

const DB_NAME = 'shou-browser-piv-v1';
const DB_VERSION = 1;
const STORE_PENDING = 'pendingKeys';
const STORE_CA = 'caVault';

const memoryStores = {
  [STORE_PENDING]: new Map(),
  [STORE_CA]: new Map(),
};

function openDb() {
  if (!globalThis.indexedDB) return Promise.resolve(null);
  return new Promise((resolve, reject) => {
    const req = globalThis.indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_PENDING)) {
        db.createObjectStore(STORE_PENDING, {keyPath: 'issuance_id'});
      }
      if (!db.objectStoreNames.contains(STORE_CA)) {
        db.createObjectStore(STORE_CA, {keyPath: 'fingerprint'});
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error || new Error('无法打开浏览器安全存储'));
  });
}

async function storePut(storeName, keyField, value) {
  const db = await openDb();
  if (!db) {
    memoryStores[storeName].set(value[keyField], value);
    return;
  }
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(value);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error || new Error('写入浏览器安全存储失败')); };
  });
}

async function storeGet(storeName, key) {
  const db = await openDb();
  if (!db) return memoryStores[storeName].get(key) || null;
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).get(key);
    req.onsuccess = () => resolve(req.result || null);
    req.onerror = () => reject(req.error || new Error('读取浏览器安全存储失败'));
    tx.oncomplete = () => db.close();
  });
}

async function storeDelete(storeName, key) {
  const db = await openDb();
  if (!db) { memoryStores[storeName].delete(key); return; }
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).delete(key);
    tx.oncomplete = () => { db.close(); resolve(); };
    tx.onerror = () => { db.close(); reject(tx.error || new Error('清理浏览器安全存储失败')); };
  });
}

async function storeAll(storeName) {
  const db = await openDb();
  if (!db) return [...memoryStores[storeName].values()];
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const req = tx.objectStore(storeName).getAll();
    req.onsuccess = () => resolve(req.result || []);
    req.onerror = () => reject(req.error || new Error('读取浏览器证书列表失败'));
    tx.oncomplete = () => db.close();
  });
}

async function deriveAesKey(passphrase, salt, usages) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) throw new Error('此浏览器不支持 WebCrypto，请使用 HTTPS');
  const pwdBytes = utf8(passphrase);
  try {
    const baseKey = await subtle.importKey('raw', pwdBytes, 'PBKDF2', false, ['deriveKey']);
    return await subtle.deriveKey(
      {name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-384'},
      baseKey,
      {name: 'AES-GCM', length: 256},
      false,
      usages,
    );
  } finally {
    pwdBytes.fill(0);
  }
}

export async function encryptSecretBytes(plainBytes, passphrase) {
  const salt = globalThis.crypto.getRandomValues(new Uint8Array(16));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const aesKey = await deriveAesKey(passphrase, salt, ['encrypt']);
  const cipher = new Uint8Array(await globalThis.crypto.subtle.encrypt({name: 'AES-GCM', iv}, aesKey, plainBytes));
  return {cipher: base64(cipher), salt: base64(salt), iv: base64(iv)};
}

export async function decryptSecretBytes(record, passphrase) {
  const aesKey = await deriveAesKey(passphrase, unbase64(record.salt), ['decrypt']);
  try {
    return new Uint8Array(await globalThis.crypto.subtle.decrypt(
      {name: 'AES-GCM', iv: unbase64(record.iv)},
      aesKey,
      unbase64(record.cipher),
    ));
  } catch (_) {
    throw new Error('口令不正确或本地加密密钥数据已损坏');
  }
}

export async function savePendingKey({issuance_id, pkcs8Der, algorithm, spki_sha256, passphrase}) {
  const encrypted = await encryptSecretBytes(pkcs8Der, passphrase);
  await storePut(STORE_PENDING, 'issuance_id', {
    issuance_id,
    algorithm,
    spki_sha256,
    ...encrypted,
    created_at: new Date().toISOString(),
  });
}

export async function hasPendingKey(issuance_id) {
  return Boolean(await storeGet(STORE_PENDING, issuance_id));
}

export async function loadPendingKey(issuance_id, passphrase) {
  const record = await storeGet(STORE_PENDING, issuance_id);
  if (!record) throw new Error('当前浏览器中未找到该任务的暂存私钥，请确认在同一设备与浏览器操作');
  const pkcs8Der = await decryptSecretBytes(record, passphrase);
  return {pkcs8Der, algorithm: record.algorithm, spki_sha256: record.spki_sha256};
}

export async function deletePendingKey(issuance_id) {
  await storeDelete(STORE_PENDING, issuance_id);
}

export async function saveCaEntry({fingerprint, cn, algorithm, expires_at, label, p12Bytes, passphrase}) {
  const encrypted = await encryptSecretBytes(p12Bytes, passphrase);
  await storePut(STORE_CA, 'fingerprint', {
    fingerprint,
    cn,
    algorithm,
    expires_at,
    label: label || `${cn} (${algorithm})`,
    ...encrypted,
    updated_at: new Date().toISOString(),
  });
}

export async function listCaEntries() {
  const items = await storeAll(STORE_CA);
  return items.map(({cipher, salt, iv, ...meta}) => meta);
}

export async function loadCaEntry(fingerprint, passphrase) {
  const record = await storeGet(STORE_CA, fingerprint);
  if (!record) throw new Error('浏览器 CA 库中未找到指定证书');
  return decryptSecretBytes(record, passphrase);
}

export async function removeCaEntry(fingerprint) {
  await storeDelete(STORE_CA, fingerprint);
}
