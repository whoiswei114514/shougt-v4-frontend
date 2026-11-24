import {bytes, concat, elements, equal, unhex, tlv, valueOf} from './bytes.js';
import {ALGORITHMS, CLIENT_SLOTS, blockCipher, generatedPublicKey, parseCertificate, sha, verifySignature} from './crypto.js';

// CanoKey's documented vendor APDU protocol, separate from the protected CCID interface.
// https://github.com/canokeys/canokey-core/blob/8b1681468ec29fd90990efa4b37f61699e83699a/interfaces/USB/class/webusb/webusb.c
export const CANOKEY_FILTER = {vendorId: 0x20a0, productId: 0x42d4, classCode: 0xff};
export const PIV_AID = unhex('a000000308000010000100');
const FIDO_AID = unhex('a0000006472f0001');
const OBJECTS = {'9a': 0x5fc105, '9c': 0x5fc10a, '9d': 0x5fc10b, '9e': 0x5fc101,
  ...Object.fromEntries(Array.from({length: 20}, (_, index) => [(0x82 + index).toString(16), 0x5fc10d + index]))};
const delay = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds));
export class PivStatusError extends Error {
  constructor(ins, status) {
    super(`PIV 指令 ${ins.toString(16)} 返回 ${status.toString(16)}，操作已停止`);
    this.ins = ins; this.status = status;
  }
}
export class CanoKeyChannel {
  constructor(device, {timeout = 90000, pollInterval = 100} = {}) {
    this.device = device; this.timeout = timeout; this.pollInterval = pollInterval;
    this.interfaceNumber = 1; this.claimed = false; this.tainted = false;
  }
  async timed(operation, deadline) {
    let timer;
    try {
      return await Promise.race([operation, new Promise((_, reject) => {
        timer = setTimeout(() => { this.tainted = true; reject(new Error('USB 指令超时，卡片状态未知；已停止操作，请勿重复生成密钥')); }, Math.max(1, deadline - Date.now()));
      })]);
    } finally { clearTimeout(timer); }
  }
  async open() {
    if (this.device.vendorId !== CANOKEY_FILTER.vendorId || this.device.productId !== CANOKEY_FILTER.productId)
      throw new Error('此设备不在支持的 WebUSB 智能卡列表内');
    const deadline = Date.now() + 15000;
    await this.timed(this.device.open(), deadline);
    if (!this.device.configuration) await this.timed(this.device.selectConfiguration(1), deadline);
    const ifaces = this.device.configuration?.interfaces || [];
    const descriptor = ifaces.find(
      item => item.interfaceNumber === 1 && item.alternates?.length > 0 && item.alternates.every(alt => alt.interfaceClass === 0xff),
    ) || ifaces.find(
      item => item.alternates?.length > 0 && item.alternates.every(alt => alt.interfaceClass === 0xff),
    );
    if (!descriptor)
      throw new Error('此卡没有提供受支持的 WebUSB APDU 介面，请使用本机读卡工具');
    this.interfaceNumber = descriptor.interfaceNumber;
    try {
      await this.timed(this.device.claimInterface(this.interfaceNumber), deadline);
    } catch (error) {
      if (error?.name === 'NetworkError' || error?.name === 'SecurityError' || /claim/i.test(error?.message || '')) {
        throw new Error(`无法独占打开 WebUSB 接口（可能正被其他浏览器标签页或本机读卡工具占用）：${error?.message || error?.name || '接口被占用'}`);
      }
      throw error;
    }
    this.claimed = true;
  }
  async close() {
    if (this.claimed) {
      try { await this.timed(this.device.releaseInterface(this.interfaceNumber), Date.now() + 3000); } catch (_) {}
      this.claimed = false;
    }
    try { await this.timed(this.device.close(), Date.now() + 3000); } catch (_) {}
  }
  async transmit(apdu) {
    if (!this.claimed || this.tainted) throw new Error('USB 连接不可用，请重新连接并核对卡片状态');
    const setup = request => ({requestType: 'vendor', recipient: 'interface', request, value: 0, index: this.interfaceNumber});
    const deadline = Date.now() + this.timeout;
    const result = await this.timed(this.device.controlTransferOut(setup(0), apdu), deadline);
    if (result.status !== 'ok' || result.bytesWritten !== apdu.length) throw new Error('USB 指令发送失败；已停止操作');
    while (true) {
      const status = await this.timed(this.device.controlTransferIn(setup(2), 1), deadline);
      if (status.status !== 'ok' || !status.data || status.data.byteLength !== 1) throw new Error('USB 卡片状态读取失败');
      const code = status.data.getUint8(0);
      if (code === 0) break;
      if (code !== 1) throw new Error('智能卡正被其他工具使用，请关闭占用工具后核对卡片状态');
      if (Date.now() >= deadline) { this.tainted = true; throw new Error('USB 指令超时；已停止操作，请勿重复生成密钥'); }
      await delay(this.pollInterval);
    }
    const response = await this.timed(this.device.controlTransferIn(setup(1), 1500), deadline);
    if (response.status !== 'ok' || !response.data || response.data.byteLength < 2 || response.data.byteLength > 1500)
      throw new Error('USB 卡片响应不完整；已停止操作');
    return new Uint8Array(response.data.buffer, response.data.byteOffset, response.data.byteLength).slice();
  }
}
export class PivCard {
  constructor(channel) { this.channel = channel; }
  async select() { await this.command(0xa4, 4, 0, PIV_AID); }
  async command(ins, p1, p2, data = new Uint8Array(), {missing = false, cla = 0} = {}) {
    if (data.length > 65536) throw new Error('PIV 指令过大');
    let output = new Uint8Array(), continuations = 0;
    const chunks = [];
    for (let offset = 0; offset < data.length; offset += 240) chunks.push(data.slice(offset, offset + 240));
    if (!chunks.length) chunks.push(new Uint8Array());
    for (let index = 0; index < chunks.length; index++) {
      const last = index === chunks.length - 1, chunk = chunks[index];
      let apdu = concat(new Uint8Array([last ? cla : cla | 0x10, ins, p1, p2]),
        chunk.length ? concat(new Uint8Array([chunk.length]), chunk) : new Uint8Array(), last ? new Uint8Array([0]) : new Uint8Array());
      let response;
      try { response = await this.channel.transmit(apdu); } finally { apdu.fill(0); chunk.fill(0); }
      if (response.length < 2) throw new Error('PIV 响应不完整');
      let status = response.at(-2) * 256 + response.at(-1);
      output = concat(output, response.subarray(0, -2));
      while ((status & 0xff00) === 0x6100) {
        if (++continuations > 256 || output.length >= 65536) throw new Error('PIV 响应超出大小或续取次数限制');
        apdu = new Uint8Array([0, 0xc0, 0, 0, status & 255]);
        try { response = await this.channel.transmit(apdu); } finally { apdu.fill(0); }
        if (response.length < 2) throw new Error('PIV 响应不完整');
        status = response.at(-2) * 256 + response.at(-1);
        output = concat(output, response.subarray(0, -2));
      }
      if (status !== 0x9000) {
        if (missing && status === 0x6a82) return null;
        throw new PivStatusError(ins, status);
      }
      if (output.length > 65536) throw new Error('PIV 响应超出大小限制');
    }
    return output;
  }
  async certificate(slot) {
    if (!(slot in OBJECTS)) throw new Error('无效的 PIV 证书槽位');
    const object = OBJECTS[slot], id = new Uint8Array([object >>> 16, object >>> 8 & 255, object & 255]);
    const response = await this.command(0xcb, 0x3f, 0xff, tlv(0x5c, id), {missing: true});
    if (response === null) return null;
    const contents = valueOf(response, 0x53);
    const compItems = elements(contents).filter(item => item.tag === 0x71);
    if (compItems.length > 1) throw new Error('卡片返回了重复的证书压缩标记');
    const compression = compItems.length === 1 ? compItems[0].data : new Uint8Array([0]);
    if (!equal(compression, new Uint8Array([0]))) throw new Error('此卡的压缩证书格式不受支持，已停止操作');
    return parseCertificate(valueOf(contents, 0x70));
  }
  async verifyPin(pin) {
    if (!/^[0-9]{6,8}$/.test(pin)) throw new Error('PIV PIN 必须为 6–8 位数字');
    const value = new Uint8Array(8).fill(255); value.set(new TextEncoder().encode(pin));
    try { await this.command(0x20, 0, 0x80, value); } finally { value.fill(0); }
  }
  async authenticateManagement(secret, scheme) {
    const key = unhex(secret), ident = {tdes: 3, aes128: 8, aes192: 10, aes256: 12}[scheme];
    const size = {tdes: 24, aes128: 16, aes192: 24, aes256: 32}[scheme], blockSize = scheme === 'tdes' ? 8 : 16;
    let witness, challenge, expected, payload;
    try {
      if (!ident || key.length !== size) throw new Error('管理密钥长度与算法不匹配');
      const encrypted = valueOf(valueOf(await this.command(0x87, ident, 0x9b, tlv(0x7c, tlv(0x80, new Uint8Array()))), 0x7c), 0x80);
      if (encrypted.length !== blockSize) throw new Error('卡片返回了无效的管理密钥挑战');
      witness = blockCipher(scheme, key, encrypted, true);
      challenge = globalThis.crypto.getRandomValues(new Uint8Array(blockSize));
      payload = tlv(0x7c, concat(tlv(0x80, witness), tlv(0x81, challenge)));
      const response = valueOf(valueOf(await this.command(0x87, ident, 0x9b, payload), 0x7c), 0x82);
      expected = blockCipher(scheme, key, challenge);
      if (!equal(response, expected)) throw new Error('PIV 管理密钥双向认证失败');
    } finally {
      key.fill(0); witness?.fill(0); challenge?.fill(0); expected?.fill(0); payload?.fill(0);
    }
  }
  async generate(name, slot) {
    if (!CLIENT_SLOTS.includes(slot) || !ALGORITHMS.includes(name)) throw new Error('目标槽位或算法不正确');
    const ident = {'P-384': 0x14, 'RSA-3072': 0x05, 'RSA-2048': 0x07}[name];
    return generatedPublicKey(name, await this.command(0x47, 0, parseInt(slot, 16), tlv(0xac, tlv(0x80, new Uint8Array([ident])))));
  }
  async generatePreferred(slot, allowed = ALGORITHMS, beforeGenerate = () => {}) {
    for (const name of ALGORITHMS.filter(name => allowed.includes(name))) {
      await beforeGenerate(name);
      try { return await this.generate(name, slot); }
      catch (error) {
        if (!(error instanceof PivStatusError) || error.ins !== 0x47 || ![0x6a80, 0x6a81].includes(error.status)) throw error;
      }
    }
    throw new Error('此 PIVApplet 不支持任务允许的 P-384 或 RSA 算法');
  }
  async sign(slot, key, message) {
    let digest = await sha(message, 'SHA-384');
    if (key.name.startsWith('RSA-')) {
      const info = concat(unhex('3041300d060960864801650304020205000430'), digest);
      digest = concat(new Uint8Array([0, 1]), new Uint8Array(key.size / 8 - info.length - 3).fill(255), new Uint8Array([0]), info);
    }
    const ident = {'P-384': 0x14, 'RSA-2048': 0x07, 'RSA-3072': 0x05, 'RSA-4096': 0x16}[key.name];
    const response = await this.command(0x87, ident, parseInt(slot, 16), tlv(0x7c, concat(tlv(0x82, new Uint8Array()), tlv(0x81, digest))));
    const signature = valueOf(valueOf(response, 0x7c), 0x82);
    await verifySignature(key, signature, message);
    return signature;
  }
  async writeCertificate(slot, certificate) {
    const old = await this.certificate(slot);
    if (old) {
      if (equal(old.der, certificate.der)) return;
      throw new Error(`槽位 ${slot} 已有不同证书，禁止覆盖`);
    }
    const object = OBJECTS[slot];
    const contents = concat(tlv(0x5c, new Uint8Array([object >>> 16, object >>> 8 & 255, object & 255])),
      tlv(0x53, concat(tlv(0x70, certificate.der), tlv(0x71, new Uint8Array([0])), tlv(0xfe, new Uint8Array()))));
    await this.command(0xdb, 0x3f, 0xff, contents);
    const readback = await this.certificate(slot);
    if (!readback || !equal(readback.der, certificate.der)) throw new Error('证书回读不一致，禁止激活');
  }
  async ensureDiscoveryObjects() {
    const initialized = [];
    const objects = [
      {
        name: 'chuid',
        id: new Uint8Array([0x5f, 0xc1, 0x02]),
        build: () => concat(
          tlv(0x30, unhex('d4e739da739ced39ce739d836858210842108421c84210c3eb')),
          tlv(0x34, globalThis.crypto.getRandomValues(new Uint8Array(16))),
          tlv(0x35, new TextEncoder().encode('20361231')),
          tlv(0x3e, new Uint8Array()),
          tlv(0xfe, new Uint8Array()),
        ),
      },
      {
        name: 'ccc',
        id: new Uint8Array([0x5f, 0xc1, 0x07]),
        build: () => concat(
          tlv(0xf0, concat(unhex('a000000116ff02'), globalThis.crypto.getRandomValues(new Uint8Array(14)))),
          tlv(0xf1, new Uint8Array([0x21])), tlv(0xf2, new Uint8Array([0x21])),
          tlv(0xf3, new Uint8Array()), tlv(0xf4, new Uint8Array([0])), tlv(0xf5, new Uint8Array([0x10])),
          tlv(0xf6, new Uint8Array()), tlv(0xf7, new Uint8Array()), tlv(0xfa, new Uint8Array()),
          tlv(0xfb, new Uint8Array()), tlv(0xfc, new Uint8Array()), tlv(0xfd, new Uint8Array()),
          tlv(0xfe, new Uint8Array()),
        ),
      },
    ];
    for (const obj of objects) {
      const existing = await this.command(0xcb, 0x3f, 0xff, tlv(0x5c, obj.id), {missing: true});
      if (existing !== null) continue;
      try {
        await this.command(0xdb, 0x3f, 0xff, concat(tlv(0x5c, obj.id), tlv(0x53, obj.build())));
        initialized.push(obj.name);
      } catch (error) {
        if (!(error instanceof PivStatusError) || ![0x6a80, 0x6a82].includes(error.status)) throw error;
      }
    }
    return initialized;
  }
  async probe() {
    let fido2 = false;
    try {
      await this.command(0xa4, 4, 0, FIDO_AID);
      const info = await this.command(0x10, 0, 0, new Uint8Array([4]), {cla: 0x80});
      if (info[0] === 0) {
        const versions = decodeCbor(info.subarray(1)).get(1);
        fido2 = Array.isArray(versions) && versions.some(version => typeof version === 'string' && version.startsWith('FIDO_2_'));
      }
    } catch (error) {
      if (!(error instanceof PivStatusError) && !error?.message?.startsWith('FIDO2 GetInfo')) throw error;
    }
    try {
      await this.select();
    } catch (error) {
      if (!(error instanceof PivStatusError) || error.status !== 0x6a82) throw error;
      return {piv: false, fido2, state: fido2 ? 'fido_only' : 'unsupported'};
    }
    let occupied = false;
    try {
      occupied = !!(await this.certificate('9a'));
    } catch (error) {
      if (error instanceof PivStatusError || /USB|超时|占用|连接不可用/.test(error?.message || '')) throw error;
      occupied = true;
    }
    return {piv: true, fido2, state: 'ready', default_slot_occupied: occupied};
  }
}
// A bounded decoder for CTAP GetInfo, including FIDO2Applet's U2F_V2 SELECT response.
function decodeCbor(data) {
  let offset = 0, items = 0;
  const byte = () => { if (offset >= data.length) throw new Error('FIDO2 GetInfo 响应不完整'); return data[offset++]; };
  const read = depth => {
    if (depth > 8 || ++items > 512) throw new Error('FIDO2 GetInfo 响应过大');
    const header = byte(), major = header >>> 5, rest = header & 31;
    let size = rest;
    if (rest >= 24 && rest <= 27) {
      size = 0;
      for (let index = 0; index < 2 ** (rest - 24); index++) size = size * 256 + byte();
      if (!Number.isSafeInteger(size)) throw new Error('FIDO2 GetInfo 整数过大');
    } else if (rest > 27) throw new Error('FIDO2 GetInfo 使用了不支持的 CBOR 格式');
    if (major === 0) return size;
    if (major === 1) return -size - 1;
    if (major === 2 || major === 3) {
      if (offset + size > data.length) throw new Error('FIDO2 GetInfo 响应不完整');
      const result = data.slice(offset, offset + size); offset += size;
      return major === 2 ? result : new TextDecoder().decode(result);
    }
    if (major === 4) {
      if (size > 128) throw new Error('FIDO2 GetInfo 数组过大');
      return Array.from({length: size}, () => read(depth + 1));
    }
    if (major === 5) {
      if (size > 128) throw new Error('FIDO2 GetInfo 映射过大');
      const map = new Map();
      for (let index = 0; index < size; index++) map.set(read(depth + 1), read(depth + 1));
      return map;
    }
    if (major === 7 && rest <= 23) return rest === 20 ? false : rest === 21 ? true : null;
    throw new Error('FIDO2 GetInfo 使用了不支持的 CBOR 类型');
  };
  const result = read(0);
  if (offset !== data.length || !(result instanceof Map)) throw new Error('FIDO2 GetInfo 格式不正确');
  return result;
}
