import {CANOKEY_FILTER, CanoKeyChannel, PivCard} from './transport.js';

export class CardRegistry {
  constructor() {
    this.records = new Map();
    this.identities = new Map();
  }
  supported() {
    return !!(globalThis.isSecureContext && navigator.usb && globalThis.crypto?.subtle);
  }
  async enumerate(probe = true, force = false) {
    if (!this.supported()) return [];
    const devices = (await navigator.usb.getDevices()).filter(
      device => device.vendorId === CANOKEY_FILTER.vendorId && device.productId === CANOKEY_FILTER.productId,
    );
    const present = new Set();
    for (const device of devices) {
      let record = [...this.records.values()].find(item => item.device === device);
      const identity = device.serialNumber ? `${device.vendorId}:${device.productId}:${device.serialNumber}` : null;
      if (!record && identity) record = this.records.get(this.identities.get(identity));
      if (!record) {
        record = {
          id: 'webusb:' + crypto.randomUUID(),
          name: device.productName || 'USB 智能卡',
          transport: 'usb',
          platform: 'browser',
          source: 'webusb',
          state: 'unavailable',
          piv: false,
          fido2: false,
          error: '',
          device,
        };
        this.records.set(record.id, record);
        if (identity) this.identities.set(identity, record.id);
      }
      if (record.device !== device) record.state = 'unavailable';
      record.device = device;
      present.add(record.id);
      if (probe && (force || record.state !== 'ready')) {
        for (let attempt = 0; attempt < 2; attempt += 1) {
          const channel = new CanoKeyChannel(device);
          try {
            await channel.open();
            Object.assign(record, await new PivCard(channel).probe(), {error: ''});
            break;
          } catch (error) {
            record.state = 'unavailable';
            record.piv = false;
            record.error = error?.message || '无法读取 USB 智能卡';
            if (attempt === 0) await new Promise(resolve => setTimeout(resolve, 300));
          } finally {
            await channel.close();
          }
        }
      }
    }
    for (const record of this.records.values()) {
      if (!present.has(record.id)) record.state = 'disconnected';
    }
    return [...this.records.values()]
      .filter(record => present.has(record.id))
      .map(({device, ...record}) => record);
  }
  async requestDevice() {
    if (!this.supported()) throw new Error('此浏览器不支持 WebUSB，请使用支持它的 Chrome / Edge，或连接本机读卡工具');
    let device;
    try {
      device = await navigator.usb.requestDevice({
        filters: [{vendorId: CANOKEY_FILTER.vendorId, productId: CANOKEY_FILTER.productId}],
      });
    } catch (error) {
      if (error?.name === 'NotFoundError') {
        throw new Error('未选择 USB 智能卡（若浏览器弹窗中未列出设备，请确认支持 WebUSB 接口的智能卡已插好，或直接改用已连接的本机助手）');
      }
      throw error;
    }
    const existing = [...this.records.values()].find(item => item.device === device);
    if (existing) existing.state = 'unavailable';
    await this.enumerate(true, true);
    const record = [...this.records.values()].find(item => item.device === device);
    if (!record?.piv) throw new Error(record?.error || '此设备尚未提供可用的 PIV WebUSB 介面，请检查卡片设置或关闭占用该卡的其他网页/工具后重试');
    return record.id;
  }
  channel(id) {
    const record = this.records.get(id);
    if (!record || record.state === 'disconnected') throw new Error('USB 智能卡已断开，请重新连接');
    return {id, name: record.name, channel: new CanoKeyChannel(record.device)};
  }
}

export function createCardRegistry() {
  return new CardRegistry();
}
