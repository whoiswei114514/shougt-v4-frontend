import {CanoKeyChannel, CANOKEY_FILTER, PivCard} from './transport.js';
import {WebPivCeremony} from './ceremony.js';
import {
  deletePendingKey, generateBrowserKey, hasPendingKey, importCaPkcs12ToVault,
  installBrowserCert, listCaEntries, removeCaEntry, signWithBrowserCa,
} from './browserCeremony.js';

class CardRegistry {
  constructor() { this.records = new Map(); this.identities = new Map(); }
  supported() { return !!(globalThis.isSecureContext && navigator.usb && globalThis.crypto?.subtle); }
  async enumerate(probe = true) {
    if (!this.supported()) return [];
    const devices = (await navigator.usb.getDevices()).filter(device => device.vendorId === CANOKEY_FILTER.vendorId && device.productId === CANOKEY_FILTER.productId);
    const present = new Set();
    for (const device of devices) {
      let record = [...this.records.values()].find(record => record.device === device);
      const identity = device.serialNumber ? `${device.vendorId}:${device.productId}:${device.serialNumber}` : null;
      if (!record && identity) record = this.records.get(this.identities.get(identity));
      if (!record) {
        record = {id: 'webusb:' + crypto.randomUUID(), name: device.productName || 'CanoKey', transport: 'usb',
          platform: 'browser', source: 'webusb', state: 'unavailable', piv: false, fido2: false, device};
        this.records.set(record.id, record);
        if (identity) this.identities.set(identity, record.id);
      }
      if (record.device !== device) record.state = 'unavailable';
      record.device = device; present.add(record.id);
      if (probe && record.state !== 'ready') {
        const channel = new CanoKeyChannel(device);
        try { await channel.open(); Object.assign(record, await new PivCard(channel).probe()); }
        catch (_) { record.state = 'unavailable'; }
        finally { await channel.close(); }
      }
    }
    for (const record of this.records.values()) if (!present.has(record.id)) record.state = 'disconnected';
    return [...this.records.values()].filter(record => present.has(record.id)).map(({device, ...record}) => record);
  }
  async requestDevice() {
    if (!this.supported()) throw new Error('此浏览器不支持 WebUSB，请使用支持它的 Chrome / Edge，或连接本机读卡工具');
    const device = await navigator.usb.requestDevice({filters: [CANOKEY_FILTER]});
    await this.enumerate(true);
    const record = [...this.records.values()].find(record => record.device === device);
    if (!record?.piv) throw new Error('此设备尚未提供可用的 PIV WebUSB 介面，请检查卡片设置或连接本机工具');
    return record.id;
  }
  channel(id) {
    const record = this.records.get(id);
    if (!record || record.state === 'disconnected') throw new Error('USB 智能卡已断开，请重新连接');
    return {id, name: record.name, channel: new CanoKeyChannel(record.device)};
  }
}
const registry = new CardRegistry();
window.ShouWebPiv = {
  supported: () => registry.supported(),
  browserSupported: () => !!(globalThis.isSecureContext && globalThis.crypto?.subtle),
  enumerate: probe => registry.enumerate(probe),
  requestDevice: () => registry.requestDevice(),
  channel: id => registry.channel(id),
  createCeremony: options => new WebPivCeremony(options),
  generateBrowserKey,
  installBrowserCert,
  signWithBrowserCa,
  importCaPkcs12ToVault,
  listCaEntries,
  removeCaEntry,
  hasPendingKey,
  deletePendingKey,
};
