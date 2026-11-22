import {base64, canonical, equal, pem} from './bytes.js';
import {
  ALGORITHMS, CLIENT_SLOTS, makeCsr, makeCertificate, selectCa, validateInstallation,
  writeProof, certificateKey, requireActive,
} from './crypto.js';
import {PivCard} from './transport.js';

export class WebPivCeremony {
  constructor({chooseCard, secret, confirm, chooseSlot, progress = () => {}, storage = globalThis.localStorage}) {
    this.chooseCard = chooseCard; this.secret = secret; this.confirm = confirm;
    this.chooseSlot = chooseSlot; this.progress = progress; this.storage = storage;
    this.operations = new Map(); this.busy = false;
  }
  markerKey(job) { return 'shou-piv-key-attempt:' + job.issuance_id; }
  marker(job) {
    try { return this.storage.getItem(this.markerKey(job)); }
    catch (_) { throw new Error('浏览器无法记录制卡状态，请启用本站存储后再开始'); }
  }
  mark(job, operationId, slot, name) {
    try { this.storage.setItem(this.markerKey(job), JSON.stringify({operation_id: operationId, slot, algorithm: name})); }
    catch (_) { throw new Error('浏览器无法记录制卡状态；尚未生成密钥'); }
  }
  finish(identifier) {
    try { this.storage.removeItem('shou-piv-key-attempt:' + identifier); } catch (_) {}
  }
  async locked(operation) {
    if (this.busy) throw new Error('另一项制卡操作正在进行');
    this.busy = true;
    try {
      if (globalThis.navigator?.locks)
        return await globalThis.navigator.locks.request('shou-piv-webusb', {ifAvailable: true}, lock => {
          if (!lock) throw new Error('另一个本站窗口正在使用智能卡，请先完成该操作');
          return operation();
        });
      return await operation();
    } finally { this.busy = false; }
  }
  async run(stage, job, options, operationId) {
    requireActive(job);
    const id = job.issuance_id + ':' + stage;
    const {reader, slot, ...fixedOptions} = options;
    const digest = canonical({job, options: fixedOptions, operationId});
    let record = this.operations.get(id);
    if (record && record.digest !== digest) throw new Error('制卡重试的任务或参数已改变，请先核对卡片状态');
    if (record?.result) return record.result;
    if (!record) {
      if (stage === 'generate' && this.marker(job)) throw new Error('此任务曾开始生成密钥。本页已失去原操作状态，禁止自动再次生成；请先核对卡片与签发任务');
      record = {digest}; this.operations.set(id, record);
    }
    return this.locked(async () => {
      if (stage === 'generate' && record.uncertain && !record.key)
        throw new Error('上次生成指令的卡片状态尚未确认，禁止重复生成密钥');
      const chosen = await this.chooseCard(stage, options.reader, job);
      if (record.key && record.deviceId !== chosen.id) throw new Error('请连接本次已生成公钥的原目标卡；不会重新生成密钥');
      const card = new PivCard(chosen.channel);
      try {
        await chosen.channel.open(); await card.select();
        if (stage === 'generate') record.result = await this.generate(card, chosen, job, options, operationId, record);
        else if (stage === 'sign') record.result = await this.sign(card, chosen, job, options);
        else if (stage === 'install') record.result = await this.install(card, chosen, job, options);
        else throw new Error('未知制卡阶段');
        return record.result;
      } finally { await chosen.channel.close(); }
    });
  }
  async generate(card, chosen, job, options, operationId, record) {
    if (job.state !== 'requested') throw new Error('任务阶段不允许生成密钥');
    let slot = record.slot || options.slot || '9a';
    if (!CLIENT_SLOTS.includes(slot)) throw new Error('无效的目标签名槽位');
    if (record.key) this.progress('继续完成本次已生成公钥的 CSR，不会重新生成密钥');
    while (!record.key) {
      while (await card.certificate(slot)) {
        let next;
        for (const candidate of CLIENT_SLOTS.slice(CLIENT_SLOTS.indexOf(slot) + 1)) {
          if (!await card.certificate(candidate)) { next = candidate; break; }
        }
        if (!next) throw new Error(`槽位 ${slot} 已有证书，没有可切换的空签名槽位；签发已停止`);
        this.progress(`槽位 ${slot} 已有证书，签发已停止`);
        if (!await this.chooseSlot({slot, next_slot: next})) throw new Error('已停止签发；已有证书未覆盖');
        slot = next;
      }
      if (!await this.confirm({stage: 'generate', name: chosen.name, slot, real_name: job.real_name, roles: job.roles,
        message: `确认槽位 ${slot} 没有需要保留的私钥，并用于本次制卡。空证书槽本身不能证明私钥槽为空。`}))
        throw new Error('已取消生成密钥');
      await card.authenticateManagement(await this.secret({kind: 'management', stage: 'generate', name: chosen.name, scheme: options.management_algorithm}), options.management_algorithm);
      requireActive(job);
      if (await card.certificate(slot)) continue;
      const allowed = options.algorithm === 'auto' ? job.algorithms : [options.algorithm];
      if (!Array.isArray(allowed) || !allowed.length || allowed.some(name => !job.algorithms.includes(name) || !ALGORITHMS.includes(name)))
        throw new Error('签发任务不允许指定算法');
      record.key = await card.generatePreferred(slot, allowed, name => {
        this.mark(job, operationId, slot, name);
        record.uncertain = true; record.slot = slot; record.deviceId = chosen.id;
        this.progress(`正在卡内生成 ${name} 密钥 · 槽位 ${slot}`);
      });
      record.uncertain = false;
    }
    await card.verifyPin(await this.secret({kind: 'pin', stage: 'generate', name: chosen.name}));
    requireActive(job);
    const csr = await makeCsr({...job, card: {slot}}, record.key, data => card.sign(slot, record.key, data));
    return {issuance_id: job.issuance_id, csr_pem: csr.pem, card: {
      reader: chosen.name, slot, algorithm: record.key.name, transport: 'usb', protocol: 'WebUSB',
      platform: 'browser', on_card_generation: true,
    }};
  }
  async sign(card, chosen, job, options) {
    if (job.state !== 'key_ready') throw new Error('请先提交新卡 CSR 并取得写卡挑战');
    const {slot, ca, chain} = await selectCa(card, job, options.ca_slot);
    if (!await this.confirm({stage: 'sign', name: chosen.name, slot, real_name: job.real_name, roles: job.roles,
      message: `核对本次签发对象及公钥摘要 ${job.public_key_sha256}，使用 CA 槽位 ${slot} 签发。`}))
      throw new Error('已取消 CA 签发');
    await card.verifyPin(await this.secret({kind: 'pin', stage: 'sign', name: chosen.name}));
    requireActive(job);
    const key = await certificateKey(ca);
    const leaf = await makeCertificate(job, ca, chain, data => card.sign(slot, key, data));
    this.progress(`CA 槽位 ${slot} 已完成签发`);
    return {...job, issuer_slot: slot, chain_pem: [leaf, ...chain].map(certificate => pem('CERTIFICATE', certificate.der))};
  }
  async install(card, chosen, job, options) {
    const {certificates, leaf, chain, key} = await validateInstallation(job), slot = job.card.slot;
    const old = await card.certificate(slot);
    if (old && !equal(old.der, leaf.der)) throw new Error(`槽位 ${slot} 已有不同证书，禁止覆盖`);
    const available = new Map();
    for (let index = 0x82; index <= 0x95; index++) {
      const candidate = index.toString(16);
      available.set(candidate, await card.certificate(candidate));
    }
    const slots = [slot];
    for (const certificate of chain) {
      const matching = [...available].find(([, old]) => old && equal(old.der, certificate.der));
      const empty = [...available].find(([, old]) => !old), selected = (matching || empty)?.[0];
      if (!selected) throw new Error('没有足够的空槽保存完整 CA 链，禁止覆盖已有证书');
      slots.push(selected); available.delete(selected);
    }
    await card.verifyPin(await this.secret({kind: 'pin', stage: 'install', name: chosen.name}));
    await card.sign(slot, key, globalThis.crypto.getRandomValues(new Uint8Array(48)));
    if (!await this.confirm({stage: 'install', name: chosen.name, slot, real_name: job.real_name, roles: job.roles,
      message: `目标私钥已匹配。将证书与完整 CA 链写入 ${slots.join('、')}，逐张回读后提交激活。`}))
      throw new Error('已取消写入证书');
    await card.authenticateManagement(await this.secret({kind: 'management', stage: 'install', name: chosen.name, scheme: options.management_algorithm}), options.management_algorithm);
    requireActive(job);
    for (let index = 0; index < slots.length; index++) await card.writeCertificate(slots[index], certificates[index]);
    await card.ensureDiscoveryObjects();
    await card.verifyPin(await this.secret({kind: 'pin', stage: 'proof', name: chosen.name}));
    requireActive(job);
    const proof = await card.sign(slot, key, await writeProof(job, leaf, chain));
    return {issuance_id: job.issuance_id, chain_pem: job.chain_pem, proof: base64(proof),
      readback_verified: true, onsite_confirmed: true, card_slot: slot, chain_slots: slots};
  }
}
