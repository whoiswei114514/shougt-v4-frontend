export async function installBrowserUsb(context) {
  await context.addInitScript(() => {
    const authorized = new Set();
    const makeDevice = (id, productName) => ({
      id, productName, serialNumber: 'software-' + id,
      vendorId: 0x20a0, productId: 0x42d4, opened: false,
      configuration: {configurationValue: 1, interfaces: [{interfaceNumber: 1, alternates: [{interfaceClass: 0xff}]}]},
      async open() { this.opened = true; },
      async close() { this.opened = false; },
      async claimInterface() {},
      async releaseInterface() {},
      async selectConfiguration() {},
      async controlTransferOut(setup, data) {
        if (setup.request !== 0 || setup.index !== 1) throw new Error('Unexpected test WebUSB request');
        const hex = Array.from(new Uint8Array(data), byte => byte.toString(16).padStart(2, '0')).join('');
        this.response = await window.__pivUsbApdu(this.id, hex);
        return {status: 'ok', bytesWritten: data.byteLength};
      },
      async controlTransferIn(setup) {
        if (setup.index !== 1) throw new Error('Unexpected test WebUSB interface');
        const value = setup.request === 2 ? new Uint8Array([0])
          : Uint8Array.from(this.response.match(/../g), byte => parseInt(byte, 16));
        return {status: 'ok', data: new DataView(value.buffer)};
      },
    });
    const target = makeDevice('target', 'CanoKey · 测试目标卡'), ca = makeDevice('ca', 'CanoKey · 测试 CA');
    const usb = new EventTarget();
    usb.getDevices = async () => [target, ca].filter(device => authorized.has(device.id));
    usb.requestDevice = async () => {
      const device = authorized.has('target') ? ca : target;
      authorized.add(device.id); return device;
    };
    Object.defineProperty(navigator, 'usb', {value: usb, configurable: true});
  });
}
