import {WebPivCeremony} from './ceremony.js';
import {createCardRegistry} from './webusb.js';

const registry = createCardRegistry();
window.ShouWebPiv = {
  supported: () => registry.supported(),
  enumerate: probe => registry.enumerate(probe),
  requestDevice: () => registry.requestDevice(),
  channel: id => registry.channel(id),
  createCeremony: options => new WebPivCeremony(options),
};
