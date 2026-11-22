export const bytes = value => value instanceof Uint8Array ? value : new Uint8Array(value);
export const concat = (...values) => {
  const output = new Uint8Array(values.reduce((size, value) => size + value.length, 0));
  let offset = 0;
  for (const value of values) { output.set(value, offset); offset += value.length; }
  return output;
};
export const hex = value => Array.from(bytes(value), byte => byte.toString(16).padStart(2, '0')).join('');
export function unhex(value) {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{2})*$/i.test(value)) throw new Error('无效的十六进制数据');
  return Uint8Array.from(value.match(/../g) || [], byte => parseInt(byte, 16));
}
export function equal(first, second) {
  if (first.length !== second.length) return false;
  let difference = 0;
  for (let index = 0; index < first.length; index++) difference |= first[index] ^ second[index];
  return difference === 0;
}
export const utf8 = value => new TextEncoder().encode(value);
export function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value !== null && typeof value === 'object')
    return '{' + Object.keys(value).sort().map(key => JSON.stringify(key) + ':' + canonical(value[key])).join(',') + '}';
  return JSON.stringify(value);
}
export function base64(value) {
  let text = '';
  for (const byte of bytes(value)) text += String.fromCharCode(byte);
  return btoa(text);
}
export function unbase64(value) {
  return Uint8Array.from(atob(value), character => character.charCodeAt(0));
}
export const pem = (label, value) => `-----BEGIN ${label}-----\n${base64(value).match(/.{1,64}/g).join('\n')}\n-----END ${label}-----\n`;
export function unpem(label, value) {
  if (typeof value !== 'string' || value.length > 16000) throw new Error('证书或 CSR 大小不正确');
  const match = value.match(new RegExp(`^\\s*-----BEGIN ${label}-----\\s+([A-Za-z0-9+/=\\s]+)-----END ${label}-----\\s*$`));
  if (!match) throw new Error('证书或 CSR 格式不正确');
  return unbase64(match[1].replace(/\s/g, ''));
}
export function tlv(tag, value) {
  const data = bytes(value), tagBytes = [];
  do { tagBytes.unshift(tag & 255); tag = Math.floor(tag / 256); } while (tag);
  const size = data.length, length = [];
  if (size < 128) length.push(size);
  else {
    let rest = size;
    do { length.unshift(rest & 255); rest = Math.floor(rest / 256); } while (rest);
    length.unshift(0x80 | length.length);
  }
  return concat(Uint8Array.from(tagBytes), Uint8Array.from(length), data);
}
export function elements(value) {
  const data = bytes(value), output = [];
  let offset = 0;
  while (offset < data.length) {
    const start = offset;
    let tag = data[offset++], tagSize = 1;
    if ((tag & 0x1f) === 0x1f) {
      let byte;
      do {
        if (offset >= data.length || tagSize++ > 4) throw new Error('卡片返回了无效的 TLV 标签');
        byte = data[offset++]; tag = tag * 256 + byte;
      } while (byte & 0x80);
    }
    if (offset >= data.length) throw new Error('卡片返回了不完整的 TLV');
    let size = data[offset++];
    if (size & 0x80) {
      const count = size & 0x7f;
      if (!count || count > 4 || offset + count > data.length) throw new Error('卡片返回了无效的 TLV 长度');
      size = 0;
      for (let index = 0; index < count; index++) size = size * 256 + data[offset++];
    }
    const end = offset + size;
    if (end > data.length) throw new Error('卡片返回了不完整的 TLV');
    output.push({tag, data: data.slice(offset, end), encoded: data.slice(start, end)});
    offset = end;
  }
  return output;
}
export function valueOf(data, tag) {
  const found = elements(data).filter(item => item.tag === tag);
  if (found.length !== 1) throw new Error('卡片返回了缺失或重复的 TLV 字段');
  return found[0].data;
}
