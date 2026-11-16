import FFT from 'fft.js';
import html2canvas from 'html2canvas';

export interface WatermarkFrame {
  version: number; watermark_id: string; actor_id: number; username: string; real_name: string;
  audit_id: number | null; operation_at: string | null; issued_at: string;
  token: string; shards: string[]; refresh_after_ms: number;
}
interface Options {
  loadFrame?: () => Promise<WatermarkFrame>;
  frame?: WatermarkFrame;
}
export interface WatermarkController {
  (): void;
  refresh: () => Promise<void>;
  capture: () => Promise<void>;
}

const bytes = (value: string) => Uint8Array.from(atob(value), char => char.charCodeAt(0));
const bits = (value: Uint8Array) => Array.from(value).flatMap(byte =>
  Array.from({length: 8}, (_, index) => (byte >> (7 - index)) & 1));
const pilot = bits(Uint8Array.from([0x53,0x48,0x4f,0x55,0x32,0xa5,0x6c,0x39,0xdb,0x81,0x17,0xee]));
const renderMask = new Uint8Array(255);
let maskState = 0x53484f55;
for (let index = 0; index < renderMask.length; index++) {
  maskState = (Math.imul(maskState, 1664525) + 1013904223) >>> 0;
  renderMask[index] = maskState >>> 24;
}
const shardBits = (value: string) => bits(bytes(value).map((byte, index) => byte ^ renderMask[index]));

function frequencyTile(payload: number[]) {
  const size = 256, fft = new FFT(size), field = new Float64Array(size * size * 2);
  const carrier = (u: number, v: number, bit: number, amplitude: number) => {
    const value = (bit ? 1 : -1) * amplitude * size * size / 2;
    field[(v * size + u) * 2] = value;
    field[((size - v) * size + size - u) * 2] = value;
  };
  pilot.forEach((bit, index) => carrier(3 + index % 12, 3 + Math.floor(index / 12), bit, 4));
  payload.forEach((bit, index) => carrier(18 + index % 64, 3 + Math.floor(index / 64), bit, 1.5));
  const input = new Float64Array(size * 2), output = new Float64Array(size * 2);
  for (let y = 0; y < size; y++) {
    fft.inverseTransform(output, field.subarray(y * size * 2, (y + 1) * size * 2));
    field.set(output, y * size * 2);
  }
  for (let x = 0; x < size; x++) {
    for (let y = 0; y < size; y++) {
      input[y * 2] = field[(y * size + x) * 2];
      input[y * 2 + 1] = field[(y * size + x) * 2 + 1];
    }
    fft.inverseTransform(output, input);
    for (let y = 0; y < size; y++) field[(y * size + x) * 2] = output[y * 2];
  }
  const canvas = document.createElement('canvas'); canvas.width = canvas.height = size;
  const context = canvas.getContext('2d')!, image = context.createImageData(size, size);
  for (let index = 0; index < size * size; index++) {
    const value = Math.max(0, Math.min(255, Math.round(128 + field[index * 2])));
    image.data.set([value, value, value, 9], index * 4);
  }
  context.putImageData(image, 0, 0);
  return canvas;
}

function embedLsb(canvas: HTMLCanvasElement, token: string) {
  const message = new TextEncoder().encode(`SHOU-WM2:${token}\0`), payload = bits(message);
  const context = canvas.getContext('2d', {willReadFrequently: true})!;
  const image = context.getImageData(0, 0, canvas.width, canvas.height);
  for (let index = 0; index < image.data.length / 4; index++) {
    image.data[index * 4] = (image.data[index * 4] & 254) | payload[index % payload.length];
  }
  context.putImageData(image, 0, 0);
}

/** Signed frame data is supplied by the server; form values are never annotated. */
export function installAdminWatermark(marker: string, actor: string,
  root: HTMLElement = document.body, options: Options = {}): WatermarkController {
  const noop = Object.assign(() => {}, {refresh: async () => {}, capture: async () => {}});
  if (!/^[0-9a-f]{24}$/i.test(marker)) return noop;
  const sessionBits = [...marker].flatMap(hex => parseInt(hex, 16).toString(2).padStart(4, '0').split(''));
  const textPacket = '\u2063' + sessionBits.map(bit => bit === '1' ? '\u200c' : '\u200b').join('') + '\u2063';
  const encoded = /\u2063{1,2}[\u200b\u200c]+\u2063{1,2}/g;
  const excluded = 'script,style,noscript,textarea,input,select,option,canvas,svg,[contenteditable]:not([contenteditable="false"]),[data-shou-text-mark]';
  const marks = new Map<Text, HTMLSpanElement>(), dialogs = new Set<HTMLCanvasElement>();
  const layers = ['visible', 'covert', 'frequency', 'lsb'].map(name => {
    const canvas = document.createElement('canvas');
    canvas.dataset.shouWatermarkLayer = name; canvas.setAttribute('aria-hidden', 'true');
    canvas.style.cssText = 'position:fixed;inset:0;width:100vw;height:100vh;pointer-events:none;z-index:2147483000;user-select:none';
    if (name === 'lsb') canvas.style.opacity = '.004';
    root.append(canvas); return canvas;
  });
  const scheme = matchMedia('(prefers-color-scheme: dark)');
  let stopped = false, pending = 0, capturing = false, frame = options.frame;
  let resizeTimer: ReturnType<typeof setTimeout>, timer: ReturnType<typeof setTimeout>;
  let loading: Promise<void> | undefined, frequencyPattern: HTMLCanvasElement | undefined, refreshAgain = false;
  const dark = () => document.body.getAttribute('arco-theme') === 'dark' ||
    (document.body.getAttribute('arco-theme') !== 'light' && scheme.matches);

  function stamp() {
    pending = 0;
    if (stopped) return;
    for (const [text, span] of marks) {
      if (!text.isConnected || !text.data.trim() || text.parentNode !== span.parentNode || text.nextSibling !== span) {
        span.remove(); marks.delete(text);
      }
    }
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT), found: Text[] = [];
    let node: Node | null;
    while ((node = walker.nextNode())) {
      const text = node as Text, parent = text.parentElement;
      if (text.data.trim() && parent?.namespaceURI === 'http://www.w3.org/1999/xhtml' && !parent.closest(excluded)) found.push(text);
    }
    for (const text of found) {
      if (marks.has(text)) continue;
      const span = document.createElement('span');
      span.dataset.shouTextMark = ''; span.setAttribute('aria-hidden', 'true');
      span.style.cssText = 'display:inline;font-size:0;line-height:0;pointer-events:none';
      span.textContent = textPacket; text.after(span); marks.set(text, span);
    }
  }

  function paintDialogs() {
    for (const canvas of dialogs) canvas.remove();
    dialogs.clear();
    for (const dialog of root.querySelectorAll<HTMLDialogElement>('dialog[open]')) {
      for (const source of layers) {
        const canvas = document.createElement('canvas');
        canvas.dataset.shouDialogLayer = source.dataset.shouWatermarkLayer;
        canvas.setAttribute('aria-hidden', 'true');
        canvas.style.cssText = 'position:absolute;inset:0;width:100%;height:100%;pointer-events:none;z-index:2147483000;user-select:none';
        if (source.dataset.shouWatermarkLayer === 'lsb') canvas.style.opacity = '.004';
        canvas.width = dialog.clientWidth; canvas.height = dialog.clientHeight;
        canvas.getContext('2d')!.drawImage(source, 0, 0);
        dialog.append(canvas); dialogs.add(canvas);
      }
    }
  }

  function paint() {
    if (stopped || capturing) return;
    const ink = dark() ? '218,230,224' : '45,75,95';
    for (const canvas of layers) {
      canvas.width = innerWidth; canvas.height = innerHeight;
      canvas.dataset.shouWatermarkVersion = frame ? '2' : '1';
      canvas.dataset.shouFrameTime = frame?.issued_at || '';
      canvas.dataset.shouAuditId = String(frame?.audit_id || '');
    }
    const visible = layers[0].getContext('2d')!;
    visible.fillStyle = `rgba(${ink},.10)`; visible.font = '12px "Microsoft YaHei",sans-serif';
    const operationTime = frame?.operation_at ? new Date(frame.operation_at).toISOString() : '';
    for (let y = 65; y < innerHeight + 100; y += 185) for (let x = -60; x < innerWidth; x += 320) {
      visible.save(); visible.translate(x, y); visible.rotate(-Math.PI / 12);
      visible.fillText(actor, 0, 0); visible.fillText(operationTime || marker.slice(0, 12), 0, 19);
      visible.restore();
    }
    if (frame) {
      const hidden = layers[1].getContext('2d')!;
      frame.shards.forEach((shard, shardIndex) => {
        const payload = shardBits(shard);
        for (let oy = shardIndex * 256; oy < innerHeight; oy += frame!.shards.length * 256) {
          for (let ox = 0; ox < innerWidth; ox += 256) {
            hidden.fillStyle = `rgba(${ink},.035)`;
            payload.forEach((bit, index) => hidden.fillRect(
              ox + index % 32 * 8 + (bit ? 5 : 1),
              oy + Math.floor(index / 32) * 4 + 1, 2, 2));
          }
        }
      });
      if (!frequencyPattern) {
        frequencyPattern = document.createElement('canvas');
        frequencyPattern.width = 256; frequencyPattern.height = frame.shards.length * 256;
        const context = frequencyPattern.getContext('2d')!;
        frame.shards.forEach((shard, index) => context.drawImage(frequencyTile(shardBits(shard)), 0, index * 256));
      }
      const frequency = layers[2].getContext('2d')!;
      frequency.fillStyle = frequency.createPattern(frequencyPattern, 'repeat')!;
      frequency.fillRect(0, 0, innerWidth, innerHeight);
      const lsb = layers[3].getContext('2d')!;
      lsb.fillStyle = dark() ? '#dce6e0' : '#2d4b5f'; lsb.fillRect(0, 0, innerWidth, innerHeight);
      embedLsb(layers[3], frame.token);
    }
    paintDialogs();
  }

  function schedule() {
    clearTimeout(timer);
    if (!stopped && options.loadFrame) timer = setTimeout(() => {
      if (document.hidden || capturing) { schedule(); return; }
      void refresh().catch(() => {});
    }, Math.max(5000, frame?.refresh_after_ms || 5000));
  }
  async function refresh() {
    if (stopped || capturing || !options.loadFrame) return;
    if (loading) { refreshAgain = true; return loading; }
    loading = (async () => {
      do {
        refreshAgain = false;
        const next = await options.loadFrame!();
        if (stopped) return;
        if (next.version !== 2 || next.watermark_id !== marker || !next.shards?.length ||
            next.shards.length > 8 || next.shards.some(shard => bytes(shard).length !== 255)) {
          throw new Error('服务端水印载荷无效');
        }
        frame = next; frequencyPattern = undefined; paint();
      } while (refreshAgain && !stopped);
    })();
    try { await loading; } finally { loading = undefined; schedule(); }
  }
  function copy(event: ClipboardEvent) {
    if (event.target instanceof Element && event.target.closest('input,textarea,[contenteditable]:not([contenteditable="false"])')) return;
    const selection = getSelection(), plain = selection?.toString().replace(encoded, '');
    if (!plain || !event.clipboardData) return;
    const extended = frame ? '\u2063\u2063' + bits(bytes(frame.token)).map(bit =>
      bit ? '\u200c' : '\u200b').join('') + '\u2063\u2063' : '';
    const chunks = Array.from(plain).reduce<string[]>((result, char, index) => {
      if (index % 64 === 0) result.push(''); result[result.length - 1] += char; return result;
    }, []);
    event.clipboardData.setData('text/plain', chunks.map(chunk => chunk + textPacket).join('') + extended);
    const wrapper = document.createElement('div');
    for (let index = 0; selection && index < selection.rangeCount; index++) wrapper.append(selection.getRangeAt(index).cloneContents());
    wrapper.append(textPacket + extended); event.clipboardData.setData('text/html', wrapper.innerHTML);
    event.preventDefault();
  }
  async function capture() {
    if (capturing || stopped) return;
    await refresh();
    if (!frame) throw new Error('无法获取服务端水印，请稍后重试');
    capturing = true;
    try {
      const snapshot = frame;
      const canvas = await html2canvas(root, {scale: 1, logging: false,
        backgroundColor: dark() ? '#141c18' : '#ffffff'});
      embedLsb(canvas, snapshot.token);
      const blob = await new Promise<Blob>((resolve, reject) => canvas.toBlob(
        (value: Blob | null) => value ? resolve(value) : reject(new Error('截图生成失败')), 'image/png'));
      const url = URL.createObjectURL(blob), link = document.createElement('a');
      link.href = url; link.download = `shou-management-${snapshot.audit_id || 'view'}-${Date.now()}.png`;
      link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000);
    } finally { capturing = false; schedule(); }
  }
  const resized = () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(paint, 140); };
  const changed = () => { if (!document.hidden) void refresh().catch(() => {}); };
  const updated = () => { void refresh().catch(() => {}); };
  const observer = new MutationObserver(records => {
    if (records.some(record => record.type === 'attributes')) paint();
    if (!pending) pending = requestAnimationFrame(stamp);
  });
  observer.observe(root, {subtree: true, childList: true, characterData: true, attributes: true,
    attributeFilter: ['arco-theme', 'data-theme', 'open']});
  root.addEventListener('copy', copy, true); window.addEventListener('resize', resized);
  document.addEventListener('visibilitychange', changed); window.addEventListener('shou-watermark-refresh', updated);
  scheme.addEventListener('change', paint);
  stamp(); paint(); void refresh().catch(() => {});
  return Object.assign(() => {
    stopped = true; observer.disconnect(); cancelAnimationFrame(pending);
    clearTimeout(resizeTimer); clearTimeout(timer);
    root.removeEventListener('copy', copy, true); window.removeEventListener('resize', resized);
    document.removeEventListener('visibilitychange', changed); window.removeEventListener('shou-watermark-refresh', updated);
    scheme.removeEventListener('change', paint);
    for (const span of marks.values()) span.remove();
    for (const canvas of [...layers, ...dialogs]) canvas.remove();
    marks.clear();
  }, {refresh, capture});
}
