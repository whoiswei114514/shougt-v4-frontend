import { installAdminWatermark } from './adminWatermark';
import type { WatermarkController } from './adminWatermark';

let controller: WatermarkController | undefined;
(window as any).ShouConsoleWatermark = {
  start(marker: string, actor: string) {
    controller?.();
    controller = installAdminWatermark(marker, actor, document.body, {
      async loadFrame() {
        const response = await fetch('/api/watermark/frame', {credentials: 'same-origin', cache: 'no-store'});
        if (!response.ok) throw new Error('管理水印刷新失败');
        return response.json();
      },
    });
  },
  stop: () => controller?.(),
  refresh: () => controller?.refresh(),
  capture: () => controller?.capture(),
};
