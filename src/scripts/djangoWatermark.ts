import { installAdminWatermark } from './adminWatermark';

const host = document.getElementById('shou-watermark');
if (host) {
  const controller = installAdminWatermark(host.dataset.marker || '', host.dataset.actor || '',
    document.body, {async loadFrame() {
      const prefix = location.pathname.startsWith('/api/') ? '/api/' : '/';
      const response = await fetch(prefix + 'django-admin/watermark/', {credentials: 'same-origin', cache: 'no-store'});
      if (!response.ok) throw new Error('管理水印刷新失败');
      return response.json();
    }});
  document.getElementById('shou-watermark-capture')?.addEventListener('click', () => {
    void controller.capture().catch(error => alert(error.message));
  });
}
