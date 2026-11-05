import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { vitePluginForArco } from '@arco-plugins/vite-vue';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [
    vue({
      template: {
        compilerOptions: {
          isCustomElement: tag => ['hcc-captcha'].includes(tag),
        },
      },
    }),
    vitePluginForArco({
      style: 'css',
    }),

  ],
  server: {
    host: '127.0.0.1',
    port: 15173,
    strictPort: true,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:18000',
        rewrite: path => path.replace(/^\/api/, ''),
        changeOrigin: true,
      },

    },
  },
});
