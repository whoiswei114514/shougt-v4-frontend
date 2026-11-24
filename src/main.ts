// Vue初始化
import './scripts/impersonationTicket';
import { createApp } from 'vue';
import './styles/arco-override.css';
import './styles/style.scss';
import App from './App.vue';
import '@arco-design/web-vue/dist/arco.css';
import router from './router';
import { createPinia } from 'pinia';
import piniaPluginPersistedstate from 'pinia-plugin-persistedstate';
import { Notification, Message } from '@arco-design/web-vue';

import { initUserInfo, syncPersistFromStorage } from './scripts/userInfo';
import { scrubTicketFromLocation } from './scripts/impersonationTicket';

const pinia = createPinia();
pinia.use(piniaPluginPersistedstate);

const app = createApp(App);
app.use(pinia);

// Arco组件初始化

Notification._context = app._context;
Message._context = app._context;
// 用户信息获取

void (async () => {
  scrubTicketFromLocation();
  await initUserInfo();
  app.use(router);
  await router.isReady();
  app.mount('#app');
})();
setInterval(() => {
  initUserInfo();
}, 1000 * 60 * 5);
window.addEventListener('storage', event => {
  if (event.key === 'persistStorage') {
    const outcome = syncPersistFromStorage();
    if (outcome === 'switched') {
      void initUserInfo();
    } else if (outcome === 'logged_out' && router.currentRoute.value.meta.requireLogin) {
      void router.replace({ name: 'login' });
    }
  }
});

// Markdown配置

import { config as mdEditorConfig } from 'md-editor-v3';
import mermaid from 'mermaid';

mdEditorConfig({
  mermaidConfig: base => ({
    ...base,
    securityLevel: 'strict',
  }),
  katexConfig: base => ({
    ...base,
    trust: false,
    strict: false,
    maxExpand: 200,
  }),
  editorExtensions: {
    prettier: {
      standaloneJs: '/js/prettier-standalone.min.js',
      parserMarkdownJs: '/js/prettier-parser-markdown.min.js',
    },
    cropper: {
      js: '/js/cropper.min.js',
      css: '/css/cropper.min.css',
    },
    katex: {
      js: '/js/katex.min.js',
      css: '/css/katex.min.css',
    },
    highlight: {
      js: '/js/highlight.min.js',
    },
    screenfull: {
      js: '/js/screenfull.min.js',
    },
    mermaid: {
      instance: mermaid,
    },
  },
});
