import axios from 'axios';
import { Message } from '@arco-design/web-vue';
// import router from '../router';
import { useStore, sharedFunctions } from '../stores';

const baseUrl = '/api';

export const Axios = axios.create({
  baseURL: baseUrl,
});

Axios.interceptors.request.use(config => {
  if (config.url?.slice(0, 4) !== 'http') {
    const jwts = [];
    sharedFunctions.checkExpired();
    const store = useStore();
    if (store.loggedIn) {
      const payload = btoa(
        JSON.stringify({
          ...store.authorization?.payload,
          role_id: store.roleId,
        })
      );
      const signature = store.authorization?.signature;
      jwts.push(`${payload}.${signature}`);
    }
    if (jwts.length > 0) {
      config.headers['Authorization'] = `JWT ${jwts.join('|')}`;
    }
  }
  return config;
});

Axios.interceptors.response.use(response => {
  if (response.headers['x-shou-audit-id']) window.dispatchEvent(new Event('shou-watermark-refresh'));
  return response;
}, error => {
  if (error.response?.status === 401) {
    const store = useStore();
    const signature = store.authorization?.signature;
    const sent = error.config?.headers?.Authorization;
    // A delayed failure from an earlier session must not clear a new login.
    if (signature && typeof sent === 'string' && sent.endsWith(`.${signature}`)) {
      if (store.security?.session_scope === 'impersonation') store.logout();
      else sharedFunctions.logout();
      Message.warning('登录已失效，请重新登录');
      void import('../router').then(({ default: router }) => {
        const current = router.currentRoute.value;
        if (current.meta.requireLogin) {
          void router.replace({ name: 'login', query: { next: current.fullPath } });
        }
      });
    }
  }
  return Promise.reject(error);
});

Axios.defaults.transformResponse = [
  (data, headers) => {
    if (
      typeof data === 'string' &&
      headers['content-type'] === 'application/json'
    ) {
      try {
        data = JSON.parse(data);
      } catch (e) {
        console.warn('JSON Parse Error', e);
      }
    }
    return data;
  },
];

export const errorHandler = (err: any) => {
  let _message = '未知错误';
  if (err.response?.data?.msg) _message = err.response.data.msg;
  else if (err.response?.data?.[0]) _message = err.response.data[0];
  else if (err.request) _message = '网络异常，请检查网络连接';
  Message.error(_message);
  // if (err.response?.data?.action)
  //   router.push({ name: err.response.data.action });
};

export default Axios;
