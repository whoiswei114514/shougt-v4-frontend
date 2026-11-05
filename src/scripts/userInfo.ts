import { toRaw } from 'vue';
import { useStore, usePersistStore, sharedFunctions } from '../stores';
import { Axios, errorHandler } from '../axios';
import { AuthResponse, Permission, Quota } from '../types';
import { Message } from '@arco-design/web-vue';

export const initUserInfo = () => {
  const store = useStore();
  const persistStore = usePersistStore();
  sharedFunctions.checkExpired();
  if (persistStore.authorization && store.security?.session_scope !== 'impersonation') {
    store.authorization = structuredClone(toRaw(persistStore.authorization));
    store.roleId = persistStore.roleId;
  }
  if (store.authorization === null || store.authorization.payload.v !== 2) {
    store.logout();
    persistStore.logout();
    return;
  }
  return Axios.get('/user/info/', {
    params: {
      remember_me: persistStore.remember_me,
    },
  })
    .then(res => {
      console.log('初始化用户信息成功');
      saveUserInfo(res.data, false);
    })
    .catch(error => {
      if (error.response?.status !== 401) errorHandler(error);
    });
};

export const saveUserInfo = (
  data: AuthResponse,
  login: boolean = true,
  remember_me: boolean | null = null
) => {
  // login用于决定是否从roles中为用户选择角色

  const store = useStore();

  const {
    authorization,
    user,
    quota,
    permission,
    roles,
    captcha_expire_time,
    signed,
  } = data;
  store.authorization = authorization;
  store.user = user;
  store.quota = quota as Quota;
  store.permission = permission as Permission;
  store.roles = roles;
  store.captcha_required = data.captcha_required !== false;
  store.captcha_expire_time = captcha_expire_time;
  store.signed = signed;
  store.security = data.security;
  store.watermark_id = data.watermark_id || '';

  if (login) {
    let flag = false;
    for (const role of roles) {
      if (role.is_active) {
        store.roleId = role.id;
        flag = true;
        break;
      }
    }
    if (!flag) {
      Message.error('未找到可用的角色，请联系管理员');
      store.roleId = roles[0]?.id ?? null;
    }
  } else {
    let flag = false;
    for (const role of roles) {
      if (role.id === store.roleId) {
        flag = true;
        break;
      }
    }
    if (!flag) {
      console.warn('角色ID不存在，已重置');
      store.roleId = roles[0]?.id ?? null;
    }
  }
  const persistStore = usePersistStore();
  if (data.security?.session_scope !== 'impersonation') {
    persistStore.authorization = structuredClone(authorization);
    persistStore.roleId = store.roleId;
    if (remember_me !== null) {
      persistStore.remember_me = remember_me;
    }
  }
};
