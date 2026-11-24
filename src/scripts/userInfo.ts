import { toRaw } from 'vue';
import { useStore, usePersistStore, sharedFunctions } from '../stores';
import { Axios, errorHandler } from '../axios';
import { AuthResponse, Authorization, Permission, Quota } from '../types';
import { Message } from '@arco-design/web-vue';

const IMPERSONATION_TAB_KEY = 'shou_impersonation_tab';
let impersonationIsolatedMemory = false;

export function markImpersonationIsolated(): void {
  impersonationIsolatedMemory = true;
  try {
    sessionStorage.setItem(IMPERSONATION_TAB_KEY, '1');
  } catch {
    // Fallback to in-memory lock if storage is unavailable
  }
}

export function clearImpersonationIsolated(): void {
  impersonationIsolatedMemory = false;
  try {
    sessionStorage.removeItem(IMPERSONATION_TAB_KEY);
  } catch {
    // Ignore storage errors
  }
}

export function isImpersonationIsolated(): boolean {
  const store = useStore();
  if (store.security?.session_scope === 'impersonation') {
    markImpersonationIsolated();
    return true;
  }
  if (impersonationIsolatedMemory) return true;
  try {
    if (sessionStorage.getItem(IMPERSONATION_TAB_KEY) === '1') {
      impersonationIsolatedMemory = true;
      return true;
    }
  } catch {
    // Ignore storage errors
  }
  return false;
}

function isValidStoredAuth(auth: unknown): auth is Authorization {
  if (!auth || typeof auth !== 'object') return false;
  const candidate = auth as Authorization;
  if (typeof candidate.signature !== 'string' || !candidate.signature || candidate.signature.length > 512) {
    return false;
  }
  const payload = candidate.payload;
  if (!payload || typeof payload !== 'object') return false;
  if (payload.v !== 2) return false;
  if (typeof payload.exp !== 'number' || !Number.isFinite(payload.exp)) return false;
  if (payload.exp < Math.floor(Date.now() / 1000)) return false;
  return typeof payload.session_id === 'string' && payload.session_id.length > 0;
}

function readStoredPersist(): {
  authorization?: AuthResponse['authorization'] | null;
  roleId?: number | null;
  remember_me?: boolean;
} | null {
  try {
    const raw = localStorage.getItem('persistStorage');
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

export const syncPersistFromStorage = (): 'unchanged' | 'switched' | 'logged_out' => {
  if (isImpersonationIsolated()) return 'unchanged';
  const store = useStore();
  const persistStore = usePersistStore();
  const stored = readStoredPersist();
  if (!stored || !('authorization' in stored)) return 'unchanged';
  if (stored.authorization === null) {
    const hadSession = persistStore.authorization !== null || store.authorization !== null;
    persistStore.logout();
    store.logout();
    return hadSession ? 'logged_out' : 'unchanged';
  }
  if (!isValidStoredAuth(stored.authorization)) {
    persistStore.logout();
    store.logout();
    return 'logged_out';
  }
  const changed =
    stored.authorization.signature !== persistStore.authorization?.signature ||
    stored.authorization.payload?.session_id !== persistStore.authorization?.payload?.session_id ||
    stored.authorization.signature !== store.authorization?.signature ||
    stored.authorization.payload?.session_id !== store.authorization?.payload?.session_id;
  if (changed) {
    const nextAuth = structuredClone(stored.authorization);
    const nextRoleId = typeof stored.roleId === 'number' ? stored.roleId : null;
    persistStore.authorization = nextAuth;
    persistStore.roleId = nextRoleId;
    if (typeof stored.remember_me === 'boolean') {
      persistStore.remember_me = stored.remember_me;
    }
    // Clear previous identity/permissions immediately so stale UI/route guards never act on old data
    store.user = null;
    store.security = null;
    store.watermark_id = '';
    store.permission = {} as Permission;
    store.roles = [];
    store.authorization = structuredClone(stored.authorization);
    store.roleId = nextRoleId;
    return 'switched';
  }
  return 'unchanged';
};

export const initUserInfo = () => {
  const store = useStore();
  const persistStore = usePersistStore();
  syncPersistFromStorage();
  sharedFunctions.checkExpired();
  const isolated = isImpersonationIsolated();
  if (persistStore.authorization && !isolated) {
    store.authorization = structuredClone(toRaw(persistStore.authorization));
    store.roleId = persistStore.roleId;
  }
  if (!isValidStoredAuth(store.authorization)) {
    store.logout();
    if (!isolated) {
      persistStore.logout();
    }
    return;
  }
  const sentSessionId = store.authorization?.payload?.session_id;
  const sentScope = store.security?.session_scope;
  return Axios.get('/user/info/', {
    params: {
      remember_me: persistStore.remember_me,
    },
  })
    .then(res => {
      if (isImpersonationIsolated() && sentScope !== 'impersonation') {
        return;
      }
      if (sentScope === 'impersonation' && res.data?.security?.session_scope !== 'impersonation') {
        return;
      }
      if (sentScope !== 'impersonation') {
        const latestSessionId = readStoredPersist()?.authorization?.payload?.session_id;
        if (latestSessionId && sentSessionId && latestSessionId !== sentSessionId) {
          const outcome = syncPersistFromStorage();
          if (outcome === 'switched') {
            void initUserInfo();
          }
          return;
        }
      }
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
  if (!isValidStoredAuth(authorization)) {
    return;
  }
  const isImpersonationResponse = data.security?.session_scope === 'impersonation';
  if (isImpersonationResponse) {
    markImpersonationIsolated();
  } else if (login) {
    clearImpersonationIsolated();
  } else if (isImpersonationIsolated()) {
    return;
  }
  if (!login && !isImpersonationResponse) {
    const latestSessionId = readStoredPersist()?.authorization?.payload?.session_id;
    if (
      latestSessionId &&
      authorization?.payload?.session_id &&
      latestSessionId !== authorization.payload.session_id
    ) {
      syncPersistFromStorage();
      return;
    }
  }
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
  if (!isImpersonationResponse) {
    persistStore.authorization = structuredClone(authorization);
    persistStore.roleId = store.roleId;
    if (remember_me !== null) {
      persistStore.remember_me = remember_me;
    }
  }
};
