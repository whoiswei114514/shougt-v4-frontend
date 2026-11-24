<script setup lang="ts">
import { onMounted, ref, defineAsyncComponent } from 'vue';
import Menu from './components/Menu.vue';
import { themeInit } from './scripts/init';
import { isMobile } from './consts/isMobile';
import { useRoute } from 'vue-router';
import router from './router';
import { useStore } from './stores';
import { sharedFunctions } from './stores';
import { clearImpersonationIsolated } from './scripts/userInfo';
import Axios from './axios';
import SmartCardConnect from './components/SmartCardConnect.vue';
const CaptchaModal = defineAsyncComponent(
  () => import('./components/CaptchaModal.vue')
);
const Report = defineAsyncComponent(() => import('./components/Report.vue'));
const DonateCoin = defineAsyncComponent(
  () => import('./components/DonateCoin.vue')
);
const NotificationList = defineAsyncComponent(
  () => import('./components/Notification.vue')
);
const IssuanceModal = defineAsyncComponent(
  () => import('./views/security/Issuance.vue')
);

const route = useRoute();
const store = useStore();
const endImpersonation = async () => {
  try {
    await Axios.post('/security/logout/');
  } finally {
    clearImpersonationIsolated();
    store.logout();
    location.assign('/');
  }
};
const goBack = () => {
  console.log(window.history.length);
  if (window.history.length > 1) {
    router.go(-1);
  } else {
    router.push('/');
  }
};

themeInit();

const showMenuDrawer = ref(false);
const showIssuanceModal = ref(false);

sharedFunctions.openIssuanceModal = () => {
  showIssuanceModal.value = true;
};

onMounted(() => {
  sharedFunctions.scrollTop = () => {
    window.scrollTo({
      top: 0,
      behavior: 'smooth',
    });
  };
});
</script>

<template>
  <a-config-provider>
    <a-layout>
      <a-layout-header
        class="shadow-5"
        :style="{
          position: 'fixed',
          top: 0,
          overflow: 'hidden',
          height: 'var(--global-header-height)',
          width: '100%',
          zIndex: 1000,
          padding: isMobile ? '0' : '0 1vw',
          backgroundColor: 'var(--color-menu-light-bg)',
        }"
      >
        <Menu :mode="'horizontal'" v-if="!isMobile" />
        <a-page-header
          v-else-if="route.meta.showHeader !== false"
          :style="{ height: 'var(--global-header-height)', padding: '10px 0' }"
          :title="route.meta.title as string"
          :subtitle="(route.meta.subtitle ?? 'shou瓜田') as string"
          :show-back="route.meta.showBack !== false"
          @back="goBack"
        >
          <template #extra>
            <a-button
              type="text"
              size="large"
              style="font-size: 1.5em"
              @click="showMenuDrawer = true"
            >
              <template #icon>
                <a-badge :count="store.unreadNotificationCount" dot>
                  <IconMenu />
                </a-badge>
              </template>
            </a-button>
          </template>
        </a-page-header>
      </a-layout-header>
      <a-layout
        :style="{
          paddingTop:
            isMobile && route.meta.showHeader === false
              ? '0'
              : 'var(--global-header-height)',
        }"
      >
        <a-alert v-if="store.security?.session_scope === 'impersonation'" type="warning" style="margin:12px auto;max-width:1000px">
          正在代登录 {{store.user?.username}}，操作将同时记录超管与目标账号。
          <a-link @click="endImpersonation">结束代登录</a-link>
        </a-alert>
        <a-alert
          v-if="!showIssuanceModal && store.security?.admin_access && (store.security?.pending_sign_requests_count || 0) > 0"
          type="info"
          style="margin:12px auto 0;max-width:1000px"
        >
          待处理提醒：有 {{ store.security.pending_sign_requests_count }} 份其他管理员提交的硬件证书公钥等待签署（CA 卡 / 超管卡 / 超级特权卡）。
          <a-link @click="showIssuanceModal = true" style="margin-left:8px;font-weight:600">打开签署弹窗</a-link>
        </a-alert>
        <a-alert
          v-if="!showIssuanceModal && store.security?.admin_access && (store.security?.signed_issuance_ready_count || 0) > 0"
          type="success"
          style="margin:12px auto 0;max-width:1000px"
        >
          证书签发提醒：您有 {{ store.security.signed_issuance_ready_count }} 份离线证书申请已由管理员签署完成，请导入证书链并完成持钥激活。
          <a-link @click="showIssuanceModal = true" style="margin-left:8px;font-weight:600">立即弹出导入激活</a-link>
        </a-alert>
        <div style="width: min(max(75vw, 1300px), 95vw); margin: 0 auto">
          <!-- <RouterView v-slot="{ Component }">
            <keep-alive>
              <component :is="Component" />
            </keep-alive>
          </RouterView> -->
          <RouterView />
        </div>
        <a-back-top />
      </a-layout>
    </a-layout>

    <a-drawer
      width="min(300px, 80vw)"
      style="z-index: 1200"
      v-model:visible="showMenuDrawer"
      :header="false"
      :footer="false"
    >
      <Menu :mode="'vertical'" @close="showMenuDrawer = false" />
    </a-drawer>

    <Suspense> <Report /> </Suspense>
    <Suspense> <DonateCoin /> </Suspense>
    <Suspense> <NotificationList /> </Suspense>
    <Suspense> <CaptchaModal /> </Suspense>
    <SmartCardConnect />
    <a-modal
      v-model:visible="showIssuanceModal"
      title="特权管理证书签发"
      :footer="false"
      :width="isMobile ? '96vw' : 900"
      unmount-on-close
    >
      <Suspense>
        <IssuanceModal modal @close="showIssuanceModal = false" />
      </Suspense>
    </a-modal>
  </a-config-provider>
</template>
