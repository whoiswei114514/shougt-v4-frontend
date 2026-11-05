<script setup lang="ts">
import { computed, reactive, ref } from 'vue';
import { Axios, errorHandler } from '../../axios';
import { Message } from '@arco-design/web-vue';
import router from '../../router';
import ArcoDescriptions from '../../components/ArcoDescriptions.vue';
import { AuthResponse } from '../../types';
import { formatDatetime } from '../../scripts/time';
import { CoinRecordType, CoinRecordTypeOptions } from '../../consts/options';
import { useStore } from '../../stores';

const store = useStore();

const currentUser = ref({} as AuthResponse),
  is_active = ref(true),
  loadingGetUser = ref(false),
  getUser = () => {
    loadingGetUser.value = true;
    Axios.get(`/admin/user/${router.currentRoute.value.params.id}/`)
      .then(res => {
        currentUser.value = res.data;
        noReview.value = Boolean(currentUser.value.permission.no_review);
        quota.value = structuredClone(res.data.quota);
        is_active.value = currentUser.value.user.is_active;
      })
      .catch(errorHandler)
      .finally(() => {
        loadingGetUser.value = false;
      });
  };
getUser();

const canResetPassword = computed(() => !currentUser.value.security?.is_management || store.permission.super_admin);

const newPassword = ref(''),
  changePassword = () => {
    if (!canResetPassword.value) return;
    Axios.post(`/admin/user/${currentUser.value.user.id}/change-password/`, {
      password: newPassword.value,
    })
      .then((_res: any) => {
        newPassword.value = '';
        Message.success('密码修改成功');
      })
      .catch(errorHandler);
  };

const noReview = ref(false);
const changePermission = () => {
  Axios.put(`/admin/user/${currentUser.value.user.id}/?type=permission`, {no_review: noReview.value})
    .then(() => Message.success('老学究权限已更新')).catch(errorHandler);
};

const quota = ref<Record<string, number>>({}),
  changeQuota = () => {
    Axios.put(
      `/admin/user/${currentUser.value.user.id}/?type=quota`,
      quota.value
    )
      .then((res: any) => {
        Message.success('配额修改成功');
        currentUser.value.quota = res.data;
      })
      .catch(errorHandler);
  };

const saveActiveInfo = () => {
  Axios.post(`/admin/user/${currentUser.value.user.id}/ban/`, {
    is_active: is_active.value,
  }).then(() => {
    Message.success('封禁状态修改成功');
  });
};

const coinChangeForm = reactive({
    type: CoinRecordType.ADMIN,
    change: 0,
    detail: '',
  }),
  changeCoin = () => {
    Axios.post(
      `/admin/user/${currentUser.value.user.id}/coin/`,
      coinChangeForm
    ).then(() => {
      Message.success('硬币修改成功');
      coinChangeForm.change = 0;
      coinChangeForm.detail = '';
    });
  };
</script>

<template>
  <a-typography-title :heading="5"> 用户信息 </a-typography-title>
  <ArcoDescriptions
    :data="[
      { label: 'ID', value: currentUser?.user?.id },
      { label: '账号', value: currentUser?.user?.username },
      { label: '姓名', value: currentUser?.user?.real_name },
      { label: '学号', value: currentUser?.user?.student_id },
      { label: '学校', value: currentUser?.user?.school },
      { label: '身份', value: currentUser?.user?.identity },
      {
        label: '注册时间',
        value: formatDatetime(currentUser?.user?.date_joined),
      },
    ]"
  />

  <a-divider />


  <div>
    <a-typography-title :heading="5"> 修改密码 </a-typography-title>
    <a-input-password
      v-model="newPassword"
      :disabled="!canResetPassword"
      autocomplete="new-password"
      placeholder="请输入新密码"
      @keydown.enter="changePassword"
      class="mb-1"
    />
    <a-button type="primary" status="danger" :disabled="!canResetPassword" @click="changePassword">
      修改
    </a-button>
    <p v-if="!canResetPassword">管理账号的密码仅能由超级管理员重置。</p>
  </div>
  <a-divider />

  <div>
    <a-typography-title :heading="5"> 硬币操作 </a-typography-title>
    <a-form :model="coinChangeForm" auto-label-width>
      <a-form-item label="类型">
        <a-select
          v-model="coinChangeForm.type"
          :options="CoinRecordTypeOptions"
        />
      </a-form-item>
      <a-form-item label="数量">
        <a-input-number v-model="coinChangeForm.change" />
      </a-form-item>
      <a-form-item label="说明">
        <a-input v-model="coinChangeForm.detail" />
      </a-form-item>
      <a-form-item>
        <a-button type="primary" @click="changeCoin"> 修改 </a-button>
      </a-form-item>
    </a-form>
  </div>

  <a-divider />

  <div>
    <a-typography-title :heading="5"> 老学究权限 </a-typography-title>
    <a-switch v-model="noReview" />
    <span style="margin-left:12px">老学究 · 免审并放宽发帖配额</span>
    <p>其他管理岗位的任免和超级管理员代登录请使用独立特权管理站。</p>
    <a-button type="primary" status="warning" @click="changePermission">
      修改
    </a-button>
  </div>

  <a-divider />

  <div>
    <a-typography-title :heading="5"> 修改配额 </a-typography-title>
    <a-form-item v-for="i in Object.keys(quota)" :key="i" :label="i">
      <a-input-number v-model="quota[i] /* @ts-ignore */" />
    </a-form-item>
    <a-button type="primary" @click="changeQuota"> 修改 </a-button>
  </div>

  <a-divider />

  <div>
    <a-typography-title :heading="5"> 封禁 </a-typography-title>
    <a-form-item label="允许使用">
      <a-switch v-model:model-value="is_active" />
    </a-form-item>
    <a-button type="primary" @click="saveActiveInfo"> 修改 </a-button>
  </div>
</template>

<style lang="scss" scoped>
.arco-form-item {
  justify-content: center;
}
</style>
