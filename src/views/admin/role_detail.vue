<script setup lang="ts">
import { ref } from 'vue';
import { Axios, errorHandler } from '../../axios';
import { Message } from '@arco-design/web-vue';
import router from '../../router';
import ArcoDescriptions from '../../components/ArcoDescriptions.vue';
import { RoleFull } from '../../types';
import { formatDatetime } from '../../scripts/time';

const data = ref({} as RoleFull),
  banMode = ref<'active' | 'temporary' | 'permanent'>('active'),
  bannedUntil = ref<number | undefined>(undefined),
  loading = ref(false),
  getData = () => {
    loading.value = true;
    Axios.get(`/admin/role/${router.currentRoute.value.params.id}/`)
      .then(res => {
        data.value = res.data;
        const until = data.value.banned_until;
        const hasFuture = Boolean(until && new Date(until).getTime() > Date.now());
        banMode.value = !data.value.is_active
          ? 'permanent'
          : hasFuture
            ? 'temporary'
            : 'active';
        bannedUntil.value = hasFuture ? new Date(until as string).getTime() : undefined;
      })
      .catch(errorHandler)
      .finally(() => {
        loading.value = false;
      });
  };
getData();

const setBanDuration = (hours: number) => {
  banMode.value = 'temporary';
  bannedUntil.value = Date.now() + hours * 3600 * 1000;
};

const saveBan = () => {
  let payload: Record<string, any>;
  if (banMode.value === 'active') {
    payload = { is_active: true };
  } else if (banMode.value === 'permanent') {
    payload = { is_active: false };
  } else {
    if (!bannedUntil.value || bannedUntil.value <= Date.now()) {
      Message.error('请选择晚于当前时间的临时封禁截止时间');
      return;
    }
    payload = { banned_until: new Date(bannedUntil.value).toISOString() };
  }
  loading.value = true;
  Axios.post(`/admin/role/${router.currentRoute.value.params.id}/ban/`, payload)
    .then(res => {
      Message.success(res.data?.msg || '封禁状态修改成功');
      getData();
    })
    .catch(errorHandler)
    .finally(() => {
      loading.value = false;
    });
};

const save = () => {
  loading.value = true;
  Axios.patch(`/admin/role/${router.currentRoute.value.params.id}/`, {
    editable: data.value.editable,
    verify: data.value.verify,
    show_like: data.value.show_like,
  })
    .then(() => {
      Message.success('保存成功');
      getData();
    })
    .catch(errorHandler)
    .finally(() => {
      loading.value = false;
    });
};
</script>

<template>
  <a-typography-title :heading="5"> 角色信息 </a-typography-title>
  <ArcoDescriptions
    :data="[
      { label: 'ID', value: data.id },
      { label: '名称', value: data.name },
      { label: '描述', value: data.description || '-' },
      { label: '匿名角色', value: data.is_private ? '是' : '否' },
      { label: '展示用户信息', value: data.show_user_info ? '是' : '否' },
      { label: '共享角色', value: data.is_shared ? '是' : '否' },
      {
        label: '所有者',
        value: data.user_info ? `${data.user_info.real_name}(${data.user_info.username})` : '-',
      },
    ]"
  />

  <div v-if="data.members?.length">
    <a-typography-title :heading="5"> 成员 </a-typography-title>
    <a-space wrap>
      <a-tag v-for="user in data.members" :key="user.id" size="large">
        {{ user.real_name }}({{ user.username }})
      </a-tag>
    </a-space>
  </div>

  <div v-if="data.admins?.length" style="margin-top: 16px">
    <a-typography-title :heading="5"> 角色管理员 </a-typography-title>
    <a-space wrap>
      <a-tag v-for="user in data.admins" :key="user.id" color="arcoblue" size="large">
        {{ user.real_name }}({{ user.username }})
      </a-tag>
    </a-space>
  </div>

  <a-divider />

  <a-form :model="data" auto-label-width>
    <a-form-item label="允许编辑">
      <a-switch v-model="data.editable" />
    </a-form-item>
    <a-form-item label="认证信息">
      <a-input
        :model-value="data.verify ?? ''" @update:model-value="value=>data.verify=value"
        placeholder="请输入认证信息"
      />
    </a-form-item>
    <a-form-item>
      <a-button type="primary" @click="save" :loading="loading">
        保存信息
      </a-button>
    </a-form-item>
  </a-form>

  <a-divider />

  <a-typography-title :heading="5"> 封禁设置 </a-typography-title>
  <p v-if="data.banned_until && new Date(data.banned_until).getTime() > Date.now()">
    当前状态：<a-tag color="orange">临时封禁至 {{ formatDatetime(data.banned_until) }}</a-tag>
  </p>
  <p v-else-if="data.is_active === false">
    当前状态：<a-tag color="red">永久封禁</a-tag>
  </p>
  <a-form :model="data" auto-label-width>
    <a-form-item label="封禁方式">
      <a-radio-group v-model="banMode" type="button">
        <a-radio value="active">正常使用</a-radio>
        <a-radio value="temporary">临时封禁</a-radio>
        <a-radio value="permanent">永久封禁</a-radio>
      </a-radio-group>
    </a-form-item>
    <a-form-item v-if="banMode === 'temporary'" label="截止时间">
      <a-space direction="vertical" style="width: 100%">
        <a-date-picker
          v-model="bannedUntil"
          show-time
          value-format="timestamp"
          placeholder="选择封禁截止时间"
        />
        <a-space wrap>
          <a-button size="mini" @click="setBanDuration(1)">1小时</a-button>
          <a-button size="mini" @click="setBanDuration(24)">1天</a-button>
          <a-button size="mini" @click="setBanDuration(72)">3天</a-button>
          <a-button size="mini" @click="setBanDuration(24 * 7)">7天</a-button>
          <a-button size="mini" @click="setBanDuration(24 * 30)">30天</a-button>
        </a-space>
      </a-space>
    </a-form-item>
    <a-form-item>
      <a-button type="primary" status="danger" @click="saveBan" :loading="loading">
        保存封禁设置
      </a-button>
    </a-form-item>
  </a-form>
</template>

<style lang="scss" scoped>
.arco-form-item {
  justify-content: center;
}
</style>
