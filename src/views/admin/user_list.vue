<script setup lang="ts">
import { ref, h, reactive, computed } from 'vue';
import { Axios, errorHandler } from '../../axios';
import { Link, Message, Tag } from '@arco-design/web-vue';
import { RouterLink } from 'vue-router';
import { SchoolLabel } from '../../consts/options';
import { formatDatetime } from '../../scripts/time';

const search = ref('');

const loadingList = ref(false),
  data = ref([]),
  pagination = ref({
    current: 1,
    pageSize: 20,
    total: 0,
  }),
  getData = () => {
    loadingList.value = true;
    Axios.get('/admin/user/', {
      params: {
        search: search.value,
        page: pagination.value.current,
        page_size: pagination.value.pageSize,
      },
    })
      .then(res => {
        data.value = res.data.results;
        pagination.value.total = res.data.count;
      })
      .catch(errorHandler)
      .finally(() => {
        loadingList.value = false;
      });
  };
getData();

const columns = [
  {
    title: 'ID',
    dataIndex: 'id',
  },
  {
    title: '用户名',
    dataIndex: 'username',
  },
  {
    title: '姓名',
    dataIndex: 'real_name',
  },
  {
    title: '身份',
    dataIndex: 'identity',
  },
  {
    title: '学校',
    render: ({ record }: { record: any }) => {
      return SchoolLabel[record.school as keyof typeof SchoolLabel];
    },
  },
  {
    title: '状态',
    render: ({ record }: { record: any }) => {
      if (record.banned_until && new Date(record.banned_until).getTime() > Date.now()) {
        return h(Tag, { color: 'orange' }, () => `临时封禁至 ${formatDatetime(record.banned_until)}`);
      }
      if (record.is_active === false) {
        return h(Tag, { color: 'red' }, () => '永久封禁');
      }
      return h(Tag, { color: 'green' }, () => '正常');
    },
  },
  {
    title: '管理',
    dataIndex: 'manage',
    render: ({ record }: { record: any }) => {
      return h(
        RouterLink,
        { to: { name: 'admin-user-detail', params: { id: record.id } } },
        () => h(Link, () => '编辑')
      );
    },
  },
];

const createVisible = ref(false), creating = ref(false);
const createForm = reactive({username:'', password:'', real_name:'', email:''});
const educationGroup = computed(() => {
  const domain = createForm.email.trim().toLowerCase().split('@')[1];
  if (domain === 'st.shou.edu.cn') return '上海海洋大学 · 学生';
  if (domain === 'shou.edu.cn' || domain?.endsWith('.shou.edu.cn')) return '上海海洋大学 · 教师';
  return '按教育邮箱确定学校与身份';
});
async function createUser({errors}: {errors?: unknown}) {
  if (errors) return;
  creating.value = true;
  try {
    const {data} = await Axios.post('/admin/user/', {...createForm});
    Message.success('用户已创建');
    createVisible.value = false;
    search.value = data.data.username;
    pagination.value.current = 1;
    Object.assign(createForm, {username:'', password:'', real_name:'', email:''});
    getData();
  } catch (error) { errorHandler(error); } finally { creating.value = false; }
}
</script>

<template>
  <div class="user-list-toolbar">
  <a-input-search
    search-button
    v-model="search"
    placeholder="请输入用户名或姓名"
    class="mb-1"
    style="max-width: 300px"
    @search="
      pagination.current = 1;
      getData();
    "
    @keydown.enter="
      pagination.current = 1;
      getData();
    "
  />
    <a-button type="primary" @click="createVisible = true">创建用户</a-button>
  </div>
  <a-table
    :columns="columns"
    :data="data"
    :pagination="pagination"
    row-key="id"
    :loading="loadingList"
    @page-change="(page:number) => {
        pagination.current = page;
        getData();
      }"
  />

  <p>管理岗位的任免请进入独立特权管理站。</p>
  <a-modal v-model:visible="createVisible" title="创建用户" :footer="false" :width="520" :mask-closable="!creating" :esc-to-close="!creating">
    <a-form :model="createForm" layout="vertical" @submit="createUser">
      <a-form-item field="username" label="用户名" :rules="[{required:true, message:'请输入用户名'}]"><a-input v-model="createForm.username" placeholder="新用户的登录账号" :max-length="150" autocomplete="off" /></a-form-item>
      <a-form-item field="password" label="初始密码" :rules="[{required:true, message:'请输入初始密码'}, {minLength:8, message:'密码至少 8 位'}]"><a-input-password v-model="createForm.password" placeholder="至少 8 位，避免常见密码" autocomplete="new-password" /></a-form-item>
      <a-form-item field="email" label="教育邮箱" :rules="[{required:true, message:'请输入教育邮箱'}]"><a-input v-model="createForm.email" placeholder="新用户的教育邮箱" inputmode="email" :max-length="254" /></a-form-item>
      <a-form-item label="姓名（选填）"><a-input v-model="createForm.real_name" placeholder="姓名" :max-length="40" /></a-form-item>
      <p class="create-user-note">{{educationGroup}}。学号按“院校缩写-邮箱前缀”生成。新用户可登录后验证邮箱；管理岗位的认证姓名取教育邮箱来信中的发件人称呼。</p>
      <a-space><a-button type="primary" html-type="submit" :loading="creating">确认创建</a-button><a-button :disabled="creating" @click="createVisible = false">取消</a-button></a-space>
    </a-form>
  </a-modal>
</template>

<style lang="scss" scoped>
.user-list-toolbar { display:flex; align-items:flex-start; justify-content:space-between; gap:16px; }
.create-user-note { color:var(--color-text-3); line-height:1.8; margin-bottom:20px; }
.arco-form-item {
  justify-content: center;
}
</style>
