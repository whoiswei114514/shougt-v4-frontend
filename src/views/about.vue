<script setup lang="ts">
import { ref } from 'vue';
import Axios from '../axios';

const contact = ref('renzheng@shouguatian.com');
Axios.get('/security/config/').then(({ data }) => {
  if (data?.material_review_contact) {
    contact.value = data.material_review_contact;
  }
}).catch(() => {});
</script>

<template>
  <a-layout class="about-layout">
    <a-typography-title :heading="2">关于 shou瓜田</a-typography-title>
    <a-typography-paragraph style="font-size: 1.1em; color: var(--color-text-2)">
      shou瓜田，面向上海海洋大学师生与教育社区的交流空间。
    </a-typography-paragraph>

    <a-divider />

    <a-row :gutter="[16, 16]">
      <a-col :xs="24" :md="8">
        <a-card title="用教育邮箱相识" style="height: 100%">
          海大学生、海大教师与外校人士，按已验证的教育邮箱确认身份。
        </a-card>
      </a-col>
      <a-col :xs="24" :md="8">
        <a-card title="按你的角色交流" style="height: 100%">
          选择公开分享，或仅向发帖角色的所有成员开放。成员可以使用当前角色继续讨论。
        </a-card>
      </a-col>
      <a-col :xs="24" :md="8">
        <a-card title="让管理有据可循" style="height: 100%">
          管理员完成实名与进阶认证，用安全密钥登录。特权操作进入独立管理站，逐次确认并记录。
        </a-card>
      </a-col>
    </a-row>

    <a-divider />

    <a-typography-title :heading="5">联系与认证材料</a-typography-title>
    <a-typography-paragraph style="color: var(--color-text-3)">
      {{ contact }}
    </a-typography-paragraph>
    <RouterLink to="/security/">
      <a-link>前往账号安全中心</a-link>
    </RouterLink>
  </a-layout>
</template>

<style lang="scss" scoped>
.about-layout {
  padding: 5vh 5vw;
  max-width: max(800px, 60vw);
  margin: 0 auto;
  h2 {
    margin: 0 0 12px;
  }
}
</style>
