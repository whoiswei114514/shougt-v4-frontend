<script setup lang="ts">
import { onMounted, ref } from 'vue';
import Axios from '../../axios';
import { Message } from '@arco-design/web-vue';
import { securityError } from '../../scripts/webauthn';
const data=ref<any[]>([]),loading=ref(false),page=ref(1),total=ref(0);
async function load(){loading.value=true;try{const response=await Axios.get('/video/',{params:{page:page.value}});data.value=response.data.results;total.value=response.data.count;}catch(error){Message.error(securityError(error));}finally{loading.value=false;}}
onMounted(load);
</script>
<template><p>论坛图片与视频由「图片小编」管理，独立于文件仓管权限。</p><a-button style="margin-bottom:20px" @click="load">刷新列表</a-button><a-table :data="data" :loading="loading" :pagination="{current:page,total,pageSize:20}" @page-change="value=>{page=value;load()}"><template #columns><a-table-column title="ID" data-index="id"/><a-table-column title="视频名称" data-index="name"/><a-table-column title="大小"><template #cell="{record}">{{(record.size/1024/1024).toFixed(1)}} MB</template></a-table-column><a-table-column title="可播放"><template #cell="{record}">{{record.is_active?'是':'否'}}</template></a-table-column><a-table-column title="创建时间" data-index="create_time"/></template></a-table></template>
