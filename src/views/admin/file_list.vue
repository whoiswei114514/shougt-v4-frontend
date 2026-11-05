<script setup lang="ts">
import { onMounted, ref } from 'vue';
import Axios from '../../axios';
import { Message } from '@arco-design/web-vue';
import { securityError } from '../../scripts/webauthn';
const data=ref<any[]>([]),loading=ref(false),page=ref(1),total=ref(0),search=ref('');
async function load(){loading.value=true;try{const response=await Axios.get('/file/',{params:{page:page.value,search:search.value}});data.value=response.data.results;total.value=response.data.count;}catch(error){Message.error(securityError(error));}finally{loading.value=false;}}
onMounted(load);
</script>
<template><a-space style="margin-bottom:20px"><a-input-search v-model="search" placeholder="搜索文件" @search="page=1;load()"/><a-button @click="load">刷新</a-button></a-space><a-table :data="data" :loading="loading" :pagination="{current:page,total,pageSize:20}" @page-change="value=>{page=value;load()}"><template #columns><a-table-column title="ID" data-index="id"/><a-table-column title="文件名" data-index="name"/><a-table-column title="类型" data-index="content_type"/><a-table-column title="大小"><template #cell="{record}">{{(record.size/1024).toFixed(1)}} KB</template></a-table-column><a-table-column title="上传时间" data-index="create_time"/></template></a-table></template>
