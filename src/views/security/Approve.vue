<script setup lang="ts">
import { computed, onMounted, ref } from 'vue';
import { Message } from '@arco-design/web-vue';
import { useRoute } from 'vue-router';
import Axios from '../../axios';
import { useStore } from '../../stores';
import { getAssertion, securityError } from '../../scripts/webauthn';
import { preferredSmartCard } from '../../scripts/smartcard';
import { getTrustedConsoleOrigin, isValidUuid } from '../../scripts/securityUrls';
import '../../styles/auth.scss';
const route=useRoute(),store=useStore(),operation=ref<any>(null),busy=ref(false),approved=ref(false),loadError=ref(''),consoleOrigin=ref('');
const showPcsc=computed(()=>route.query.pcsc==='1'||preferredSmartCard());
const connection=ref<'browser'|'smartcard'>(showPcsc.value?'smartcard':'browser');
const labels:Record<string,string>={issuance_begin:'开始签发',issuance_key:'确认目标公钥',issuance_sign:'保存 CA 已签发证书链',issuance_finish:'确认安装并激活角色',issuance_status:'读取签发状态',list_certificates:'查看证书身份',list_users:'查找用户',browse_access:'开启 3 分钟只读查看授权',assign_roles:'调整管理角色',nominate:'提名管理员',user_detail:'查看用户档案',password_hash:'查看密码 Hash 与 Salt',update_user:'修改用户基础信息',set_exemption:'设置限时登录许可',list_logs:'查询管理日志',list_verifications:'查询实名申请',review_verification:'通过实名与进阶认证',get_contact:'查看审核联系方式',set_contact:'修改审核联系方式',impersonate:'发起临时代登录',bind_certificate:'登记客户端证书',inspect_watermark:'检验水印并关联操作管理员'};
const fieldLabels:Record<string,string>={user_id:'目标用户 ID',roles:'拟分配角色',temporary:'短期临时签发',validity_days:'临时有效期（天）',issuer_slot:'CA 槽位',chain_pem:'已签发证书链',banned_until:'临时封禁截止时间',reason:'操作理由',days:'许可天数',search:'搜索内容',updates:'修改内容',verification_id:'认证申请',contact:'联系方式',real_name_confirmed:'已确认实名',certificate_pem:'待登记证书',after:'用户分页',before:'日志分页',window_minutes:'授权有效期（分钟）',kind:'检验类型',file_name:'文件名称',file_sha256:'文件 SHA-256',byte_count:'文件字节数',scale:'图像倍率',alignment:'原点模式',origin_x:'原点 X',origin_y:'原点 Y',reference:'参考水印标记'};
const closeWindow=()=>window.close();
async function approve(){
  busy.value=true;
  try{
    if(store.security?.session_scope==='impersonation')throw new Error('临时代登录会话不允许确认管理操作');
    const operationId=route.query.operation;
    if(!isValidUuid(operationId)||!consoleOrigin.value)throw new Error('操作上下文无效');
    const base=`/security/operation/${operationId}/`;
    const {data}=await Axios.post(base+'begin/');
    await Axios.post(base+'finish/',await getAssertion(data,showPcsc.value?connection.value:'browser'));
    approved.value=true;
    const opener=window.opener;
    if(opener&&opener!==window&&!opener.closed){
      opener.postMessage({operation_id:operationId,approved:true},consoleOrigin.value);
    }
  }catch(error){
    Message.error(securityError(error));
  }finally{
    busy.value=false;
  }
}
onMounted(async()=>{
  loadError.value='';
  try{
    if(store.security?.session_scope==='impersonation')throw new Error('临时代登录会话不允许确认管理操作');
    const operationId=route.query.operation;
    if(!isValidUuid(operationId))throw new Error('操作编号无效');
    const [response,config]=await Promise.all([Axios.get(`/security/operation/${operationId}/`),Axios.get('/security/config/')]);
    const origin=getTrustedConsoleOrigin(config.data?.console_url);
    if(!origin)throw new Error('特权管理站配置地址无效');
    if(document.referrer){
      let refOrigin='';
      try{refOrigin=new URL(document.referrer).origin;}catch{throw new Error('来源页面校验失败');}
      if(refOrigin!==origin&&refOrigin!==window.location.origin)throw new Error('操作来源页面不受信任');
    }
    operation.value=response.data;
    consoleOrigin.value=origin;
  }catch(error){
    loadError.value=securityError(error);
    Message.error(loadError.value);
  }
});
</script>
<template>
  <div class="card-container">
    <a-card class="auth-card-wide">
      <a-typography-title :heading="2">确认这一次管理操作</a-typography-title>
      <a-divider class="divider-30" />

      <template v-if="operation && !approved">
        <a-typography-title :heading="5" style="margin-bottom: 16px">
          {{ labels[operation.action] || operation.action }}
        </a-typography-title>
        <a-descriptions :column="1" bordered>
          <a-descriptions-item
            v-for="(value, key) in operation.payload"
            :key="key"
            :label="fieldLabels[String(key)] || String(key)"
          >
            <span style="overflow-wrap: anywhere">
              {{ typeof value === 'object' ? JSON.stringify(value) : String(value).slice(0, 500) }}
            </span>
          </a-descriptions-item>
        </a-descriptions>
        <a-select
          v-if="showPcsc"
          v-model="connection"
          :disabled="busy"
          aria-label="安全密钥连接方式"
          style="margin-top: 20px"
        >
          <a-option value="browser">USB / NFC 安全密钥</a-option>
          <a-option value="smartcard">接触式智能卡（PC/SC）</a-option>
        </a-select>
        <a-button type="primary" long style="margin-top: 20px" :loading="busy" @click="approve">
          验证安全密钥并授权
        </a-button>
      </template>

      <a-result
        v-else-if="approved"
        status="success"
        title="操作已授权"
        subtitle="管理站将完成此次操作，你可以关闭此窗口。"
      />
      <a-result v-else-if="loadError" status="error" title="无法载入此操作" :subtitle="loadError">
        <template #extra>
          <a-button @click="closeWindow">关闭窗口</a-button>
        </template>
      </a-result>
      <a-spin v-else />
    </a-card>
  </div>
</template>
