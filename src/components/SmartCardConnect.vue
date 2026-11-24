<script setup lang="ts">
import { computed } from 'vue';
import { cardConnection, detectSmartCards, cancelSmartCard, confirmSmartCard, resetSmartCardConnection } from '../scripts/smartcard';
const command=computed(()=>`python -m backend.fido_bridge --origin ${location.origin}${location.protocol==='http:'?' --allow-loopback-http':''}`);
</script>
<template>
  <a-modal :visible="cardConnection.visible" title="连接接触式智能卡" width="min(480px, calc(100vw - 32px))"
    :mask-closable="false" :ok-button-props="{disabled:!cardConnection.connected || !cardConnection.reader}"
    @cancel="cancelSmartCard" @ok="confirmSmartCard">
    <a-form :model="cardConnection" layout="vertical">
      <a-form-item v-if="!cardConnection.connected" label="一次性配对码">
        <a-input-password v-model="cardConnection.code" autocomplete="off" placeholder="接触式 FIDO2 工具的配对码" />
      </a-form-item>
      <a-form-item label="本机端口"><a-input-number v-model="cardConnection.port" :min="10000" :max="65535" :disabled="cardConnection.connected" /></a-form-item>
      <a-button :loading="cardConnection.busy" @click="detectSmartCards">检测智能卡</a-button>
      <a-button v-if="cardConnection.connected" :disabled="cardConnection.busy" type="text" @click="resetSmartCardConnection">更换本机工具</a-button>
      <a-form-item v-if="cardConnection.connected" label="智能卡读卡器" style="margin-top:16px">
        <a-select v-model="cardConnection.reader"><a-option v-for="card in cardConnection.readers" :key="card.id" :value="card.id">{{card.name}} · {{card.fido2?(card.fido2_pin_set===false?'FIDO2（首次需设 PIN）':'FIDO2'):card.fido2_access_denied?'FIDO2 需管理员权限':'等待卡片'}}</a-option></a-select>
      </a-form-item>
      <p role="status" style="overflow-wrap:anywhere">{{cardConnection.message}}</p>
      <details><summary>启动本机工具</summary><pre style="white-space:pre-wrap;overflow-wrap:anywhere">{{command}}</pre></details>
    </a-form>
  </a-modal>
</template>
