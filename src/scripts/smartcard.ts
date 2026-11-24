import { reactive } from 'vue';
import {
  isValidBridgePort,
  isValidBridgeToken,
  validateBridgePath,
  validateFidoAssertionResult,
  validateFidoReadersPayload,
  validatePairResponse,
  validateSmartcardSessionShare,
  type SanitizedFidoCard,
} from './bridgeValidation';

type Card = SanitizedFidoCard;
const ALLOWED_FIDO_BRIDGE_PATHS = ['/pair', '/readers', '/start', '/status'] as const;

export const cardConnection = reactive({
  visible:false, port:18445, code:'', reader:'', readers:[] as Card[],
  connected:false, busy:false, message:'',
});
let token='', deadline=0, pending:Promise<void>|null=null, savePreferenceOnConfirm=true;
let resolveConnection:(()=>void)|null=null, rejectConnection:((error:Error)=>void)|null=null;
const operations=new Map<string,string>();
let channel:BroadcastChannel|null=null;
const sharing=new Map<string,(data:any)=>void>();
const sessionKey='shou-contact-smartcard-session';
function saveSession() {
  try {
    if(token&&isValidBridgeToken(token)&&Date.now()<deadline)sessionStorage.setItem(sessionKey,JSON.stringify({token,deadline,port:cardConnection.port,reader:cardConnection.reader}));
    else sessionStorage.removeItem(sessionKey);
  }catch(_) {}
}
try {
  const stored=JSON.parse(sessionStorage.getItem(sessionKey)||'null');
  if(stored&&typeof stored==='object'&&isValidBridgeToken(stored.token)&&
     typeof stored.deadline==='number'&&Number.isFinite(stored.deadline)&&
     stored.deadline>Date.now()&&stored.deadline<=Date.now()+1800000&&
     isValidBridgePort(stored.port)&&typeof stored.reader==='string'&&
     stored.reader.length<=300&&!/[\u0000-\u001f\u007f]/.test(stored.reader)) {
    token=stored.token;deadline=stored.deadline;cardConnection.port=stored.port;
    cardConnection.reader=stored.reader;cardConnection.connected=true;
  }else sessionStorage.removeItem(sessionKey);
}catch(_) {}
try {
  channel=new BroadcastChannel('shou-contact-smartcard');
  channel.onmessage=event=>{
    const data=event.data;
    if(data&&typeof data==='object'&&data.type==='request'&&typeof data.nonce==='string'&&data.nonce.length<=64&&token&&isValidBridgeToken(token)&&Date.now()<deadline) {
      channel?.postMessage({type:'session',nonce:data.nonce,token,deadline,port:cardConnection.port,reader:cardConnection.reader});
    }
    if(data&&typeof data==='object'&&data.type==='session'&&typeof data.nonce==='string'&&sharing.has(data.nonce))sharing.get(data.nonce)?.(data);
  };
}catch(_) {}
export function preferredSmartCard():boolean {
  try{return localStorage.getItem('shou-contact-smartcard-preferred')==='true';}catch(_){return false;}
}
export function preferSmartCard(value:boolean) {
  try{localStorage.setItem('shou-contact-smartcard-preferred',String(value));}catch(_) {}
}
async function shareSession() {
  if(token&&Date.now()<deadline)return;
  if(!channel)return;
  const nonce=crypto.randomUUID();
  await new Promise<void>(resolve=>{
    const finish=(data?:any)=>{
      sharing.delete(nonce);
      const valid=validateSmartcardSessionShare(data,nonce);
      if(valid){
        token=valid.token;deadline=valid.deadline;cardConnection.port=valid.port;cardConnection.reader=valid.reader;
        cardConnection.connected=true;saveSession();
      }
      resolve();
    };
    sharing.set(nonce,finish);channel!.postMessage({type:'request',nonce});
    setTimeout(()=>{if(sharing.has(nonce))finish();},500);
  });
}
async function local(path:string,data:Record<string,any>={}) {
  const safePath=validateBridgePath(path,ALLOWED_FIDO_BRIDGE_PATHS);
  const port=cardConnection.port;
  if(!isValidBridgePort(port))throw new Error('本机端口必须为 10000–65535');
  const authHeaders:Record<string,string>={};
  if(token){
    if(!isValidBridgeToken(token)){token='';deadline=0;cardConnection.connected=false;saveSession();throw new Error('本机配对令牌无效，请重新连接');}
    authHeaders['X-Shou-Piv-Token']=token;
  }
  let response:Response;
  try {
    response=await fetch(`http://127.0.0.1:${port}${safePath}`,{method:'POST',credentials:'omit',cache:'no-store',
      signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/json',...authHeaders},
      body:JSON.stringify(data)});
  }catch(_){throw new Error('无法连接接触式 FIDO2 工具，请检查本机工具与本地网络权限');}
  let result:any;
  try{result=await response.json();}catch(_){throw new Error('接触式 FIDO2 工具返回了无效响应');}
  if(!result||typeof result!=='object'||Array.isArray(result))throw new Error('接触式 FIDO2 工具返回格式无效');
  if(!response.ok){
    if(response.status===401){token='';deadline=0;cardConnection.connected=false;saveSession();}
    const msg=typeof result.msg==='string'?result.msg:'';
    throw new Error(msg||'智能卡请求未完成');
  }
  return result;
}
export async function detectSmartCards() {
  if(cardConnection.busy)return;
  cardConnection.busy=true;
  try {
    if(!token||Date.now()>=deadline) {
      token='';
      const pairRes=await local('/pair',{code:cardConnection.code.trim()});
      const paired=validatePairResponse(pairRes,true);
      token=paired.token;deadline=Date.now()+paired.expiresIn*1000;cardConnection.code='';
    }
    const result=await local('/readers');
    const cards=validateFidoReadersPayload(result);
    cardConnection.readers=cards.filter((card:Card)=>
      card.fido2||card.fido2_access_denied||['waiting','unavailable','permission_required'].includes(card.state));
    if(!cardConnection.readers.some(card=>card.id===cardConnection.reader))
      cardConnection.reader=cardConnection.readers[0]?.id||'';
    cardConnection.connected=true;saveSession();
    const denied=cardConnection.readers.some(card=>card.fido2_access_denied&&!card.fido2);
    cardConnection.message=denied
      ?'Windows 阻止非管理员进程读取 PC/SC FIDO2（0x80100027），请以管理员身份运行本机工具，或在浏览器改用 USB / NFC 安全密钥。'
      :cardConnection.readers.length?'已检测到智能卡读卡器':'未发现 FIDO2 智能卡，请连接设备后重新检测';
  }catch(error:any){cardConnection.message=error.message;}
  finally{cardConnection.busy=false;}
}
export function cancelSmartCard() {
  cardConnection.visible=false;rejectConnection?.(new Error('已取消智能卡连接'));
  pending=null;resolveConnection=rejectConnection=null;
}
export function confirmSmartCard() {
  if(!cardConnection.connected||!cardConnection.reader)return;
  cardConnection.visible=false;if(savePreferenceOnConfirm)preferSmartCard(true);saveSession();resolveConnection?.();
  pending=null;resolveConnection=rejectConnection=null;
}
export function resetSmartCardConnection() {
  token='';deadline=0;cardConnection.connected=false;cardConnection.readers=[];cardConnection.reader='';
  cardConnection.code='';cardConnection.message='';saveSession();
}
export async function connectSmartCard(changeReader=false, rememberPreference=true) {
  savePreferenceOnConfirm=rememberPreference;
  await shareSession();
  if(!changeReader&&token&&Date.now()<deadline&&cardConnection.reader)return;
  if(pending)return pending;
  cardConnection.visible=true;cardConnection.message='';
  pending=new Promise<void>((resolve,reject)=>{resolveConnection=resolve;rejectConnection=reject;});
  if(token)void detectSmartCards();
  return pending;
}
export async function smartCardCredential(operation:'create'|'get',publicKey:Record<string,any>,rememberPreference=true) {
  await connectSmartCard(false, rememberPreference);if(rememberPreference)preferSmartCard(true);
  const key=operation+':'+JSON.stringify(publicKey);
  if(!operations.has(key)) {
    if(operations.size>=128)operations.clear();
    operations.set(key,crypto.randomUUID());
  }
  const operation_id=operations.get(key)!;
  await local('/start',{operation_id,operation,reader:cardConnection.reader,publicKey});
  const timeoutMs=Math.max(5000,Math.min(120000,Number(publicKey.timeout)||90000));
  const until=Date.now()+timeoutMs;
  while(Date.now()<until) {
    const status=await local('/status',{operation_id});
    if(status.status==='complete')return validateFidoAssertionResult(status.result,operation);
    if(status.status==='failed'){
      const msg=typeof status.msg==='string'?status.msg:'智能卡验证失败';
      throw new Error(msg);
    }
    await new Promise(resolve=>setTimeout(resolve,500));
  }
  throw new Error('智能卡验证超时，请检查本机工具');
}
