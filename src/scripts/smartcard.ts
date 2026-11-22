import { reactive } from 'vue';

type Card = {id:string;name:string;fido2:boolean;state:string};
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
    if(token&&Date.now()<deadline)sessionStorage.setItem(sessionKey,JSON.stringify({token,deadline,port:cardConnection.port,reader:cardConnection.reader}));
    else sessionStorage.removeItem(sessionKey);
  }catch(_) {}
}
try {
  const stored=JSON.parse(sessionStorage.getItem(sessionKey)||'null');
  if(stored&&typeof stored.token==='string'&&stored.token.length<=100&&stored.deadline>Date.now()&&
     stored.deadline<=Date.now()+1800000&&Number.isInteger(stored.port)&&stored.port>=10000&&stored.port<=65535&&
     typeof stored.reader==='string'&&stored.reader.length<=300) {
    token=stored.token;deadline=stored.deadline;cardConnection.port=stored.port;
    cardConnection.reader=stored.reader;cardConnection.connected=true;
  }else sessionStorage.removeItem(sessionKey);
}catch(_) {}
try {
  channel=new BroadcastChannel('shou-contact-smartcard');
  channel.onmessage=event=>{
    const data=event.data;
    if(data?.type==='request'&&typeof data.nonce==='string'&&token&&Date.now()<deadline) {
      channel?.postMessage({type:'session',nonce:data.nonce,token,deadline,port:cardConnection.port,reader:cardConnection.reader});
    }
    if(data?.type==='session'&&sharing.has(data.nonce))sharing.get(data.nonce)?.(data);
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
      if(data&&typeof data.token==='string'&&data.token.length<=100&&Number.isInteger(data.port)&&data.port>=10000&&data.port<=65535&&data.deadline>Date.now()){
        token=data.token;deadline=data.deadline;cardConnection.port=data.port;cardConnection.reader=data.reader;
        cardConnection.connected=true;saveSession();
      }
      resolve();
    };
    sharing.set(nonce,finish);channel!.postMessage({type:'request',nonce});
    setTimeout(()=>{if(sharing.has(nonce))finish();},500);
  });
}
async function local(path:string,data:Record<string,any>={}) {
  const port=cardConnection.port;
  if(!Number.isInteger(port)||port<10000||port>65535)throw new Error('本机端口必须为 10000–65535');
  let response:Response;
  try {
    response=await fetch(`http://127.0.0.1:${port}${path}`,{method:'POST',credentials:'omit',cache:'no-store',
      signal:AbortSignal.timeout(15000),headers:{'Content-Type':'application/json',...(token?{'X-Shou-Piv-Token':token}:{})},
      body:JSON.stringify(data)});
  }catch(_){throw new Error('无法连接接触式 FIDO2 工具，请检查本机工具与本地网络权限');}
  const result=await response.json();
  if(!response.ok){
    if(response.status===401){token='';deadline=0;cardConnection.connected=false;saveSession();}
    throw new Error(result.msg||'智能卡请求未完成');
  }
  return result;
}
export async function detectSmartCards() {
  if(cardConnection.busy)return;
  cardConnection.busy=true;
  try {
    if(!token||Date.now()>=deadline) {
      token='';
      const result=await local('/pair',{code:cardConnection.code.trim()});
      token=result.token;deadline=Date.now()+result.expires_in*1000;cardConnection.code='';
    }
    const result=await local('/readers');
    cardConnection.readers=result.cards.filter((card:Card)=>card.fido2||['waiting','unavailable','permission_required'].includes(card.state));
    if(!cardConnection.readers.some(card=>card.id===cardConnection.reader))
      cardConnection.reader=cardConnection.readers[0]?.id||'';
    cardConnection.connected=true;saveSession();cardConnection.message=cardConnection.readers.length?'已检测到智能卡读卡器':'未发现 FIDO2 智能卡，请连接设备后重新检测';
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
  const until=Date.now()+Math.min(120000,Number(publicKey.timeout)||90000);
  while(Date.now()<until) {
    const status=await local('/status',{operation_id});
    if(status.status==='complete')return status.result;
    if(status.status==='failed')throw new Error(status.msg);
    await new Promise(resolve=>setTimeout(resolve,500));
  }
  throw new Error('智能卡验证超时，请检查本机工具');
}
