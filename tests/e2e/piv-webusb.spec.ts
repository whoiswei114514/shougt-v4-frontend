import {test,expect,type Page} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import {appletRPC} from '../webpiv-rpc.mjs';
import {installBrowserUsb} from '../webpiv-browser.mjs';
import {keyCounter,saveKeyCounter} from './key-counters';

const fixture=JSON.parse(fs.readFileSync(path.join(process.env.SHOUGT_UI_WORK!,'fixture.json'),'utf8'));
const previews=process.env.SHOUGT_UI_PREVIEWS!;
function virtualKey(key:any) {
  let counter=keyCounter(key);
  return async(page:Page)=>{
    const cdp=await page.context().newCDPSession(page);await cdp.send('WebAuthn.enable');
    const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
    const credential={credentialId:key.credential_id,isResidentCredential:true,rpId:'localhost',privateKey:key.private_key,userHandle:Buffer.from(String(key.user_id)).toString('base64'),signCount:counter};
    await cdp.send('WebAuthn.addCredential',{authenticatorId,credential});
    cdp.on('WebAuthn.credentialAsserted',({credential:value})=>{counter=Math.max(counter,value.signCount);saveKeyCounter(key,counter);});
    await page.exposeFunction('__syncWebPivTestKey',async()=>{await cdp.send('WebAuthn.removeCredential',{authenticatorId,credentialId:key.credential_id});await cdp.send('WebAuthn.addCredential',{authenticatorId,credential:{...credential,signCount:counter}});});
    await page.addInitScript(()=>{const original=navigator.credentials.get.bind(navigator.credentials);navigator.credentials.get=async options=>{await (window as any).__syncWebPivTestKey();return original(options);};});
  };
}

for(const rsa of [false,true])test(`browser directly issues a USB PIV card (${rsa?'RSA fallback / mobile layout':'P-384 / desktop'})`,async({browser})=>{
  const rpc=appletRPC();
  await rpc.send({action:'init',work:process.env.SHOUGT_UI_WORK,existing:true,supported:rsa?['RSA-2048']:['P-384','RSA-3072','RSA-2048']});
  const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:rsa?390:1440,height:980},
    clientCertificates:[{origin:'https://privileged.localhost:18443',certPath:fixture.issuer_certificate,keyPath:fixture.issuer_private_key}]});
  await installBrowserUsb(context);
  await context.route('**/*',route=>{const url=new URL(route.request().url());return ['localhost','127.0.0.1','privileged.localhost'].includes(url.hostname)&&Number(url.port)>=10000?route.continue():route.abort();});
  const addKey=virtualKey(fixture.issuer), setup=new Map<Page,Promise<void>>(), approvals:Promise<void>[]=[];
  context.on('page',page=>setup.set(page,addKey(page)));
  try {
    const page=await context.newPage();await setup.get(page);
    await page.goto('http://localhost:15173/login/');await page.getByPlaceholder('你的瓜田账号').fill(fixture.issuer.username);
    await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
    if(!fixture.certified_key){await page.locator('.auth-panel input[type=password]').fill(fixture.issuer.password);await page.getByRole('button',{name:'确认并继续'}).click();}
    await expect(page).toHaveURL('http://localhost:15173/');
    await page.goto('http://localhost:15173/settings/?tab=security');
    const popup=context.waitForEvent('page');await page.getByRole('button',{name:'进入独立特权管理站'}).click();
    const consolePage=await popup;await setup.get(consolePage);await expect(consolePage.locator('#workspace')).toBeVisible();
    await consolePage.exposeFunction('__pivUsbApdu',(device:string,apdu:string)=>rpc.send({action:'apdu',device,apdu}));
    const bodies:string[]=[], localCalls:string[]=[];
    consolePage.on('request',request=>{
      if(request.method()==='POST')bodies.push(request.postData()||'');
      if(new URL(request.url()).hostname==='127.0.0.1')localCalls.push(request.url());
    });
    context.on('page',approval=>{
      const action=(async()=>{await setup.get(approval);await approval.waitForURL(/\/security\/approve/);await approval.getByRole('button',{name:'验证安全密钥并授权'}).click();})();
      approvals.push(action);action.catch(()=>{});
    });
    const recipient=rsa?fixture.webusb_rsa_recipient:fixture.webusb_recipient;
    await consolePage.locator('#search').fill(recipient.username);await consolePage.getByRole('button',{name:'查找 / 浏览',exact:true}).click();
    await consolePage.getByRole('button',{name:'选择用户'}).click();await consolePage.locator('#role-options input[value=global_reader]').check();
    await consolePage.getByRole('button',{name:'验证密钥并更新角色'}).click();
    await expect(consolePage.locator('#issuance-dialog')).toBeVisible();
    await expect(consolePage.locator('#piv-local-tool')).not.toHaveAttribute('open');
    await expect(consolePage.locator('#issuance-dialog input[type=file]')).toHaveCount(0);
    await consolePage.screenshot({path:path.join(previews,`webusb-${rsa?'mobile':'desktop'}-entry.png`),animations:'disabled'});
    await consolePage.getByRole('button',{name:'授权 USB 智能卡（WebUSB 直连）'}).click();
    await expect(consolePage.locator('#piv-connection')).toContainText('助手已就绪');
    await expect(consolePage.locator('#piv-reader option').first()).toContainText('PIV + FIDO2');
    await consolePage.locator('#piv-ca-reader').selectOption('webusb:auto');
    await consolePage.getByRole('button',{name:'开始制卡并授予角色'}).click();
    let rejected=false, authorizedCa=false;
    const until=Date.now()+65000;
    while(Date.now()<until&&!((await consolePage.locator('#issuance-state').textContent())||'').includes('签发完成，角色已授予')){
      if(await consolePage.locator('#piv-slot-dialog').isVisible()){
        const stats=await rpc.send({action:'stats'});expect(stats.generations).toBe(0);expect(stats.management_attempts).toBe(0);
        await consolePage.screenshot({path:path.join(previews,`webusb-${rsa?'mobile':'desktop'}-occupied.png`),animations:'disabled'});
        if(!rsa&&!rejected){
          rejected=true;await consolePage.getByRole('button',{name:'停止本次签发',exact:true}).click();
          await expect(consolePage.locator('#issuance-state')).toContainText('已停止签发');
          await consolePage.getByRole('button',{name:'开始制卡并授予角色'}).click();
        }else await consolePage.getByRole('button',{name:'改用槽位 9c',exact:true}).click();
      }else if(await consolePage.locator('#piv-web-dialog').isVisible()){
        if(await consolePage.getByRole('heading',{name:'连接签发卡（CA 卡 / 超管卡 / 超级特权卡）',exact:true}).isVisible()&&!authorizedCa){
          authorizedCa=true;await consolePage.locator('#piv-web-authorize').click();
          await expect(consolePage.locator('#piv-web-device option')).toHaveCount(2);
          await expect(consolePage.locator('#piv-web-device option:checked')).toContainText('测试 CA');
        }
        if(await consolePage.locator('#piv-web-confirm-empty').isVisible())await consolePage.locator('#piv-web-confirm-empty').check();
        if(await consolePage.getByRole('heading',{name:'确认签发卡类型与签发信息',exact:true}).isVisible())await expect(consolePage.locator('#piv-web-message')).toContainText(`槽位 ${rsa?'9c':'9a'}`);
        if(await consolePage.locator('#piv-web-secret').isVisible())
          await consolePage.locator('#piv-web-secret').fill(await consolePage.getByRole('heading',{name:'输入目标卡管理密钥',exact:true}).isVisible()?'00112233445566778899aabbccddeeff0123456789abcdef':'654321');
        expect(await consolePage.locator('#piv-web-dialog').evaluate(node=>node.scrollWidth<=node.clientWidth+1)).toBe(true);
        await consolePage.locator('#piv-web-submit').click();
      }else await consolePage.waitForTimeout(100);
    }
    await expect(consolePage.locator('#issuance-state')).toContainText('签发完成，角色已授予');
    await expect(consolePage.locator('#piv-target-slot')).toContainText('9c');
    await expect(consolePage.locator('#piv-selected-algorithm')).toContainText(rsa?'RSA-2048':'P-384');
    await expect(consolePage.locator('#piv-web-secret')).toHaveValue('');
    expect(localCalls).toEqual([]);
    expect(bodies.some(body=>body.includes('"654321"')||body.includes('00112233445566778899aabbccddeeff0123456789abcdef'))).toBe(false);
    const stats=await rpc.send({action:'stats'});
    expect(stats.generations).toBe(1);expect(stats.algorithms).toEqual(rsa?['P-384','RSA-3072','RSA-2048']:['P-384']);
    expect(stats.writes).toEqual(['9c','83','84']);expect(stats.old_default_preserved).toBe(true);expect(stats.old_chain_preserved).toBe(true);
    await consolePage.screenshot({path:path.join(previews,`webusb-${rsa?'mobile':'desktop'}-complete.png`),animations:'disabled'});
    await Promise.all(approvals);
  }finally{rpc.close();await context.close();}
});
