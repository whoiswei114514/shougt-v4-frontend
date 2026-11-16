import {test,expect,type Page,type BrowserContext} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
const fixture=JSON.parse(fs.readFileSync(path.join(process.env.SHOUGT_UI_WORK!,'fixture.json'),'utf8'));
const previews=process.env.SHOUGT_UI_PREVIEWS!;
async function local(context:BrowserContext){await context.route('**/*',route=>{const u=new URL(route.request().url());return ['localhost','127.0.0.1','privileged.localhost'].includes(u.hostname)&&Number(u.port)>=10000?route.continue():route.abort();});}
function installKey(key:any){
  let counter=key.sign_count;
  return async(page:Page)=>{
    const cdp=await page.context().newCDPSession(page);await cdp.send('WebAuthn.enable');
    const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
    const credential={credentialId:key.credential_id,isResidentCredential:true,rpId:'localhost',privateKey:key.private_key,userHandle:Buffer.from(String(key.user_id)).toString('base64'),signCount:counter};
    await cdp.send('WebAuthn.addCredential',{authenticatorId,credential});
    cdp.on('WebAuthn.credentialAsserted',({credential:value})=>counter=Math.max(counter,value.signCount));
    await page.exposeFunction('__syncPivTestKey',async()=>{await cdp.send('WebAuthn.removeCredential',{authenticatorId,credentialId:key.credential_id});await cdp.send('WebAuthn.addCredential',{authenticatorId,credential:{...credential,signCount:counter}});});
    await page.addInitScript(()=>{const original=navigator.credentials.get.bind(navigator.credentials);navigator.credentials.get=async options=>{await (window as any).__syncPivTestKey();return original(options);};});
  };
}
async function login(page:Page,key:any){
  await page.goto('http://localhost:15173/login/');await page.getByPlaceholder('你的瓜田账号').fill(key.username);
  await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
  if(!fixture.certified_key){await page.locator('.auth-panel input[type=password]').fill(key.password);await page.getByRole('button',{name:'确认并继续'}).click();}
}

test('granting a privileged role opens an automatic PIV dialog without file exchange',async({browser})=>{
  const context=await browser.newContext({ignoreHTTPSErrors:true,clientCertificates:[{origin:'https://privileged.localhost:18443',certPath:fixture.issuer_certificate,keyPath:fixture.issuer_private_key}]});
  await local(context);const addKey=installKey(fixture.issuer),setup=new Map<Page,Promise<void>>();
  context.on('page',page=>setup.set(page,addKey(page)));
  const approvals:Promise<void>[]=[];
  try{
    const page=await context.newPage();await setup.get(page);await login(page,fixture.issuer);await expect(page).toHaveURL('http://localhost:15173/');
    await page.goto('http://localhost:15173/settings/?tab=security');
    const popup=context.waitForEvent('page');await page.getByRole('button',{name:'进入独立特权管理站'}).click();
    const consolePage=await popup;await setup.get(consolePage);await expect(consolePage.locator('#workspace')).toBeVisible();
    context.on('page',approval=>{
      const task=(async()=>{await setup.get(approval);await approval.waitForURL(/\/security\/approve/);await approval.getByRole('button',{name:'验证安全密钥并授权'}).click();})();
      approvals.push(task);task.catch(()=>{});
    });
    await consolePage.locator('#search').fill(fixture.issuance_recipient.username);
    await consolePage.getByRole('button',{name:'查找用户'}).click();await consolePage.getByRole('button',{name:'选择用户'}).click();
    await consolePage.locator('#role-options input[value=global_reader]').check();
    await consolePage.getByRole('button',{name:'验证密钥并更新角色'}).click();
    await expect(consolePage.getByRole('heading',{name:'签发并授予角色'})).toBeVisible();
    await expect(consolePage.locator('nav [data-page=issuance]')).toHaveCount(0);
    await expect(consolePage.locator('#issuance-dialog input[type=file]')).toHaveCount(0);
    for(const width of [1440,390]){
      await consolePage.setViewportSize({width,height:980});
      expect(await consolePage.locator('#issuance-dialog').evaluate(node=>node.scrollWidth<=node.clientWidth+1)).toBe(true);
      await consolePage.screenshot({path:path.join(previews,`automatic-issuance-${width}.png`),animations:'disabled'});
    }
    await consolePage.locator('#piv-pair-code').fill(fixture.piv_pair_code);
    await consolePage.getByRole('button',{name:'连接本机制卡工具'}).click();
    await expect(consolePage.locator('#piv-connection')).toContainText('已连接');
    await consolePage.getByRole('button',{name:'开始制卡并授予角色'}).click();
    await expect(consolePage.locator('#issuance-state')).toContainText('签发完成，角色已授予',{timeout:45000});
    await expect(consolePage.getByRole('button',{name:'开始制卡并授予角色'})).toBeDisabled();
    await Promise.all(approvals);
  }finally{await context.close();}
});

test('new administrator first login guides FIDO2 setup before management access',async({page,context})=>{
  await local(context);await installKey(fixture.onboarding)(page);await login(page,fixture.onboarding);
  await expect(page).toHaveURL(/\/settings\/\?tab=security/);
  await expect(page.getByRole('heading',{name:'欢迎加入管理团队'})).toBeVisible();
  await expect(page.locator('.arco-message')).toHaveCount(0);
  for(const width of [1440,390]){
    await page.setViewportSize({width,height:980});
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
    await page.screenshot({path:path.join(previews,`admin-first-login-${width}.png`),fullPage:true,animations:'disabled'});
    await page.locator('.admin-welcome').screenshot({path:path.join(previews,`admin-first-login-card-${width}.png`),animations:'disabled'});
  }
  await page.evaluate(()=>document.body.setAttribute('arco-theme','dark'));
  await page.locator('.admin-welcome').screenshot({path:path.join(previews,'admin-first-login-dark.png'),animations:'disabled'});
  await page.evaluate(()=>document.body.removeAttribute('arco-theme'));
  const response=page.waitForResponse(response=>response.url().endsWith('/security/admin-setup-finish/'));
  await page.getByRole('button',{name:'验证安全密钥并完成配置'}).click();
  expect((await response).status()).toBe(200);
  await expect(page.getByRole('heading',{name:'欢迎加入管理团队'})).toBeHidden();
  await page.reload();await expect(page.getByRole('heading',{name:'欢迎加入管理团队'})).toBeHidden();
});
