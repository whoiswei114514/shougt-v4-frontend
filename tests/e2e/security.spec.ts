import { test, expect, type BrowserContext, type Page } from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import { createHmac } from 'node:crypto';
import {checkWatermarks} from './watermark-checks';
const work=process.env.SHOUGT_UI_WORK!;
const fixture=JSON.parse(fs.readFileSync(path.join(work,'fixture.json'),'utf8'));
const previews=process.env.SHOUGT_UI_PREVIEWS || path.join(work,'previews');
fs.mkdirSync(previews,{recursive:true});
let latestCounter=fixture.root.sign_count;
async function localOnly(context:BrowserContext){await context.route('**/*',route=>{const url=new URL(route.request().url());if(['localhost','127.0.0.1','privileged.localhost'].includes(url.hostname)&&Number(url.port)>=10000)return route.continue();return route.abort();});}
async function authenticator(page:Page){
  const cdp=await page.context().newCDPSession(page);await cdp.send('WebAuthn.enable');
  const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  const rootCredential={credentialId:fixture.root.credential_id,isResidentCredential:true,rpId:'localhost',privateKey:fixture.root.private_key,userHandle:Buffer.from(String(fixture.root.user_id)).toString('base64'),signCount:latestCounter};
  await cdp.send('WebAuthn.addCredential',{authenticatorId,credential:rootCredential});
  cdp.on('WebAuthn.credentialAsserted',({credential})=>{if(credential.credentialId===fixture.root.credential_id)latestCounter=Math.max(latestCounter,credential.signCount);});
  await page.exposeFunction('__syncTestKey',async()=>{await cdp.send('WebAuthn.removeCredential',{authenticatorId,credentialId:fixture.root.credential_id});await cdp.send('WebAuthn.addCredential',{authenticatorId,credential:{...rootCredential,signCount:latestCounter}});});
  await page.addInitScript(()=>{const get=navigator.credentials.get.bind(navigator.credentials);navigator.credentials.get=async options=>{await (window as any).__syncTestKey();return get(options);};});
}
async function screenshot(page:Page,name:string){await page.evaluate(()=>document.fonts.ready);await page.locator('img').evaluateAll(images=>Promise.all(images.map(image=>(image as HTMLImageElement).decode().catch(()=>{}))));await page.locator('#nprogress').waitFor({state:'detached'});await page.screenshot({path:path.join(previews,name),fullPage:true,animations:'disabled'});}

function authenticatorCode(secret:string,counter:number){
  const alphabet='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567',bytes:number[]=[];
  let buffer=0,bits=0;
  for(const character of secret){buffer=(buffer<<5)|alphabet.indexOf(character);bits+=5;if(bits>=8){bits-=8;bytes.push((buffer>>bits)&255);}}
  const movingFactor=Buffer.alloc(8);movingFactor.writeBigUInt64BE(BigInt(counter));
  const mac=createHmac('sha1',Buffer.from(bytes)).update(movingFactor).digest();
  return String((mac.readUInt32BE(mac[mac.length-1]&15)&0x7fffffff)%1000000).padStart(6,'0');
}

test('education registration verifies OTP and classifies students',async({page,context})=>{
  await localOnly(context);await page.goto('/register/');
  await expect(page.getByRole('heading',{name:'注册 shou瓜田'})).toBeVisible();
  await screenshot(page,'registration-desktop.png');
  const username='new_ui_'+Date.now();const email=username+'@st.shou.edu.cn';
  await page.getByPlaceholder('设置一个唯一账号').fill(username);await page.getByPlaceholder('name@st.shou.edu.cn').fill(email);
  await page.getByRole('button',{name:'获取验证码'}).click();
  await expect(page.getByText('验证码已发送，10 分钟内有效')).toBeVisible();
  const files=fs.readdirSync(path.join(work,'mail')).filter(file=>file.endsWith('.log')).map(file=>path.join(work,'mail',file)).sort((a,b)=>fs.statSync(b).mtimeMs-fs.statSync(a).mtimeMs);
  const raw=fs.readFileSync(files[0],'utf8');const parts=raw.split(/\r?\n\r?\n/);const body=/Content-Transfer-Encoding: base64/i.test(raw)?Buffer.from(parts[1].replace(/\s/g,''),'base64').toString('utf8'):parts.slice(1).join('\n');
  const code=body.match(/验证码为\s*([0-9]{6})/)?.[1];expect(code).toBeTruthy();
  await page.getByPlaceholder('六位验证码').fill(code!);await page.getByPlaceholder('至少 8 位，避免常见密码').fill(fixture.normal.password);await page.getByPlaceholder('再次输入密码').fill(fixture.normal.password);
  await page.getByRole('button',{name:'创建账号'}).click();await expect(page).toHaveURL(/\/settings\/\?tab=security/);
  await expect(page.getByText('教育邮箱 · 已验证')).toBeVisible();await expect(page.getByText('上海海洋大学 · 学生')).toBeVisible();
});

test('disabled human verification allows posting comments and check-in after captcha expiry',async({page,context})=>{
  await localOnly(context);
  const captchaRequests:string[]=[];
  context.on('request',request=>{
    if (/\/api\/user\/captcha\//.test(request.url()) || new URL(request.url()).hostname === 'captcha.shouguatian.com') captchaRequests.push(request.url());
  });
  await context.route('**/api/user/info/**',async route=>{
    const response=await route.fetch();
    await route.fulfill({response,json:{...await response.json(),captcha_expire_time:0}});
  });
  await page.goto('/login/');
  await page.getByText('密码',{exact:true}).first().click();
  await page.getByPlaceholder('你的瓜田账号').fill(fixture.normal.username);
  await page.getByPlaceholder('请输入密码').fill(fixture.normal.password);
  const loginResponse=page.waitForResponse(response=>response.url().includes('/security/password-login/'));
  await page.getByRole('button',{name:'登录',exact:true}).click();
  expect((await (await loginResponse).json()).captcha_required).toBe(false);
  await expect(page).toHaveURL('http://localhost:15173/');
  await page.reload();
  await expect(page.locator('.post-list')).toBeVisible();
  await page.locator('.arco-layout-header').getByText('签到',{exact:true}).click();
  await expect(page.locator('.arco-layout-header').getByText('已签到',{exact:true})).toBeVisible();

  await page.goto('/edit/');
  const content='无需人机验证的角色内讨论 '+Date.now();
  await page.getByPlaceholder('记录此刻...').fill(content);
  await page.getByText('仅我可见',{exact:true}).click();
  await page.getByRole('button',{name:'发布',exact:true}).click();
  await expect(page).toHaveURL(/\/moment\/\d+\//);
  await expect(page.getByText(content,{exact:true})).toBeVisible();
  const comment='无需图形验证码的回复';
  await page.getByPlaceholder('请输入评论').fill(comment);
  await page.getByRole('button',{name:'评论',exact:true}).click();
  await expect(page.getByText(comment,{exact:true})).toBeVisible();
  await expect(page.getByRole('dialog',{name:'人机验证',exact:true})).toHaveCount(0);
  expect(captchaRequests).toEqual([]);
});

test('browser WebAuthn registration and passkey login work on desktop and mobile',async({page,context})=>{
  await localOnly(context);await authenticator(page);await page.goto('/login/');
  await screenshot(page,'login-desktop.png');
  await page.getByText('密码',{exact:true}).first().click();await page.getByPlaceholder('你的瓜田账号').fill(fixture.normal.username);await page.getByPlaceholder('请输入密码').fill(fixture.normal.password);
  await page.getByRole('button',{name:'登录',exact:true}).click();await expect(page).toHaveURL('http://localhost:15173/');
  await page.goto('/security/');await page.getByPlaceholder('用于确认此次安全设置').fill(fixture.normal.password);await page.getByPlaceholder('例如：随身安全密钥').fill('浏览器测试密钥');
  await page.getByRole('button',{name:'绑定新凭据'}).click();await expect(page.getByText('凭据已绑定',{exact:true})).toBeVisible();await expect(page.getByText('浏览器测试密钥',{exact:true})).toBeVisible();
  await screenshot(page,'security-center.png');
  await page.evaluate(()=>{sessionStorage.clear();localStorage.clear();});await page.goto('/login/');await page.getByPlaceholder('你的瓜田账号').fill(fixture.normal.username);await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();await expect(page).toHaveURL('http://localhost:15173/');
  await page.goto('/security/');await expect(page.getByText('本次登录 · 通行密钥')).toBeVisible();
  await page.evaluate(()=>{sessionStorage.clear();localStorage.clear();});await page.setViewportSize({width:390,height:844});await page.goto('/login/');await expect(page.getByRole('heading',{name:'登录',exact:true})).toBeVisible();
  expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBeTruthy();await screenshot(page,'login-mobile.png');
});

test('primary management badge stays public while real-name visibility changes',async({page,context,browser})=>{
  test.skip(fixture.certified_key, 'This case exercises the ordinary hardware trust profile.');
  await localOnly(context);await authenticator(page);
  await page.goto('/login/');
  await page.getByPlaceholder('你的瓜田账号').fill(fixture.root.username);
  await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
  await page.locator('.auth-panel input[type=password]').fill(fixture.root.password);
  await page.getByRole('button',{name:'确认并继续'}).click();
  await expect(page).toHaveURL('http://localhost:15173/');
  await page.goto('/settings/?tab=account');
  await expect(page.getByRole('heading',{name:'基础信息',exact:true})).toBeVisible();
  await screenshot(page,'settings-account.png');
  await page.goto('/settings/?tab=security');
  await expect(page.getByText('本次登录 · 安全密钥',{exact:true})).toHaveClass(/complete/);
  await expect(page.locator('.security-key-gold')).toHaveCount(0);
  await screenshot(page,'settings-security-unified.png');
  const hidden=page.getByRole('switch',{name:'隐藏公开的实名信息'});
  await expect(hidden).toBeChecked();
  await expect(page.getByText('隐藏公开的管理认证',{exact:true})).toHaveCount(0);
  await expect(page.getByRole('link',{name:'查看主角色'})).toHaveAttribute('href',`/role/${fixture.root.primary_role_id}/`);

  const visitorContext=await browser.newContext();
  await localOnly(visitorContext);
  const visitor=await visitorContext.newPage();
  try {
    await visitor.goto(`http://localhost:15173/role/${fixture.root.primary_role_id}/`);
    await expect(visitor.locator('.role-certification').filter({hasText:'超级管理员'})).toBeVisible();
    await expect(visitor.getByText('已实名',{exact:true})).toHaveCount(0);
    const showResponse=page.waitForResponse(response=>response.url().includes('/security/privacy/') && response.request().method()==='POST');
    await hidden.click();
    expect((await (await showResponse).json()).show_real_name).toBe(true);
    await expect(hidden).not.toBeChecked();
    await visitor.reload();
    await visitor.getByText('已实名',{exact:true}).hover();
    await expect(visitor.getByText(`实名信息：${fixture.root.real_name}(${fixture.root.student_id})`,{exact:true})).toBeVisible();
    const hideResponse=page.waitForResponse(response=>response.url().includes('/security/privacy/') && response.request().method()==='POST');
    await hidden.click();
    expect((await (await hideResponse).json()).show_real_name).toBe(false);
    await expect(hidden).toBeChecked();
    await visitor.reload();
    await expect(visitor.locator('.role-certification').filter({hasText:'超级管理员'})).toBeVisible();
    await expect(visitor.getByText('已实名',{exact:true})).toHaveCount(0);
    await screenshot(visitor,'primary-admin-private-name.png');
    await page.goto('/settings/?tab=role');
    await expect(page.getByRole('switch',{name:'展示实名信息'})).not.toBeChecked();
    await expect(page.getByRole('button',{name:'删除角色',exact:true})).toHaveCount(0);
  } finally { await visitorContext.close(); }
});

test('certified key shows gold levels on hover focus and touch',async({page,context,browser})=>{
  test.skip(!fixture.certified_key, 'Run this case with SHOUGT_UI_CERTIFIED_KEY=1 in an isolated fixture.');
  await localOnly(context);await authenticator(page);
  await page.goto('/login/');
  await page.getByPlaceholder('你的瓜田账号').fill(fixture.root.username);
  await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
  await expect(page).toHaveURL('http://localhost:15173/');
  const statusResponse=page.waitForResponse(response=>response.url().includes('/security/status/'));
  await page.goto('/settings/?tab=security');
  const status=await (await statusResponse).json();
  expect(status.session_key_assurance.high_assurance).toBe(true);
  expect(status.session_key_assurance.certifications).toEqual(['FIPS 140-2 L2','CC EAL4+']);
  const badge=page.getByRole('button',{name:'本次登录 · 安全密钥，查看安全等级'});
  const tooltip=page.locator('#security-key-levels');
  await expect(badge).toHaveClass(/security-key-gold/);
  await expect(tooltip).not.toBeVisible();
  await badge.hover();
  await expect(tooltip.getByText('FIPS 140-2 L2',{exact:true})).toBeVisible();
  await expect(tooltip.getByText('CC EAL4+',{exact:true})).toBeVisible();
  await expect(badge).toHaveAttribute('aria-expanded','true');
  await screenshot(page,'certified-key-gold-desktop.png');
  await page.mouse.move(0,0);
  await badge.focus();
  await expect(tooltip).toBeVisible();
  await page.keyboard.press('Escape');
  await expect(tooltip).not.toBeVisible();
  await page.evaluate(()=>document.body.setAttribute('arco-theme','dark'));
  await badge.hover();
  await expect(tooltip).toBeVisible();
  expect(await badge.evaluate(element=>getComputedStyle(element).color)).toBe('rgb(240, 209, 138)');
  await screenshot(page,'certified-key-gold-dark.png');
  const mobileContext=await browser.newContext({viewport:{width:390,height:844},hasTouch:true,isMobile:true,colorScheme:'dark',reducedMotion:'reduce'});
  await localOnly(mobileContext);
  const mobile=await mobileContext.newPage();await authenticator(mobile);
  try {
    await mobile.goto('http://localhost:15173/login/');
    await mobile.getByPlaceholder('你的瓜田账号').fill(fixture.root.username);
    await mobile.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).tap();
    await expect(mobile).toHaveURL('http://localhost:15173/');
    await mobile.goto('http://localhost:15173/settings/?tab=security');
    const mobileBadge=mobile.getByRole('button',{name:'本次登录 · 安全密钥，查看安全等级'});
    await mobileBadge.tap();
    await expect(mobileBadge).toHaveAttribute('aria-expanded','true');
    await expect(mobile.locator('#security-key-levels')).toBeVisible();
    expect(await mobileBadge.evaluate(element=>getComputedStyle(element,'::after').display)).toBe('none');
    expect(await mobile.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
    const bounds=await mobile.locator('#security-key-levels').boundingBox();
    expect(bounds!.x).toBeGreaterThanOrEqual(0);
    expect(bounds!.x+bounds!.width).toBeLessThanOrEqual(390);
    await screenshot(mobile,'certified-key-gold-mobile.png');
  } finally { await mobileContext.close(); }
});

test('independent mTLS console requires the original FIDO key for database operations',async({browser})=>{
  const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1000},clientCertificates:[{origin:'https://privileged.localhost:18443',certPath:fixture.client_certificate,keyPath:fixture.client_key}]});
  await localOnly(context);
  const setups=new Map<Page,Promise<void>>();context.on('page',page=>{setups.set(page,authenticator(page));});
  const page=await context.newPage();await setups.get(page);await page.goto('http://localhost:15173/login/');await page.getByPlaceholder('你的瓜田账号').fill(fixture.root.username);await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
  await expect(page.getByRole('heading',{name:'再确认一次，是你本人'})).toBeVisible();await page.locator('.auth-panel input[type=password]').fill(fixture.root.password);await page.getByRole('button',{name:'确认并继续'}).click();await expect(page).toHaveURL('http://localhost:15173/');
  await page.goto('http://localhost:15173/security/');
  await expect(page.getByText('实名取认证邮件的发件人称呼，学号按“院校缩写-邮箱前缀”生成。发信前，请将教育邮箱的发件人称呼设置为本人姓名。',{exact:true})).toBeVisible();
  await expect(page.getByPlaceholder('与认证材料、客户端证书一致的姓名')).toHaveCount(0);
  const popup=context.waitForEvent('page');await page.getByRole('button',{name:'进入独立特权管理站'}).click();const consolePage=await popup;await setups.get(consolePage);await expect(consolePage).toHaveURL(/https:\/\/privileged\.localhost:18443/);await expect(consolePage.locator('#workspace')).toBeVisible();
  const approvalWindow=context.waitForEvent('page');await consolePage.getByRole('button',{name:'查找用户',exact:true}).click();const approval=await approvalWindow;await setups.get(approval);await expect(approval.getByRole('heading',{name:'确认这一次管理操作'})).toBeVisible();await approval.getByRole('button',{name:'验证安全密钥并授权'}).click();
  await expect(consolePage.locator('#users')).toContainText('ui_root');await checkWatermarks(consolePage);await screenshot(consolePage,'privileged-console.png');
  await context.close();
});

test('revoked remembered session returns to login on reload',async({page,context})=>{
  await localOnly(context);await page.goto('/login/');
  await page.getByText('密码',{exact:true}).first().click();
  await page.getByPlaceholder('你的瓜田账号').fill(fixture.normal.username);
  await page.getByPlaceholder('请输入密码').fill(fixture.normal.password);
  await page.getByRole('button',{name:'登录',exact:true}).click();
  await expect(page).toHaveURL('http://localhost:15173/');
  const request=context.waitForEvent('request',request=>request.url().includes('/api/security/status/'));
  await page.goto('/settings/?tab=security');
  const authorization=(await request).headers()['authorization'];
  expect(authorization).toBeTruthy();
  expect((await context.request.post('http://localhost:15173/api/security/logout/',{headers:{Authorization:authorization}})).ok()).toBeTruthy();
  await page.reload();
  await expect(page).toHaveURL(/\/login\//);
  await expect(page.getByRole('heading',{name:'登录',exact:true})).toBeVisible();
  await page.reload();
  await expect(page.getByRole('heading',{name:'登录',exact:true})).toBeVisible();
});

for (const popupBlocked of [false,true]) test(`super admin impersonation ${popupBlocked?'manual fallback':'automatic handoff'} keeps the original admin session`,async({browser})=>{
  const context=await browser.newContext({ignoreHTTPSErrors:true,viewport:{width:1440,height:1000},clientCertificates:[{origin:'https://privileged.localhost:18443',certPath:fixture.client_certificate,keyPath:fixture.client_key}]});
  await localOnly(context);
  const setups=new Map<Page,Promise<void>>();context.on('page',page=>{setups.set(page,authenticator(page));});
  const admin=await context.newPage();await setups.get(admin);
  await admin.goto('http://localhost:15173/login/');
  await admin.getByText('记住这次登录',{exact:true}).click();
  await admin.getByPlaceholder('你的瓜田账号').fill(fixture.root.username);
  await admin.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
  await admin.locator('.auth-panel input[type=password]').fill(fixture.root.password);
  await admin.getByRole('button',{name:'确认并继续'}).click();
  await expect(admin).toHaveURL('http://localhost:15173/');
  const persistedIdentity = (page:Page) => page.evaluate(() => {
    const saved=JSON.parse(localStorage.getItem('persistStorage') || '{}');
    return {user_id:saved.authorization?.payload.user_id,role_id:saved.roleId,remember_me:saved.remember_me};
  });
  const originalAdmin=await persistedIdentity(admin);
  expect(originalAdmin.remember_me).toBe(true);
  await admin.goto('http://localhost:15173/settings/?tab=security');
  const consoleOpened=context.waitForEvent('page');
  await admin.getByRole('button',{name:'进入独立特权管理站'}).click();
  const consolePage=await consoleOpened;await setups.get(consolePage);
  await expect(consolePage.locator('#workspace')).toBeVisible();
  await consolePage.locator('nav button[data-page="profile"]').click();
  await consolePage.locator('#profile-id').fill(String(fixture.normal.user_id));
  async function authorize(button:string) {
    const opened=context.waitForEvent('page');await consolePage.locator(button).click();
    const approval=await opened;await setups.get(approval);
    await approval.getByRole('button',{name:'验证安全密钥并授权'}).click();
    await expect(consolePage.locator('#authorize-dialog')).not.toBeVisible();
    return approval;
  }
  await authorize('#load-profile');
  await expect(consolePage.locator('#field-username')).toHaveValue(fixture.normal.username);
  await consolePage.locator('#profile-reason').fill('浏览器回归检查临时代登录');
  let target:Page;
  if (popupBlocked) {
    await consolePage.evaluate(() => { window.open = () => null; });
    await consolePage.locator('#impersonate').click();
    await expect(consolePage.locator('#authorize-dialog')).toBeVisible();
    const manualApproval=context.waitForEvent('page');
    await consolePage.locator('#authorize-link').click();
    const approval=await manualApproval;await setups.get(approval);
    await approval.getByRole('button',{name:'验证安全密钥并授权'}).click();
    await expect(consolePage.locator('#authorize-dialog')).not.toBeVisible();
    const opened=context.waitForEvent('page');
    await consolePage.getByRole('link',{name:'进入临时代登录会话',exact:true}).click();
    target=await opened;await setups.get(target);
  } else {
    await consolePage.clock.install();
    await authorize('#view-hash');
    target=await authorize('#impersonate');
    await consolePage.clock.fastForward(61000);
    await expect(consolePage.locator('#password-parts')).not.toBeVisible();
    await expect(consolePage.locator('#impersonation-result a[href]')).toBeVisible();
  }
  await expect(target.getByText(`正在代登录 ${fixture.normal.username}`,{exact:false})).toBeVisible();
  await expect(target).toHaveURL('http://localhost:15173/');
  expect(await persistedIdentity(target)).toEqual(originalAdmin);
  await target.getByText('切换角色',{exact:true}).first().click();
  await target.locator('.arco-modal:visible .arco-select').click();
  await target.locator('.arco-select-dropdown:visible').getByText(fixture.normal.alternate_role_name,{exact:true}).first().click();
  await target.locator('.arco-modal:visible').getByRole('button',{name:'确定',exact:true}).click();
  expect(await persistedIdentity(target)).toEqual(originalAdmin);
  await target.reload();
  await expect(target.getByText(`正在代登录 ${fixture.normal.username}`,{exact:false})).toBeVisible();
  expect(await target.evaluate(()=>JSON.parse(sessionStorage.getItem('__default__') || '{}').roleId)).toBe(fixture.normal.alternate_role_id);
  await admin.reload();
  await expect(admin.getByRole('button',{name:'进入独立特权管理站'})).toBeVisible();
  await expect(admin.getByText('结束代登录',{exact:true})).toHaveCount(0);
  await target.getByText('结束代登录',{exact:true}).click();
  await expect(target.getByText('结束代登录',{exact:true})).toHaveCount(0);
  expect(await persistedIdentity(target)).toEqual(originalAdmin);
  await admin.reload();
  await expect(admin.getByRole('button',{name:'进入独立特权管理站'})).toBeVisible();
  await context.close();
});

test('user list creates ordinary users and watermarks text without changing input values',async({page,context})=>{
  await localOnly(context);await authenticator(page);await page.goto('/login/');
  await page.getByPlaceholder('你的瓜田账号').fill(fixture.root.username);
  await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
  await page.locator('.auth-panel input[type=password]').fill(fixture.root.password);
  await page.getByRole('button',{name:'确认并继续'}).click();
  await expect(page).toHaveURL('http://localhost:15173/');
  await page.goto('/admin/user/');
  await page.getByRole('button',{name:'创建用户',exact:true}).click();
  const username='admin_created_'+Date.now();
  await page.getByPlaceholder('新用户的登录账号').fill(username);
  await page.getByPlaceholder('至少 8 位，避免常见密码').fill(fixture.normal.password);
  await page.getByPlaceholder('新用户的教育邮箱').fill(username+'@st.shou.edu.cn');
  await expect(page.getByRole('button',{name:'获取验证码',exact:true})).toHaveCount(0);
  await checkWatermarks(page);
  await expect(page.getByPlaceholder('新用户的登录账号')).toHaveValue(username);
  const response=page.waitForResponse(response=>response.url().endsWith('/api/admin/user/')&&response.request().method()==='POST');
  await page.getByRole('button',{name:'确认创建',exact:true}).click();
  const result=await response;expect(result.status()).toBe(201);expect(JSON.stringify(result.request().postDataJSON())).not.toMatch(/[\u2063\u200b\u200c]/);
  const created=await result.json();expect(created.data.email_verified_at).toBeNull();expect(created.data.student_id).toBe('shou-'+username);
  expect(result.request().postDataJSON()).not.toHaveProperty('code');
  await expect(page.getByRole('cell',{name:username,exact:true})).toBeVisible();
  await expect(page.getByPlaceholder('新用户的登录账号')).toBeHidden();
  await screenshot(page,'admin-user-list.png');
  await page.goto('/settings/?tab=security');
  await expect(page.locator('[data-shou-text-mark]')).toHaveCount(0);
});

test('post pinning from management survives reload and keeps the original visibility',async({page,context})=>{
  test.skip(fixture.certified_key,'Run with the ordinary hardware trust profile.');
  await localOnly(context);await authenticator(page);
  await page.goto('/login/');
  await page.getByPlaceholder('你的瓜田账号').fill(fixture.root.username);
  await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
  await page.locator('.auth-panel input[type=password]').fill(fixture.root.password);
  await page.getByRole('button',{name:'确认并继续'}).click();
  await expect(page).toHaveURL('http://localhost:15173/');
  await page.goto('/admin/post/');
  const row=page.getByRole('row').filter({hasText:fixture.pin_post.title});
  await row.getByRole('link',{name:'编辑',exact:true}).click();
  const toggle=page.getByRole('switch',{name:'置顶帖子',exact:true});
  await expect(toggle).not.toBeChecked();
  const pin=page.waitForResponse(response=>response.url().endsWith(`/api/admin/post/${fixture.pin_post.id}/pin/`));
  await toggle.click();
  expect((await pin).status()).toBe(200);
  await expect(toggle).toBeChecked();
  await page.reload();
  await expect(toggle).toBeChecked();
  await screenshot(page,'post-pinning-management.png');
  await page.goto('/admin/post/');
  await expect(page.getByRole('row').filter({hasText:fixture.pin_post.title})).toContainText('已置顶');
  const posts=await context.request.get('http://localhost:15173/api/post/');
  const first=(await posts.json()).results[0];
  expect(first.id).toBe(fixture.pin_post.id);expect(first.share_with).toBe(0);expect(first.review_status).toBe(0);
  await page.getByRole('row').filter({hasText:fixture.pin_post.title}).getByRole('link',{name:'编辑',exact:true}).click();
  const unpin=page.waitForResponse(response=>response.url().endsWith(`/api/admin/post/${fixture.pin_post.id}/pin/`));
  await toggle.click();
  expect((await unpin).status()).toBe(200);
  await expect(toggle).not.toBeChecked();
});

for(const account of ['normal','root'] as const) test(`TOTP binding renders a QR and completes ${account} login`,async({page,context})=>{
  test.skip(fixture.certified_key,'Run with the ordinary hardware trust profile.');
  await localOnly(context);
  if(account==='root')await authenticator(page);
  const errors:string[]=[];page.on('pageerror',error=>errors.push(error.message));
  const user=fixture[account];
  const signIn=async()=>{
    await page.goto('/login/');
    if(account==='normal')await page.getByText('密码',{exact:true}).first().click();
    await page.getByPlaceholder('你的瓜田账号').fill(user.username);
    if(account==='normal')await page.getByPlaceholder('请输入密码').fill(user.password);
    await page.getByRole('button',{name:account==='root'?'使用安全密钥或通行密钥登录':'登录',exact:true}).click();
  };
  await signIn();
  if(account==='root'){
    await page.locator('.auth-panel input[type=password]').fill(user.password);
    await page.getByRole('button',{name:'确认并继续'}).click();
  }
  await expect(page).toHaveURL('http://localhost:15173/');
  await page.goto('/settings/?tab=security');
  await expect(page.getByRole('heading',{name:'账号安全中心',exact:true})).toBeVisible();
  if(account==='normal')await page.getByPlaceholder('用于确认此次安全设置').fill(user.password);
  const start=page.getByRole('button',{name:'设置二次验证器',exact:true});
  await expect(start).not.toHaveClass(/arco-btn-loading/);
  const setupResponse=page.waitForResponse(response=>response.url().endsWith('/api/security/totp-begin/'),{timeout:15000});
  await start.click();
  const response=await setupResponse;expect(response.status()).toBe(200);
  const setup=await response.json();
  await expect.poll(()=>errors).toEqual([]);
  await expect(page.locator('.totp-setup img')).toHaveAttribute('src',/^data:image\/png;base64,/);
  await expect.poll(()=>page.locator('.totp-setup img').evaluate(element=>(element as HTMLImageElement).naturalWidth)).toBeGreaterThan(0);
  const secret=(await page.locator('.totp-secret').innerText()).trim();
  expect(secret).toBe(setup.secret);
  const uri=new URL(setup.uri);expect(uri.protocol).toBe('otpauth:');expect(uri.hostname).toBe('totp');
  expect(uri.searchParams.get('secret')).toBe(secret);expect(uri.searchParams.get('issuer')).toBe('shou瓜田');
  const counter=Math.floor(Date.now()/30000);
  await page.getByPlaceholder('六位动态验证码').fill(authenticatorCode(secret,counter));
  await page.getByRole('button',{name:'确认启用',exact:true}).click();
  await expect(page.getByText('二次验证器 · 已启用',{exact:true})).toBeVisible();
  await expect(page.locator('.totp-setup')).toHaveCount(0);
  await page.reload();
  await expect(page.getByText('二次验证器 · 已启用',{exact:true})).toBeVisible();
  await page.evaluate(()=>{sessionStorage.clear();localStorage.clear();});
  await signIn();
  await expect(page.getByRole('heading',{name:'再确认一次，是你本人'})).toBeVisible();
  await page.getByPlaceholder('000000').fill(authenticatorCode(secret,Math.max(counter+1,Math.floor(Date.now()/30000))));
  await page.getByRole('button',{name:'确认并继续'}).click();
  await expect(page).toHaveURL('http://localhost:15173/');
  expect(errors).toEqual([]);
});
