import {test,expect,type Page,type BrowserContext} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
const work=process.env.SHOUGT_UI_WORK!;
const fixture=JSON.parse(fs.readFileSync(path.join(work,'fixture.json'),'utf8'));
const previews=process.env.SHOUGT_UI_PREVIEWS || path.join(work,'previews');
fs.mkdirSync(previews,{recursive:true});
const counters=new Map<string,number>();
async function local(context:BrowserContext){await context.route('**/*',route=>{const url=new URL(route.request().url());return ['localhost','127.0.0.1','privileged.localhost'].includes(url.hostname)&&Number(url.port)>=10000?route.continue():route.abort();});}
async function addKey(page:Page,key:any){
  const cdp=await page.context().newCDPSession(page);await cdp.send('WebAuthn.enable');
  const {authenticatorId}=await cdp.send('WebAuthn.addVirtualAuthenticator',{options:{protocol:'ctap2',transport:'usb',hasResidentKey:true,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true}});
  const credential={credentialId:key.credential_id,isResidentCredential:true,rpId:'localhost',privateKey:key.private_key,userHandle:Buffer.from(String(key.user_id)).toString('base64'),signCount:counters.get(key.credential_id)||key.sign_count};
  await cdp.send('WebAuthn.addCredential',{authenticatorId,credential});
  cdp.on('WebAuthn.credentialAsserted',({credential:value})=>counters.set(key.credential_id,Math.max(counters.get(key.credential_id)||key.sign_count,value.signCount)));
  return {cdp,authenticatorId};
}
test('two different security keys can complete administrator login',async({page,context})=>{
  test.skip(fixture.certified_key,'The high-assurance fixture is exempt from the additional login factor.');
  await local(context);const first=await addKey(page,fixture.dual);
  await page.goto('/login/');await page.getByPlaceholder('你的瓜田账号').fill(fixture.dual.username);
  await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
  await expect(page.getByRole('heading',{name:'再确认一次，是你本人'})).toBeVisible();
  // Simulate unplugging the first key before connecting the second one.
  await first.cdp.send('WebAuthn.removeVirtualAuthenticator',{authenticatorId:first.authenticatorId});
  await first.cdp.detach();
  await addKey(page,fixture.dual_second);
  await page.locator('.arco-select-view').click();await page.getByText('另一把安全密钥',{exact:true}).click();
  await expect(page.getByRole('option',{name:'另一把安全密钥'})).toBeHidden();
  await expect(page.locator('.arco-select-dropdown')).toBeHidden();
  await expect(page.getByText('请连接或轻触另一把已绑定的安全密钥。重复验证第一把密钥无法完成登录。')).toBeVisible();
  await page.screenshot({path:path.join(previews,'dual-key-login.png'),fullPage:true,animations:'disabled'});
  const finished=page.waitForResponse(response=>response.url().endsWith('/security/factor-finish/'));
  await page.getByRole('button',{name:'确认并继续'}).click();
  expect((await finished).status()).toBe(200);
  await expect(page).toHaveURL('http://localhost:15173/');
});

test('global reader has all console sections with writes disabled on desktop and mobile',async({browser})=>{
  const context=await browser.newContext({ignoreHTTPSErrors:true,clientCertificates:[{origin:'https://privileged.localhost:18443',certPath:fixture.reader_certificate,keyPath:fixture.reader_private_key}]});
  await local(context);
  const setup=new Map<Page,Promise<unknown>>();context.on('page',page=>setup.set(page,addKey(page,fixture.reader)));
  try {
    const page=await context.newPage();await setup.get(page);await page.goto('http://localhost:15173/login/');
    await page.getByPlaceholder('你的瓜田账号').fill(fixture.reader.username);await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
    await page.locator('.auth-panel input[type=password]').fill(fixture.reader.password);await page.getByRole('button',{name:'确认并继续'}).click();
    await expect(page).toHaveURL('http://localhost:15173/');await page.goto('http://localhost:15173/settings/?tab=security');
    const popup=context.waitForEvent('page');await page.getByRole('button',{name:'进入独立特权管理站'}).click();
    const consolePage=await popup;await setup.get(consolePage);await expect(consolePage.locator('#workspace')).toBeVisible();
    await expect(consolePage.locator('#read-only-banner')).toBeVisible();
    await expect(consolePage.locator('nav [data-page]')).toHaveCount(6);
    expect(await consolePage.locator('[data-write]').evaluateAll(nodes=>nodes.every(node=>(node as HTMLButtonElement).disabled))).toBe(true);
    await consolePage.getByRole('button',{name:'审计日志'}).click();
    const approval=context.waitForEvent('page');await consolePage.getByRole('button',{name:'查询审计日志'}).click();
    const approvalPage=await approval;await setup.get(approvalPage);
    await approvalPage.getByRole('button',{name:'验证安全密钥并授权'}).click();
    await expect(consolePage.locator('#logs table')).toBeVisible();
    await consolePage.getByRole('button',{name:'权限任命',exact:false}).click();
    // Read-only users query a record from the assignment UI; no standalone page.
    await consolePage.getByRole('button',{name:'查看签发记录'}).click();
    await expect(consolePage.locator('#issuance-dialog')).toBeVisible();
    await expect(consolePage.locator('#issuance-controls')).toBeHidden();
    for(const width of [1440,390]){
      await consolePage.setViewportSize({width,height:980});
      expect(await consolePage.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);
      await consolePage.screenshot({path:path.join(previews,`reader-issuance-${width}.png`),fullPage:true});
    }
  } finally {await context.close();}
});
