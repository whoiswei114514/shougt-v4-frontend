import {test,expect} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
const fixture=JSON.parse(fs.readFileSync(path.join(process.env.SHOUGT_UI_WORK!,'fixture.json'),'utf8'));
test('contact smartcard logs in and binds a credential through the real FIDO2 client',async({page,context})=>{
  await context.route('**/*',route=>{const url=new URL(route.request().url());return ['localhost','127.0.0.1','privileged.localhost'].includes(url.hostname)&&Number(url.port)>=10000?route.continue():route.abort();});
  await page.goto('http://localhost:15173/login/');
  await expect(page.getByRole('button',{name:'使用接触式智能卡登录'})).toHaveCount(0);
  await page.goto('http://localhost:15173/login/?pcsc=1');
  await page.getByPlaceholder('你的瓜田账号').fill(fixture.contact_card.username);
  await page.getByRole('button',{name:'使用接触式智能卡登录'}).click();
  const modal=page.locator('.arco-modal').filter({has:page.getByText('连接接触式智能卡',{exact:true})});
  await expect(modal).toBeVisible();
  await modal.getByPlaceholder('接触式 FIDO2 工具的配对码').fill(fixture.fido_pair_code);
  await modal.getByRole('button',{name:'检测智能卡'}).click();
  await expect(modal).toContainText('已检测到智能卡');
  for(const width of [1440,390]){
    await page.setViewportSize({width,height:980});
    expect(await modal.evaluate(node=>node.scrollWidth<=node.clientWidth+1)).toBe(true);
    await page.screenshot({path:path.join(process.env.SHOUGT_UI_PREVIEWS!,`contact-fido2-${width}.png`),animations:'disabled'});
  }
  await page.evaluate(()=>document.body.setAttribute('arco-theme','dark'));
  await page.screenshot({path:path.join(process.env.SHOUGT_UI_PREVIEWS!,'contact-fido2-dark.png'),animations:'disabled'});
  await page.evaluate(()=>document.body.removeAttribute('arco-theme'));
  await modal.getByRole('button',{name:/^(确定|OK)$/}).click();
  await expect(page).toHaveURL('http://localhost:15173/');
  await page.goto('http://localhost:15173/settings/?tab=security');
  await page.getByPlaceholder('例如：随身安全密钥').fill('接触式卡新凭据');
  await page.getByRole('button',{name:'绑定新凭据'}).click();
  await expect(page.locator('.key-name').filter({hasText:'接触式卡新凭据'})).toBeVisible();
});

test('mobile Android browser defaults to non-discoverable NFC key registration and logs in cleanly',async({browser})=>{
  const context=await browser.newContext({
    viewport:{width:390,height:844},
    userAgent:'Mozilla/5.0 (Linux; Android 15; Pixel 9) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Mobile Safari/537.36 EdgA/135.0.0.0',
  });
  await context.route('**/*',route=>{const url=new URL(route.request().url());return ['localhost','127.0.0.1','privileged.localhost'].includes(url.hostname)&&Number(url.port)>=10000?route.continue():route.abort();});
  try{
    const page=await context.newPage();
    const cdp=await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable');
    await cdp.send('WebAuthn.addVirtualAuthenticator',{
      options:{protocol:'ctap2',transport:'nfc',hasResidentKey:false,hasUserVerification:true,isUserVerified:true,automaticPresenceSimulation:true},
    });
    await page.goto('http://localhost:15173/login/');
    await page.getByText('密码',{exact:true}).first().click();
    await page.getByPlaceholder('你的瓜田账号').fill(fixture.normal.username);
    await page.getByPlaceholder('请输入密码').fill(fixture.normal.password);
    await page.getByRole('button',{name:'登录',exact:true}).click();
    await expect(page).toHaveURL('http://localhost:15173/');

    await page.goto('http://localhost:15173/settings/?tab=security');
    await expect(page.locator('#security-key-setup')).toBeVisible();
    expect(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth+1)).toBe(true);

    const beginReqPromise=page.waitForRequest(req=>req.url().includes('/security/key-register-begin/')&&req.method()==='POST');
    await page.getByPlaceholder('用于确认此次安全设置').fill(fixture.normal.password);
    await page.getByPlaceholder('例如：随身安全密钥').fill('移动 NFC 智能卡');
    await page.getByRole('button',{name:'绑定新凭据'}).click();
    const beginReq=await beginReqPromise;
    expect(beginReq.postDataJSON().resident_key).toBe('discouraged');
    await expect(page.locator('.key-name').filter({hasText:'移动 NFC 智能卡'})).toBeVisible();

    await context.clearCookies();
    await page.evaluate(()=>{localStorage.clear();sessionStorage.clear();});
    await page.goto('http://localhost:15173/login/');
    await page.getByPlaceholder('你的瓜田账号').fill(fixture.normal.username);
    await page.getByRole('button',{name:'使用安全密钥或通行密钥登录'}).click();
    await expect(page).toHaveURL('http://localhost:15173/');
  }finally{
    await context.close();
  }
});
