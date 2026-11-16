import {expect, type Page} from '@playwright/test';
import fs from 'node:fs';
import path from 'node:path';
import {spawnSync} from 'node:child_process';

let sequence=0;
export function analyzeWatermarkFile(file:string) {
  const consoleApp=path.resolve('../shougt-sa');
  const python=path.join(consoleApp,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
  const result=spawnSync(python,['-m','backend.watermark_detection',file,'--scale','1'],{
    cwd:consoleApp,encoding:'utf8',env:{...process.env,PYTHONIOENCODING:'utf-8'},
    maxBuffer:8*1024*1024,windowsHide:true,
  });
  expect(result.status,result.stderr).toBe(0);
  return JSON.parse(result.stdout);
}

export async function checkWatermarks(page:Page) {
  await expect(page.locator('[data-shou-text-mark]').first()).toBeAttached();
  await expect(page.locator('[data-shou-watermark-layer="frequency"]')).toHaveAttribute('data-shou-watermark-version','2');
  const result=await page.evaluate(()=>{
    const decode=(text:string)=>{const bit=text.replaceAll('\u2063','').split('').map(c=>c==='\u200c'?'1':'0').join('');return bit.match(/.{4}/g)!.map(b=>parseInt(b,2).toString(16)).join('');};
    const stamp=document.querySelector('[data-shou-text-mark]')!;
    const marker=decode(stamp.textContent!);
    const images=Array.from(document.querySelectorAll<HTMLCanvasElement>('[data-shou-watermark-layer]'))
      .filter(canvas=>canvas.dataset.shouWatermarkLayer!=='visible')
      .map(canvas=>({kind:canvas.dataset.shouWatermarkLayer!,png:canvas.toDataURL('image/png')}));
    const probe=document.createElement('p');probe.id='watermark-dynamic-probe';probe.textContent='动态管理数据';
    (Array.from(document.querySelectorAll('.arco-modal-body')).find(node=>node.getBoundingClientRect().height>0) || document.body).append(probe);
    return {marker,images,layers:document.querySelectorAll('[data-shou-watermark-layer]').length};
  });
  const work=process.env.SHOUGT_UI_WORK!,current=++sequence;
  let token:string|undefined;
  for(const image of result.images) {
    const file=path.join(work,`watermark-v2-${current}-${image.kind}.png`);
    fs.writeFileSync(file,Buffer.from(image.png.split(',')[1],'base64'));
    const report=analyzeWatermarkFile(file),payload=report.payloads.find((item:any)=>
      item.sources.includes(image.kind==='covert'?'spatial_v2':image.kind==='frequency'?'frequency_v2':'lsb_v2'));
    expect(payload,`No complete ${image.kind} payload in ${file}`).toBeTruthy();
    expect(payload.watermark_id).toBe(result.marker);
    expect(payload.actor_id).toBeGreaterThan(0);
    expect(payload.audit_id).toBeGreaterThan(0);
    expect(payload.operation_at).toBeTruthy();
    if(token)expect(payload.token).toBe(token);else token=payload.token;
  }
  const screenshot=path.join(work,`watermark-v2-${current}-screenshot.png`);
  await page.screenshot({path:screenshot});
  expect(analyzeWatermarkFile(screenshot).payloads.some((item:any)=>item.watermark_id===result.marker)).toBe(true);
  expect(result.layers).toBe(4);
  await expect(page.locator('#watermark-dynamic-probe [data-shou-text-mark]')).toHaveCount(1);
  const copied=await page.locator('#watermark-dynamic-probe').evaluate(probe=>{
    const selection=getSelection()!,range=document.createRange();range.setStart(probe.firstChild!,0);range.setEnd(probe.firstChild!,2);
    selection.removeAllRanges();selection.addRange(range);
    const transfer=new DataTransfer();probe.dispatchEvent(new ClipboardEvent('copy',{bubbles:true,cancelable:true,clipboardData:transfer}));
    selection.removeAllRanges();return transfer.getData('text/plain');
  });
  expect(copied).toMatch(/^动态\u2063[\u200b\u200c]{96}\u2063\u2063\u2063[\u200b\u200c]+\u2063\u2063$/);
  await page.locator('#watermark-dynamic-probe').evaluate(element=>{element.textContent='更新后的管理数据';});
  await expect(page.locator('#watermark-dynamic-probe [data-shou-text-mark]')).toHaveCount(1);
  await page.locator('#watermark-dynamic-probe').evaluate(element=>element.remove());
}
