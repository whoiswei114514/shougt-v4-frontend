import {expect, type Page} from '@playwright/test';

export async function checkWatermarks(page:Page) {
  await expect(page.locator('[data-shou-text-mark]').first()).toBeAttached();
  const result=await page.evaluate(()=>{
    const decode=(text:string)=>{const bit=text.replaceAll('\u2063','').split('').map(c=>c==='\u200c'?'1':'0').join('');return bit.match(/.{4}/g)!.map(b=>parseInt(b,2).toString(16)).join('');};
    const stamp=document.querySelector('[data-shou-text-mark]')!;
    const marker=decode(stamp.textContent!);
    const frequency=document.querySelector<HTMLCanvasElement>('[data-shou-watermark-layer="frequency"]')!;
    const pixel=frequency.getContext('2d')!.getImageData(0,0,128,128).data;
    let recovered='';
    for(let i=0;i<96;i++){
      let correlation=0;
      for(let y=0;y<128;y++)for(let x=0;x<128;x++) correlation+=(pixel[(y*128+x)*4]-128)*Math.cos(2*Math.PI*((3+i%12)*x+(3+Math.floor(i/12))*y)/128);
      recovered+=correlation>0?'1':'0';
    }
    const spectrum=recovered.match(/.{4}/g)!.map(b=>parseInt(b,2).toString(16)).join('');
    const covert=document.querySelector<HTMLCanvasElement>('[data-shou-watermark-layer="covert"]')!.getContext('2d')!;
    let spatial='';
    for(let i=0;i<96;i++)spatial+=covert.getImageData(12+i%16*10,16+Math.floor(i/16)*16,1,1).data[3]>5?'1':'0';
    const spatialMarker=spatial.match(/.{4}/g)!.map(b=>parseInt(b,2).toString(16)).join('');
    const probe=document.createElement('p');probe.id='watermark-dynamic-probe';probe.textContent='动态管理数据';
    (Array.from(document.querySelectorAll('.arco-modal-body')).find(node=>node.getBoundingClientRect().height>0) || document.body).append(probe);
    return {marker,spectrum,spatialMarker,layers:document.querySelectorAll('[data-shou-watermark-layer]').length};
  });
  expect(result.spectrum).toBe(result.marker);
  expect(result.spatialMarker).toBe(result.marker);
  expect(result.layers).toBe(3);
  await expect(page.locator('#watermark-dynamic-probe [data-shou-text-mark]')).toHaveCount(1);
  const copied=await page.locator('#watermark-dynamic-probe').evaluate(probe=>{
    const selection=getSelection()!,range=document.createRange();range.setStart(probe.firstChild!,0);range.setEnd(probe.firstChild!,2);
    selection.removeAllRanges();selection.addRange(range);
    const transfer=new DataTransfer();probe.dispatchEvent(new ClipboardEvent('copy',{bubbles:true,cancelable:true,clipboardData:transfer}));
    selection.removeAllRanges();return transfer.getData('text/plain');
  });
  expect(copied).toMatch(/^动态\u2063[\u200b\u200c]{96}\u2063$/);
  await page.locator('#watermark-dynamic-probe').evaluate(element=>{element.textContent='更新后的管理数据';});
  await expect(page.locator('#watermark-dynamic-probe [data-shou-text-mark]')).toHaveCount(1);
  await page.locator('#watermark-dynamic-probe').evaluate(element=>element.remove());
}
