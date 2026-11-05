import { readFile, writeFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { Resvg } from '@resvg/resvg-js';
const directory=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../public');
const svg=await readFile(path.join(directory,'logo.svg'),'utf8');
const png=size=>new Resvg(svg,{fitTo:{mode:'width',value:size}}).render().asPng();
for(const [name,size] of [['pwa-64x64.png',64],['pwa-192x192.png',192],['pwa-512x512.png',512],['apple-touch-icon-180x180.png',180],['maskable-icon-512x512.png',512]])await writeFile(path.join(directory,name),png(size));
const sizes=[16,32,48], images=sizes.map(png), header=Buffer.alloc(6+16*sizes.length);header.writeUInt16LE(1,2);header.writeUInt16LE(sizes.length,4);let offset=header.length;
for(let i=0;i<sizes.length;i++){const pos=6+i*16;header[pos]=header[pos+1]=sizes[i];header.writeUInt16LE(1,pos+4);header.writeUInt16LE(32,pos+6);header.writeUInt32LE(images[i].length,pos+8);header.writeUInt32LE(offset,pos+12);offset+=images[i].length;}
await writeFile(path.join(directory,'favicon.ico'),Buffer.concat([header,...images]));
process.stdout.write('Generated shou icons from the original SVG artwork.\n');
