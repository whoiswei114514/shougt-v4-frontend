import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';

const front = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const targets = [
  ['src/scripts/djangoWatermark.ts', '../shougt-v0-backend/gt_admin/static/gt_admin/watermark.js'],
  ['src/scripts/consoleWatermark.ts', '../shougt-sa/frontend/watermark.js'],
];
for (const [entry, output] of targets) {
  await build({entryPoints: [path.join(front, entry)], outfile: path.resolve(front, output),
    bundle: true, format: 'iife', platform: 'browser', target: 'es2020', minify: true,
    banner: {js: '// Generated management watermark runtime. See scripts/build-admin-watermark.mjs.'},
    legalComments: 'eof'});
  const artifact = path.resolve(front, output);
  fs.writeFileSync(artifact, fs.readFileSync(artifact, 'utf8').replace(/[ \t]+$/gm, ''));
}
const codec = fs.readFileSync(path.resolve(front, '../shougt-sa/backend/watermark_codec.py'), 'utf8');
fs.writeFileSync(path.resolve(front, '../shougt-v0-backend/gt_admin/watermark_codec.py'),
  '# Generated public wire codec; source: shougt-sa/backend/watermark_codec.py.\n' + codec);
const licenses = [['fft.js', 'README.md'], ['html2canvas', 'LICENSE']].map(([name, file]) => {
  let text = fs.readFileSync(path.join(front, 'node_modules', name, file), 'utf8');
  if (file === 'README.md') {
    const heading = '#### LICENSE';
    if (!text.includes(heading)) throw new Error(`Missing license for ${name}`);
    text = text.slice(text.indexOf(heading) + heading.length).trim();
  }
  return name + '\n' + text.replace(/[ \t]+$/gm, '');
}).join('\n\n');
for (const directory of ['../shougt-sa', '../shougt-v0-backend/gt_admin/static/gt_admin']) {
  fs.writeFileSync(path.resolve(front, directory, 'WATERMARK-LICENSES.txt'), licenses);
}
console.log('Updated both management runtimes and the public wire codec.');
