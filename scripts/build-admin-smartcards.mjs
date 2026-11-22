import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {build} from 'esbuild';

const front = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const target = path.resolve(front, '../shougt-sa/frontend/piv-webusb.js');
await build({
  entryPoints: [path.join(front, 'src/scripts/webpiv/console.js')],
  outfile: target, bundle: true, format: 'iife', platform: 'browser', target: 'es2022',
  minify: true, legalComments: 'eof',
  banner: {js: '// Generated browser PIV runtime. Source: shougt-v4-frontend/src/scripts/webpiv; npm run build:smartcards.'},
});
const packages = ['pkijs', 'asn1js', 'pvutils', 'pvtsutils', 'bytestreamjs', '@noble/hashes', 'tslib', 'crypto-js'];
const licenses = packages.map(name => {
  const directory = path.join(front, 'node_modules', name);
  const file = ['LICENSE', 'LICENSE.txt', 'LICENSE.md', 'CopyrightNotice.txt'].find(file => fs.existsSync(path.join(directory, file)));
  if (!file) throw new Error(`Missing license for ${name}`);
  const version = JSON.parse(fs.readFileSync(path.join(directory, 'package.json'), 'utf8')).version;
  return `${name} ${version}\n${fs.readFileSync(path.join(directory, file), 'utf8').trim()}`;
}).join('\n\n');
fs.writeFileSync(path.resolve(front, '../shougt-sa/SMARTCARD-LICENSES.txt'), licenses + '\n');
console.log('Updated the browser PIV runtime and bundled dependency licenses.');
