import fs from 'node:fs';
import path from 'node:path';

const file = path.join(process.env.SHOUGT_UI_WORK!, 'smartcard-webauthn-counters.json');
function stored():Record<string,number> {
  return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
}
export function keyCounter(key:any):number {
  return Math.max(key.sign_count, stored()[key.credential_id] || 0);
}
export function saveKeyCounter(key:any, value:number) {
  const values=stored();
  values[key.credential_id]=Math.max(key.sign_count, values[key.credential_id] || 0, value);
  fs.writeFileSync(file,JSON.stringify(values));
}
