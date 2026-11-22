import {spawn} from 'node:child_process';
import {createInterface} from 'node:readline';
import path from 'node:path';
import {fileURLToPath} from 'node:url';

export function appletRPC() {
  const front = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const app = path.resolve(front, '../shougt-sa');
  const python = path.join(app, '.venv', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  const child = spawn(python, ['-u', path.join(app, 'tests/webpiv_applet.py')], {
    cwd: app, env: {...globalThis.process.env, SHOUGT_WEBPIV_TEST: '1', PYTHONIOENCODING: 'utf-8'},
    stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true,
  });
  const pending = [];
  const reader = createInterface({input: child.stdout});
  let failure = null;
  reader.on('line', line => {
    const item = pending.shift();
    if (!item) return;
    clearTimeout(item.timer);
    try {
      const response = JSON.parse(line);
      response.ok ? item.resolve(response.result) : item.reject(new Error(response.error));
    } catch (error) { item.reject(error); }
  });
  const stop = error => {
    failure = error;
    for (const item of pending.splice(0)) { clearTimeout(item.timer); item.reject(error); }
  };
  child.on('error', stop);
  child.on('exit', () => stop(new Error('Software PIV test process ended')));
  child.stderr.on('data', () => {}); // Never include test APDU or secret data in the test report.
  return {
    send(request) {
      if (failure) return Promise.reject(failure);
      return new Promise((resolve, reject) => {
        const item = {resolve, reject, timer: null};
        item.timer = setTimeout(() => { stop(new Error('Software PIV test timed out')); child.kill(); }, 20000);
        pending.push(item);
        child.stdin.write(JSON.stringify(request) + '\n');
      });
    },
    close() { reader.close(); child.stdin.end(); child.kill(); },
  };
}
