import { spawn, spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, openSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import net from 'node:net';

const front=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'..');
const back=path.resolve(front,'../shougt-v0-backend'), consoleApp=path.resolve(front,'../shougt-sa');
const work=path.resolve(process.env.SHOUGT_UI_WORK || path.join(front,'.test-work/ui'));
const serveDist=process.env.SHOUGT_UI_SERVE_DIST==='1';
mkdirSync(work,{recursive:true});
const python=path.join(back,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
const consolePython=path.join(consoleApp,'.venv',process.platform==='win32'?'Scripts/python.exe':'bin/python');
const env={...process.env,SHOUGT_UI_TEST:'1',SHOUGT_UI_WORK:work,SHOUGT_TEST_TMP:work,
  NODE_OPTIONS:`${process.env.NODE_OPTIONS || ''} --require="${path.join(front,'tests/local-dns.cjs').replaceAll('\\','/')}"`.trim()};
const children=[];
function start(command,args,cwd,log){const fd=openSync(path.join(work,log),'w');const process=spawn(command,args,{cwd,env,stdio:['ignore',fd,fd],windowsHide:true});children.push(process);return process;}
async function waitPort(port){for(let i=0;i<120;i++){const open=await new Promise(resolve=>{const socket=net.connect({host:'127.0.0.1',port});socket.setTimeout(500);socket.once('connect',()=>{socket.destroy();resolve(true)});socket.once('error',()=>{socket.destroy();resolve(false)});socket.once('timeout',()=>{socket.destroy();resolve(false)});});if(open)return;await new Promise(resolve=>setTimeout(resolve,250));}throw new Error(`Local test service ${port} did not start; see ${work}`);}
async function freePort(port){await new Promise((resolve,reject)=>{const socket=net.createServer();socket.once('error',()=>reject(new Error(`Test port ${port} is already occupied`)));socket.listen(port,'127.0.0.1',()=>socket.close(resolve));});}
function stop(){for(const child of children)if(!child.killed)child.kill();}
process.once('SIGINT',()=>{stop();process.exit(130)});
let code=1;
try{
  if(serveDist&&!existsSync(path.join(front,'dist/index.html')))throw new Error('Build the frontend before using SHOUGT_UI_SERVE_DIST=1');
  for(const port of [15173,18000,18443,18444,18445,18448])await freePort(port);
  const setup=spawnSync(python,[path.join(front,'tests/setup_ui.py')],{cwd:front,env,stdio:'inherit',windowsHide:true});
  if(setup.status!==0)throw new Error('Fixture setup failed');
  start(python,['-u','manage.py','runserver','127.0.0.1:18000','--noreload','--settings=gt.ui_test_settings'],back,'backend.log');
  start(consolePython,['-u','-m','backend.server','--config',path.join(work,'console.json')],consoleApp,'console.log');
  start(consolePython,['-u',path.join(front,'tests/piv_fixture_bridge.py')],consoleApp,'piv-bridge.log');
  start(consolePython,['-u',path.join(front,'tests/fido_fixture_bridge.py')],consoleApp,'fido-bridge.log');
  start(process.execPath,[path.join(front,'node_modules/vite/bin/vite.js'),...(serveDist?['preview']:[]),'--host','127.0.0.1','--port','15173','--strictPort'],front,'vite.log');
  await Promise.all([waitPort(15173),waitPort(18000),waitPort(18443),waitPort(18444),waitPort(18445),waitPort(18448)]);
  const tests=spawn(process.execPath,[path.join(front,'node_modules/@playwright/test/cli.js'),'test',...process.argv.slice(2)],{cwd:front,env,stdio:'inherit',windowsHide:true});
  code=await new Promise(resolve=>tests.once('exit',status=>resolve(status??1)));
}catch(error){console.error(error.message);}finally{stop();}
process.exitCode=code;
