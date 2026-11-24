import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtemp, readFile, rm, writeFile} from 'node:fs/promises';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {launcherProject} from './helpers/launcher-project.mjs';

const root=fileURLToPath(new URL('../..',import.meta.url));
test('interrupted runner stops its child group and retains the current diagnostic slot',{timeout:30_000},async()=>{
 const fixture=await mkdtemp(resolve(root,'.tmp/test-interrupt-')),file=resolve(fixture,'interrupt.test.mjs');
 const launcher=await launcherProject(fixture,root);
 const env={...process.env};delete env.NODE_TEST_CONTEXT;delete env.AVA_TEST_OUTPUT_ROOT;
 let child,directory,output='';
 try{
  await writeFile(file,`import {test} from 'node:test';
import {writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
test('running check',async()=>{
 process.on('SIGTERM',()=>{writeFileSync(resolve(process.env.AVA_TEST_OUTPUT_ROOT,'stopped.txt'),'stopped');process.exit(0);});
 writeFileSync(resolve(process.env.AVA_TEST_OUTPUT_ROOT,'ready.txt'),String(process.pid));
 await new Promise(()=>setInterval(()=>{},1000));
});\n`);
  child=spawn(process.execPath,[launcher,file],{cwd:fixture,env,stdio:['ignore','pipe','pipe']});
  child.stdout.on('data',chunk=>{output+=chunk;});child.stderr.on('data',chunk=>{output+=chunk;});
  let pid;
  for(let i=0;i<500;i++){
   directory=output.match(/Disposable test deployments: (.+)/)?.[1];
   if(directory){try{pid=Number(await readFile(resolve(directory,'ready.txt'),'utf8'));break;}catch(error){if(error.code!=='ENOENT')throw error;}}
   if(child.exitCode!==null)throw new Error(output);
   await new Promise(done=>setTimeout(done,20));
  }
  assert(pid,'check must start before interruption');
  const exited=once(child,'exit');child.kill('SIGTERM');
  assert.equal((await exited)[0],130,output);
  assert.equal(await readFile(resolve(directory,'stopped.txt'),'utf8'),'stopped');
  assert.throws(()=>process.kill(pid,0),{code:'ESRCH'});
 }finally{
  if(child&&child.exitCode===null&&child.signalCode===null){const exited=once(child,'exit');child.kill('SIGTERM');await exited;}
  if(directory)await rm(directory,{recursive:true,force:true,maxRetries:3});
  await rm(fixture,{recursive:true,force:true,maxRetries:3});
 }
});
