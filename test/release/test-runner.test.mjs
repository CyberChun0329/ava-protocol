import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtemp, readFile, rm, stat, writeFile} from 'node:fs/promises';
import {spawnSync} from 'node:child_process';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {launcherProject} from './helpers/launcher-project.mjs';

const root=fileURLToPath(new URL('../..',import.meta.url));
test('test runner removes successful output and retains failed output for diagnosis',async()=>{
 const fixture=await mkdtemp(resolve(root,'.tmp/test-runner-check-'));
 const file=resolve(fixture,'fixture.test.mjs');
 const launcher=await launcherProject(fixture,root);
 const outputs=[];
 try{
  for(const fail of [false,true]){
   await writeFile(file,`import {test} from 'node:test';
import {writeFileSync} from 'node:fs';
import {resolve} from 'node:path';
test('artifact ownership',()=>{
 writeFileSync(resolve(process.env.AVA_TEST_OUTPUT_ROOT,'diagnostic.txt'),'retained failure evidence');
 ${fail?"throw new Error('intentional failure');":''}
});\n`);
   const env={...process.env};delete env.NODE_TEST_CONTEXT;delete env.AVA_TEST_OUTPUT_ROOT;
   const result=spawnSync(process.execPath,[launcher,file],{cwd:fixture,env,encoding:'utf8'});
   const output=result.stdout.match(/Disposable test deployments: (.+)/)?.[1];
   assert(output,'runner must identify the directory it owns');outputs.push(output);
   assert.equal(result.status,fail?1:0,result.stdout+result.stderr);
   assert.match(result.stdout,/artifact ownership/);
   if(fail)assert.equal(await readFile(resolve(output,'diagnostic.txt'),'utf8'),'retained failure evidence');
   else await assert.rejects(stat(output),{code:'ENOENT'});
  }
 }finally{
  for(const output of outputs)await rm(output,{recursive:true,force:true});
  await rm(fixture,{recursive:true,force:true});
 }
});
