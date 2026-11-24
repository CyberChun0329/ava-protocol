import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {readdir} from 'node:fs/promises';
import {resolve} from 'node:path';
import {fileURLToPath} from 'node:url';
import {beginTestArtifacts} from './test-artifacts.mjs';

const root=fileURLToPath(new URL('..',import.meta.url));
const artifactsRun=await beginTestArtifacts(root),output=artifactsRun.directory;
console.log(`Disposable test deployments: ${output}`);
let passed=false;
try{
 const files=[];
 for(const directory of ['packages/ava-sdk/test','packages/ava-agent-sdk/test','packages/ava-service/test','test/release']){
  for(const name of (await readdir(resolve(root,directory))).sort()){
   if(/\.test\.(ts|mjs)$/.test(name))files.push(resolve(root,directory,name));
  }
 }
 const args=process.argv.slice(2);
 const selected=args.some(arg=>!arg.startsWith('-')&&/\.test\.(ts|mjs)$/.test(arg));
 const child=spawn(process.execPath,['--import','tsx','--test',
  `--test-concurrency=${process.env.AVA_TEST_CONCURRENCY||'1'}`,...args,...(selected?[]:files)],
 {cwd:root,env:{...process.env,AVA_TEST_OUTPUT_ROOT:output},stdio:'inherit',detached:true});
 let interrupted=false;
 const stop=signal=>{
  interrupted=true;
  try{process.kill(-child.pid,signal);}catch(error){if(error.code!=='ESRCH')throw error;}
 };
 const interrupt=()=>stop('SIGINT'),terminate=()=>stop('SIGTERM');
 process.once('SIGINT',interrupt);process.once('SIGTERM',terminate);
 try{
  const [code]=await once(child,'close');
  passed=code===0&&!interrupted;
  process.exitCode=interrupted?130:code??1;
 }finally{
  process.off('SIGINT',interrupt);process.off('SIGTERM',terminate);
 }
}finally{
 await artifactsRun.finish(passed);
 if(passed)console.log(artifactsRun.owned?'Disposable test deployments removed after the complete suite passed.':`Checks completed in caller-owned artifacts: ${output}`);
}
