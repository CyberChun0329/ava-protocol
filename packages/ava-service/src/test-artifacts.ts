import {assertArtifactCapacity} from './artifact-capacity.ts';
export {assertArtifactCapacity};
import {createHash, randomUUID} from 'node:crypto';
import {createReadStream, createWriteStream} from 'node:fs';
import {link, lstat, mkdir, readFile, rm, unlink} from 'node:fs/promises';
import {resolve} from 'node:path';
import {pipeline} from 'node:stream/promises';
import {createGzip, createGunzip} from 'node:zlib';

/** Three exclusive slots bound retained failures and concurrent standalone checks. */
export async function beginTestArtifacts(projectRoot: string){
 const previous=process.env.AVA_TEST_OUTPUT_ROOT;
 if(previous)return {directory:resolve(previous),owned:false,finish:async()=>{}};
 await assertArtifactCapacity(projectRoot);
 const parent=resolve(projectRoot,'.tmp/test-runs');
 await mkdir(parent,{recursive:true,mode:0o700});
 let directory: string | undefined;
 for(let i=1;i<=3;i++){
  const candidate=resolve(parent,`run-${i}`);
  try{await mkdir(candidate,{mode:0o700});directory=candidate;break;}
  catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;}
 }
 if(!directory)throw new Error('3 retained or active test runs occupy .tmp/test-runs. Review them before starting another check; no evidence was removed.');
 console.log(`Test artifacts: ${directory}`);
 process.env.AVA_TEST_OUTPUT_ROOT=directory;
 const ownedDirectory=directory;
 let finishing: Promise<void> | undefined;
 return {directory,owned:true,finish(passed: boolean){
  return finishing??=(async()=>{
   try{
    if(passed)await rm(ownedDirectory,{recursive:true,force:true,maxRetries:3});
    else console.error(`Check artifacts retained for diagnosis: ${directory}`);
   }finally{
    if(process.env.AVA_TEST_OUTPUT_ROOT===directory){
     if(previous===undefined)delete process.env.AVA_TEST_OUTPUT_ROOT;else process.env.AVA_TEST_OUTPUT_ROOT=previous;
    }
   }
  })();
 }};
}

/** Compact a closed synthetic test checkpoint without changing its exact replay bytes. */
async function archiveState(statePath: string){
 const before=await lstat(statePath);
 if(!before.isFile())throw new Error('Test checkpoint must be a regular file');
 const checkpointPath=`${statePath}.checkpoint.json`;
 const checkpointBytes=await readFile(checkpointPath);
 const checkpoint=JSON.parse(checkpointBytes.toString('utf8'));
 if(checkpoint.status!=='saved'||!/^[a-f0-9]{64}$/.test(checkpoint.sha256))throw new Error('Test checkpoint is not sealed');
 const temporary=`${statePath}.gz.${randomUUID()}.tmp`;
 try{
  const originalHash=createHash('sha256'),source=createReadStream(statePath);
  source.on('data',chunk=>originalHash.update(chunk));
  await pipeline(source,createGzip(),createWriteStream(temporary,{flags:'wx',mode:0o600}));
  const restoredHash=createHash('sha256');
  await pipeline(createReadStream(temporary),createGunzip(),async chunks=>{
   for await(const chunk of chunks)restoredHash.update(chunk);
  });
  if(originalHash.digest('hex')!==checkpoint.sha256||restoredHash.digest('hex')!==checkpoint.sha256){
   throw new Error('Test archive does not match its checkpoint');
  }
  const after=await lstat(statePath);
  if(before.ino!==after.ino||before.size!==after.size||before.mtimeMs!==after.mtimeMs
   ||!checkpointBytes.equals(await readFile(checkpointPath)))throw new Error('Test checkpoint changed while archiving');
  // An exclusive link publishes the complete archive without replacing an existing one.
  await link(temporary,`${statePath}.gz`);
  await unlink(statePath);
 }finally{await rm(temporary,{force:true});}
}

/** The caller owns these test paths; a failure in the test or shutdown keeps diagnostics. */
export async function finishTestArtifacts({passed,close,statePath,consumer}: {passed:boolean;close:()=>Promise<unknown>;statePath?:string;consumer?:string}){
 await close();
 if(!passed)return;
 if(statePath)await archiveState(statePath);
 if(consumer)await rm(resolve(consumer,'node_modules'),{recursive:true,force:true,maxRetries:3});
}

