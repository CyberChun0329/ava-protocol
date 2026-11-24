import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdtemp, mkdir, readFile, readdir, rm, stat, symlink, writeFile} from 'node:fs/promises';
import {createHash} from 'node:crypto';
import {resolve} from 'node:path';
import {gunzipSync} from 'node:zlib';

test('successful retained tests archive exact state and remove only consumer dependencies',async()=>{
 const {finishTestArtifacts}=await import('../../scripts/test-artifacts.mjs');
 const directory=await mkdtemp(resolve('.tmp/artifact-retention-'));
 const statePath=resolve(directory,'chain-state.json'),consumer=resolve(directory,'consumer');
 const bytes=Buffer.from('{"saved":"exact bytes"}\n'),hash=createHash('sha256').update(bytes).digest('hex');
 const checkpoint=JSON.stringify({status:'saved',sha256:hash});
 try{
  await mkdir(resolve(consumer,'node_modules'),{recursive:true});
  await writeFile(resolve(consumer,'readback.json'),'retained evidence');
  await writeFile(statePath,bytes);await writeFile(`${statePath}.checkpoint.json`,checkpoint);
  let closed=false;
  await finishTestArtifacts({passed:true,close:async()=>{closed=true;},statePath,consumer});
  assert(closed);
  assert.deepEqual(gunzipSync(await readFile(`${statePath}.gz`)),bytes);
  assert.equal(await readFile(`${statePath}.checkpoint.json`,'utf8'),checkpoint);
  assert.equal(await readFile(resolve(consumer,'readback.json'),'utf8'),'retained evidence');
  await assert.rejects(stat(statePath),{code:'ENOENT'});
  await assert.rejects(stat(resolve(consumer,'node_modules')),{code:'ENOENT'});
 }finally{await rm(directory,{recursive:true,force:true});}
});

test('failed tests, failed shutdown and mismatched checkpoints retain original state and diagnostics',async()=>{
 const {finishTestArtifacts}=await import('../../scripts/test-artifacts.mjs');
 for(const mode of ['test-failed','shutdown-failed','hash-mismatch','archive-exists']){
  const directory=await mkdtemp(resolve('.tmp/artifact-retention-'));
  const statePath=resolve(directory,'chain-state.json'),consumer=resolve(directory,'consumer');
  try{
   await mkdir(resolve(consumer,'node_modules'),{recursive:true});await writeFile(statePath,'original');
   await writeFile(`${statePath}.checkpoint.json`,JSON.stringify({status:'saved',sha256:mode==='hash-mismatch'?'0'.repeat(64):createHash('sha256').update('original').digest('hex')}));
   if(mode==='archive-exists')await writeFile(`${statePath}.gz`,'existing archive');
   const run=()=>finishTestArtifacts({passed:mode!=='test-failed',statePath,consumer,
    close:async()=>{if(mode==='shutdown-failed')throw new Error('shutdown failed');}});
   if(mode==='test-failed')await run();else await assert.rejects(run());
   assert.equal(await readFile(statePath,'utf8'),'original');
   assert((await stat(resolve(consumer,'node_modules'))).isDirectory());
   assert(!(await readdir(directory)).some(name=>name.endsWith('.tmp')));
   if(mode==='archive-exists')assert.equal(await readFile(`${statePath}.gz`,'utf8'),'existing archive');
  }finally{await rm(directory,{recursive:true,force:true});}
 }
});

test('successful consumer cleanup unlinks dependencies without removing their shared target',async()=>{
 const {finishTestArtifacts}=await import('../../scripts/test-artifacts.mjs');
 const directory=await mkdtemp(resolve('.tmp/artifact-retention-'));
 const consumer=resolve(directory,'consumer'),shared=resolve(directory,'shared-dependencies');
 try{
  await mkdir(consumer);await mkdir(shared);await writeFile(resolve(shared,'keep.txt'),'shared dependency');
  await symlink(shared,resolve(consumer,'node_modules'),'dir');
  await finishTestArtifacts({passed:true,consumer,close:async()=>{}});
  assert.equal(await readFile(resolve(shared,'keep.txt'),'utf8'),'shared dependency');
  await assert.rejects(stat(resolve(consumer,'node_modules')),{code:'ENOENT'});
 }finally{await rm(directory,{recursive:true,force:true});}
});
