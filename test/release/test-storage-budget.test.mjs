import assert from 'node:assert/strict';
import {test} from 'node:test';
import {mkdir, mkdtemp, readFile, rm, stat, writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';

test('owned checks clean successes, preserve three failures and refuse further accumulation',async()=>{
 const {beginTestArtifacts}=await import('../../scripts/test-artifacts.mjs');
 const fixture=await mkdtemp(resolve('.tmp/storage-budget-test-'));
 const previous=process.env.AVA_TEST_OUTPUT_ROOT;
 delete process.env.AVA_TEST_OUTPUT_ROOT;
 try{
  const first=await beginTestArtifacts(fixture);
  await writeFile(resolve(first.directory,'diagnostic.txt'),'passed');
  const nested=await beginTestArtifacts(fixture);
  assert.equal(nested.owned,false);assert.equal(nested.directory,first.directory);
  await nested.finish(true);assert((await stat(first.directory)).isDirectory());
  await first.finish(true);await assert.rejects(stat(first.directory),{code:'ENOENT'});
  const failed=[];
  for(let i=0;i<3;i++){
   const run=await beginTestArtifacts(fixture);failed.push(run.directory);
   await writeFile(resolve(run.directory,'diagnostic.txt'),`failure ${i}`);await run.finish(false);
  }
  await assert.rejects(beginTestArtifacts(fixture),/3.*retained|retained.*3/i);
  for(const [i,path] of failed.entries())assert.equal(await readFile(resolve(path,'diagnostic.txt'),'utf8'),`failure ${i}`);
 }finally{
  if(previous===undefined)delete process.env.AVA_TEST_OUTPUT_ROOT;else process.env.AVA_TEST_OUTPUT_ROOT=previous;
  await rm(fixture,{recursive:true,force:true,maxRetries:3});
 }
});

test('capacity admission counts allocated bytes and preserves all files when the limit is reached',async()=>{
 const {assertArtifactCapacity}=await import('../../scripts/test-artifacts.mjs');
 const fixture=await mkdtemp(resolve('.tmp/storage-budget-test-'));
 try{
  await mkdir(resolve(fixture,'.local'));await mkdir(resolve(fixture,'.tmp'));
  await writeFile(resolve(fixture,'.local','keep.bin'),Buffer.alloc(16*1024,1));
  const before=await readFile(resolve(fixture,'.local','keep.bin'));
  await assert.rejects(assertArtifactCapacity(fixture,1024),/capacity reached/i);
  assert.deepEqual(await readFile(resolve(fixture,'.local','keep.bin')),before);
  assert((await assertArtifactCapacity(fixture))>=16*1024);
 }finally{await rm(fixture,{recursive:true,force:true,maxRetries:3});}
});
