import assert from 'node:assert/strict';
import {copyFile, mkdir, readFile, symlink} from 'node:fs/promises';
import {resolve,dirname} from 'node:path';

/** Execute the current launcher unchanged, with a private ownership/capacity pool. */
export async function launcherProject(directory,source){
 for(const path of ['scripts','packages/ava-sdk/test','packages/ava-agent-sdk/test','packages/ava-service/test','test/release']){
  await mkdir(resolve(directory,path),{recursive:true});
 }
 for(const name of ['run_tests.mjs','test-artifacts.mjs']){
  const original=resolve(source,'scripts',name),copy=resolve(directory,'scripts',name);
  await copyFile(original,copy);
  assert.deepEqual(await readFile(copy),await readFile(original),'Launcher fixture must execute the exact current source');
 }
 for(const name of ['test-artifacts.ts','artifact-capacity.ts']){
  const relative='packages/ava-service/src/'+name;await mkdir(dirname(resolve(directory,relative)),{recursive:true});await copyFile(resolve(source,relative),resolve(directory,relative));
 }
 await symlink(resolve(source,'node_modules'),resolve(directory,'node_modules'),'dir');
 return resolve(directory,'scripts/run_tests.mjs');
}
