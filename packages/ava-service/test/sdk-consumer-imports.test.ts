import assert from 'node:assert/strict';
import test from 'node:test';
import {mkdir,mkdtemp,rm,writeFile} from 'node:fs/promises';
import {resolve} from 'node:path';
import {assertIndependentSdkImports} from '../../../scripts/consumer-imports.ts';

test('consumer source checking follows local subdirectories and refuses a nested repository import',async()=>{
 const directory=await mkdtemp(resolve('.tmp/sdk-imports-'));
 try{
  await mkdir(resolve(directory,'sub'));
  await writeFile(resolve(directory,'check.ts'),"import './sub/helper.js'; const route='/ojs-native/import';");
  await writeFile(resolve(directory,'sub/helper.ts'),"import {localApplication} from '../../../examples/peer-review/local-runtime.js';");
  await assert.rejects(assertIndependentSdkImports(directory),/relative import escapes/);
 }finally{await rm(directory,{recursive:true,force:true});}
});

test('consumer source checking accepts public modules and route strings in nested local files',async()=>{
 const directory=await mkdtemp(resolve('.tmp/sdk-imports-'));
 try{
  await mkdir(resolve(directory,'sub'));
  await writeFile(resolve(directory,'check.ts'),"import './sub/helper.js'; import type {Hex} from 'viem'; const route='/ojs-native/import';");
  await writeFile(resolve(directory,'sub/helper.ts'),"export {AvaClient} from '@ava-protocol/sdk'; import {jevChoices} from '@ava-protocol/agent-sdk'; import assert from 'node:assert/strict'; import {privateKeyToAccount} from 'viem/accounts';");
  await assertIndependentSdkImports(directory);
 }finally{await rm(directory,{recursive:true,force:true});}
});

test('consumer source checking refuses unsupported module forms and computed imports',async t=>{
 for(const source of ["import value from '@private/internal';","export * from '@private/internal';",
  "import value = require('@private/internal');","const value=import('@private/internal');",
  "type Value=import('@private/internal').Value;","const name='@private/internal'; const value=import(name);"]){
  await t.test(source,async()=>{
   const directory=await mkdtemp(resolve('.tmp/sdk-imports-'));
   try{
    await writeFile(resolve(directory,'check.ts'),source);
    await assert.rejects(assertIndependentSdkImports(directory),/Unsupported consumer import|explicit modules/);
   }finally{await rm(directory,{recursive:true,force:true});}
  });
 }
});
