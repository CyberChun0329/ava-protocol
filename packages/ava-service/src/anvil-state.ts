import {createHash} from 'node:crypto';
import {Readable} from 'node:stream';
import {pipeline} from 'node:stream/promises';
import {parser} from 'stream-json';
import {pick} from 'stream-json/filters/pick.js';
import {streamValues} from 'stream-json/streamers/stream-values.js';

/** Inspect a local Anvil dump without assembling its account/history trees or one file-sized string. */
export async function inspectAnvilState(source:Readable,head?:bigint){
 const hash=createHash('sha256');
 let genesisTimestamp:bigint|undefined,bestBlockNumber:bigint|undefined,containsHead=false;
 source.on('data',(chunk:Buffer)=>hash.update(chunk));
 await pipeline(source,parser.asStream({streamValues:false}),
  pick.asStream({filter:/^(best_block_number|blocks\.\d+\.header)$/}),
  streamValues.asStream({numberAsString:true}),async values=>{
   for await(const {value} of values){
    if(typeof value==='string'&&/^(0|[1-9][0-9]*)$/.test(value)){bestBlockNumber=BigInt(value);continue;}
    if(!value||typeof value!=='object'||typeof value.number!=='string'||!/^0x[0-9a-f]+$/i.test(value.number))continue;
    const number=BigInt(value.number);
    if(number===head)containsHead=true;
    if(number===0n&&typeof value.timestamp==='string'&&/^0x[0-9a-f]+$/i.test(value.timestamp))genesisTimestamp=BigInt(value.timestamp);
   }
  });
 return {sha256:hash.digest('hex'),genesisTimestamp,bestBlockNumber,containsHead};
}
