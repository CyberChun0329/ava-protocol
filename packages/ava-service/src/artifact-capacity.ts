import {lstat} from 'node:fs/promises';
import {resolve} from 'node:path';
import {execFile} from 'node:child_process';
import {promisify} from 'node:util';

const diskUsage=promisify(execFile);
export const artifactLimitBytes=31_000_000_000;

/** Admission only: never evict existing evidence or interrupt an already-running instance. */
export async function assertArtifactCapacity(projectRoot: string,limitBytes=artifactLimitBytes){
 const paths=[];
 for(const name of ['.local','.tmp']){
  const path=resolve(projectRoot,name);
  try{await lstat(path);paths.push(path);}catch(error){if((error as NodeJS.ErrnoException).code!=='ENOENT')throw error;}
 }
 const {stdout}=paths.length?await diskUsage('du',['-sk',...paths]):{stdout:''};
 const bytes=stdout.trim()?stdout.trim().split('\n').reduce((sum,line)=>sum+Number(line.split(/\s/,1)[0])*1024,0):0;
 if(!Number.isSafeInteger(bytes)||bytes>=limitBytes){
  throw new Error(`Artifact capacity reached (${bytes} bytes; limit ${limitBytes} bytes). Existing data was preserved; review .local and .tmp before starting another check.`);
 }
 return bytes;
}

