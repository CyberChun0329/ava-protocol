import {assertArtifactCapacity} from '../packages/ava-service/src/test-artifacts.ts';
import {artifactLimitBytes} from '../packages/ava-service/src/artifact-capacity.ts';
export {assertArtifactCapacity,beginTestArtifacts,finishTestArtifacts} from '../packages/ava-service/src/test-artifacts.ts';
import {fileURLToPath} from 'node:url';
import {resolve} from 'node:path';
if(process.argv[1]&&resolve(process.argv[1])===fileURLToPath(import.meta.url)){
 if(process.argv.length!==3||process.argv[2]!=='--check-capacity')throw new Error('Usage: node scripts/test-artifacts.mjs --check-capacity');
 const bytes=await assertArtifactCapacity(fileURLToPath(new URL('..',import.meta.url)));
 console.log(`Artifact allocation: ${bytes} bytes; admission limit: ${artifactLimitBytes} bytes.`);
}
