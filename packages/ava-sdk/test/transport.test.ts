import assert from 'node:assert/strict';
import { createServer, type Server } from 'node:http';
import { test } from 'node:test';
import { localClient } from '../src/index.ts';

async function listen(server: Server) {
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', resolve);
  });
  return `http://127.0.0.1:${(server.address() as { port: number }).port}`;
}
async function close(server: Server) {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
}

test('local RPC accepts direct HTTP replies and rejects every HTTP redirect before forwarding', async () => {
  let destinationRequests = 0;
  const destination = createServer(async (request, response) => {
    destinationRequests++;
    let body = '';
    for await (const chunk of request) body += chunk;
    const rpc = body ? JSON.parse(body) : { id: null };
    response.setHeader('content-type', 'application/json');
    response.end(JSON.stringify({ jsonrpc: '2.0', id: rpc.id, result: '0x7a69' }));
  });
  const destinationUrl = await listen(destination);
  let status = 307;
  const redirect = createServer((_request, response) => {
    response.writeHead(status, { location: destinationUrl }).end();
  });
  const redirectUrl = await listen(redirect);
  try {
    assert.equal(await localClient(destinationUrl).getChainId(), 31337);
    destinationRequests = 0;
    for (status of [301, 302, 303, 307, 308]) {
      await assert.rejects(localClient(redirectUrl).getChainId(), `redirect ${status} must fail`);
    }
    assert.equal(destinationRequests, 0, 'RPC contents never reach a redirect destination');
  } finally { await close(redirect); await close(destination); }
});
