import { createServer } from 'node:http';
import { createHash, webcrypto } from 'node:crypto';

const originalDigest = webcrypto.subtle.digest.bind(webcrypto.subtle);
Object.defineProperty(globalThis, 'crypto', {
  value: {
    ...webcrypto,
    subtle: {
      ...webcrypto.subtle,
      async digest(algorithm, data) {
        const name = typeof algorithm === 'string' ? algorithm : algorithm.name;
        if (String(name).toUpperCase() === 'MD5') {
          return createHash('md5').update(Buffer.from(data)).digest().buffer;
        }
        return originalDigest(algorithm, data);
      },
    },
  },
});

const { default: worker } = await import('./_worker.js');
const host = process.env.HOST || '127.0.0.1';
const port = Number(process.env.PORT || 3002);

// Builds the public URL that the Worker-style handler expects behind Nginx.
function requestUrl(req) {
  const proto = req.headers['x-forwarded-proto'] || 'http';
  const forwardedHost = req.headers['x-forwarded-host'] || req.headers.host;
  return `${proto}://${forwardedHost}${req.url}`;
}

// Reads an incoming Node request body for methods that may carry payloads.
async function requestBody(req) {
  if (req.method === 'GET' || req.method === 'HEAD') return undefined;
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);
  return Buffer.concat(chunks);
}

// Converts Node's HTTP request into a Web Fetch API Request for the worker.
async function toFetchRequest(req) {
  return new Request(requestUrl(req), {
    method: req.method,
    headers: req.headers,
    body: await requestBody(req),
  });
}

// Writes a Web Fetch API Response back to Node's HTTP response object.
async function sendFetchResponse(res, response) {
  res.writeHead(response.status, Object.fromEntries(response.headers));
  if (response.body) {
    const body = Buffer.from(await response.arrayBuffer());
    res.end(body);
  } else {
    res.end();
  }
}

createServer(async (req, res) => {
  try {
    const request = await toFetchRequest(req);
    const response = await worker.fetch(request, process.env);
    await sendFetchResponse(res, response);
  } catch (error) {
    res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' });
    res.end(`Internal Server Error: ${error.message}`);
  }
}).listen(port, host, () => {
  console.log(`WorkerVless2sub listening on http://${host}:${port}`);
});
