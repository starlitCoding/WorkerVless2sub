import assert from 'node:assert/strict';
import { webcrypto, createHash } from 'node:crypto';
import test from 'node:test';

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

const { default: worker } = await import('../_worker.js');

function decodeSubscription(body) {
  return Buffer.from(body, 'base64').toString('utf8').trim().split('\n');
}

function decodeVmess(line) {
  assert.ok(line.startsWith('vmess://'));
  return JSON.parse(Buffer.from(line.slice('vmess://'.length), 'base64').toString('utf8'));
}

test('uses add query parameter as preferred IP list for VMess subscriptions', async () => {
  const url = new URL('https://example.com:2083/sub');
  url.searchParams.set('host', 'star.shadowrocket666.dpdns.org');
  url.searchParams.set('uuid', 'a1b94b8b-6f4f-4ee2-8695-0bcd565dd283');
  url.searchParams.set('path', '/la');
  url.searchParams.set('sni', 'star.shadowrocket666.dpdns.org');
  url.searchParams.set('type', 'none');
  url.searchParams.set('alterid', '0');
  url.searchParams.set('security', 'auto');
  url.searchParams.set('add', '104.27.96.219:443#LAX-01\n104.24.164.58:443#LAX-02');

  const response = await worker.fetch(new Request(url, {
    headers: { 'User-Agent': 'Shadowrocket' },
  }), {});

  assert.equal(response.status, 200);
  const nodes = decodeSubscription(await response.text()).map(decodeVmess);

  assert.equal(nodes.length, 2);
  assert.deepEqual(nodes.map(node => node.add), ['104.27.96.219', '104.24.164.58']);
  assert.deepEqual(nodes.map(node => node.port), [443, 443]);
  assert.deepEqual(nodes.map(node => node.ps), ['LAX-01', 'LAX-02']);
  assert.ok(nodes.every(node => node.host === 'star.shadowrocket666.dpdns.org'));
  assert.ok(nodes.every(node => node.sni === 'star.shadowrocket666.dpdns.org'));
});

test('emits parser-friendly VMess JSON for subscription converters', async () => {
  const url = new URL('https://example.com:2083/sub');
  url.searchParams.set('host', 'star.shadowrocket666.dpdns.org');
  url.searchParams.set('uuid', 'a1b94b8b-6f4f-4ee2-8695-0bcd565dd283');
  url.searchParams.set('path', '/la');
  url.searchParams.set('sni', 'star.shadowrocket666.dpdns.org');
  url.searchParams.set('type', 'none');
  url.searchParams.set('alterid', '0');
  url.searchParams.set('security', 'auto');
  url.searchParams.set('alpn', 'h2,http/1.1');
  url.searchParams.set('add', '104.27.96.219:443#LAX-01');

  const response = await worker.fetch(new Request(url, {
    headers: { 'User-Agent': 'Shadowrocket' },
  }), {});
  const [node] = decodeSubscription(await response.text()).map(decodeVmess);

  assert.equal(node.alpn, 'h2,http/1.1');
  assert.equal(node.allowInsecure, false);
  assert.equal('fragment' in node, false);
});

test('home page exposes preferred IP input and preserves non-default port in generated links', async () => {
  const response = await worker.fetch(new Request('https://example.com:2083/'), {});
  const html = await response.text();

  assert.match(html, /id="addresses"/);
  assert.match(html, /window\.location\.origin/);
  assert.doesNotMatch(html, /window\.location\.hostname/);
});

test('returns built-in Clash YAML for Clash user agents', async () => {
  const url = new URL('https://example.com:2083/sub');
  url.searchParams.set('host', 'star.shadowrocket666.dpdns.org');
  url.searchParams.set('uuid', 'ec544097-aa05-46e3-a04e-a0d7466b2f11');
  url.searchParams.set('path', '/la');
  url.searchParams.set('sni', 'star.shadowrocket666.dpdns.org');
  url.searchParams.set('type', 'none');
  url.searchParams.set('alterid', '0');
  url.searchParams.set('security', 'auto');
  url.searchParams.set('alpn', 'h2,http/1.1');
  url.searchParams.set('add', 'star.shadowrocket666.dpdns.org#洛杉矶-原生\n104.17.157.42#洛杉矶优选-01');

  const response = await worker.fetch(new Request(url, {
    headers: { 'User-Agent': 'Clash.Meta' },
  }), {});
  const yaml = await response.text();

  assert.equal(response.headers.get('content-type'), 'text/yaml; charset=utf-8');
  assert.match(yaml, /proxies:/);
  assert.match(yaml, /type: vmess/);
  assert.match(yaml, /server: "104.17.157.42"/);
  assert.match(yaml, /servername: "star.shadowrocket666.dpdns.org"/);
  assert.ok(yaml.includes('path: "/la"'));
  assert.match(yaml, /proxy-groups:/);
  assert.doesNotMatch(yaml, /^dm1lc3M/m);
});
