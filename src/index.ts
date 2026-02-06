/*
Cloudflare Workers — KV Multi-Tenant Service (E2E encryption + JWT Authentication)

This file contains a runnable TypeScript example for a Cloudflare Worker that:
- Uses Durable Objects to serialize per-document operations (concurrency-safe)
- Stores opaque ciphertext (clients perform end-to-end encryption)
- Uses short-lived JWTs (HS256) for tenant authentication
- Uses KV (TENANT_KV) to store tenant metadata (e.g., shared secret for login) and DATA_KV for snapshots/backups

Bindings expected (wrangler.toml):
- Durable Object binding name: DOC_STORE
- KV namespaces: DATA_KV, TENANT_KV
- Secret: JWT_SECRET (set via `wrangler secret put JWT_SECRET`)

Notes:
- For production, tenant shared secrets in TENANT_KV should be stored as salted hashes (e.g., bcrypt). This example stores plaintext only for brevity.
- JWT uses HS256 (HMAC-SHA256) implemented via Web Crypto.

API endpoints (high level):
- POST /auth/login { tenant_id, shared_secret } -> { token }
- GET  /tenant/:tenantId/docs/:docId -> requires Authorization: Bearer <token>
- PUT  /tenant/:tenantId/docs/:docId -> requires Authorization: Bearer <token>

*/

// ---------- Types & Env ----------

type Env = {
  DATA_KV: KVNamespace;
  TENANT_KV: KVNamespace;
  DOC_STORE: DurableObjectNamespace;
  JWT_SECRET: string; // provided via wrangler secret
};

// ---------- Utility: base64url ----------
function base64UrlEncode(input: Uint8Array) {
  // regular base64
  let str = '';
  for (let i = 0; i < input.length; i++) str += String.fromCharCode(input[i]);
  const b64 = btoa(str);
  // base64url
  return b64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlDecodeToUint8Array(b64u: string) {
  // restore padding
  let b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  while (b64.length % 4) b64 += '=';
  const bin = atob(b64);
  const arr = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
  return arr;
}

function utf8ToUint8(str: string) {
  return new TextEncoder().encode(str);
}

function uint8ToUtf8(arr: Uint8Array) {
  return new TextDecoder().decode(arr);
}

// ---------- JWT HS256 helpers (Web Crypto) ----------
async function importHmacKey(secret: string) {
  const keyData = utf8ToUint8(secret);
  return crypto.subtle.importKey('raw', keyData, {name: 'HMAC', hash: 'SHA-256'}, false, ['sign', 'verify']);
}

async function jwtSign(payload: object, secret: string, ttlSeconds = 600) {
  const header = {alg: 'HS256', typ: 'JWT'};
  const now = Math.floor(Date.now() / 1000);
  const body = {...payload, iat: now, exp: now + ttlSeconds};
  const encoded = base64UrlEncode(utf8ToUint8(JSON.stringify(header))) + '.' + base64UrlEncode(utf8ToUint8(JSON.stringify(body)));
  const key = await importHmacKey(secret);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, utf8ToUint8(encoded)));
  return encoded + '.' + base64UrlEncode(sig);
}

async function jwtVerify(token: string, secret: string) {
  const parts = token.split('.');
  if (parts.length !== 3) return {ok:false, reason:'invalid_format'};
  const [h64, p64, s64] = parts;
  const unsigned = h64 + '.' + p64;
  const key = await importHmacKey(secret);
  const sig = base64UrlDecodeToUint8Array(s64);
  const valid = await crypto.subtle.verify('HMAC', key, sig, utf8ToUint8(unsigned));
  if (!valid) return {ok:false, reason:'invalid_signature'};
  const payloadJson = uint8ToUtf8(base64UrlDecodeToUint8Array(p64));
  const payload = JSON.parse(payloadJson);
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && now > payload.exp) return {ok:false, reason:'expired'};
  return {ok:true, payload};
}

// ---------- Durable Object: DocActor ----------
export class DocStore {
  state: DurableObjectState;
  env: Env | undefined;
  constructor(state: DurableObjectState, env?: Env) {
    this.state = state;
    this.env = env;
  }

  async persistSnapshot(tenantId: string, docId: string, data: any, version: number) {
    if (!this.env) throw new Error('env missing');
    const key = `${tenantId}:doc:${docId}:v${version}`;
    await this.env.DATA_KV.put(key, JSON.stringify({data, version, ts: Date.now()}));
  }

  async fetch(request: Request) {
    if (!this.env) return new Response('env missing', {status:500});
    const url = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean);
    if (parts.length < 4 || parts[0] !== 'tenant' || parts[2] !== 'docs') return new Response('bad path', {status:400});
    const tenantId = parts[1];
    const docId = parts[3];

    if (request.method === 'GET') {
      const stored = await this.state.storage.get<{data:any, version:number}>('doc');
      if (!stored) return new Response(JSON.stringify({exists:false}), {status:404});
      return new Response(JSON.stringify({exists:true, data: stored.data, version: stored.version}), {headers:{'content-type':'application/json'}});
    }

    if (request.method === 'PUT') {
      const body = await request.json().catch(()=>({}));
      const {cipher_b64, iv_b64, meta} = body;
      const expectedVersion = body.expectedVersion ?? null;
      if (!cipher_b64 || !iv_b64) return new Response(JSON.stringify({error:'missing_cipher_or_iv'}), {status:400});
      const stored = await this.state.storage.get<{data:any, version:number}>('doc');
      const curVersion = stored?.version ?? 0;
      if (expectedVersion !== null && expectedVersion !== curVersion) return new Response(JSON.stringify({error:'version_mismatch', curVersion}), {status:409});
      const newVersion = curVersion + 1;
      await this.state.storage.put('doc', {data: {cipher_b64, iv_b64, meta}, version: newVersion});
      await this.persistSnapshot(tenantId, docId, {cipher_b64, iv_b64, meta}, newVersion);
      return new Response(JSON.stringify({ok:true, version:newVersion}), {headers:{'content-type':'application/json'}});
    }

    return new Response('method not allowed', {status:405});
  }
}

// ---------- Worker front-end with JWT auth ----------
export default {
  async fetch(request: Request, env: Env) {
    const url = new URL(request.url);
    const parts = url.pathname.split('/').filter(Boolean);

    // Auth login endpoint
    if (request.method === 'POST' && url.pathname === '/auth/login') {
      const body = await request.json().catch(()=>({}));
      const tenantId = body.tenant_id;
      const sharedSecret = body.shared_secret;
      if (!tenantId || !sharedSecret) return new Response(JSON.stringify({error:'missing_fields'}), {status:400});
      // verify against TENANT_KV (for demo we store shared secret at key: shared:<tenantId>)
      const stored = await env.TENANT_KV.get(`shared:${tenantId}`);
      if (!stored) return new Response(JSON.stringify({error:'tenant_not_found'}), {status:404});
      // production: compare hashed secrets. here we compare plaintext for brevity.
      if (stored !== sharedSecret) return new Response(JSON.stringify({error:'invalid_credentials'}), {status:403});
      const token = await jwtSign({tenant: tenantId}, env.JWT_SECRET, Number(env.JWT_TTL ?? 600));
      return new Response(JSON.stringify({token}), {headers:{'content-type':'application/json'}});
    }

    // Document routes require JWT authentication
    if (parts.length >= 4 && parts[0] === 'tenant' && parts[2] === 'docs') {
      // verify JWT
      const auth = request.headers.get('Authorization') || '';
      if (!auth.startsWith('Bearer ')) return new Response(JSON.stringify({error:'missing_token'}), {status:401, headers:{'content-type':'application/json'}});
      const token = auth.slice(7);
      const verify = await jwtVerify(token, env.JWT_SECRET);
      if (!verify.ok) return new Response(JSON.stringify({error:'invalid_token', reason: verify.reason}), {status:401, headers:{'content-type':'application/json'}});
      const tenantClaim = verify.payload.tenant;
      const tenantId = parts[1];
      if (tenantClaim !== tenantId) return new Response(JSON.stringify({error:'tenant_mismatch'}), {status:403, headers:{'content-type':'application/json'}});

      // forward to Durable Object for concurrency-safe handling
      const docId = parts[3];
      const idString = `${tenantId}::${docId}`;
      const doId = env.DOC_STORE.idFromName(idString);
      const obj = env.DOC_STORE.get(doId);
      const newUrl = new URL(request.url);
      newUrl.pathname = `/tenant/${tenantId}/docs/${docId}${parts.length>4?'/'+parts.slice(4).join('/'):''}`;
      const forwarded = new Request(newUrl.toString(), request);
      return obj.fetch(forwarded);
    }

    return new Response('not found', {status:404});
  }
};

/*
Deployment notes:
- Set JWT_SECRET via `wrangler secret put JWT_SECRET`.
- Pre-provision tenant shared secrets for testing via:
  wrangler kv:key put --binding=TENANT_KV shared:tenantA "my_shared_secret"
- JWT_TTL can be set in wrangler.toml [vars] as JWT_TTL = 600

Security notes / improvements:
- Store tenant shared secrets as salted hashes (bcrypt/argon2) and compare using a secure method.
- Consider using asymmetric JWTs (RS256) with a rotation-friendly key set for scaling.
- Use short TTLs for JWTs and implement refresh tokens if needed.
- Rate limit / abuse protect the /auth/login endpoint.
- Ensure TLS and CORS rules are correctly configured for your domain.
*/
