import { extractNonceFromHeader } from './crypto.js';
import {
  rotLower,
  uint8ToBase64,
  parseBoolean,
} from './utils.js';
import { renderLandingPage } from './frontend.js';

const REQUIRED_ENV = ['ADDRESS', 'TOKEN'];

const hopByHopHeaders = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade',
  'content-length',
  'host',
]);

const ensureRequiredEnv = (env) => {
  REQUIRED_ENV.forEach((key) => {
    if (!env[key] || String(env[key]).trim() === '') {
      throw new Error(`environment variable ${key} is required`);
    }
  });
};

const resolveConfig = (env = {}) => {
  ensureRequiredEnv(env);
  return {
    address: env.ADDRESS,
    token: env.TOKEN,
    verifyHeader: env.VERIFY_HEADER || '',
    verifySecret: env.VERIFY_SECRET || '',
    ipv4Only: parseBoolean(env.IPV4_ONLY, false),
    signSecret: env.SIGN_SECRET && env.SIGN_SECRET.trim() !== '' ? env.SIGN_SECRET : env.TOKEN,
  };
};

const hmacSha256Sign = async (secret, data, expire) => {
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const payload = `${data}:${expire}`;
  const buf = await crypto.subtle.sign(
    { name: 'HMAC', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(payload),
  );
  return btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, '-')
    .replace(/\//g, '_') + `:${expire}`;
};

const verifySignature = async (secret, data, signature) => {
  if (!signature) return 'sign missing';
  const parts = signature.split(':');
  const expirePart = parts[parts.length - 1];
  if (!expirePart) return 'expire missing';
  const expire = Number.parseInt(expirePart, 10);
  if (Number.isNaN(expire)) return 'expire invalid';
  if (expire < Date.now() / 1e3 && expire > 0) return 'expire expired';
  const expected = await hmacSha256Sign(secret, data, expire);
  if (expected !== signature) return 'sign mismatch';
  return '';
};

const appendCandidateVariants = (target, rawValue) => {
  if (rawValue === undefined || rawValue === null) return;
  const value = String(rawValue).trim();
  if (!value) return;
  const variants = new Set([value]);
  if (!value.startsWith('/')) {
    variants.add(`/${value}`);
  }
  try {
    const decoded = decodeURIComponent(value);
    if (decoded && decoded !== value) {
      variants.add(decoded);
      if (!decoded.startsWith('/')) {
        variants.add(`/${decoded}`);
      }
    }
  } catch (error) {
    // ignore decode errors
  }
  try {
    const encoded = encodeURI(value);
    if (encoded && encoded !== value) {
      variants.add(encoded);
      if (!encoded.startsWith('/')) {
        variants.add(`/${encoded}`);
      }
    }
  } catch (error) {
    // ignore encode errors
  }
  variants.forEach((variant) => target.add(variant));
};

const collectVerifyCandidates = (path, meta) => {
  const candidates = new Set();
  appendCandidateVariants(candidates, path);
  if (meta) {
    appendCandidateVariants(candidates, meta.path);
    appendCandidateVariants(candidates, meta.encrypted_path);
    appendCandidateVariants(candidates, meta.encrypted_actual_path);
    appendCandidateVariants(candidates, meta.remote?.raw_path);
    appendCandidateVariants(candidates, meta.remote?.url);
    if (meta.remote?.url) {
      try {
        const parsed = new URL(meta.remote.url);
        appendCandidateVariants(candidates, parsed.pathname);
      } catch (error) {
        // ignore invalid url
      }
    }
  }
  return candidates;
};

const verifyWithCandidates = async (secret, sign, candidates) => {
  if (!sign) return 'sign missing';
  let lastError = 'sign mismatch';
  for (const candidate of candidates) {
    if (!candidate || typeof candidate !== 'string') continue;
    const result = await verifySignature(secret, candidate, sign);
    if (!result) {
      return '';
    }
    if (result !== 'sign mismatch') {
      return result;
    }
    lastError = result;
  }
  return lastError;
};

const cloneRemoteHeaders = (headerMap = {}) => {
  const headers = new Headers();
  Object.entries(headerMap).forEach(([key, value]) => {
    if (value === undefined || value === null || value === '') return;
    headers.set(key, value);
  });
  return headers;
};

const sanitizeUpstreamHeaders = (headers) => {
  const sanitized = new Headers();
  headers.forEach((value, key) => {
    const lower = rotLower(key);
    if (hopByHopHeaders.has(lower)) return;
    sanitized.set(key, value);
  });
  sanitized.set('Accept-Encoding', 'identity');
  return sanitized;
};

const toSerializableHeaderList = (headers) => {
  const entries = [];
  headers.forEach((value, key) => {
    entries.push([key, value]);
  });
  return entries;
};

const safeHeaders = (origin) => {
  const headers = new Headers();
  if (origin) {
    headers.set('Access-Control-Allow-Origin', origin);
    headers.append('Vary', 'Origin');
  } else {
    headers.set('Access-Control-Allow-Origin', '*');
  }
  headers.set('Access-Control-Allow-Headers', '*');
  headers.set('Access-Control-Allow-Methods', 'GET,HEAD,OPTIONS');
  return headers;
};

const respondJson = (origin, payload, status = 200) => {
  const headers = safeHeaders(origin);
  headers.set('content-type', 'application/json;charset=UTF-8');
  headers.set('cache-control', 'no-store');
  return new Response(JSON.stringify(payload), { status, headers });
};

const ensureIPv4 = (request, ipv4Only) => {
  if (!ipv4Only) return null;
  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  if (clientIP.includes(':')) {
    return respondJson(
      request.headers.get('origin') || '*',
      { code: 403, message: 'ipv6 access is prohibited' },
      403,
    );
  }
  return null;
};

const fetchCryptMeta = async (config, path, clientIP) => {
  const headers = {
    'content-type': 'application/json;charset=UTF-8',
    Authorization: config.token,
    'CF-Connecting-IP-WORKERS': clientIP || '',
  };
  if (config.verifyHeader && config.verifySecret) {
    headers[config.verifyHeader] = config.verifySecret;
  }
  const response = await fetch(`${config.address}/api/fs/crypt_meta`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ path }),
  });
  const text = await response.text();
  let payload;
  try {
    payload = JSON.parse(text);
  } catch (error) {
    const snippet = text.length > 256 ? `${text.slice(0, 256)}…` : text;
    throw new Error(`unexpected response from crypt_meta: ${snippet}`);
  }
  if (payload.code !== 200) {
    throw new Error(payload.message || 'crypt_meta failed');
  }
  return payload.data;
};

const fetchEncryptedHeader = async (meta, remoteHeaders) => {
  const headerSize = meta.file_header_size;
  if (!headerSize || headerSize <= 0) {
    throw new Error('invalid file header size from metadata');
  }
  const headers = new Headers(remoteHeaders);
  headers.set('Range', `bytes=0-${headerSize - 1}`);
  const resp = await fetch(meta.remote.url, {
    method: meta.remote.method || 'GET',
    headers,
  });
  if (!resp.ok && resp.status !== 206) {
    throw new Error(`failed to fetch header: ${resp.status}`);
  }
  const data = new Uint8Array(await resp.arrayBuffer());
  if (data.length < headerSize) {
    throw new Error('header length insufficient');
  }
  return data;
};

const handleOptions = (request) => new Response(null, { headers: safeHeaders(request.headers.get('Origin')) });

const handleInfo = async (request, config) => {
  const origin = request.headers.get('origin') || '*';
  const url = new URL(request.url);
  const path = url.searchParams.get('path');
  const sign = url.searchParams.get('sign') || '';
  if (!path) {
    return respondJson(origin, { code: 400, message: 'path is required' }, 400);
  }

  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const meta = await fetchCryptMeta(config, path, clientIP);
  const verifyCandidates = collectVerifyCandidates(path, meta);
  const verifyResult = await verifyWithCandidates(config.signSecret, sign, verifyCandidates);
  if (verifyResult) {
    return respondJson(origin, { code: 401, message: verifyResult }, 401);
  }

  const remoteHeaders = sanitizeUpstreamHeaders(cloneRemoteHeaders(meta.remote?.headers));
  const headerBytes = await fetchEncryptedHeader(meta, remoteHeaders);
  const nonce = extractNonceFromHeader(headerBytes, meta.file_header_size);

  const responsePayload = {
    code: 200,
    data: {
      download: {
        url: meta.remote.url,
        method: meta.remote.method || 'GET',
        headers: toSerializableHeaderList(remoteHeaders),
        rawPath: meta.remote?.raw_path || '',
      },
      meta: {
        path,
        size: meta.size,
        fileName: meta.file_name,
        blockDataSize: meta.block_data_size,
        blockHeaderSize: meta.block_header_size,
        fileHeaderSize: meta.file_header_size,
        dataKey: meta.data_key,
        nonce: uint8ToBase64(nonce),
      },
    },
  };
  return respondJson(origin, responsePayload, 200);
};

const handleFileRequest = async (request) => {
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    return respondJson(request.headers.get('origin') || '*', { code: 405, message: 'method not allowed' }, 405);
  }
  if (request.method === 'HEAD') {
    return new Response(null, {
      status: 200,
      headers: {
        'content-type': 'text/html; charset=UTF-8',
        'cache-control': 'no-store',
      },
    });
  }
  const url = new URL(request.url);
  return renderLandingPage(url.pathname);
};

const routeRequest = async (request, config) => {
  if (request.method === 'OPTIONS') {
    return handleOptions(request);
  }
  const ipv4Error = ensureIPv4(request, config.ipv4Only);
  if (ipv4Error) return ipv4Error;

  const pathname = new URL(request.url).pathname || '/';
  if (request.method === 'GET' && pathname === '/info') {
    return handleInfo(request, config);
  }
  return handleFileRequest(request);
};

export default {
  async fetch(request, env) {
    const config = resolveConfig(env || {});
    try {
      return await routeRequest(request, config);
    } catch (error) {
      const origin = request.headers.get('origin') || '*';
      const message = error instanceof Error ? error.message : String(error);
      return respondJson(origin, { code: 500, message }, 500);
    }
  },
};
