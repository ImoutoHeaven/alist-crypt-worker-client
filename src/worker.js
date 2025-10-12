import { extractNonceFromHeader } from './crypto.js';
import {
  rotLower,
  uint8ToBase64,
  parseBoolean,
  parseInteger,
} from './utils.js';
import { renderLandingPage } from './frontend.js';

const REQUIRED_ENV = ['ADDRESS', 'TOKEN'];
const preservedResponseHeaders = [
  'content-type',
  'content-length',
  'content-range',
  'accept-ranges',
  'etag',
  'last-modified',
  'cache-control',
  'expires',
  'content-disposition',
];

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

const sessionStore = new Map();
let lastCleanup = 0;

const createHttpError = (status, message, code) => {
  const error = new Error(message);
  error.status = status;
  if (code) {
    error.code = code;
  }
  return error;
};

const writeUint32BE = (target, offset, value) => {
  target[offset] = (value >>> 24) & 0xff;
  target[offset + 1] = (value >>> 16) & 0xff;
  target[offset + 2] = (value >>> 8) & 0xff;
  target[offset + 3] = value & 0xff;
};

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
    sessionTtlMs: parseInteger(env.SESSION_TTL_SECONDS, 300) * 1000,
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

const headersFromList = (list = []) => {
  const headers = new Headers();
  for (const [key, value] of list) {
    headers.set(key, value);
  }
  return headers;
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

const formatMetaPayload = (meta, nonce) => ({
  path: meta.path,
  size: meta.size,
  fileName: meta.file_name,
  blockDataSize: meta.block_data_size,
  blockHeaderSize: meta.block_header_size,
  fileHeaderSize: meta.file_header_size,
  dataKey: meta.data_key,
  nonce: uint8ToBase64(nonce),
});

const prepareDownloadContext = async (config, path, sign, clientIP) => {
  const meta = await fetchCryptMeta(config, path, clientIP);
  const verifyCandidates = collectVerifyCandidates(path, meta);
  const verifyResult = await verifyWithCandidates(config.signSecret, sign, verifyCandidates);
  if (verifyResult) {
    throw createHttpError(401, verifyResult, 'invalid-signature');
  }
  const remoteHeaders = sanitizeUpstreamHeaders(cloneRemoteHeaders(meta.remote?.headers));
  const headerBytes = await fetchEncryptedHeader(meta, remoteHeaders);
  const nonce = extractNonceFromHeader(headerBytes, meta.file_header_size);
  return {
    meta,
    remoteHeaders,
    nonce,
  };
};

const cleanupSessions = (now, ttlMs) => {
  if (now - lastCleanup < ttlMs) return;
  for (const [key, value] of sessionStore.entries()) {
    if (value.expires <= now) {
      sessionStore.delete(key);
    }
  }
  lastCleanup = now;
};

const storeSession = (info, ttlMs) => {
  const now = Date.now();
  cleanupSessions(now, ttlMs);
  const id = crypto.randomUUID().replace(/-/g, '');
  const expires = now + ttlMs;
  sessionStore.set(id, { ...info, expires });
  return { id, expires };
};

const getSession = (id) => {
  const record = sessionStore.get(id);
  if (!record) return null;
  if (record.expires <= Date.now()) {
    sessionStore.delete(id);
    return null;
  }
  return record;
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
  let context;
  try {
    context = await prepareDownloadContext(config, path, sign, clientIP);
  } catch (error) {
    if (error.status) {
      return respondJson(origin, { code: error.status, message: error.message }, error.status);
    }
    throw error;
  }
  const { meta, remoteHeaders, nonce } = context;

  const { id: sessionId, expires } = storeSession(
    {
      remote: {
        url: meta.remote.url,
        method: meta.remote.method || 'GET',
        headers: toSerializableHeaderList(remoteHeaders),
        rawPath: meta.remote?.raw_path || '',
      },
      path,
    },
    config.sessionTtlMs,
  );

  const downloadUrl = new URL(url);
  downloadUrl.pathname = '/fetch';
  downloadUrl.search = `session=${sessionId}`;

  const responsePayload = {
    code: 200,
    data: {
      session: sessionId,
      expires: new Date(expires).toISOString(),
      downloadUrl: downloadUrl.toString(),
      meta: {
        ...formatMetaPayload(meta, nonce),
        path,
      },
    },
  };
  return respondJson(origin, responsePayload, 200);
};

const createWebSocketErrorPayload = (message, code) => ({
  type: 'error',
  message,
  code,
});

const sendJson = (socket, payload) => {
  try {
    socket.send(JSON.stringify(payload));
  } catch (error) {
    // ignore failures when socket is closed
  }
};

const sendBinarySegment = (socket, segmentId, data) => {
  const body = data instanceof Uint8Array ? data : new Uint8Array(data);
  const payload = new Uint8Array(body.byteLength + 5);
  payload[0] = 1;
  writeUint32BE(payload, 1, segmentId >>> 0);
  payload.set(body, 5);
  socket.send(payload);
};

const handleWebSocket = (request, config) => {
  const upgrade = request.headers.get('Upgrade');
  if (!upgrade || upgrade.toLowerCase() !== 'websocket') {
    return new Response('Expected WebSocket upgrade', {
      status: 426,
      headers: {
        Connection: 'Upgrade',
        Upgrade: 'websocket',
      },
    });
  }

  const clientIP = request.headers.get('CF-Connecting-IP') || '';
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);

  const state = {
    socket: server,
    config,
    clientIP,
    initialized: false,
    closing: false,
    meta: null,
    remote: null,
    nonce: null,
    controllers: new Map(),
  };

  const cleanupControllers = () => {
    state.controllers.forEach((controller) => {
      try {
        controller.abort('socket-closed');
      } catch (error) {
        // ignore abort error
      }
    });
    state.controllers.clear();
  };

  const closeWithMessage = (message, code = 'internal-error', status = 1011) => {
    if (state.closing) return;
    state.closing = true;
    sendJson(server, createWebSocketErrorPayload(message, code));
    try {
      server.close(status, message.slice(0, 123));
    } catch (error) {
      // ignore close errors
    }
  };

  const handleInit = async (payload) => {
    if (state.initialized) {
      sendJson(server, createWebSocketErrorPayload('duplicate init message', 'duplicate-init'));
      return;
    }
    const { path, sign } = payload;
    if (!path) {
      sendJson(server, createWebSocketErrorPayload('path is required', 'missing-path'));
      server.close(1008, 'path required');
      return;
    }
    if (!sign) {
      sendJson(server, createWebSocketErrorPayload('sign is required', 'missing-sign'));
      server.close(1008, 'sign required');
      return;
    }
    let context;
    try {
      context = await prepareDownloadContext(config, path, sign, state.clientIP);
    } catch (error) {
      const code = error.code || 'init-failed';
      if (error.status === 401 || error.status === 403) {
        sendJson(server, createWebSocketErrorPayload(error.message, code));
        server.close(1008, error.message.slice(0, 123));
        return;
      }
      closeWithMessage(error.message || 'init failed', code);
      return;
    }

    state.initialized = true;
    state.meta = context.meta;
    state.remote = {
      url: context.meta.remote.url,
      method: context.meta.remote.method || 'GET',
      headers: toSerializableHeaderList(context.remoteHeaders),
    };
    state.nonce = context.nonce;

    sendJson(server, {
      type: 'meta',
      data: {
        sessionExpires: new Date(Date.now() + config.sessionTtlMs).toISOString(),
        meta: {
          ...formatMetaPayload(context.meta, context.nonce),
          path,
        },
      },
    });
  };

  const handleSegment = async (payload) => {
    if (!state.initialized || !state.remote) {
      sendJson(server, createWebSocketErrorPayload('connection not initialized', 'not-initialized'));
      return;
    }
    const { id, offset, length } = payload;
    if (!Number.isInteger(id) || id < 0) {
      sendJson(server, createWebSocketErrorPayload('invalid segment id', 'invalid-segment'));
      return;
    }
    if (!Number.isFinite(offset) || offset < 0) {
      sendJson(server, createWebSocketErrorPayload('invalid offset', 'invalid-offset'));
      return;
    }
    if (!Number.isFinite(length) || length === 0) {
      sendJson(server, createWebSocketErrorPayload('invalid length', 'invalid-length'));
      return;
    }

    const headers = headersFromList(state.remote.headers);
    if (length > 0) {
      headers.set('Range', `bytes=${offset}-${offset + length - 1}`);
    } else {
      headers.set('Range', `bytes=${offset}-`);
    }

    const controller = new AbortController();
    state.controllers.set(id, controller);
    let response;
    try {
      response = await fetch(state.remote.url, {
        method: state.remote.method,
        headers,
        signal: controller.signal,
      });
    } catch (error) {
      state.controllers.delete(id);
      if (controller.signal.aborted) {
        sendJson(server, { type: 'segment-aborted', id });
        return;
      }
      sendJson(server, {
        type: 'segment-error',
        id,
        message: error.message || 'failed to reach upstream',
      });
      return;
    }

    state.controllers.delete(id);
    if (!(response.ok || response.status === 206)) {
      sendJson(server, {
        type: 'segment-error',
        id,
        message: `upstream request failed: ${response.status}`,
        status: response.status,
      });
      return;
    }

    try {
      const arrayBuffer = await response.arrayBuffer();
      if (!arrayBuffer || arrayBuffer.byteLength === 0) {
        sendJson(server, { type: 'segment-error', id, message: 'empty response from upstream' });
        return;
      }
      sendBinarySegment(server, id, arrayBuffer);
    } catch (error) {
      sendJson(server, {
        type: 'segment-error',
        id,
        message: error.message || 'failed to read upstream response',
      });
    }
  };

  const handleCancel = (payload) => {
    const { id } = payload;
    if (!Number.isInteger(id)) return;
    const controller = state.controllers.get(id);
    if (!controller) return;
    controller.abort('client-cancelled');
    state.controllers.delete(id);
    sendJson(server, { type: 'segment-aborted', id });
  };

  server.accept();

  server.addEventListener('message', (event) => {
    if (state.closing) return;
    try {
      if (typeof event.data !== 'string') {
        sendJson(server, createWebSocketErrorPayload('binary message not supported', 'invalid-payload'));
        return;
      }
      let payload;
      try {
        payload = JSON.parse(event.data);
      } catch (error) {
        sendJson(server, createWebSocketErrorPayload('invalid json payload', 'invalid-json'));
        return;
      }
      if (!payload || typeof payload !== 'object') {
        sendJson(server, createWebSocketErrorPayload('invalid message format', 'invalid-message'));
        return;
      }
      switch (payload.type) {
        case 'init':
          handleInit(payload);
          break;
        case 'segment':
          handleSegment(payload);
          break;
        case 'cancel':
          handleCancel(payload);
          break;
        case 'ping':
          sendJson(server, { type: 'pong', ts: Date.now() });
          break;
        default:
          sendJson(server, createWebSocketErrorPayload('unknown message type', 'unknown-type'));
          break;
      }
    } catch (error) {
      closeWithMessage(error.message || 'internal error');
    }
  });

  server.addEventListener('close', () => {
    cleanupControllers();
  });
  server.addEventListener('error', () => {
    cleanupControllers();
  });

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
};

const handleFetch = async (request) => {
  const origin = request.headers.get('origin') || '*';
  const url = new URL(request.url);
  const sessionId = url.searchParams.get('session');
  if (!sessionId) {
    return respondJson(origin, { code: 400, message: 'session is required' }, 400);
  }
  const record = getSession(sessionId);
  if (!record) {
    return respondJson(origin, { code: 410, message: 'session expired' }, 410);
  }

  const upstreamHeaders = headersFromList(record.remote.headers);
  upstreamHeaders.set('Accept-Encoding', 'identity');
  const rangeHeader = request.headers.get('Range');
  if (rangeHeader) {
    upstreamHeaders.set('Range', rangeHeader);
  } else {
    upstreamHeaders.delete('Range');
  }

  const upstreamResp = await fetch(record.remote.url, {
    method: record.remote.method || 'GET',
    headers: upstreamHeaders,
    body: record.remote.method && record.remote.method !== 'GET' && record.remote.method !== 'HEAD' ? await request.arrayBuffer() : undefined,
  });

  if (!upstreamResp.ok && upstreamResp.status !== 206) {
    const message = `upstream request failed: ${upstreamResp.status}`;
    return respondJson(origin, { code: upstreamResp.status, message }, upstreamResp.status);
  }

  const responseHeaders = safeHeaders(origin);
  preservedResponseHeaders.forEach((name) => {
    const value = upstreamResp.headers.get(name);
    if (value !== null && value !== undefined) {
      responseHeaders.set(name, value);
    }
  });
  responseHeaders.set('Access-Control-Expose-Headers', preservedResponseHeaders.join(','));
  responseHeaders.delete('content-type');
  responseHeaders.set('Content-Type', 'application/octet-stream');
  responseHeaders.delete('content-disposition');

  return new Response(upstreamResp.body, {
    status: upstreamResp.status,
    headers: responseHeaders,
  });
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
  if (request.method === 'GET' && pathname === '/fetch') {
    return handleFetch(request);
  }
  if (request.method === 'GET' && pathname === '/ws') {
    return handleWebSocket(request, config);
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
