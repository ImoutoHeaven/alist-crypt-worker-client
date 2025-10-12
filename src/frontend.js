const escapeHtml = (value = '') =>
  value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

const pageScript = String.raw`
(() => {
  'use strict';

  const MAX_CONCURRENCY = 4;
  const MAX_RETRY_PER_SEGMENT = 3;
  const RETRY_DELAY_MS = 20000;
  const SESSION_EXPIRED_CODE = 'session-expired';

  const $ = (id) => document.getElementById(id);
  const statusEl = $('status');
  const fileNameEl = $('fileName');
  const downloadBar = $('downloadBar');
  const decryptBar = $('decryptBar');
  const downloadText = $('downloadText');
  const decryptText = $('decryptText');
  const speedText = $('speedText');
  const toggleBtn = $('toggleBtn');
  const retryBtn = $('retryBtn');
  const logEl = $('log');

  const log = (message) => {
    const time = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.textContent = '[' + time + '] ' + message;
    logEl.appendChild(entry);
    logEl.scrollTop = logEl.scrollHeight;
  };

  const setStatus = (text) => {
    statusEl.textContent = text;
    log(text);
  };

  const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes) || bytes < 0) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let value = bytes;
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    const digits = value >= 100 || unit === 0 ? 0 : 1;
    return value.toFixed(digits) + ' ' + units[unit];
  };

  const base64ToUint8 = (value) => {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i += 1) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  };

  const incrementNonce = (baseNonce, increment) => {
    const output = baseNonce.slice();
    let carry = BigInt(increment);
    let index = 0;
    while (carry > 0n && index < output.length) {
      const sum = BigInt(output[index]) + (carry & 0xffn);
      output[index] = Number(sum & 0xffn);
      carry = (carry >> 8n) + (sum >> 8n);
      index += 1;
    }
    return output;
  };

  const decryptBlock = (cipherBlock, dataKey, baseNonce, blockIndex) => {
    const nonce = incrementNonce(baseNonce, blockIndex);
    const opened = window.nacl.secretbox.open(cipherBlock, nonce, dataKey);
    if (!opened) return null;
    return new Uint8Array(opened);
  };

  const calculateUnderlying = (offset, limit, meta) => {
    const blockData = meta.blockDataSize;
    const blockHeader = meta.blockHeaderSize;
    const headerSize = meta.fileHeaderSize;

    const blocks = Math.floor(offset / blockData);
    const discard = offset % blockData;

    let underlyingOffset = headerSize + blocks * (blockHeader + blockData);
    let underlyingLimit = -1;
    if (limit >= 0) {
      let bytesToRead = limit - (blockData - discard);
      let blocksToRead = 1;
      if (bytesToRead > 0) {
        const extraBlocks = Math.floor(bytesToRead / blockData);
        const remainder = bytesToRead % blockData;
        blocksToRead += extraBlocks;
        if (remainder !== 0) {
          blocksToRead += 1;
        }
      }
      underlyingLimit = blocksToRead * (blockHeader + blockData);
    }

    return { underlyingOffset, underlyingLimit, discard, blocks };
  };

  const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

  const state = {
    infoParams: null,
    refreshingSession: null,
    meta: null,
    socket: null,
    socketReady: false,
    socketPromise: null,
    segmentResolvers: new Map(),
    inflightSegments: new Set(),
    total: 0,
    totalEncrypted: 0,
    blockDataSize: 0,
    blockHeaderSize: 0,
    fileHeaderSize: 0,
    dataKey: null,
    baseNonce: null,
    segments: [],
    pendingSegments: [],
    downloadedEncrypted: 0,
    decrypted: 0,
    started: false,
    infoReady: false,
    paused: false,
    mode: 'idle',
    resumeResolvers: [],
    speedTimer: null,
    bytesSinceSpeedCheck: 0,
    lastSpeedAt: performance.now(),
    writer: null,
    workflowPromise: null,
  };

  const readUint32BE = (bytes, offset) =>
    ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;

  const buildWebSocketUrl = () => {
    if (!state.infoParams) {
      throw new Error('缺少下载参数');
    }
    const url = new URL('/ws', state.infoParams.origin);
    url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
    return url.toString();
  };

  const createAbortError = () => {
    const error = new Error('操作已取消');
    error.name = 'AbortError';
    return error;
  };

  const failPendingSegments = (error) => {
    if (state.segmentResolvers.size === 0) return;
    const failure = error instanceof Error ? error : new Error(String(error || '连接异常'));
    if (!failure.code) {
      failure.code = SESSION_EXPIRED_CODE;
    }
    state.segmentResolvers.forEach(({ reject }) => {
      try {
        reject(failure);
      } catch (rejectError) {
        console.error(rejectError);
      }
    });
    state.segmentResolvers.clear();
    state.inflightSegments.clear();
  };

  const sendSocketMessage = (payload) => {
    if (!state.socket || state.socket.readyState !== WebSocket.OPEN) {
      throw new Error('WebSocket 未连接');
    }
    state.socket.send(JSON.stringify(payload));
  };

  const cancelSegment = (id) => {
    if (!state.socket || state.socket.readyState !== WebSocket.OPEN) return;
    try {
      state.socket.send(
        JSON.stringify({
          type: 'cancel',
          id,
        }),
      );
    } catch (error) {
      console.error(error);
    }
  };

  const handleSegmentAborted = (payload) => {
    const { id } = payload;
    if (!Number.isInteger(id)) return;
    const entry = state.segmentResolvers.get(id);
    if (!entry) return;
    state.segmentResolvers.delete(id);
    state.inflightSegments.delete(id);
    entry.reject(createAbortError());
  };

  const handleSegmentError = (payload) => {
    const { id } = payload;
    if (!Number.isInteger(id)) return;
    const entry = state.segmentResolvers.get(id);
    if (!entry) return;
    state.segmentResolvers.delete(id);
    state.inflightSegments.delete(id);
    const error = new Error(payload.message || '分段下载失败');
    if (payload.status) {
      error.status = payload.status;
      if ([401, 403, 410, 429].includes(payload.status)) {
        error.code = SESSION_EXPIRED_CODE;
      }
    }
    if (!error.code && payload.code === SESSION_EXPIRED_CODE) {
      error.code = SESSION_EXPIRED_CODE;
    }
    entry.reject(error);
  };

  const handleSocketPayload = (payload) => {
    if (!payload || typeof payload !== 'object') return;
    switch (payload.type) {
      case 'segment-error':
        handleSegmentError(payload);
        break;
      case 'segment-aborted':
        handleSegmentAborted(payload);
        break;
      case 'error': {
        const error = new Error(payload.message || 'WebSocket 错误');
        if (payload.code === 'invalid-signature') {
          error.code = SESSION_EXPIRED_CODE;
        }
        failPendingSegments(error);
        if (state.socket && state.socket.readyState === WebSocket.OPEN) {
          try {
            state.socket.close(1011, 'error');
          } catch (closeError) {
            console.error(closeError);
          }
        }
        setStatus('连接错误：' + error.message);
        break;
      }
      case 'pong':
        break;
      default:
        break;
    }
  };

  const handleSocketBinary = async (data) => {
    let bytes;
    if (data instanceof Uint8Array) {
      bytes = data;
    } else if (data instanceof ArrayBuffer) {
      bytes = new Uint8Array(data);
    } else if (data && typeof data.arrayBuffer === 'function') {
      const buffer = await data.arrayBuffer();
      bytes = new Uint8Array(buffer);
    } else {
      return;
    }
    if (bytes.length < 5) return;
    const type = bytes[0];
    if (type !== 1) return;
    const id = readUint32BE(bytes, 1);
    const entry = state.segmentResolvers.get(id);
    if (!entry) return;
    state.segmentResolvers.delete(id);
    state.inflightSegments.delete(id);
    const payload = bytes.subarray(5);
    entry.resolve(payload);
  };

  const ensureSocket = async ({ force = false } = {}) => {
    if (!force && state.socket && state.socketReady && state.socket.readyState === WebSocket.OPEN) {
      return state.socket;
    }
    if (state.socketPromise) {
      return state.socketPromise;
    }
    if (force && state.socket) {
      try {
        state.socket.close(1000, 'reconnect');
      } catch (error) {
        console.error(error);
      }
      state.socket = null;
      state.socketReady = false;
    }
    const info = state.infoParams;
    if (!info) {
      throw new Error('缺少下载参数');
    }
    const url = buildWebSocketUrl();
    state.socketPromise = new Promise((resolve, reject) => {
      const socket = new WebSocket(url);
      state.socket = socket;
      state.socketReady = false;
      let settled = false;
      const finalizeFailure = (error) => {
        if (settled) return;
        settled = true;
        state.socketPromise = null;
        state.socket = null;
        state.socketReady = false;
        failPendingSegments(error);
        reject(error);
      };
      const finalizeSuccess = () => {
        if (settled) return;
        settled = true;
        state.socketPromise = null;
        state.socketReady = true;
        resolve(socket);
      };
      socket.addEventListener('open', () => {
        try {
          socket.send(
            JSON.stringify({
              type: 'init',
              path: info.path,
              sign: info.sign,
            }),
          );
        } catch (error) {
          finalizeFailure(error instanceof Error ? error : new Error(String(error)));
        }
      });
      socket.addEventListener('message', async (event) => {
        try {
          if (typeof event.data === 'string') {
            let payload;
            try {
              payload = JSON.parse(event.data);
            } catch (error) {
              if (!state.socketReady) {
                finalizeFailure(new Error('服务端返回无效 JSON'));
              }
              return;
            }
            if (payload.type === 'meta') {
              const data = payload.data || {};
              const meta = data.meta;
              if (!meta) {
                throw new Error('服务端未返回元数据');
              }
              state.meta = meta;
              state.dataKey = base64ToUint8(meta.dataKey);
              state.baseNonce = base64ToUint8(meta.nonce);
              state.total = meta.size;
              state.blockDataSize = meta.blockDataSize;
              state.blockHeaderSize = meta.blockHeaderSize;
              state.fileHeaderSize = meta.fileHeaderSize;
              finalizeSuccess();
              return;
            }
            if (!state.socketReady) {
              // 忽略握手前的其他消息
              return;
            }
            handleSocketPayload(payload);
          } else {
            if (!state.socketReady) {
              return;
            }
            await handleSocketBinary(event.data);
          }
        } catch (error) {
          finalizeFailure(error instanceof Error ? error : new Error(String(error)));
        }
      });
      socket.addEventListener('error', () => {
        finalizeFailure(new Error('WebSocket 连接异常'));
      });
      socket.addEventListener('close', (event) => {
        if (!settled) {
          const reason = event.reason || 'WebSocket 提前关闭';
          finalizeFailure(new Error(reason));
          return;
        }
        state.socket = null;
        state.socketReady = false;
        state.socketPromise = null;
        const reason = event.reason || 'WebSocket 已关闭';
        const error = new Error(reason);
        error.code = SESSION_EXPIRED_CODE;
        failPendingSegments(error);
        state.inflightSegments.clear();
      });
    });
    return state.socketPromise;
  };

  const resetProgressBars = () => {
    downloadBar.style.width = '0%';
    decryptBar.style.width = '0%';
    downloadText.textContent = '0%';
    decryptText.textContent = '0%';
    speedText.textContent = '--';
    state.downloadedEncrypted = 0;
    state.decrypted = 0;
    state.bytesSinceSpeedCheck = 0;
    state.lastSpeedAt = performance.now();
  };

  const updateProgress = () => {
    const totalEncrypted = Math.max(state.totalEncrypted, 1);
    const totalPlain = Math.max(state.total, 1);
    const downloadPercent = Math.min(100, (state.downloadedEncrypted / totalEncrypted) * 100);
    const decryptPercent = Math.min(100, (state.decrypted / totalPlain) * 100);
    downloadBar.style.width = downloadPercent.toFixed(2) + '%';
    decryptBar.style.width = decryptPercent.toFixed(2) + '%';
    downloadText.textContent = downloadPercent.toFixed(2) + '% (' + formatBytes(state.downloadedEncrypted) + ' / ' + formatBytes(totalEncrypted) + ')';
    decryptText.textContent = decryptPercent.toFixed(2) + '% (' + formatBytes(state.decrypted) + ' / ' + formatBytes(totalPlain) + ')';
  };

  const updateSpeed = () => {
    const now = performance.now();
    const elapsed = (now - state.lastSpeedAt) / 1000;
    if (elapsed <= 0) return;
    const speed = state.bytesSinceSpeedCheck / elapsed;
    state.bytesSinceSpeedCheck = 0;
    state.lastSpeedAt = now;
    speedText.textContent = speed > 0 ? formatBytes(speed) + '/s' : '--';
  };

  const ensureWriter = async (fileName) => {
    if ('showSaveFilePicker' in window) {
      const suggestedName = fileName && fileName.trim() !== '' ? fileName : 'download.bin';
      const handle = await window.showSaveFilePicker({
        suggestedName,
        types: [{ description: 'Binary file', accept: { 'application/octet-stream': ['.bin'] } }],
      });
      const writable = await handle.createWritable();
      state.writer = { type: 'fs', writable };
      log('已选择保存位置：' + suggestedName);
      return;
    }
    state.writer = { type: 'memory', chunks: [] };
    log('当前浏览器不支持文件系统访问 API，将在解密完成后触发浏览器下载');
  };

  const writeChunk = async (chunk) => {
    if (!state.writer) throw new Error('writer not initialised');
    if (state.writer.type === 'fs') {
      await state.writer.writable.write(chunk);
    } else {
      state.writer.chunks.push(chunk);
    }
  };

  const finalizeWriter = async () => {
    if (!state.writer) return;
    if (state.writer.type === 'fs') {
      await state.writer.writable.close();
      log('文件已保存到指定位置');
      return;
    }
    const blob = new Blob(state.writer.chunks, { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = state.meta.fileName || 'download.bin';
    document.body.appendChild(anchor);
    anchor.click();
    document.body.removeChild(anchor);
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    log('已触发浏览器下载');
  };

  const waitForResume = () =>
    new Promise((resolve) => {
      state.resumeResolvers.push(resolve);
    });

  const enqueueSegment = (index, toFront = false) => {
    const segment = state.segments[index];
    if (!segment || segment.encrypted) return;
    if (state.pendingSegments.includes(index)) return;
    if (toFront) {
      state.pendingSegments.unshift(index);
    } else {
      state.pendingSegments.push(index);
    }
  };

  const takeSegment = () => {
    while (state.pendingSegments.length > 0) {
      const index = state.pendingSegments.shift();
      const segment = state.segments[index];
      if (!segment || segment.encrypted) {
        continue;
      }
      return index;
    }
    return undefined;
  };

  const setPaused = (value) => {
    if (state.mode !== 'downloading') return;
    if (state.paused === value) return;
    state.paused = value;
    if (value) {
      toggleBtn.textContent = '继续下载';
      setStatus('已暂停');
      const inflight = Array.from(state.inflightSegments);
      inflight.forEach((id) => cancelSegment(id));
    } else {
      toggleBtn.textContent = '暂停';
      setStatus('恢复下载');
      const resolvers = state.resumeResolvers.splice(0, state.resumeResolvers.length);
      resolvers.forEach((resolve) => resolve());
    }
  };

  const prepareSegments = () => {
    const segments = [];
    const pending = [];
    const segmentSize = state.blockDataSize * 16 || 64 * 1024;
    let offset = 0;
    let index = 0;
    let totalEncrypted = 0;
    while (offset < state.total) {
      const length = Math.min(segmentSize, state.total - offset);
      const mapping = calculateUnderlying(offset, length, state.meta);
      if (!mapping || mapping.underlyingLimit <= 0) {
        throw new Error('无法计算有效的数据块');
      }
      segments.push({
        index,
        offset,
        length,
        mapping,
        encrypted: null,
        retries: 0,
      });
      pending.push(index);
      totalEncrypted += mapping.underlyingLimit;
      offset += length;
      index += 1;
    }
    state.segments = segments;
    state.pendingSegments = pending;
    state.totalEncrypted = totalEncrypted;
  };

  const refreshPendingQueue = () => {
    state.pendingSegments = [];
    let encryptedTotal = 0;
    state.segments.forEach((segment) => {
      if (segment.encrypted) {
        encryptedTotal += segment.encrypted.length;
      } else {
        segment.retries = 0;
        state.pendingSegments.push(segment.index);
      }
    });
    state.downloadedEncrypted = encryptedTotal;
    state.decrypted = 0;
  };

  const fetchInfo = async ({ initial = false, refresh = false } = {}) => {
    if (!refresh && !initial && !state.infoParams) {
      throw new Error('缺少初始信息');
    }
    if (initial) {
      const currentUrl = new URL(window.location.href);
      const path = decodeURIComponent(currentUrl.pathname);
      const sign = currentUrl.searchParams.get('sign') || '';
      if (!sign) {
        throw new Error('签名缺失');
      }
      state.infoParams = {
        origin: currentUrl.origin,
        path,
        sign,
      };
    }
    if (!state.infoParams) {
      throw new Error('缺少下载参数');
    }

    await ensureSocket({ force: refresh });
    if (!state.meta) {
      throw new Error('缺少元数据');
    }

    if (refresh) {
      log('已刷新下载会话');
      return { meta: state.meta };
    }

    state.total = state.meta.size;
    state.blockDataSize = state.meta.blockDataSize;
    state.blockHeaderSize = state.meta.blockHeaderSize;
    state.fileHeaderSize = state.meta.fileHeaderSize;
    state.started = false;
    state.paused = false;
    state.mode = 'idle';
    state.resumeResolvers = [];
    state.writer = null;
    state.segmentResolvers.clear();
    state.inflightSegments.clear();
    state.downloadedEncrypted = 0;
    state.bytesSinceSpeedCheck = 0;
    state.totalEncrypted = 0;
    state.decrypted = 0;
    state.segments = [];
    state.pendingSegments = [];
    prepareSegments();
    resetProgressBars();
    updateProgress();
    fileNameEl.textContent = state.meta.fileName || state.infoParams.path.split('/').pop() || '未命名文件';
    state.infoReady = true;
    toggleBtn.textContent = '开始下载';
    toggleBtn.disabled = false;
    retryBtn.disabled = true;
    setStatus('信息获取成功，请点击“开始下载”');
    logEl.innerHTML = '';
    return { meta: state.meta };
  };

  const refreshSession = async () => {
    if (state.refreshingSession) {
      return state.refreshingSession;
    }
    const promise = (async () => {
      setStatus('连接已断开，正在重新连接');
      const data = await fetchInfo({ refresh: true });
      if (data.meta) {
        if (data.meta.size !== state.total || data.meta.blockDataSize !== state.blockDataSize) {
          throw new Error('刷新后元数据与当前会话不一致');
        }
      }
      setStatus('连接已恢复，继续下载');
    })();
    state.refreshingSession = promise;
    try {
      await promise;
    } finally {
      state.refreshingSession = null;
    }
  };

  const requestSegment = async (segment) => {
    await ensureSocket();
    return new Promise((resolve, reject) => {
      const id = segment.index;
      if (state.segmentResolvers.has(id)) {
        reject(new Error('该分段正在处理中'));
        return;
      }
      state.segmentResolvers.set(id, {
        resolve: (payload) => {
          if (payload instanceof Uint8Array) {
            resolve(payload);
          } else if (payload instanceof ArrayBuffer) {
            resolve(new Uint8Array(payload));
          } else {
            resolve(new Uint8Array(payload));
          }
        },
        reject,
      });
      state.inflightSegments.add(id);
      try {
        sendSocketMessage({
          type: 'segment',
          id,
          offset: segment.mapping.underlyingOffset,
          length: segment.mapping.underlyingLimit,
        });
      } catch (error) {
        state.segmentResolvers.delete(id);
        state.inflightSegments.delete(id);
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
  };

  const downloadSegment = async (index) => {
    const segment = state.segments[index];
    if (!segment || segment.encrypted) return;
    const buffer = await requestSegment(segment);
    if (!buffer || buffer.length === 0) {
      throw new Error('上游返回空数据');
    }
    segment.encrypted = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
    state.downloadedEncrypted += segment.encrypted.length;
    state.bytesSinceSpeedCheck += segment.encrypted.length;
    updateProgress();
  };

  const downloadAllSegments = async () => {
    const worker = async () => {
      while (true) {
        if (state.paused) {
          await waitForResume();
          continue;
        }
        const index = takeSegment();
        if (index === undefined) {
          return;
        }
        const segment = state.segments[index];
        if (!segment || segment.encrypted) {
          continue;
        }
        try {
          await downloadSegment(index);
          segment.retries = 0;
        } catch (error) {
          if (error && error.name === 'AbortError') {
            enqueueSegment(index, true);
            continue;
          }
          if (error && error.code === SESSION_EXPIRED_CODE) {
            await refreshSession();
            enqueueSegment(index, true);
            continue;
          }
          segment.retries += 1;
          if (segment.retries <= MAX_RETRY_PER_SEGMENT) {
            const attempt = segment.retries;
            setStatus('分段 #' + (index + 1) + ' 下载失败（' + error.message + '），' + Math.round(RETRY_DELAY_MS / 1000) + ' 秒后重试（' + attempt + '/' + MAX_RETRY_PER_SEGMENT + '）');
            await sleep(RETRY_DELAY_MS);
            enqueueSegment(index, true);
            continue;
          }
          throw error;
        }
      }
    };

    const workers = [];
    const workerCount = Math.min(MAX_CONCURRENCY, state.segments.length);
    for (let i = 0; i < workerCount; i += 1) {
      workers.push(worker());
    }
    await Promise.all(workers);

    const unfinished = state.segments.find((segment) => !segment.encrypted);
    if (unfinished) {
      throw new Error('仍有分段未完成下载');
    }
  };

  const decryptSegment = async (segment) => {
    if (!segment.encrypted) {
      throw new Error('缺少加密数据');
    }
    const buffer = segment.encrypted;
    const totalNeeded = segment.length;
    const dataKey = state.dataKey;
    const baseNonce = state.baseNonce;
    let produced = 0;
    let currentBlock = segment.mapping.blocks;
    let discard = segment.mapping.discard;
    let offset = 0;

    while (offset < buffer.length && produced < totalNeeded) {
      if (offset + state.blockHeaderSize > buffer.length) {
        throw new Error('加密块头不足');
      }
      let end = offset + state.blockHeaderSize + state.blockDataSize;
      if (end > buffer.length) {
        end = buffer.length;
      }
      const cipherBlock = buffer.subarray(offset, end);
      offset = end;
      const plainBlock = decryptBlock(cipherBlock, dataKey, baseNonce, currentBlock);
      if (!plainBlock) {
        throw new Error('解密失败，请稍后重试');
      }
      let chunk = plainBlock;
      if (currentBlock === segment.mapping.blocks && discard > 0) {
        if (chunk.length <= discard) {
          discard -= chunk.length;
          currentBlock += 1;
          continue;
        }
        chunk = chunk.subarray(discard);
        discard = 0;
      }
      if (chunk.length === 0) {
        currentBlock += 1;
        continue;
      }
      const remaining = totalNeeded - produced;
      if (remaining <= 0) {
        break;
      }
      if (chunk.length > remaining) {
        const slice = chunk.subarray(0, remaining);
        await writeChunk(slice);
        produced += slice.length;
        state.decrypted += slice.length;
        break;
      }
      await writeChunk(chunk);
      produced += chunk.length;
      state.decrypted += chunk.length;
      currentBlock += 1;
      if (state.decrypted % (state.blockDataSize * 4) === 0) {
        updateProgress();
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }
    segment.encrypted = null;
    updateProgress();
  };

  const decryptAllSegments = async () => {
    setStatus('下载完成，准备解密');
    for (const segment of state.segments) {
      await decryptSegment(segment);
    }
  };

  const startWorkflow = async () => {
    if (state.workflowPromise) return;
    state.workflowPromise = (async () => {
      try {
        if (!state.infoReady) return;
        if (!window.nacl || !window.nacl.secretbox || !window.nacl.secretbox.open) {
          throw new Error('TweetNaCl 加载失败，请刷新页面重试');
        }
        await ensureWriter(state.meta.fileName);
        refreshPendingQueue();
        updateProgress();
        state.started = true;
        state.paused = false;
        state.mode = 'downloading';
        toggleBtn.textContent = '暂停';
        toggleBtn.disabled = false;
        retryBtn.disabled = true;
        setStatus('正在下载（' + MAX_CONCURRENCY + ' 线程）');
        if (state.speedTimer) {
          clearInterval(state.speedTimer);
        }
        state.speedTimer = setInterval(updateSpeed, 1000);
        await downloadAllSegments();
        if (state.speedTimer) {
          clearInterval(state.speedTimer);
          state.speedTimer = null;
        }
        updateSpeed();
        state.mode = 'decrypting';
        toggleBtn.textContent = '解密中';
        toggleBtn.disabled = true;
        setStatus('全部分段下载完成，执行解密');
        await decryptAllSegments();
        state.decrypted = state.total;
        updateProgress();
        await finalizeWriter();
        state.mode = 'finished';
        toggleBtn.textContent = '完成';
        setStatus('解密完成，文件已保存');
        retryBtn.disabled = true;
      } catch (error) {
        console.error(error);
        if (error && error.name === 'AbortError' && state.paused) {
          setStatus('已暂停');
        } else if (error && error.code === SESSION_EXPIRED_CODE) {
          setStatus('会话刷新失败：' + error.message);
          retryBtn.disabled = false;
          toggleBtn.textContent = '开始下载';
          toggleBtn.disabled = false;
          state.started = false;
          state.mode = 'idle';
        } else if (error instanceof Error) {
          setStatus('处理失败：' + error.message);
          retryBtn.disabled = false;
          toggleBtn.textContent = '开始下载';
          toggleBtn.disabled = false;
          state.started = false;
          state.mode = 'idle';
        } else {
          setStatus('处理失败，已中止');
          retryBtn.disabled = false;
          toggleBtn.textContent = '开始下载';
          toggleBtn.disabled = false;
          state.started = false;
          state.mode = 'idle';
        }
      } finally {
        if (state.speedTimer) {
          clearInterval(state.speedTimer);
          state.speedTimer = null;
        }
        state.workflowPromise = null;
      }
    })();
    await state.workflowPromise;
  };

  toggleBtn.addEventListener('click', () => {
    if (!state.infoReady) return;
    if (!state.started) {
      startWorkflow();
      return;
    }
    if (state.mode === 'downloading') {
      setPaused(!state.paused);
    }
  });

  retryBtn.addEventListener('click', () => {
    if (state.workflowPromise) return;
    toggleBtn.disabled = true;
    toggleBtn.textContent = '加载中';
    retryBtn.disabled = true;
    fetchInfo({ initial: true }).catch((error) => {
      console.error(error);
      setStatus('重新获取信息失败：' + error.message);
      toggleBtn.disabled = false;
      toggleBtn.textContent = '开始下载';
      retryBtn.disabled = false;
    });
  });

  const initialise = async () => {
    toggleBtn.disabled = true;
    toggleBtn.textContent = '加载中';
    retryBtn.disabled = true;
    try {
      await fetchInfo({ initial: true });
    } catch (error) {
      console.error(error);
      setStatus('初始化失败：' + error.message);
      toggleBtn.disabled = false;
      toggleBtn.textContent = '开始下载';
      retryBtn.disabled = false;
    }
  };

  initialise();
})();
`;

const renderLandingPageHtml = (path) => {
  const display = path && path !== '/' ? decodeURIComponent(path) : '文件下载';
  const title = escapeHtml(display);
  const script = pageScript.replace(/<\/script>/g, '<\\/script>');

  return `
<!DOCTYPE html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width,initial-scale=1,shrink-to-fit=no">
    <title>${title}</title>
    <style>
      :root {
        color-scheme: dark;
        font-family: "Segoe UI", -apple-system, BlinkMacSystemFont, "PingFang SC", "Hiragino Sans GB", sans-serif;
      }
      body {
        margin: 0;
        background: #0b0b0f;
        color: #f4f4f8;
      }
      header {
        padding: 1.5rem 1.25rem 0.5rem;
        border-bottom: 1px solid rgba(255,255,255,0.08);
      }
      main {
        padding: 1.25rem;
        max-width: 720px;
        margin: 0 auto;
      }
      h1 {
        margin: 0 0 0.5rem;
        font-size: 1.5rem;
        word-break: break-all;
      }
      .status {
        margin-bottom: 1rem;
        font-size: 0.95rem;
        color: #9ca3af;
      }
      .metric {
        margin-bottom: 1rem;
      }
      .label {
        margin-bottom: 0.25rem;
        font-size: 0.9rem;
        color: #9ca3af;
      }
      .bar {
        position: relative;
        background: rgba(255,255,255,0.08);
        border-radius: 999px;
        height: 10px;
        overflow: hidden;
      }
      .bar > span {
        display: block;
        height: 100%;
        background: linear-gradient(90deg, #38bdf8, #22d3ee);
        width: 0%;
        border-radius: inherit;
        transition: width 0.2s ease;
      }
      .value {
        margin-top: 0.25rem;
        font-size: 0.85rem;
        color: #f8fafc;
      }
      .controls {
        display: flex;
        gap: 0.5rem;
        margin: 1.5rem 0;
      }
      button {
        cursor: pointer;
        border: none;
        border-radius: 0.5rem;
        padding: 0.65rem 1.25rem;
        font-size: 0.95rem;
        font-weight: 600;
        background: rgba(56,189,248,0.18);
        color: #e0f2fe;
        transition: background 0.2s ease, transform 0.2s ease;
      }
      button:hover:not(:disabled) {
        background: rgba(56,189,248,0.28);
        transform: translateY(-1px);
      }
      button:disabled {
        opacity: 0.5;
        cursor: not-allowed;
      }
      .log {
        background: rgba(15,23,42,0.6);
        border-radius: 0.75rem;
        padding: 1rem;
        max-height: 260px;
        overflow-y: auto;
        font-size: 0.85rem;
        line-height: 1.5;
      }
      @media (max-width: 600px) {
        main {
          padding: 0.75rem;
        }
        header {
          padding: 1rem 0.75rem 0.5rem;
        }
        .controls {
          flex-direction: column;
        }
        button {
          width: 100%;
        }
      }
    </style>
    <script src="https://cdn.jsdelivr.net/npm/tweetnacl@1.0.3/nacl-fast.min.js" crossorigin="anonymous"></script>
  </head>
  <body>
    <header>
      <h1 id="fileName">${title}</h1>
      <div class="status" id="status">准备就绪</div>
    </header>
    <main>
      <section class="metric">
        <div class="label">下载进度</div>
        <div class="bar"><span id="downloadBar"></span></div>
        <div class="value" id="downloadText">0%</div>
      </section>
      <section class="metric">
        <div class="label">解密进度</div>
        <div class="bar"><span id="decryptBar"></span></div>
        <div class="value" id="decryptText">0%</div>
      </section>
      <div class="status">当前速度：<span id="speedText">--</span></div>
      <div class="controls">
        <button id="toggleBtn" disabled>加载中</button>
        <button id="retryBtn" disabled>重试</button>
      </div>
      <section>
        <div class="label">事件日志</div>
        <div class="log" id="log"></div>
      </section>
    </main>
    <script type="module">
      ${script}
    </script>
  </body>
</html>`;
};

export const renderLandingPage = (path) => {
  const html = renderLandingPageHtml(path);
  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html; charset=UTF-8',
      'cache-control': 'no-store',
    },
  });
};
