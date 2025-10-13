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

  const REQUESTS_PER_SECOND = 4;
  const REQUEST_INTERVAL_MS = Math.floor(1000 / REQUESTS_PER_SECOND);
  const MAX_RETRY_PER_SEGMENT = 3;
  const RETRY_DELAY_MS = 20000;
  const SEGMENT_SIZE_BYTES = 32 * 1024 * 1024;
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
    meta: null,
    remote: null,
    cacheKey: '',
    cacheHit: false,
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

  const STORAGE_PREFIX = 'alist-crypt-info::';
  const STORAGE_VERSION = 1;

  const getCacheKey = () => {
    if (state.cacheKey) return state.cacheKey;
    if (!state.infoParams) return '';
    const pathPart = encodeURIComponent(state.infoParams.path || '');
    const signPart = encodeURIComponent(state.infoParams.sign || '');
    const key = STORAGE_PREFIX + pathPart + '::' + signPart;
    state.cacheKey = key;
    return key;
  };

  const loadInfoFromCache = () => {
    const key = getCacheKey();
    if (!key) return null;
    if (typeof window === 'undefined' || !window.sessionStorage) return null;
    try {
      const raw = window.sessionStorage.getItem(key);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || parsed.version !== STORAGE_VERSION) return null;
      if (!parsed.data || !parsed.data.meta || !parsed.data.download) return null;
      return parsed.data;
    } catch (error) {
      console.warn('读取缓存信息失败', error);
      return null;
    }
  };

  const saveInfoToCache = (data) => {
    const key = getCacheKey();
    if (!key) return;
    if (typeof window === 'undefined' || !window.sessionStorage) return;
    try {
      const payload = JSON.stringify({ version: STORAGE_VERSION, timestamp: Date.now(), data });
      window.sessionStorage.setItem(key, payload);
    } catch (error) {
      console.warn('缓存下载信息失败', error);
    }
  };

  const clearInfoCache = () => {
    const key = getCacheKey();
    if (!key) return;
    if (typeof window === 'undefined' || !window.sessionStorage) return;
    try {
      window.sessionStorage.removeItem(key);
    } catch (error) {
      console.warn('清理缓存信息失败', error);
    }
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

  const updateToggleLabel = () => {
    if (!state.started || state.mode === 'idle') {
      toggleBtn.textContent = '开始下载';
      return;
    }
    if (state.mode === 'downloading') {
      toggleBtn.textContent = state.paused ? '继续下载' : '暂停下载';
      return;
    }
    if (state.mode === 'decrypting') {
      toggleBtn.textContent = state.paused ? '继续解密' : '暂停解密';
      return;
    }
    if (state.mode === 'finished') {
      toggleBtn.textContent = '完成';
      return;
    }
    toggleBtn.textContent = '处理中';
  };

  const waitWhilePaused = async () => {
    while (state.paused) {
      await waitForResume();
    }
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
    if (!state.started) return;
    if (state.mode !== 'downloading' && state.mode !== 'decrypting') return;
    if (state.paused === value) return;
    state.paused = value;
    if (value) {
      if (state.mode === 'downloading') {
        setStatus('下载已暂停');
        for (const segment of state.segments) {
          if (segment.controller) {
            segment.controller.abort();
          }
        }
      } else {
        setStatus('解密已暂停');
      }
    } else {
      setStatus(state.mode === 'decrypting' ? '恢复解密' : '恢复下载');
      const resolvers = state.resumeResolvers.splice(0, state.resumeResolvers.length);
      resolvers.forEach((resolve) => resolve());
    }
    updateToggleLabel();
  };

  const prepareSegments = () => {
    const segments = [];
    const pending = [];
    const segmentSize = Math.max(state.blockDataSize || 0, SEGMENT_SIZE_BYTES);
    let offset = 0;
    let index = 0;
    let totalEncrypted = 0;
    while (offset < state.total) {
      const length = Math.min(segmentSize, state.total - offset);
      const mapping = calculateUnderlying(offset, length, state.meta);
      if (!mapping || mapping.underlyingLimit <= 0) {
        throw new Error('无法计算有效的加密数据段');
      }
      segments.push({
        index,
        offset,
        length,
        mapping,
        encrypted: null,
        retries: 0,
        controller: null,
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
        segment.controller = null;
        state.pendingSegments.push(segment.index);
      }
    });
    state.downloadedEncrypted = encryptedTotal;
    state.decrypted = 0;
  };

  const restoreCompletedSegments = (previousSegments, previousMeta, nextMeta) => {
    if (!Array.isArray(previousSegments) || previousSegments.length === 0) {
      return 0;
    }
    if (!previousMeta || !nextMeta) {
      return 0;
    }
    const comparableKeys = ['blockDataSize', 'blockHeaderSize', 'fileHeaderSize', 'size'];
    const incompatible = comparableKeys.some((key) => {
      const prevValue = Number(previousMeta[key]);
      const nextValue = Number(nextMeta[key]);
      return Number.isFinite(prevValue) && Number.isFinite(nextValue) && prevValue !== nextValue;
    });
    if (incompatible) {
      return 0;
    }
    const previousMap = new Map();
    previousSegments.forEach((segment) => {
      if (!segment || !(segment.encrypted instanceof Uint8Array) || segment.encrypted.length === 0) {
        return;
      }
      const key = segment.offset + ':' + segment.length;
      if (!previousMap.has(key)) {
        previousMap.set(key, segment);
      }
    });
    let reused = 0;
    let encryptedTotal = 0;
    const pending = [];
    state.segments.forEach((segment) => {
      const key = segment.offset + ':' + segment.length;
      const previous = previousMap.get(key);
      segment.controller = null;
      segment.retries = 0;
      if (previous) {
        segment.encrypted = previous.encrypted;
        encryptedTotal += previous.encrypted.length;
        reused += 1;
      } else {
        segment.encrypted = null;
        pending.push(segment.index);
      }
    });
    state.pendingSegments = pending;
    state.downloadedEncrypted = encryptedTotal;
    state.decrypted = 0;
    return reused;
  };

  const buildInfoUrl = () => {
    const info = state.infoParams;
    if (!info) {
      throw new Error('缺少下载参数');
    }
    const infoUrl = new URL('/info', info.origin);
    infoUrl.searchParams.set('path', info.path);
    infoUrl.searchParams.set('sign', info.sign);
    return infoUrl;
  };

    const applyInfo = (data, { fromCache = false } = {}) => {
    if (!data || !data.meta || !data.download) {
      throw new Error('下载信息不完整');
    }
    if (!data.download.url) {
      throw new Error('缺少远程下载地址');
    }
    const meta = data.meta;
    const download = data.download;
    const previousMeta = state.meta;
    const previousSegments = state.segments;

    state.meta = meta;
    state.remote = {
      url: download.url,
      method: download.method || 'GET',
      headers: Array.isArray(download.headers) ? download.headers : [],
      rawPath: download.rawPath || '',
    };
    state.total = Number(meta.size) || 0;
    state.blockDataSize = Number(meta.blockDataSize) || 0;
    state.blockHeaderSize = Number(meta.blockHeaderSize) || 0;
    state.fileHeaderSize = Number(meta.fileHeaderSize) || 0;
    state.dataKey = base64ToUint8(meta.dataKey);
    state.baseNonce = base64ToUint8(meta.nonce);
    state.started = false;
    state.paused = false;
    state.mode = 'idle';
    state.resumeResolvers = [];
    state.writer = null;
    state.workflowPromise = null;
    state.cacheHit = fromCache;

    prepareSegments();
    resetProgressBars();
    const reusedSegments = restoreCompletedSegments(previousSegments, previousMeta, meta);
    updateProgress();
    fileNameEl.textContent = meta.fileName || state.infoParams.path.split('/').pop() || '未命名文件';
    state.infoReady = true;
    updateToggleLabel();
    toggleBtn.disabled = false;
    retryBtn.disabled = true;
    logEl.innerHTML = '';
    const statusMessage = fromCache
      ? '已从缓存恢复下载信息，随时可以开始下载。'
      : reusedSegments > 0
        ? '信息获取成功，已保留 ' + reusedSegments + ' 个已完成分段，可继续下载。'
        : '信息获取成功，可以开始下载。';
    setStatus(statusMessage);
  };

  const fetchInfo = async ({ initial = false, forceRefresh = false } = {}) => {
    if (!initial && !state.infoParams) {
      throw new Error('缺少初始化信息');
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
      state.cacheKey = '';
    }

    if (forceRefresh) {
      clearInfoCache();
    } else {
      const cached = loadInfoFromCache();
      if (cached) {
        applyInfo(cached, { fromCache: true });
        return cached;
      }
    }

    const infoUrl = buildInfoUrl();
    const response = await fetch(infoUrl.toString(), {
      headers: { Accept: 'application/json' },
    });
    if (!response.ok) {
      throw new Error('获取信息失败，HTTP ' + response.status);
    }
    const payload = await response.json();
    if (payload.code !== 200 || !payload.data) {
      throw new Error(payload.message || '接口返回异常');
    }
    const data = payload.data;
    applyInfo(data);
    saveInfoToCache(data);
    return data;
  };

  const buildRemoteHeaders = () => {
    const headers = new Headers();
    if (state.remote && Array.isArray(state.remote.headers)) {
      state.remote.headers.forEach((entry) => {
        if (!Array.isArray(entry) || entry.length < 2) return;
        const [key, value] = entry;
        if (!key) return;
        if (value === undefined || value === null) return;
        headers.set(key, String(value));
      });
    }
    headers.delete('Range');
    headers.set('Accept-Encoding', 'identity');
    return headers;
  };

  const downloadSegment = async (index) => {
    const segment = state.segments[index];
    if (!segment || segment.encrypted) return;
    if (!state.remote || !state.remote.url) {
      throw new Error('远程下载信息缺失');
    }
    const headers = buildRemoteHeaders();
    const startOffset = segment.mapping.underlyingOffset;
    const endOffset = startOffset + segment.mapping.underlyingLimit - 1;
    headers.set('Range', 'bytes=' + startOffset + '-' + endOffset);

    const controller = new AbortController();
    segment.controller = controller;
    const chunks = [];
    let received = 0;
    try {
      const response = await fetch(state.remote.url, {
        method: state.remote.method || 'GET',
        headers,
        signal: controller.signal,
      });
      if (!(response.ok || response.status === 206)) {
        throw new Error('远程响应状态 ' + response.status);
      }
      const reader = response.body && response.body.getReader ? response.body.getReader() : null;
      if (reader) {
        // Stream the response to update progress incrementally.
        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          if (!value || value.length === 0) continue;
          chunks.push(value);
          received += value.length;
          state.downloadedEncrypted += value.length;
          state.bytesSinceSpeedCheck += value.length;
          updateProgress();
        }
      } else {
        const arrayBuffer = await response.arrayBuffer();
        const chunk = new Uint8Array(arrayBuffer);
        if (chunk.length > 0) {
          chunks.push(chunk);
          received += chunk.length;
          state.downloadedEncrypted += chunk.length;
          state.bytesSinceSpeedCheck += chunk.length;
          updateProgress();
        }
      }

      if (received === 0) {
        throw new Error('远程响应为空');
      }
      const buffer = new Uint8Array(received);
      let position = 0;
      for (const chunk of chunks) {
        buffer.set(chunk, position);
        position += chunk.length;
      }
      segment.encrypted = buffer;
      updateProgress();
    } catch (error) {
      if (received > 0) {
        state.downloadedEncrypted = Math.max(0, state.downloadedEncrypted - received);
        state.bytesSinceSpeedCheck = Math.max(0, state.bytesSinceSpeedCheck - received);
        updateProgress();
      }
      throw error;
    } finally {
      segment.controller = null;
    }
  };

  const downloadAllSegments = async () => {
    if (state.segments.length === 0) return;

    const inFlight = new Set();

    const launchSegment = (index) => {
      const segment = state.segments[index];
      if (!segment || segment.encrypted) {
        return null;
      }
      const task = (async () => {
        try {
          await downloadSegment(index);
          segment.retries = 0;
        } catch (error) {
          if (error && error.name === 'AbortError') {
            enqueueSegment(index, true);
            return;
          }
          const message = error instanceof Error && error.message ? error.message : '未知错误';
          segment.retries += 1;
          if (segment.retries <= MAX_RETRY_PER_SEGMENT) {
            const attempt = segment.retries;
            setStatus('分段 #' + (index + 1) + ' 下载失败：' + message + '，' + Math.round(RETRY_DELAY_MS / 1000) + ' 秒后重试（' + attempt + '/' + MAX_RETRY_PER_SEGMENT + '）');
            await sleep(RETRY_DELAY_MS);
            enqueueSegment(index, true);
            return;
          }
          throw error;
        }
      })().finally(() => {
        inFlight.delete(task);
      });
      inFlight.add(task);
      return task;
    };

    let lastDispatchAt = 0;
    const rateDelay = async () => {
      const now = performance.now();
      const elapsed = now - lastDispatchAt;
      if (elapsed < REQUEST_INTERVAL_MS) {
        await sleep(REQUEST_INTERVAL_MS - elapsed);
      }
      lastDispatchAt = performance.now();
    };

    while (true) {
      if (state.paused) {
        await waitForResume();
        lastDispatchAt = performance.now();
        continue;
      }
      const index = takeSegment();
      if (index === undefined) {
        const pending = Array.from(inFlight);
        if (pending.length === 0) {
          break;
        }
        try {
          await Promise.race(pending);
        } catch (error) {
          throw error;
        }
        continue;
      }
      launchSegment(index);
      await rateDelay();
    }

    await Promise.all(inFlight);

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
      if (state.paused) {
        await waitWhilePaused();
      }
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
      if (state.paused) {
        await waitWhilePaused();
      }
      await decryptSegment(segment);
    }
  };

    const startWorkflow = async () => {
    if (state.workflowPromise) return;
    state.workflowPromise = (async () => {
      try {
        if (!state.infoReady) return;
        if (!window.nacl || !window.nacl.secretbox || !window.nacl.secretbox.open) {
          throw new Error('TweetNaCl 初始化失败，请刷新页面重试');
        }
        await ensureWriter(state.meta.fileName);
        refreshPendingQueue();
        updateProgress();
        state.started = true;
        state.paused = false;
        state.mode = 'downloading';
        updateToggleLabel();
        toggleBtn.disabled = false;
        retryBtn.disabled = true;
        setStatus('开始下载，目标速率 ' + REQUESTS_PER_SECOND + ' 请求/秒');
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
        state.paused = false;
        updateToggleLabel();
        toggleBtn.disabled = false;
        setStatus('所有分段下载完成，开始解密');
        await decryptAllSegments();
        state.decrypted = state.total;
        updateProgress();
        await finalizeWriter();
        state.mode = 'finished';
        updateToggleLabel();
        setStatus('下载完成，文件已保存');
        retryBtn.disabled = true;
      } catch (error) {
        console.error(error);
        if (error && error.name === 'AbortError' && state.paused) {
          setStatus('下载已暂停');
        } else if (error instanceof Error) {
          setStatus('流程失败：' + error.message);
          retryBtn.disabled = false;
          toggleBtn.disabled = false;
          state.paused = false;
          state.started = false;
          state.mode = 'idle';
          updateToggleLabel();
        } else {
          setStatus('流程失败：发生未知错误');
          retryBtn.disabled = false;
          toggleBtn.disabled = false;
          state.paused = false;
          state.started = false;
          state.mode = 'idle';
          updateToggleLabel();
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
    if (state.mode === 'downloading' || state.mode === 'decrypting') {
      setPaused(!state.paused);
    }
  });

    retryBtn.addEventListener('click', () => {
    if (state.workflowPromise) return;
    toggleBtn.disabled = true;
    toggleBtn.textContent = '加载中';
    retryBtn.disabled = true;
    fetchInfo({ initial: true, forceRefresh: true }).catch((error) => {
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
