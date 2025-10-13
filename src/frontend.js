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
  const DEFAULT_SEGMENT_RETRY_LIMIT = 10;
  const INFINITE_RETRY_TOKEN = 'inf';
  const RETRY_DELAY_MS = 20000;
  const SEGMENT_SIZE_BYTES = 32 * 1024 * 1024;
  const DEFAULT_PARALLEL_THREADS = 6;
  const MIN_PARALLEL_THREADS = 1;
  const MAX_PARALLEL_THREADS = 32;
  const PARALLEL_STORAGE_KEY = 'alist-crypt-parallelism';
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
  const advancedToggleBtn = $('advancedToggle');
  const advancedPanel = $('advancedPanel');
  const advancedBackdrop = $('advancedBackdrop');
  const advancedCloseBtn = $('advancedCloseBtn');
  const retryLimitInput = $('retryLimitInput');
  const parallelLimitInput = $('parallelLimitInput');
  const clearCacheBtn = $('clearCacheBtn');
  const clearEnvBtn = $('clearEnvBtn');
  const logEl = $('log');

  const log = (message) => {
    const time = new Date().toLocaleTimeString();
    const entry = document.createElement('div');
    entry.textContent = '[' + time + '] ' + message;
    logEl.appendChild(entry);
    logEl.scrollTop = logEl.scrollHeight;
  };

  const markNonRetryable = (error, hint) => {
    if (error && typeof error === 'object') {
      error.retryable = false;
      if (hint) {
        error.retryHint = hint;
      }
    }
    return error;
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
    segmentRetryLimit: DEFAULT_SEGMENT_RETRY_LIMIT,
    segmentRetryRaw: String(DEFAULT_SEGMENT_RETRY_LIMIT),
    decryptParallelism: DEFAULT_PARALLEL_THREADS,
    decryptParallelRaw: String(DEFAULT_PARALLEL_THREADS),
    advancedOpen: false,
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
    writerHandle: null,
    writerKey: '',
    workflowPromise: null,
  };

  const formatRetryLimit = (value) => (Number.isFinite(value) ? String(value) + ' 次' : '无限重试');

  const persistRetrySetting = (rawValue) => {
    if (typeof window === 'undefined' || !window.location || !window.history || !window.history.replaceState) {
      return;
    }
    try {
      const url = new URL(window.location.href);
      if (rawValue && rawValue !== String(DEFAULT_SEGMENT_RETRY_LIMIT)) {
        url.searchParams.set('retry', rawValue);
      } else {
        url.searchParams.delete('retry');
      }
      const nextHref = url.toString();
      if (nextHref !== window.location.href) {
        window.history.replaceState(null, '', nextHref);
      }
    } catch (error) {
      console.warn('更新 retry 参数失败', error);
    }
  };

  const syncRetryInput = () => {
    if (retryLimitInput) {
      retryLimitInput.value = state.segmentRetryRaw;
    }
  };

  const syncParallelInput = () => {
    if (parallelLimitInput) {
      parallelLimitInput.value = state.decryptParallelRaw;
    }
  };

  const loadParallelSetting = () => {
    if (typeof window === 'undefined' || !window.localStorage) return null;
    try {
      const stored = window.localStorage.getItem(PARALLEL_STORAGE_KEY);
      if (!stored) return null;
      const parsed = Number.parseInt(stored, 10);
      if (!Number.isFinite(parsed)) return null;
      if (parsed < MIN_PARALLEL_THREADS || parsed > MAX_PARALLEL_THREADS) return null;
      return parsed;
    } catch (error) {
      console.warn('读取并行解密设置失败', error);
      return null;
    }
  };

  const persistParallelSetting = (rawValue) => {
    if (typeof window === 'undefined' || !window.localStorage) return;
    try {
      window.localStorage.setItem(PARALLEL_STORAGE_KEY, rawValue);
    } catch (error) {
      console.warn('保存并行解密设置失败', error);
    }
  };

  const applyParallelValue = (inputValue, { notify = false, persist = true } = {}) => {
    const rawInput = typeof inputValue === 'string' ? inputValue.trim() : '';
    if (!rawInput) {
      return { ok: false, reason: 'empty' };
    }
    const parsed = Number.parseInt(rawInput, 10);
    if (!Number.isFinite(parsed) || parsed < MIN_PARALLEL_THREADS || parsed > MAX_PARALLEL_THREADS) {
      return { ok: false, reason: 'invalid' };
    }
    state.decryptParallelism = parsed;
    state.decryptParallelRaw = String(parsed);
    syncParallelInput();
    if (persist) {
      persistParallelSetting(state.decryptParallelRaw);
    }
    if (notify) {
      log('并行解密线程数已更新为 ' + parsed + ' 条线程');
    }
    return { ok: true, limit: parsed, raw: state.decryptParallelRaw };
  };

  const syncAdvancedPanel = () => {
    if (!advancedPanel || !advancedToggleBtn || !advancedBackdrop) return;
    if (state.advancedOpen) {
      advancedPanel.classList.add('is-open');
      advancedPanel.setAttribute('aria-hidden', 'false');
      advancedBackdrop.hidden = false;
      advancedToggleBtn.setAttribute('aria-expanded', 'true');
    } else {
      advancedPanel.classList.remove('is-open');
      advancedPanel.setAttribute('aria-hidden', 'true');
      advancedBackdrop.hidden = true;
      advancedToggleBtn.setAttribute('aria-expanded', 'false');
    }
  };

  const openAdvancedPanel = () => {
    if (state.advancedOpen) return;
    state.advancedOpen = true;
    syncAdvancedPanel();
  };

  const closeAdvancedPanel = ({ restoreFocus = false } = {}) => {
    if (!state.advancedOpen) return;
    state.advancedOpen = false;
    syncAdvancedPanel();
    if (restoreFocus && advancedToggleBtn) {
      advancedToggleBtn.focus({ preventScroll: true });
    }
  };

  const applySegmentRetryValue = (inputValue, { notify = false, persist = true } = {}) => {
    const rawInput = typeof inputValue === 'string' ? inputValue.trim() : '';
    if (!rawInput) {
      return { ok: false, reason: 'empty' };
    }
    const lower = rawInput.toLowerCase();
    let limit = null;
    let raw = rawInput;
    if (lower === INFINITE_RETRY_TOKEN) {
      limit = Infinity;
      raw = INFINITE_RETRY_TOKEN;
    } else {
      const parsed = Number.parseInt(rawInput, 10);
      if (!Number.isFinite(parsed) || parsed <= 0) {
        return { ok: false, reason: 'invalid' };
      }
      limit = parsed;
      raw = String(parsed);
    }
    state.segmentRetryLimit = limit;
    state.segmentRetryRaw = raw;
    syncRetryInput();
    if (persist) {
      persistRetrySetting(raw);
    }
    if (notify) {
      log('分段重试次数已更新为 ' + formatRetryLimit(limit));
    }
    return { ok: true, limit, raw };
  };

  const storedParallel = loadParallelSetting();
  if (Number.isFinite(storedParallel)) {
    state.decryptParallelism = storedParallel;
    state.decryptParallelRaw = String(storedParallel);
  }

  if (advancedToggleBtn) {
    advancedToggleBtn.setAttribute('aria-controls', 'advancedPanel');
    advancedToggleBtn.setAttribute('aria-expanded', 'false');
  }
  syncAdvancedPanel();
  syncRetryInput();
  syncParallelInput();

  const STORAGE_PREFIX = 'alist-crypt-info::';
  const STORAGE_VERSION = 1;
  const WRITER_DB_NAME = 'alist-crypt-writer';
  const WRITER_DB_VERSION = 1;
  const WRITER_STORE_NAME = 'handles';

  const openWriterDatabase = () =>
    new Promise((resolve, reject) => {
      if (typeof window === 'undefined' || !window.indexedDB) {
        reject(new Error('当前环境不支持 IndexedDB'));
        return;
      }
      const request = window.indexedDB.open(WRITER_DB_NAME, WRITER_DB_VERSION);
      request.onerror = () => reject(request.error || new Error('打开文件句柄数据库失败'));
      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(WRITER_STORE_NAME)) {
          db.createObjectStore(WRITER_STORE_NAME);
        }
      };
      request.onsuccess = () => resolve(request.result);
    });

  const runWriterStore = async (mode, executor) => {
    try {
      const db = await openWriterDatabase();
      return await new Promise((resolve, reject) => {
        let settled = false;
        const tx = db.transaction(WRITER_STORE_NAME, mode);
        const store = tx.objectStore(WRITER_STORE_NAME);
        const request = executor(store);
        request.onsuccess = () => {
          settled = true;
          resolve(request.result);
        };
        request.onerror = () => {
          settled = true;
          reject(request.error || new Error('访问文件句柄存储失败'));
        };
        tx.oncomplete = () => {
          if (!settled) resolve(undefined);
          db.close();
        };
        tx.onabort = () => {
          const reason = tx.error || new Error('文件句柄事务被中止');
          if (!settled) reject(reason);
          db.close();
        };
        tx.onerror = () => {
          const reason = tx.error || new Error('文件句柄事务失败');
          if (!settled) reject(reason);
          db.close();
        };
      });
    } catch (error) {
      console.warn('访问文件句柄存储时发生异常', error);
      return undefined;
    }
  };

  const saveWriterHandle = async (key, handle) => {
    if (!key || !handle || typeof window === 'undefined' || !window.indexedDB) return;
    await runWriterStore('readwrite', (store) => store.put(handle, key));
  };

  const loadWriterHandle = async (key) => {
    if (!key || typeof window === 'undefined' || !window.indexedDB) return null;
    const handle = await runWriterStore('readonly', (store) => store.get(key));
    return handle || null;
  };

  const deleteWriterHandle = async (key) => {
    if (!key || typeof window === 'undefined' || !window.indexedDB) return;
    await runWriterStore('readwrite', (store) => store.delete(key));
  };

  const ensureHandlePermission = async (handle) => {
    if (!handle) return false;
    const ensure = async (mode) => {
      if (typeof handle.queryPermission === 'function') {
        const status = await handle.queryPermission({ mode });
        if (status === 'granted') return true;
        if (status === 'prompt' && typeof handle.requestPermission === 'function') {
          const granted = await handle.requestPermission({ mode });
          return granted === 'granted';
        }
        if (status === 'denied' && typeof handle.requestPermission === 'function') {
          const granted = await handle.requestPermission({ mode });
          return granted === 'granted';
        }
        return status === 'granted';
      }
      if (typeof handle.requestPermission === 'function') {
        const granted = await handle.requestPermission({ mode });
        return granted === 'granted';
      }
      return true;
    };
    try {
      return await ensure('readwrite');
    } catch (error) {
      console.warn('文件权限请求失败', error);
      return false;
    }
  };

  const getPersistedWriterHandle = async (key) => {
    if (!key || typeof window === 'undefined') return null;
    if (state.writerHandle && state.writerKey === key) {
      if (await ensureHandlePermission(state.writerHandle)) {
        return state.writerHandle;
      }
    }
    const stored = await loadWriterHandle(key);
    if (!stored) return null;
    const allowed = await ensureHandlePermission(stored);
    if (!allowed) {
      await deleteWriterHandle(key);
      return null;
    }
    state.writerHandle = stored;
    state.writerKey = key;
    return stored;
  };

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

  const clearDownloadEnvironment = async () => {
    if (state.speedTimer) {
      clearInterval(state.speedTimer);
      state.speedTimer = null;
    }
    state.segments.forEach((segment) => {
      if (segment.controller) {
        try {
          segment.controller.abort();
        } catch (error) {
          console.warn('终止分段请求失败', error);
        }
      }
      segment.encrypted = null;
    });
    state.segments = [];
    state.pendingSegments = [];
    state.total = 0;
    state.totalEncrypted = 0;
    state.downloadedEncrypted = 0;
    state.decrypted = 0;
    state.resumeResolvers.splice(0, state.resumeResolvers.length).forEach((resolve) => resolve());
    state.workflowPromise = null;
    state.started = false;
    state.paused = false;
    state.mode = 'idle';
    state.infoReady = false;
    state.cacheHit = false;
    state.meta = null;
    state.remote = null;
    state.dataKey = null;
    state.baseNonce = null;
    await releaseCurrentWriter();
    resetProgressBars();
    updateToggleLabel();
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

  const releaseCurrentWriter = async () => {
    if (!state.writer) return;
    if (state.writer.type === 'fs' && state.writer.writable && typeof state.writer.writable.close === 'function') {
      try {
        await state.writer.writable.close();
      } catch (error) {
        console.warn('关闭文件写入器失败', error);
      }
    }
    if (state.writer.type === 'memory' && state.writer.chunks) {
      state.writer.chunks = [];
    }
    state.writer = null;
  };

  const ensureWriter = async (fileName) => {
    await releaseCurrentWriter();
    if ('showSaveFilePicker' in window) {
      const key = getCacheKey();
      const suggestedName = fileName && fileName.trim() !== '' ? fileName : 'download.bin';
      let handle = null;
      let reused = false;
      if (key) {
        handle = await getPersistedWriterHandle(key);
        reused = !!handle;
      }
      if (!handle) {
        try {
          handle = await window.showSaveFilePicker({
            suggestedName,
            types: [{ description: 'Binary file', accept: { 'application/octet-stream': ['.bin'] } }],
          });
        } catch (error) {
          throw new Error('已取消选择保存位置');
        }
      }
      const granted = await ensureHandlePermission(handle);
      if (!granted) {
        if (key) await deleteWriterHandle(key);
        throw new Error('未授予文件写入权限');
      }
      let writable;
      try {
        writable = await handle.createWritable({ keepExistingData: false });
      } catch (error) {
        console.warn('使用已保存的文件句柄失败', error);
        if (!reused) throw error;
        if (key) await deleteWriterHandle(key);
        try {
          handle = await window.showSaveFilePicker({
            suggestedName,
            types: [{ description: 'Binary file', accept: { 'application/octet-stream': ['.bin'] } }],
          });
        } catch (retryError) {
          throw new Error('无法重新选择保存位置');
        }
        const retryGranted = await ensureHandlePermission(handle);
        if (!retryGranted) {
          throw new Error('未授予文件写入权限');
        }
        writable = await handle.createWritable({ keepExistingData: false });
        reused = false;
      }
      state.writer = { type: 'fs', writable };
      state.writerHandle = handle;
      state.writerKey = key || '';
      if (key) {
        await saveWriterHandle(key, handle);
      }
      const handleName = handle && handle.name ? handle.name : suggestedName;
      if (reused) {
        log('已复用上次保存的位置：' + handleName);
      } else {
        log('已选择保存位置：' + handleName);
      }
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
      state.writer = null;
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
    state.writer = null;
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
    infoUrl.searchParams.set('retry', state.segmentRetryRaw);
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
    if (data.settings && typeof data.settings.segmentRetry === 'string') {
      const workerRetry = data.settings.segmentRetry.trim();
      if (workerRetry) {
        const applied = applySegmentRetryValue(workerRetry, { notify: false, persist: true });
        if (!applied.ok) {
          log('来自 worker 的分段重试参数无效：' + workerRetry);
          syncRetryInput();
        }
      }
    }
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
    const nextWriterKey = getCacheKey();
    if (state.writerKey && state.writerKey !== nextWriterKey) {
      state.writerHandle = null;
    }
    state.writerKey = nextWriterKey;

    prepareSegments();
    resetProgressBars();
    const reusedSegments = restoreCompletedSegments(previousSegments, previousMeta, meta);
    updateProgress();
    fileNameEl.textContent = meta.fileName || state.infoParams.path.split('/').pop() || '未命名文件';
    state.infoReady = true;
    updateToggleLabel();
    toggleBtn.disabled = false;
    retryBtn.disabled = true;
    clearCacheBtn.disabled = false;
    clearEnvBtn.disabled = false;
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
      const retryParam = currentUrl.searchParams.get('retry');
      if (retryParam) {
        const applied = applySegmentRetryValue(retryParam, { notify: false, persist: false });
        if (!applied.ok) {
          log('忽略无效的分段重试参数：' + retryParam);
          syncRetryInput();
        }
      } else {
        syncRetryInput();
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
    let retries = 0;
    while (true) {
      try {
        const response = await fetch(infoUrl.toString(), {
          headers: { Accept: 'application/json' },
        });
        if (!response.ok) {
          const status = response.status;
          let messageText = '';
          try {
            const rawText = await response.text();
            if (rawText) {
              try {
                const parsed = JSON.parse(rawText);
                if (parsed && parsed.message) {
                  messageText = String(parsed.message);
                } else {
                  messageText = rawText.trim();
                }
              } catch (parseError) {
                messageText = rawText.trim();
              }
            }
          } catch (readError) {
            console.warn('读取 /info 错误响应失败', readError);
          }
          const cleaned = messageText ? messageText.trim() : '';
          const finalMessage = cleaned
            ? cleaned + '（HTTP ' + status + '）'
            : '获取信息失败，HTTP ' + status;
          const fatal = new Error(finalMessage);
          if (status === 410) {
            markNonRetryable(fatal, 'http410');
          }
          throw fatal;
        }
        const payload = await response.json();
        if (payload.code !== 200 || !payload.data) {
          const finalMessage = payload.message || '接口返回异常';
          const fatal = new Error(finalMessage);
          if (payload.code === 410) {
            markNonRetryable(fatal, 'code410');
          }
          throw fatal;
        }
        const data = payload.data;
        applyInfo(data);
        saveInfoToCache(data);
        return data;
      } catch (error) {
        const limit = state.segmentRetryLimit;
        const message = error instanceof Error && error.message ? error.message : String(error);
        if (error && error.retryable === false) {
          setStatus('/info 请求失败：' + message + '（不再重试）');
          throw error;
        }
        if (Number.isFinite(limit) && retries >= limit) {
          throw new Error('/info 请求失败已达重试上限：' + message);
        }
        retries += 1;
        const retryLabel = Number.isFinite(limit)
          ? '第 ' + retries + ' 次重试（共 ' + limit + ' 次）'
          : '第 ' + retries + ' 次重试（无限重试）';
        setStatus('/info 请求失败：' + message + '，' + Math.round(RETRY_DELAY_MS / 1000) + ' 秒后重试，' + retryLabel + '。');
        await sleep(RETRY_DELAY_MS);
      }
    }
  };

  const refreshInfoAfterCleanup = async ({ clearSegments = false } = {}) => {
    if (!state.infoParams && !state.infoReady) {
      setStatus('尚未初始化，请稍后再试');
      return;
    }
    if (state.workflowPromise) {
      setStatus('当前流程正在进行，请稍后重试');
      log('忽略清理请求：流程正在进行');
      return;
    }
    const actionKey = clearSegments ? '环境' : '缓存';
    const actionLabel = '清理' + actionKey;
    toggleBtn.disabled = true;
    toggleBtn.textContent = '加载中';
    retryBtn.disabled = true;
    clearCacheBtn.disabled = true;
    clearEnvBtn.disabled = true;
    state.infoReady = false;
    setStatus(actionLabel + '中，请稍候...');
    log(actionLabel + '操作开始');

    if (clearSegments) {
      await clearDownloadEnvironment();
      log('本地分段数据已清理');
    }

    clearInfoCache();
    log('本地缓存的 /info 信息已清理');
    setStatus('正在重新获取最新的下载信息...');
    try {
      await fetchInfo({ initial: true, forceRefresh: true });
      log('已重新获取 /info 信息并完成缓存');
      setStatus(actionLabel + '完成，信息已刷新，可开始下载。');
      toggleBtn.disabled = false;
      clearCacheBtn.disabled = false;
      clearEnvBtn.disabled = false;
    } catch (error) {
      console.error(error);
      setStatus(actionLabel + '后重新获取信息失败：' + error.message);
      toggleBtn.disabled = false;
      toggleBtn.textContent = '开始下载';
      retryBtn.disabled = false;
      clearCacheBtn.disabled = false;
      clearEnvBtn.disabled = false;
      return;
    }
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
        const status = response.status;
        const baseMessage = '远程响应状态 ' + status;
        if (status === 410) {
          const fatal = markNonRetryable(new Error('远程签名已过期或失效（HTTP 410），请重新生成链接'));
          throw fatal;
        }
        throw new Error(baseMessage);
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
          if (error && error.retryable === false) {
            setStatus('分段 #' + (index + 1) + ' 下载失败：' + message + '（不再重试）');
            throw error;
          }
          segment.retries += 1;
          const retryLimit = state.segmentRetryLimit;
          const shouldRetry = Number.isFinite(retryLimit) ? segment.retries <= retryLimit : true;
          if (shouldRetry) {
            const attempt = segment.retries;
            const retryLabel = Number.isFinite(retryLimit)
              ? '第 ' + attempt + ' 次重试（共 ' + retryLimit + ' 次）'
              : '第 ' + attempt + ' 次重试（无限重试）';
            setStatus('分段 #' + (index + 1) + ' 下载失败：' + message + '，' + Math.round(RETRY_DELAY_MS / 1000) + ' 秒后重试，' + retryLabel + '。');
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

  const shouldYieldForProgress = (value) =>
    Number.isFinite(state.blockDataSize) &&
    state.blockDataSize > 0 &&
    value > 0 &&
    value % (state.blockDataSize * 4) === 0;

  const decryptSegmentData = async (segment) => {
    if (!segment || !segment.encrypted) {
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
    const output = new Uint8Array(totalNeeded);

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
        output.set(chunk.subarray(0, remaining), produced);
        produced += remaining;
        break;
      }
      output.set(chunk, produced);
      produced += chunk.length;
      currentBlock += 1;
      if (shouldYieldForProgress(produced)) {
        await new Promise((resolve) => setTimeout(resolve, 0));
      }
    }

    if (produced !== totalNeeded) {
      throw new Error('解密输出长度不匹配');
    }
    segment.encrypted = null;
    return output;
  };

  const clampParallelThreads = (value) => {
    if (!Number.isFinite(value)) {
      return DEFAULT_PARALLEL_THREADS;
    }
    const rounded = Math.max(MIN_PARALLEL_THREADS, Math.floor(value));
    return Math.min(MAX_PARALLEL_THREADS, rounded);
  };

  const resolveParallelism = () => {
    const configured = clampParallelThreads(
      Number.isFinite(state.decryptParallelism) ? state.decryptParallelism : DEFAULT_PARALLEL_THREADS,
    );
    if (typeof navigator !== 'undefined' && navigator && Number.isFinite(navigator.hardwareConcurrency)) {
      const hardwareClamped = clampParallelThreads(navigator.hardwareConcurrency);
      return Math.max(MIN_PARALLEL_THREADS, Math.min(configured, hardwareClamped));
    }
    return configured;
  };

  const decryptAllSegments = async (requestedThreads) => {
    setStatus('下载完成，准备解密');
    const requested = Number.isFinite(requestedThreads) ? requestedThreads : resolveParallelism();
    const parallelism = clampParallelThreads(requested);
    const totalSegments = state.segments.length;
    if (totalSegments === 0) {
      return;
    }
    let nextToAssign = 0;
    let nextToWrite = 0;
    const pendingResults = new Map();
    let flushChain = Promise.resolve();
    let flushError = null;

    const scheduleFlush = () => {
      flushChain = flushChain
        .then(async () => {
          while (pendingResults.has(nextToWrite)) {
            const data = pendingResults.get(nextToWrite);
            pendingResults.delete(nextToWrite);
            await writeChunk(data);
            state.decrypted = Math.min(state.total, state.decrypted + data.length);
            nextToWrite += 1;
            updateProgress();
            if (shouldYieldForProgress(state.decrypted) || state.decrypted === state.total) {
              await new Promise((resolve) => setTimeout(resolve, 0));
            }
          }
        })
        .catch((error) => {
          flushError = error instanceof Error ? error : new Error(String(error));
          throw flushError;
        });
    };

    const worker = async () => {
      while (true) {
        if (flushError) {
          throw flushError;
        }
        if (state.paused) {
          await waitWhilePaused();
        }
        const currentIndex = nextToAssign;
        if (currentIndex >= totalSegments) {
          break;
        }
        nextToAssign += 1;
        const segment = state.segments[currentIndex];
        const plain = await decryptSegmentData(segment);
        pendingResults.set(currentIndex, plain);
        scheduleFlush();
        if (flushError) {
          throw flushError;
        }
      }
    };

    const workerCount = Math.min(parallelism, totalSegments);
    const workers = [];
    for (let i = 0; i < workerCount; i += 1) {
      workers.push(worker());
    }
    await Promise.all(workers);
    await flushChain;
    if (nextToWrite !== totalSegments) {
      throw new Error('仍有分段未完成解密');
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
        clearCacheBtn.disabled = true;
        clearEnvBtn.disabled = true;
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
        const configuredParallel = clampParallelThreads(
          Number.isFinite(state.decryptParallelism) ? state.decryptParallelism : DEFAULT_PARALLEL_THREADS,
        );
        const effectiveParallel = resolveParallelism();
        if (effectiveParallel < configuredParallel) {
          log(
            '浏览器可用线程数限制为 ' +
              effectiveParallel +
              ' 条，已从配置的 ' +
              configuredParallel +
              ' 条线程进行调整',
          );
        }
        setStatus('所有分段下载完成，开始解密（并行 ' + effectiveParallel + ' 线程）');
        await decryptAllSegments(effectiveParallel);
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
          clearCacheBtn.disabled = false;
          clearEnvBtn.disabled = false;
        } else {
          setStatus('流程失败：发生未知错误');
          retryBtn.disabled = false;
          toggleBtn.disabled = false;
          state.paused = false;
          state.started = false;
          state.mode = 'idle';
          updateToggleLabel();
          clearCacheBtn.disabled = false;
          clearEnvBtn.disabled = false;
        }
      } finally {
        if (state.speedTimer) {
          clearInterval(state.speedTimer);
          state.speedTimer = null;
        }
        if (state.infoReady) {
          clearCacheBtn.disabled = false;
          clearEnvBtn.disabled = false;
        }
        state.workflowPromise = null;
      }
    })();
    await state.workflowPromise;
  };

  if (advancedToggleBtn) {
    advancedToggleBtn.addEventListener('click', () => {
      if (advancedToggleBtn.disabled) return;
      if (state.advancedOpen) {
        closeAdvancedPanel({ restoreFocus: false });
      } else {
        openAdvancedPanel();
      }
    });
  }

  if (advancedCloseBtn) {
    advancedCloseBtn.addEventListener('click', () => {
      closeAdvancedPanel({ restoreFocus: true });
    });
  }

  if (advancedBackdrop) {
    advancedBackdrop.addEventListener('click', () => {
      closeAdvancedPanel({ restoreFocus: true });
    });
  }

  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && state.advancedOpen) {
      closeAdvancedPanel({ restoreFocus: true });
    }
  });

  const handleRetryInputCommit = () => {
    if (!retryLimitInput) return;
    const rawInput = retryLimitInput.value || '';
    const trimmed = rawInput.trim();
    if (trimmed.toLowerCase() === state.segmentRetryRaw.toLowerCase()) {
      syncRetryInput();
      return;
    }
    const result = applySegmentRetryValue(trimmed, { notify: true });
    if (!result.ok) {
      setStatus('分段重试次数无效，请输入正整数或 inf（无限重试）。');
      syncRetryInput();
      retryLimitInput.focus({ preventScroll: true });
    }
  };

  if (retryLimitInput) {
    retryLimitInput.addEventListener('change', handleRetryInputCommit);
    retryLimitInput.addEventListener('blur', handleRetryInputCommit);
    retryLimitInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        handleRetryInputCommit();
        retryLimitInput.blur();
      }
    });
  }

  const handleParallelInputCommit = () => {
    if (!parallelLimitInput) return;
    const rawInput = parallelLimitInput.value || '';
    const trimmed = rawInput.trim();
    if (trimmed === state.decryptParallelRaw) {
      syncParallelInput();
      return;
    }
    const result = applyParallelValue(trimmed, { notify: true });
    if (!result.ok) {
      setStatus('并行解密线程数无效，请输入 1-32 之间的整数。');
      syncParallelInput();
      parallelLimitInput.focus({ preventScroll: true });
    }
  };

  if (parallelLimitInput) {
    parallelLimitInput.addEventListener('change', handleParallelInputCommit);
    parallelLimitInput.addEventListener('blur', handleParallelInputCommit);
    parallelLimitInput.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        handleParallelInputCommit();
        parallelLimitInput.blur();
      }
    });
  }

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

  retryBtn.addEventListener('click', async () => {
    if (state.workflowPromise) return;
    toggleBtn.disabled = true;
    toggleBtn.textContent = '加载中';
    retryBtn.disabled = true;
    clearCacheBtn.disabled = true;
    clearEnvBtn.disabled = true;
    try {
      await fetchInfo({ initial: true, forceRefresh: true });
      startWorkflow();
    } catch (error) {
      console.error(error);
      setStatus('重新获取信息失败：' + error.message);
      toggleBtn.disabled = false;
      toggleBtn.textContent = '开始下载';
      retryBtn.disabled = false;
      clearCacheBtn.disabled = false;
      clearEnvBtn.disabled = false;
    }
  });

  clearCacheBtn.addEventListener('click', () => {
    refreshInfoAfterCleanup({ clearSegments: false }).catch((error) => {
      console.error(error);
      setStatus('清理缓存失败：' + (error && error.message ? error.message : '未知错误'));
      clearCacheBtn.disabled = false;
      clearEnvBtn.disabled = false;
      toggleBtn.disabled = false;
      toggleBtn.textContent = '开始下载';
      retryBtn.disabled = false;
    });
  });

  clearEnvBtn.addEventListener('click', () => {
    refreshInfoAfterCleanup({ clearSegments: true }).catch((error) => {
      console.error(error);
      setStatus('清理数据失败：' + (error && error.message ? error.message : '未知错误'));
      clearCacheBtn.disabled = false;
      clearEnvBtn.disabled = false;
      toggleBtn.disabled = false;
      toggleBtn.textContent = '开始下载';
      retryBtn.disabled = false;
    });
  });

  const initialise = async () => {
    toggleBtn.disabled = true;
    toggleBtn.textContent = '加载中';
    retryBtn.disabled = true;
    clearCacheBtn.disabled = true;
    clearEnvBtn.disabled = true;
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
        flex-wrap: wrap;
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
      .controls button.secondary {
        background: rgba(148,163,184,0.16);
        color: #e2e8f0;
      }
      .controls button.secondary:hover:not(:disabled) {
        background: rgba(148,163,184,0.28);
      }
      .advanced-panel {
        position: fixed;
        top: 0;
        right: 0;
        transform: translateX(100%);
        width: 320px;
        max-width: 90vw;
        height: 100%;
        z-index: 30;
        background: rgba(15,23,42,0.95);
        border-left: 1px solid rgba(148,163,184,0.16);
        box-shadow: -16px 0 32px rgba(15,23,42,0.5);
        backdrop-filter: blur(6px);
        transition: transform 0.3s ease;
        display: flex;
        flex-direction: column;
        padding: 1.5rem 1.25rem;
      }
      .advanced-panel.is-open {
        transform: translateX(0);
      }
      .advanced-panel[aria-hidden="true"] {
        pointer-events: none;
      }
      .advanced-backdrop {
        position: fixed;
        inset: 0;
        background: rgba(15,23,42,0.55);
        backdrop-filter: blur(2px);
        z-index: 20;
      }
      .advanced-backdrop[hidden] {
        display: none;
      }
      .advanced-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 1rem;
      }
      .advanced-header h2 {
        margin: 0;
        font-size: 1.1rem;
        color: #f8fafc;
      }
      .advanced-close {
        background: transparent;
        border: none;
        color: #94a3b8;
        font-size: 0.9rem;
        padding: 0.35rem 0.75rem;
        border-radius: 999px;
        cursor: pointer;
        transition: color 0.2s ease, background 0.2s ease;
      }
      .advanced-close:hover {
        color: #f8fafc;
        background: rgba(148,163,184,0.14);
      }
      .advanced-body {
        flex: 1;
        display: flex;
        flex-direction: column;
        gap: 1.25rem;
        overflow-y: auto;
      }
      .retry-label {
        display: flex;
        flex-direction: column;
        gap: 0.35rem;
        font-size: 0.95rem;
        color: #e0f2fe;
      }
      .retry-hint {
        font-size: 0.8rem;
        color: #94a3b8;
      }
      .retry-input {
        background: rgba(15,23,42,0.85);
        border: 1px solid rgba(148,163,184,0.3);
        border-radius: 0.5rem;
        padding: 0.6rem 0.75rem;
        color: #f1f5f9;
        font-size: 0.95rem;
        transition: border-color 0.2s ease, box-shadow 0.2s ease;
      }
      .retry-input:focus {
        outline: none;
        border-color: rgba(56,189,248,0.6);
        box-shadow: 0 0 0 2px rgba(56,189,248,0.2);
      }
      .advanced-actions {
        display: flex;
        flex-direction: column;
        gap: 0.75rem;
      }
      .advanced-actions button {
        width: 100%;
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
        .advanced-panel {
          width: 100%;
          padding: 1.25rem;
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
        <button id="advancedToggle" class="secondary" type="button">高级选项</button>
      </div>
      <aside id="advancedPanel" class="advanced-panel" aria-hidden="true">
        <div class="advanced-header">
          <h2>高级选项</h2>
          <button id="advancedCloseBtn" type="button" class="advanced-close">关闭</button>
        </div>
        <div class="advanced-body">
          <div class="advanced-actions">
            <button id="clearCacheBtn" disabled>清理缓存</button>
            <button id="clearEnvBtn" disabled>清理数据</button>
          </div>
          <label class="retry-label" for="retryLimitInput">
            分段重试次数
            <span class="retry-hint">支持正整数或 inf（无限重试）</span>
          </label>
          <input id="retryLimitInput" class="retry-input" type="text" inputmode="numeric" autocomplete="off" value="10">
          <label class="retry-label" for="parallelLimitInput">
            并行解密线程数
            <span class="retry-hint">范围 1-32，默认 6</span>
          </label>
          <input id="parallelLimitInput" class="retry-input" type="number" inputmode="numeric" autocomplete="off" min="1" max="32" value="6">
        </div>
      </aside>
      <div id="advancedBackdrop" class="advanced-backdrop" hidden></div>
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
