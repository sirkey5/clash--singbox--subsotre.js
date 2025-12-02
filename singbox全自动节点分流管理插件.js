/*
 * 实现动态代理选择机制，包含故障转移、断路器、EWMA 延迟跟踪、基于分数调度与滞后控制。
 * 同步移植并整合 clash 中的全部功能与性能，包括：
 * - 中央编排器架构（CentralManager）与事件驱动
 * - 节点质量打分、可用性优先、紧急切换与冷却机制
 * - LRU 缓存、地理信息获取与 DNS 解析
 * - 多指标探测（延迟/抖动/丢包/吞吐）、AI 分级微调
 * - 配置处理（保留原格式与规则/组构建）、跨平台兼容
 * - 统一、科学、精简、模块化与多平台兼容
 *
 * 保留 singbox 原有文件结构、触发器与格式规范，代码可直接使用。
 *
 * TODO: 解决切换配置未自动接管新的代理组
 */

/*
调整参数可用大语言模型提示词：
你是一个代理服务器调度系统的参数专家。我想要不同风格的调度参数配置。系统包括 EWMA、优先级、断路器、惩罚分机制和滞后控制（hysteresis）等策略。请只输出**与默认值不同的参数和注释**，格式如下：

{
  "参数名": 新值,
  "_参数名": "简洁说明"
}

默认值如下（用于参考）：  
ewmaAlpha: 0.3
failureThreshold: 3
circuitBreakerTimeout: 360000
penaltyIncrement: 5
penaltyDecayRate: 0.1
priorityWeight: 1.0
latencyWeight: 100.0
penaltyWeight: 1.0
hysteresisMargin: 0.1

请根据以下风格返回配置（任选一种或多种）：

- 稳定型：减少切换，宽容波动
- 延迟优先型：频繁检测，追求最快响应
- 高可用型：容忍短暂失败，但快速恢复
- 掉线惩罚型：代理一旦失败，长时间惩罚不让用
- 最小波动型：非常保守切换策略

返回 JSON 格式，只输出修改过的参数及注释。
*/

// ================= Constants (统一/精简/多平台兼容) =================
const CONSTANTS = {
  PREHEAT_NODE_COUNT: 10,
  BATCH_SIZE: 5,
  NODE_TEST_TIMEOUT: 5000,
  BASE_SWITCH_COOLDOWN: 30 * 60 * 1000,
  MIN_SWITCH_COOLDOWN: 5 * 60 * 1000,
  MAX_SWITCH_COOLDOWN: 2 * 60 * 60 * 1000,
  MAX_HISTORY_RECORDS: 100,
  NODE_EVALUATION_THRESHOLD: 3 * 60 * 60 * 1000,
  LRU_CACHE_MAX_SIZE: 1000,
  LRU_CACHE_TTL: 3600000,
  CONCURRENCY_LIMIT: 3,
  MIN_SAMPLE_SIZE: 5,
  GEO_FALLBACK_TTL: 3600000,
  QUALITY_SCORE_THRESHOLD: 30,
  NODE_CLEANUP_THRESHOLD: 20,
  GEO_INFO_TIMEOUT: 3000,
  FEATURE_WINDOW_SIZE: 50,
  ENABLE_SCORE_DEBUGGING: false,
  QUALITY_WEIGHT: 0.5,
  METRIC_WEIGHT: 0.35,
  SUCCESS_WEIGHT: 0.15,
  CACHE_CLEANUP_THRESHOLD: 0.1,
  CACHE_CLEANUP_BATCH_SIZE: 50,
  MAX_RETRY_ATTEMPTS: 3,
  RETRY_DELAY_BASE: 200,
  DEFAULT_USER_AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  AVAILABILITY_MIN_RATE: 0.75,
  AVAILABILITY_EMERGENCY_FAILS: 2,
  THROUGHPUT_SOFT_CAP_BPS: 50_000_000,
  THROUGHPUT_SCORE_MAX: 15,
  LATENCY_CLAMP_MS: 3000,
  JITTER_CLAMP_MS: 500,
  LOSS_CLAMP: 1.0
};

// ================= Logging =================
class Logger {
  static error(...args) { console.error(...args); }
  static info(...args) { console.info(...args); }
  static debug(...args) { if (CONSTANTS.ENABLE_SCORE_DEBUGGING) console.debug(...args); }
  static warn(...args) { console.warn(...args); }
}

// ================= Errors =================
class ConfigurationError extends Error { constructor(message) { super(message); this.name = "ConfigurationError"; } }
class InvalidRequestError extends Error { constructor(message) { super(message); this.name = "InvalidRequestError"; } }

// ================= Event emitter =================
class EventEmitter {
  constructor() { this.eventListeners = new Map(); }
  on(event, listener) {
    if (!this.eventListeners.has(event)) this.eventListeners.set(event, []);
    this.eventListeners.get(event).push(listener);
  }
  off(event, listener) {
    if (!this.eventListeners.has(event)) return;
    const arr = this.eventListeners.get(event);
    const idx = arr.indexOf(listener);
    if (idx !== -1) arr.splice(idx, 1);
    if (arr.length === 0) this.eventListeners.delete(event);
  }
  emit(event, ...args) {
    if (!this.eventListeners.has(event)) return;
    [...this.eventListeners.get(event)].forEach(fn => { try { fn(...args); } catch (e) { Logger.error(`事件 ${event} 处理失败:`, e.stack || e); } });
  }
  removeAllListeners(event) { if (event) this.eventListeners.delete(event); else this.eventListeners.clear(); }
}

// ================= App state =================
class AppState {
  constructor() {
    this.nodes = new Map();   // nodeId -> { metrics, score, geoInfo, lastEvaluated, availability... }
    this.metrics = new Map(); // nodeId -> recent metrics array
    this.config = {};
    this.lastUpdated = Date.now();
  }
  updateNodeStatus(nodeId, status) {
    this.nodes.set(nodeId, { ...this.nodes.get(nodeId), ...status });
    this.lastUpdated = Date.now();
  }
}

// ================= LRU cache =================
class LRUCache {
  constructor({ maxSize = CONSTANTS.LRU_CACHE_MAX_SIZE, ttl = CONSTANTS.LRU_CACHE_TTL } = {}) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttl = ttl;
    this.head = { key: null, prev: null, next: null };
    this.tail = { key: null, prev: this.head, next: null };
    this.head.next = this.tail;
  }
  _removeEntry(node) {
    if (!node) return;
    try {
      if (node.prev) node.prev.next = node.next;
      if (node.next) node.next.prev = node.prev;
      node.prev = null; node.next = null;
    } catch {}
  }
  _moveToFront(node) {
    if (!node || !node.prev || !node.next) return;
    try {
      node.prev.next = node.next;
      node.next.prev = node.prev;
      node.next = this.head.next;
      node.prev = this.head;
      if (this.head.next) this.head.next.prev = node;
      this.head.next = node;
    } catch {}
  }
  _removeTail() {
    const node = this.tail.prev;
    if (!node || node === this.head) return null;
    this._removeEntry(node);
    const key = node.key;
    this.cache.delete(key);
    return key;
  }
  get(key) {
    const entry = this.cache.get(key);
    if (!entry || Date.now() - entry.timestamp > entry.ttl) {
      if (entry) { this._removeEntry(entry); this.cache.delete(key); }
      return null;
    }
    this._moveToFront(entry);
    entry.timestamp = Date.now();
    return entry.value;
  }
  set(key, value, ttl = this.ttl) {
    const ratio = this.cache.size / this.maxSize;
    if (ratio > CONSTANTS.CACHE_CLEANUP_THRESHOLD) {
      this._cleanupExpiredEntries(CONSTANTS.CACHE_CLEANUP_BATCH_SIZE);
    }
    if (this.cache.has(key)) {
      const entry = this.cache.get(key);
      entry.value = value; entry.timestamp = Date.now();
      this._moveToFront(entry);
      return;
    }
    if (this.cache.size >= this.maxSize) {
      const k = this._removeTail();
      if (k) Logger.debug(`LRU 移除键: ${k}`);
    }
    const newNode = { key, value, ttl, timestamp: Date.now(), prev: this.head, next: this.head.next };
    this.head.next.prev = newNode;
    this.head.next = newNode;
    this.cache.set(key, newNode);
  }
  _cleanupExpiredEntries(limit = 100) {
    const now = Date.now();
    let cleaned = 0, iterations = 0;
    const maxIter = Math.min(this.cache.size, limit * 2);
    const toDelete = [];
    for (const [key, entry] of this.cache) {
      iterations++;
      if (now - entry.timestamp > entry.ttl) {
        toDelete.push(key);
        cleaned++;
        if (cleaned >= limit) break;
      }
      if (iterations >= maxIter) break;
    }
    for (const k of toDelete) {
      const entry = this.cache.get(k);
      if (entry) this._removeEntry(entry);
      this.cache.delete(k);
    }
    if (cleaned > 0) Logger.debug(`清理了 ${cleaned} 个过期缓存项`);
  }
  clear() {
    this.cache.clear();
    this.head.next = this.tail;
    this.tail.prev = this.head;
  }
  delete(key) {
    const entry = this.cache.get(key);
    if (!entry) return false;
    this._removeEntry(entry);
    this.cache.delete(key);
    return true;
  }
}

// ================= Rolling stats and trackers =================
class RollingStats {
  constructor(windowSize = 100) {
    this.windowSize = windowSize;
    this.data = new Array(windowSize).fill(0);
    this.index = 0; this.count = 0; this.sum = 0;
  }
  add(value) {
    value = Number(value) || 0;
    if (this.count < this.windowSize) { this.data[this.index] = value; this.sum += value; this.count++; }
    else { const prev = this.data[this.index] || 0; this.data[this.index] = value; this.sum += value - prev; }
    this.index = (this.index + 1) % this.windowSize;
  }
  get average() { return this.count ? this.sum / this.count : 0; }
  reset() { this.data.fill(0); this.index = 0; this.count = 0; this.sum = 0; }
}
class SuccessRateTracker {
  constructor() { this.successCount = 0; this.totalCount = 0; this.hardFailStreak = 0; }
  record(success, { hardFail = false } = {}) {
    this.totalCount++;
    if (success) { this.successCount++; this.hardFailStreak = 0; }
    else { if (hardFail) this.hardFailStreak++; }
  }
  get rate() { return this.totalCount ? this.successCount / this.totalCount : 0; }
  reset() { this.successCount = 0; this.totalCount = 0; this.hardFailStreak = 0; }
}

// ================= Utils =================
const Utils = {
  sleep(ms = 0) { return new Promise(r => setTimeout(r, ms)); },
  async retry(fn, attempts = CONSTANTS.MAX_RETRY_ATTEMPTS, delay = CONSTANTS.RETRY_DELAY_BASE) {
    if (typeof fn !== "function") throw new Error("retry: 第一个参数必须是函数");
    const maxAttempts = Math.max(1, Math.min(10, Math.floor(attempts) || 3));
    const baseDelay = Math.max(0, Math.min(5000, Math.floor(delay) || 200));
    let lastErr;
    for (let i = 0; i < maxAttempts; i++) {
      try { return await fn(); }
      catch (e) { lastErr = e; if (i < maxAttempts - 1) await Utils.sleep(baseDelay * Math.pow(2, i)); }
    }
    throw lastErr || new Error("retry: 所有重试都失败");
  },
  async runWithConcurrency(tasks, limit = 5) {
    if (!Array.isArray(tasks) || tasks.length === 0) return [];
    const validLimit = Math.max(1, Math.min(50, Math.floor(limit) || 5));
    const results = []; let idx = 0; const errors = [];
    async function next() {
      while (idx < tasks.length) {
        const current = idx++;
        if (current >= tasks.length) break;
        const task = tasks[current];
        if (typeof task !== "function") { results[current] = { status: "rejected", reason: new Error(`任务 ${current} 不是函数`) }; continue; }
        try {
          const ret = task();
          const value = ret && typeof ret.then === "function" ? await ret : ret;
          results[current] = { status: "fulfilled", value };
        } catch (e) {
          results[current] = { status: "rejected", reason: e || new Error("任务执行失败") };
          errors.push({ index: current, error: e });
        }
      }
    }
    try {
      const runners = Array(Math.min(validLimit, tasks.length)).fill(0).map(() => next());
      await Promise.all(runners);
      if (errors.length > 0 && errors.length === tasks.length) Logger.warn(`所有任务都失败了 (${errors.length}/${tasks.length})`);
    } catch (error) {
      Logger.error("runWithConcurrency 执行失败:", error && error.message ? error.message : error);
      while (idx < tasks.length) { if (!results[idx]) results[idx] = { status: "rejected", reason: error }; idx++; }
    }
    return results;
  },
  async asyncPool(tasks, concurrency = CONSTANTS.CONCURRENCY_LIMIT) {
    if (!Array.isArray(tasks) || tasks.length === 0) return [];
    const validConcurrency = Math.max(1, Math.min(50, Math.floor(concurrency) || CONSTANTS.CONCURRENCY_LIMIT || 3));
    try {
      const results = await Utils.runWithConcurrency(tasks, validConcurrency);
      return results.map(r => r && r.status === "fulfilled" ? r.value : { __error: (r && r.reason) || new Error("任务执行失败") });
    } catch (error) {
      Logger.error("asyncPool 执行失败:", error && error.message ? error.message : error);
      return tasks.map(() => ({ __error: error }));
    }
  },
  calculateWeightedAverage(values, weightFactor = 0.9) {
    if (!Array.isArray(values) || values.length === 0) return 0;
    let sum = 0, weightSum = 0;
    values.forEach((val, idx) => { const weight = Math.pow(weightFactor, values.length - idx - 1); sum += val * weight; weightSum += weight; });
    return weightSum === 0 ? 0 : sum / weightSum;
  },
  calculateStdDev(values) {
    if (!Array.isArray(values) || values.length === 0) return 0;
    const avg = values.reduce((a, b) => a + b, 0) / values.length;
    return Math.sqrt(values.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / values.length);
  },
  calculateTrend(values) {
    const n = Array.isArray(values) ? values.length : 0;
    if (n < 2) return 0;
    let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumW = 0;
    for (let i = 0; i < n; i++) { const w = (i + 1) / n; const x = i; const y = values[i];
      sumW += w; sumX += x * w; sumY += y * w; sumXY += x * y * w; sumX2 += x * x * w; }
    const num = sumW * sumXY - sumX * sumY;
    const den = sumW * sumX2 - sumX * sumX;
    if (den === 0) return 0;
    return num / den;
  },
  calculatePercentile(values, percentile) {
    if (!Array.isArray(values) || values.length === 0) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const index = (percentile / 100) * (sorted.length - 1);
    if (Math.floor(index) === index) return sorted[index];
    const i = Math.floor(index); const f = index - i;
    return sorted[i] + (sorted[i + 1] - sorted[i]) * f;
  }
};

// ================= ThroughputEstimator =================
class ThroughputEstimator {
  async tcpConnectLatency(host, port, timeout) {
    if (!(typeof process !== "undefined" && process.versions?.node)) throw new Error("Not Node");
    const net = require("net");
    return new Promise((resolve, reject) => {
      const start = Date.now();
      const socket = new net.Socket();
      let done = false;
      const cleanup = (err) => { if (done) return; done = true; try { socket.destroy(); } catch {} if (err) reject(err); };
      socket.setTimeout(timeout, () => cleanup(new Error("TCP connect timeout")));
      socket.once("error", err => cleanup(err));
      socket.connect(port, host, () => { const ms = Date.now() - start; cleanup(); resolve(ms); });
    });
  }
  async measureResponse(response, timeoutMs) {
    let bytes = 0; let jitter = 0;
    try {
      if (response?.body && typeof response.body.getReader === "function") {
        const reader = response.body.getReader();
        const maxBytes = 64 * 1024;
        const readStart = Date.now();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          bytes += value.byteLength || value.length || 0;
          if (bytes >= maxBytes) break;
        }
        const readTime = Math.max(1, Date.now() - readStart);
        const speedKbps = (bytes * 8) / readTime;
        jitter = Math.max(1, 200 - Math.min(200, Math.round(speedKbps / 10)));
        return { bytes, jitter };
      }
      if (response?.arrayBuffer) {
        const buf = await response.arrayBuffer();
        bytes = buf.byteLength || 0;
        jitter = 0;
        return { bytes, jitter };
      }
      const len = response?.headers?.get?.("Content-Length");
      bytes = parseInt(len || "0");
      jitter = 0;
      return { bytes, jitter };
    } catch {
      return { bytes, jitter: 0 };
    }
  }
  bpsFromBytesLatency({ bytes = 0, latency = 0 }) {
    const ms = Math.max(1, Number(latency) || 1);
    const bps = Math.max(0, Math.round((bytes * 8 / ms) * 1000)); // bits per second
    return Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, bps);
  }
}

// ================= Geo/DNS helpers =================
async function _safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
  if (!url || typeof url !== "string") throw new Error("_safeFetch: 无效的URL参数");
  if (timeout && (typeof timeout !== "number" || timeout <= 0)) timeout = CONSTANTS.GEO_INFO_TIMEOUT;

  let _fetch = (typeof fetch === "function") ? fetch : null;
  let _AbortController = (typeof AbortController !== "undefined") ? AbortController : null;

  if (!_fetch && typeof process !== "undefined" && process.versions && process.versions.node) {
    try { const nf = require("node-fetch"); _fetch = nf.default || nf; } catch {}
    if (!_AbortController) {
      try { const AC = require("abort-controller"); _AbortController = AC.default || AC; }
      catch { if (typeof AbortController !== "undefined") _AbortController = AbortController; }
    }
  }
  if (!_fetch) throw new Error("fetch 不可用于当前运行环境，且未找到可回退的实现（node-fetch）");

  const defaultOptions = { headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT, ...(options.headers || {}) }, ...options };
  const hasAbort = !!_AbortController;

  if (hasAbort && timeout > 0) {
    const controller = new _AbortController();
    defaultOptions.signal = controller.signal;
    const tid = setTimeout(() => { try { controller.abort(); } catch {} }, timeout);
    try { const resp = await _fetch(url, defaultOptions); clearTimeout(tid); return resp; }
    catch (err) { clearTimeout(tid); if (err.name === "AbortError" || err.name === "TimeoutError") throw new Error(`请求超时 (${timeout}ms): ${url}`); throw err; }
  }

  if (timeout > 0) {
    const fp = _fetch(url, defaultOptions);
    const tp = new Promise((_, reject) => setTimeout(() => reject(new Error(`请求超时 (${timeout}ms): ${url}`)), timeout));
    return Promise.race([fp, tp]);
  }
  return _fetch(url, defaultOptions);
}

async function fetchGeoPrimary(ip) {
  try {
    const resp = await _safeFetch(`https://ipapi.co/${ip}/json/`, { headers: { "User-Agent": "Mozilla/5.0" } }, CONSTANTS.GEO_INFO_TIMEOUT);
    if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
    const data = await resp.json();
    if (data.country_name) return { country: data.country_name, region: data.region || data.city || "Unknown" };
    Logger.warn(`主API返回无效数据: ${JSON.stringify(data)}`); return null;
  } catch (error) { Logger.warn(`主API调用失败: ${error.message}`); return null; }
}
async function fetchGeoFallback(ip) {
  try {
    const resp = await _safeFetch(`https://ipinfo.io/${ip}/json`, {}, CONSTANTS.GEO_INFO_TIMEOUT);
    if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
    const data = await resp.json();
    if (data.country) return { country: data.country, region: data.region || data.city || "Unknown" };
    Logger.warn(`备用API返回无效数据: ${JSON.stringify(data)}`); return null;
  } catch (error) { Logger.warn(`备用API调用失败: ${error.message}`); return null; }
}
function fallbackGeo(domain) {
  if (domain && typeof domain === "string" && /^[a-zA-Z0-9.-]+$/.test(domain)) {
    const tld = domain.split(".").pop().toLowerCase();
    const map = { cn: "China", hk: "Hong Kong", tw: "Taiwan", jp: "Japan", kr: "Korea", us: "United States", uk: "United Kingdom", de: "Germany", fr: "France", ca: "Canada", au: "Australia" };
    if (map[tld]) return { country: map[tld], region: "Unknown" };
  }
  return { country: "Unknown", region: "Unknown" };
}
async function resolveDomainToIP(domain, lruCache) {
  if (!domain || typeof domain !== "string") { Logger.error("无效的域名参数"); return null; }
  try {
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) { Logger.error(`无效的域名格式: ${domain}`); return null; }
    const cacheKey = `dns:${domain}`;
    const cachedIP = lruCache.get(cacheKey);
    if (cachedIP) return cachedIP;
    const response = await _safeFetch(`https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=A`,
      { headers: { "Accept": "application/dns-json", "User-Agent": "Mozilla/5.0" } },
      CONSTANTS.GEO_INFO_TIMEOUT
    );
    if (!response.ok) throw new Error(`DNS query failed: ${response.status}`);
    const data = await response.json();
    if (data.Answer && data.Answer.length > 0) {
      const ip = data.Answer[0].data;
      if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) { lruCache.set(cacheKey, ip); return ip; }
      Logger.error(`无效的IP地址: ${ip}`);
    }
    return null;
  } catch (error) {
    if (error.name !== "AbortError") Logger.error(`域名解析失败: ${error.message}`);
    return null;
  }
}

// ================= Config (保留原样式与规则) =================
const Config = {
  enable: true,
  ruleOptions: {
    apple: true, microsoft: true, github: true, google: true, openai: true, spotify: true,
    youtube: true, bahamut: true, netflix: true, tiktok: true, disney: true, pixiv: true,
    hbo: true, biliintl: true, tvb: true, hulu: true, primevideo: true, telegram: true,
    line: true, whatsapp: true, games: true, japan: true, tracker: true, ads: true
  },
  preRules: [
    "RULE-SET,applications,下载软件",
    "PROCESS-NAME,SunloginClient,DIRECT",
    "PROCESS-NAME,SunloginClient.exe,DIRECT",
    "PROCESS-NAME,AnyDesk,DIRECT",
    "PROCESS-NAME,AnyDesk.exe,DIRECT"
  ],
  regionOptions: {
    excludeHighPercentage: true, ratioLimit: 2,
    regions: [
      { name: "HK香港", regex: /港|🇭🇰|hk|hongkong|hong kong/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Hong_Kong.png" },
      { name: "US美国", regex: /美|🇺🇸|us|united state|america/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/United_States.png" },
      { name: "JP日本", regex: /日本|🇯🇵|jp|japan/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Japan.png" },
      { name: "KR韩国", regex: /韩|🇰🇷|kr|korea/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Korea.png" },
      { name: "SG新加坡", regex: /新加坡|🇸🇬|sg|singapore/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Singapore.png" },
      { name: "CN中国大陆", regex: /中国|🇨🇳|cn|china/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/China_Map.png" },
      { name: "TW台湾省", regex: /台湾|🇹🇼|tw|taiwan|tai wan/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/China.png" },
      { name: "GB英国", regex: /英|🇬🇧|uk|united kingdom|great britain/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/United_Kingdom.png" },
      { name: "DE德国", regex: /德国|🇩🇪|de|germany/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Germany.png" },
      { name: "MY马来西亚", regex: /马来|my|malaysia/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Malaysia.png" },
      { name: "TK土耳其", regex: /土耳其|🇹🇷|tk|turkey/i, icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Turkey.png" }
    ]
  },
  dns: {
    enable: true, listen: ":1053", ipv6: true, "prefer-h3": true, "use-hosts": true, "use-system-hosts": true,
    "respect-rules": true, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": ["*", "+.lan", "+.local", "+.market.xiaomi.com"],
    nameserver: ["https://120.53.53.53/dns-query", "https://223.5.5.5/dns-query"],
    "proxy-server-nameserver": ["https://120.53.53.53/dns-query", "https://223.5.5.5/dns-query"],
    "nameserver-policy": { "geosite:private": "system", "geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn": ["119.29.29.29", "223.5.5.5"] }
  },
  services: [
    { id: "openai", rule: ["DOMAIN-SUFFIX,grazie.ai,国外AI", "DOMAIN-SUFFIX,grazie.aws.intellij.net,国外AI", "RULE-SET,ai,国外AI"], name: "国外AI", url: "https://chat.openai.com/cdn-cgi/trace", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/ChatGPT.png", ruleProvider: {name: "ai", url: "https://github.com/dahaha-365/YaNet/raw/refs/heads/dist/rulesets/mihomo/ai.list"} },
    { id: "youtube", rule: ["GEOSITE,youtube,YouTube"], name: "YouTube", url: "https://www.youtube.com/s/desktop/494dd881/img/favicon.ico", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/YouTube.png" },
    { id: "biliintl", rule: ["GEOSITE,biliintl,哔哩哔哩东南亚"], name: "哔哩哔哩东南亚", url: "https://www.bilibili.tv/", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/bilibili_3.png", proxiesOrder: ["默认节点", "直连"] },
    { id: "bahamut", rule: ["GEOSITE,bahamut,巴哈姆特"], name: "巴哈姆特", url: "https://ani.gamer.com.tw/ajax/getdeviceid.php", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Bahamut.png", proxiesOrder: ["默认节点", "直连"] },
    { id: "disney", rule: ["GEOSITE,disney,Disney+"], name: "Disney+", url: "https://disney.api.edge.bamgrid.com/devices", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Disney+.png" },
    { id: "netflix", rule: ["GEOSITE,netflix,NETFLIX"], name: "NETFLIX", url: "https://api.fast.com/netflix/speedtest/v2?https=true", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Netflix.png" },
    { id: "tiktok", rule: ["GEOSITE,tiktok,Tiktok"], name: "Tiktok", url: "https://www.tiktok.com/", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/TikTok.png" },
    { id: "spotify", rule: ["GEOSITE,spotify,Spotify"], name: "Spotify", url: "http://spclient.wg.spotify.com/signup/public/v1/account", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Spotify.png" },
    { id: "pixiv", rule: ["GEOSITE,pixiv,Pixiv"], name: "Pixiv", url: "https://www.pixiv.net/favicon.ico", icon: "https://play-lh.googleusercontent.com/8pFuLOHF62ADcN0ISUAyEueA5G8IF49mX_6Az6pQNtokNVHxIVbS1L2NM62H-k02rLM=w240-h480-rw" },
    { id: "hbo", rule: ["GEOSITE,hbo,HBO"], name: "HBO", url: "https://www.hbo.com/favicon.ico", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/HBO.png" },
    { id: "tvb", rule: ["GEOSITE,tvb,TVB"], name: "TVB", url: "https://www.tvb.com/logo_b.svg", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/TVB.png" },
    { id: "primevideo", rule: ["GEOSITE,primevideo,Prime Video"], name: "Prime Video", url: "https://m.media-amazon.com/images/G/01/digital/video/web/logo-min-remaster.png", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Prime_Video.png" },
    { id: "hulu", rule: ["GEOSITE,hulu,Hulu"], name: "Hulu", url: "https://auth.hulu.com/v4/web/password/authenticate", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Hulu.png" },
    { id: "telegram", rule: ["GEOIP,telegram,Telegram"], name: "Telegram", url: "http://www.telegram.org/img/website_icon.svg", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Telegram.png" },
    { id: "whatsapp", rule: ["GEOSITE,whatsapp,WhatsApp"], name: "WhatsApp", url: "https://web.whatsapp.com/data/manifest.json", icon: "https://static.whatsapp.net/rsrc.php/v3/yP/r/rYZqPCBaG70.png" },
    { id: "line", rule: ["GEOSITE,line,Line"], name: "Line", url: "https://line.me/page-data/app-data.json", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Line.png" },
    { id: "games", rule: ["GEOSITE,category-games@cn,国内网站", "GEOSITE,category-games,游戏专用"], name: "游戏专用", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Game.png" },
    { id: "tracker", rule: ["GEOSITE,tracker,跟踪分析"], name: "跟踪分析", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Reject.png", proxies: ["REJECT", "直连", "默认节点"] },
    { id: "ads", rule: ["GEOSITE,category-ads-all,广告过滤", "RULE-SET,adblockmihomo,广告过滤"], name: "广告过滤", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Advertising.png", proxies: ["REJECT", "直连", "默认节点"], ruleProvider: {name: "adblockmihomo", url: "https://github.com/217heidai/adblockfilters/raw/refs/heads/main/rules/adblockmihomo.mrs", format: "mrs", behavior: "domain"} },
    { id: "apple", rule: ["GEOSITE,apple-cn,苹果服务"], name: "苹果服务", url: "http://www.apple.com/library/test/success.html", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Apple_2.png" },
    { id: "google", rule: ["GEOSITE,google,谷歌服务"], name: "谷歌服务", url: "http://www.google.com/generate_204", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Google_Search.png" },
    { id: "microsoft", rule: ["GEOSITE,microsoft@cn,国内网站", "GEOSITE,microsoft,微软服务"], name: "微软服务", url: "http://www.msftconnecttest.com/connecttest.txt", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Microsoft.png" },
    { id: "github", rule: ["GEOSITE,github,Github"], name: "Github", url: "https://github.com/robots.txt", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/GitHub.png" },
    { id: "japan", rule: ["RULE-SET,category-bank-jp,日本网站", "GEOIP,jp,日本网站,no-resolve"], name: "日本网站", url: "https://r.r10s.jp/com/img/home/logo/touch.png", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/JP.png", ruleProvider: {name: "category-bank-jp", url: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-bank-jp.mrs", format: "mrs", behavior: "domain"} }
  ],
  system: {
    "allow-lan": true, "bind-address": "*", mode: "rule",
    profile: { "store-selected": true, "store-fake-ip": true },
    "unified-delay": true, "tcp-concurrent": true, "keep-alive-interval": 1800,
    "find-process-mode": "strict", "geodata-mode": true, "geodata-loader": "memconservative",
    "geo-auto-update": true, "geo-update-interval": 24,
    sniffer: {
      enable: true, "force-dns-mapping": true, "parse-pure-ip": false, "override-destination": true,
      sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, "8080-8880"] }, QUIC: { ports: [443, 8443] } },
      "skip-src-address": ["127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
      "force-domain": ["+.google.com", "+.googleapis.com", "+.googleusercontent.com", "+.youtube.com", "+.facebook.com", "+.messenger.com", "+.fbcdn.net", "fbcdn-a.akamaihd.net"],
      "skip-domain": ["Mijia Cloud", "+.oray.com"]
    },
    ntp: { enable: true, "write-to-system": false, server: "cn.ntp.org.cn" },
    "geox-url": {
      geoip: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat",
      geosite: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat",
      mmdb: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb",
      asn: "https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb"
    }
  },
  common: {
    ruleProvider: { type: "http", format: "yaml", interval: 86400 },
    proxyGroup: { interval: 300, timeout: 3000, url: "http://cp.cloudflare.com/generate_204", lazy: true, "max-failed-times": 3, hidden: false },
    defaultProxyGroups: [
      { name: "下载软件", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Download.png", proxies: ["直连", "REJECT", "默认节点", "国内网站"] },
      { name: "其他外网", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Streaming!CN.png", proxies: ["默认节点", "国内网站"] },
      { name: "国内网站", url: "http://wifi.vivo.com.cn/generate_204", icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/StreamingCN.png", proxies: ["直连", "默认节点"] }
    ],
    postRules: ["GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve", "GEOSITE,cn,国内网站", "GEOIP,cn,国内网站,no-resolve", "MATCH,其他外网"]
  }
};

// ================= Core orchestration (移植自 clash，嵌入 singbox 管理器) =================
class MetricsManager { constructor(state) { this.state = state; } append(nodeId, metrics) {
  if (!nodeId) return; const arr = this.state.metrics.get(nodeId) || []; arr.push(metrics);
  if (arr.length > CONSTANTS.FEATURE_WINDOW_SIZE) this.state.metrics.set(nodeId, arr.slice(-CONSTANTS.FEATURE_WINDOW_SIZE));
  else this.state.metrics.set(nodeId, arr);
}}

class AvailabilityTracker {
  constructor(state, nodeManager) { this.state = state; this.nodeManager = nodeManager; this.trackers = nodeManager.nodeSuccess; }
  ensure(nodeId) { if (!this.trackers.get(nodeId)) this.trackers.set(nodeId, new SuccessRateTracker()); }
  record(nodeId, success, opts = {}) {
    this.ensure(nodeId); const tracker = this.trackers.get(nodeId);
    tracker.record(success, opts);
    const rate = tracker.rate; this.state.updateNodeStatus(nodeId, { availabilityRate: rate });
  }
  rate(nodeId) { return (this.trackers.get(nodeId)?.rate) || 0; }
  hardFailStreak(nodeId) { return (this.trackers.get(nodeId)?.hardFailStreak) || 0; }
}

class NodeManager extends EventEmitter {
  static getInstance() { if (!NodeManager.instance) NodeManager.instance = new NodeManager(); return NodeManager.instance; }
  constructor() { super(); this.currentNode = null; this.nodeQuality = new Map(); this.switchCooldown = new Map(); this.nodeHistory = new Map(); this.nodeSuccess = new Map(); }
  isInCooldown(nodeId) { const end = this.switchCooldown.get(nodeId); return !!(end && Date.now() < end); }
  _getCooldownTime(nodeId) {
    const score = this.nodeQuality.get(nodeId) || 0;
    return Math.max(CONSTANTS.MIN_SWITCH_COOLDOWN, Math.min(CONSTANTS.MAX_SWITCH_COOLDOWN, CONSTANTS.BASE_SWITCH_COOLDOWN * (1 + score / 100)));
  }
  _recordSwitchEvent(oldNodeId, newNodeId, targetGeo) {
    const event = { timestamp: Date.now(), oldNodeId, newNodeId, targetGeo: targetGeo ? { country: targetGeo.country, region: targetGeo.regionName || targetGeo.region } : null, reason: oldNodeId ? "质量过低" : "初始选择" };
    // 可集成外部日志
  }
  _updateNodeHistory(nodeId, score) {
    const history = this.nodeHistory.get(nodeId) || [];
    history.push({ timestamp: Date.now(), score });
    if (history.length > CONSTANTS.MAX_HISTORY_RECORDS) this.nodeHistory.set(nodeId, history.slice(-CONSTANTS.MAX_HISTORY_RECORDS));
    else this.nodeHistory.set(nodeId, history);
  }
  updateNodeQuality(nodeId, scoreDelta) {
    const current = this.nodeQuality.get(nodeId) || 0;
    const newScore = Math.max(0, Math.min(100, current + (Number(scoreDelta) || 0)));
    this.nodeQuality.set(nodeId, newScore);
    this._updateNodeHistory(nodeId, newScore);
  }
  _selectBestPerformanceNode(nodes, central) {
    if (!Array.isArray(nodes) || nodes.length === 0) { Logger.warn("_selectBestPerformanceNode: 节点列表为空"); return null; }
    const scoreFor = (node) => {
      if (!node || !node.id) return 0;
      try {
        const quality = this.nodeQuality.get(node.id) || 0;
        const nodeState = (central?.state?.nodes?.get(node.id)) || {};
        const metrics = nodeState.metrics || {};
        const availabilityRate = Number(nodeState.availabilityRate) || 0;

        const availabilityPenalty = availabilityRate < CONSTANTS.AVAILABILITY_MIN_RATE ? -30 : 0;

        const latencyVal = Math.max(0, Math.min(CONSTANTS.LATENCY_CLAMP_MS, Number(metrics.latency) || 1000));
        const jitterVal = Math.max(0, Math.min(CONSTANTS.JITTER_CLAMP_MS, Number(metrics.jitter) || 100));
        const lossVal = Math.max(0, Math.min(CONSTANTS.LOSS_CLAMP, Number(metrics.loss) || 0));
        const bps = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, Number(metrics.bps) || 0));

        const latencyScore = Math.max(0, Math.min(50, 50 - latencyVal / 20));
        const jitterScore  = Math.max(0, Math.min(25, 25 - jitterVal));
        const lossScore    = Math.max(0, Math.min(15, 15 * (1 - lossVal)));
        const throughputScore = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SCORE_MAX, Math.round(Math.log10(1 + bps) * 2)));
        const metricScore = Math.round(latencyScore + jitterScore + lossScore + throughputScore);

        const tracker = this.nodeSuccess.get(node.id);
        let successRatePercent = (tracker && typeof tracker.rate === "number") ? Math.max(0, Math.min(100, tracker.rate * 100)) : 0;

        const qw = Math.max(0, Math.min(1, CONSTANTS.QUALITY_WEIGHT || 0.5));
        const mw = Math.max(0, Math.min(1, CONSTANTS.METRIC_WEIGHT || 0.35));
        const sw = Math.max(0, Math.min(1, CONSTANTS.SUCCESS_WEIGHT || 0.15));
        const tw = qw + mw + sw || 1;

        const composite = ((quality * (qw / tw)) + (metricScore * (mw / tw)) + (successRatePercent * (sw / tw)) + availabilityPenalty);
        return Math.max(0, Math.min(100, composite));
      } catch (e) { Logger.debug(`计算节点得分失败 (${node.id}):`, e.message); return 0; }
    };
    let best = nodes[0]; let bestVal = scoreFor(best);
    for (let i = 1; i < nodes.length; i++) { const n = nodes[i]; if (!n) continue; const val = scoreFor(n); if (val > bestVal) { best = n; bestVal = val; } }
    return best;
  }
  async getBestNode(nodes, targetGeo, central) {
    if (!Array.isArray(nodes) || nodes.length === 0) { Logger.warn("getBestNode: 节点列表为空或无效"); return null; }
    const availableNodes = nodes.filter(node => node && node.id && !this.isInCooldown(node.id));
    const pool = availableNodes.length > 0 ? availableNodes : nodes;
    if (targetGeo && typeof targetGeo.regionName === "string" && central?.state?.nodes) {
      const regionalNodes = pool.filter(node => { const ns = central.state.nodes.get(node.id); return ns?.geoInfo?.regionName === targetGeo.regionName; });
      if (regionalNodes.length > 0) return this._selectBestPerformanceNode(regionalNodes, central) || pool[0];
    }
    return this._selectBestPerformanceNode(pool, central) || pool[0];
  }
  async switchToBestNode(nodes, targetGeo, central) {
    if (!nodes || nodes.length === 0) return null;
    const bestNode = await this.getBestNode(nodes, targetGeo, central);
    if (!bestNode) return null;
    const oldNodeId = this.currentNode;
    this.currentNode = bestNode.id;
    this.switchCooldown.set(bestNode.id, Date.now() + this._getCooldownTime(bestNode.id));
    this._recordSwitchEvent(oldNodeId, bestNode.id, targetGeo);
    const nodeStatus = central.state.nodes.get(bestNode.id);
    const nodeRegion = nodeStatus?.geoInfo?.regionName || "未知区域";
    Logger.info(`节点已切换: ${oldNodeId || "无"} -> ${bestNode.id} (质量分: ${this.nodeQuality.get(bestNode.id)}, 区域: ${nodeRegion})`);
    return bestNode;
  }
}

class CentralManager extends EventEmitter {
  static getInstance() { return CentralManager.instance; }
  constructor(kernelApiAdapter) {
    super();
    this.state = new AppState();
    this.stats = new RollingStats();
    this.successTracker = new SuccessRateTracker();
    this.nodeManager = NodeManager.getInstance();
    this.lruCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.metricsManager = new MetricsManager(this.state);
    this.availabilityTracker = new AvailabilityTracker(this.state, this.nodeManager);
    this.throughputEstimator = new ThroughputEstimator();
    this.kernelApiAdapter = kernelApiAdapter;
    CentralManager.instance = this;
  }

  async initialize() {
    try {
      await this.loadAIDBFromFile();
      this.preheatNodes();
      Logger.info("CentralManager 初始化完成");
    } catch (error) { Logger.error("CentralManager 初始化失败:", error && error.stack ? error.stack : error); }
  }

  async destroy() {
    try {
      await this.saveAIDBToFile();
      if (this.lruCache) this.lruCache.clear();
      if (this.geoInfoCache) this.geoInfoCache.clear();
    } catch (error) { Logger.error("资源清理失败:", error && error.stack ? error.stack : error); }
  }

  async preheatNodes() {
    const proxies = this.state.config.proxies || [];
    if (proxies.length === 0) return;
    const testNodes = proxies.slice(0, CONSTANTS.PREHEAT_NODE_COUNT);
    const tasks = testNodes.map(node => () => Utils.retry(() => this.testNodeMultiMetrics(node), 2, 200));
    const results = await Utils.asyncPool(tasks, CONSTANTS.CONCURRENCY_LIMIT);
    results.forEach((res, i) => {
      const node = testNodes[i];
      if (res && res.__error) { Logger.error(`节点预热失败: ${node.id}`, res.__error?.message || res.__error); return; }
      const bps = this.throughputEstimator.bpsFromBytesLatency(res);
      const enriched = { ...res, bps };
      this.state.updateNodeStatus(node.id, { initialMetrics: enriched, lastTested: Date.now() });
      this.metricsManager.append(node.id, enriched);
      this.nodeManager.updateNodeQuality(node.id, this.calculateInitialQualityScore(enriched));
      this.availabilityTracker.ensure(node.id);
    });
  }

  calculateInitialQualityScore(metrics) {
    metrics = metrics || {};
    const latency = Math.max(0, Math.min(CONSTANTS.LATENCY_CLAMP_MS, Number(metrics.latency) || 0));
    const loss    = Math.max(0, Math.min(CONSTANTS.LOSS_CLAMP, Number(metrics.loss) || 0));
    const jitter  = Math.max(0, Math.min(CONSTANTS.JITTER_CLAMP_MS, Number(metrics.jitter) || 0));
    const bps     = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, Number(metrics.bps) || 0));
    const latencyScore = Math.max(0, Math.min(35, 35 - latency / 25));
    const jitterScore  = Math.max(0, Math.min(25, 25 - jitter));
    const lossScore    = Math.max(0, Math.min(25, 25 * (1 - loss)));
    const throughputScore = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SCORE_MAX, Math.round(Math.log10(1 + bps) * 2)));
    const total = Math.round(latencyScore + jitterScore + lossScore + throughputScore);
    return Math.max(0, Math.min(100, total));
  }

  async evaluateAllNodes() {
    const proxies = this.state.config.proxies || [];
    if (proxies.length === 0) return;
    const tasks = proxies.map(node => () => this.evaluateNodeQuality(node));
    const results = await Utils.asyncPool(tasks, CONSTANTS.CONCURRENCY_LIMIT);
    results.forEach((r, idx) => { if (r && r.__error) Logger.warn(`节点评估失败: ${proxies[idx]?.id}`, r.__error?.message || r.__error); });
  }

  async evaluateNodeQuality(node) {
    if (!node || !node.id || typeof node.id !== "string") { Logger.warn("evaluateNodeQuality: 无效的节点对象"); return; }
    let metrics = null;
    try { metrics = await Utils.retry(() => this.testNodeMultiMetrics(node), CONSTANTS.MAX_RETRY_ATTEMPTS, CONSTANTS.RETRY_DELAY_BASE); }
    catch { Logger.warn(`节点探测多次失败，使用回退模拟: ${node.id}`); try { metrics = await this.testNodeMultiMetrics(node); }
      catch { Logger.error(`节点回退测试也失败: ${node.id}`); metrics = { latency: CONSTANTS.NODE_TEST_TIMEOUT, loss: 1, jitter: 100, bytes: 0, bps: 0, __simulated: true }; } }

    if (typeof metrics.bps !== "number") metrics.bps = this.throughputEstimator.bpsFromBytesLatency(metrics);

    this.availabilityTracker.ensure(node.id);
    const isSimulated = metrics && metrics.__simulated === true;
    const latency = Math.max(0, Number(metrics?.latency) || 0);
    const timeoutThreshold = (CONSTANTS.NODE_TEST_TIMEOUT || 5000) * 2;

    const hardFail = !!metrics.__hardFail;
    const success = !!(metrics && !isSimulated && latency > 0 && latency < timeoutThreshold && !hardFail);
    this.availabilityTracker.record(node.id, success, { hardFail });

    let score = 0;
    try { score = Math.max(0, Math.min(100, this.calculateNodeQualityScore(metrics))); }
    catch (e) { Logger.error(`计算节点质量分失败 (${node.id}):`, e.message); score = 0; }

    let geoInfo = null;
    try {
      const nodeIp = (node.server && typeof node.server === "string") ? node.server.split(":")[0] : null;
      if (nodeIp && /^(\d{1,3}\.){3}\d{1,3}$/.test(nodeIp)) geoInfo = await this.getGeoInfo(nodeIp);
    } catch (e) { Logger.debug(`获取节点地理信息失败 (${node.id}):`, e.message); }

    try {
      this.nodeManager.updateNodeQuality(node.id, score);
      this.metricsManager.append(node.id, metrics);
      const avail = this.availabilityTracker.rate(node.id);
      this.state.updateNodeStatus(node.id, { metrics, score, geoInfo, lastEvaluated: Date.now(), availabilityRate: avail });
    } catch (e) { Logger.error(`更新节点状态失败 (${node.id}):`, e.message); }

    try {
      const isCurrent = this.nodeManager.currentNode === node.id;
      const availRate = this.availabilityTracker.rate(node.id);
      const failStreak = this.availabilityTracker.hardFailStreak(node.id);
      if (isCurrent && (hardFail || availRate < CONSTANTS.AVAILABILITY_MIN_RATE || score < CONSTANTS.QUALITY_SCORE_THRESHOLD)) {
        const proxies = this.state?.config?.proxies;
        if (Array.isArray(proxies) && proxies.length > 0) {
          if (failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS) this.nodeManager.switchCooldown.delete(node.id);
          await this.nodeManager.switchToBestNode(proxies, null, this);
          // 同步到 singbox 内核策略组（如果可用）
          if (this.kernelApiAdapter) this.kernelApiAdapter.syncCurrent(bestNode?.id);
        }
      }
    } catch (e) { Logger.warn(`节点切换失败 (${node.id}):`, e.message); }
  }

  async handleRequestWithGeoRouting(targetIp) {
    if (!targetIp || !this.state.config.proxies || this.state.config.proxies.length === 0) { Logger.warn("无法进行地理路由: 缺少目标IP或代理节点"); return; }
    const targetGeo = await this.getGeoInfo(targetIp);
    if (!targetGeo) { Logger.warn("无法获取目标IP地理信息，使用默认路由"); await this.nodeManager.switchToBestNode(this.state.config.proxies, null, this); return; }
    await this.nodeManager.switchToBestNode(this.state.config.proxies, targetGeo, this);
  }

  calculateNodeQualityScore(metrics) {
    metrics = metrics || {};
    const latencyVal = Math.max(0, Math.min(CONSTANTS.LATENCY_CLAMP_MS, Number(metrics.latency) || 0));
    const jitterVal  = Math.max(0, Math.min(CONSTANTS.JITTER_CLAMP_MS, Number(metrics.jitter) || 0));
    const lossVal    = Math.max(0, Math.min(CONSTANTS.LOSS_CLAMP, Number(metrics.loss) || 0));
    const bps        = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, Number(metrics.bps) || 0));

    const latencyScore = Math.max(0, Math.min(35, 35 - latencyVal / 25));
    const jitterScore  = Math.max(0, Math.min(25, 25 - jitterVal));
    const lossScore    = Math.max(0, Math.min(25, 25 * (1 - lossVal)));
    const throughputScore = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SCORE_MAX, Math.round(Math.log10(1 + bps) * 2)));

    const total = Math.round(latencyScore + jitterScore + lossScore + throughputScore);
    return Math.max(0, Math.min(100, total));
  }

  autoEliminateNodes() {
    const proxies = this.state.config.proxies || [];
    const thresholdTime = Date.now() - CONSTANTS.NODE_EVALUATION_THRESHOLD;
    proxies.forEach(node => {
      const status = this.state.nodes.get(node.id);
      if (!status || status.lastEvaluated < thresholdTime || status.score < CONSTANTS.NODE_CLEANUP_THRESHOLD) {
        this.state.nodes.delete(node.id);
        this.state.metrics.delete(node.id);
        this.nodeManager.nodeQuality.delete(node.id);
        Logger.info(`已清理异常节点: ${node.id}`);
      }
    });
  }

  async smartDispatchNode(user, nodes, context) {
    if (!Array.isArray(nodes) || nodes.length === 0) throw new InvalidRequestError("smartDispatchNode: 节点列表不能为空");
    if (!context || typeof context !== "object") throw new InvalidRequestError("smartDispatchNode: 无效的上下文信息");

    const userStr = typeof user === "string" ? user : "default";
    const country = (context.clientGeo && typeof context.clientGeo.country === "string") ? context.clientGeo.country : "unknown";
    const hostname = (context.req && context.req.url)
      ? (typeof context.req.url === "string" ? new URL(context.req.url).hostname : (context.req.url.hostname || "unknown"))
      : "unknown";
    const cacheKey = `${userStr}:${country}:${hostname}`;

    let cachedNode = null;
    try { cachedNode = this.lruCache?.get(cacheKey); } catch (e) { Logger.debug("缓存查询失败:", e.message); }
    if (cachedNode) {
      try {
        const node = nodes.find(n => n && n.id === cachedNode);
        if (node) { Logger.debug(`使用缓存的节点选择: ${cachedNode}`); return node; }
      } catch (e) { Logger.debug("缓存节点查找失败:", e.message); }
      try { this.lruCache?.delete(cacheKey); } catch (e) { Logger.debug("清理无效缓存失败:", e.message); }
    }

    const contentType = (context.req && context.req.headers && typeof context.req.headers["Content-Type"] === "string")
      ? context.req.headers["Content-Type"] : "";
    const url = (context.req && context.req.url)
      ? (typeof context.req.url === "string" ? context.req.url : context.req.url.toString())
      : "";

    if (contentType.includes("video") || (url && /youtube|netflix|stream/i.test(url))) {
      try {
        const candidateIds = Array.from(this.state.nodes.entries())
          .filter(([_, node]) => node && typeof node.score === "number" && node.score > CONSTANTS.QUALITY_SCORE_THRESHOLD)
          .map(([id]) => id);
        const candidates = candidateIds
          .map(id => { try { return this.state.config?.proxies?.find(p => p && p.id === id); } catch { return null; } })
          .filter(Boolean);

        const limit = CONSTANTS.CONCURRENCY_LIMIT || 3;
        if (candidates.length > 0) {
          try {
            const testTasks = candidates.slice(0, limit * 2).map(node =>
              () => Utils.retry(() => this.testNodeMultiMetrics(node), CONSTANTS.MAX_RETRY_ATTEMPTS, CONSTANTS.RETRY_DELAY_BASE)
            );
            await Utils.asyncPool(testTasks, limit);
          } catch (e) { Logger.warn("节点测试批次处理失败:", e.message); }

          Logger.info(`筛选出 ${candidates.length} 个符合质量要求的节点`);
          const best = await this.nodeManager.getBestNode(candidates, null, this);
          if (best) { try { if (this.lruCache && best.id) this.lruCache.set(cacheKey, best.id); } catch (e) { Logger.debug("缓存节点选择结果失败:", e.message); }
            return best; }
        }
      } catch (error) { Logger.warn("视频流节点选择失败，使用默认策略:", error.message); }
    }

    if (context.targetGeo && context.targetGeo.country && typeof context.targetGeo.country === "string") {
      try {
        if (Config && Config.regionOptions && Array.isArray(Config.regionOptions.regions)) {
          const targetRegion = Config.regionOptions.regions.find(r =>
            r && ((r.name && r.name.includes(context.targetGeo.country)) ||
                  (r.regex && typeof context.targetGeo.country === "string" && r.regex.test(context.targetGeo.country)))
          );
          if (targetRegion) {
            const regionNodes = (this.state.config.proxies || []).filter(p => p?.name?.match(targetRegion.regex));
            if (regionNodes.length > 0) {
              const bestRegionNode = await this.nodeManager.getBestNode(regionNodes, null, this);
              if (bestRegionNode) { try { if (this.lruCache && bestRegionNode.id) this.lruCache.set(cacheKey, bestRegionNode.id); } catch (e) { Logger.debug("缓存区域节点选择结果失败:", e.message); }
                return bestRegionNode; }
            }
          }
        }
      } catch (error) { Logger.warn("区域节点选择失败，使用默认策略:", error.message); }
    }

    const bestNode = await this.nodeManager.getBestNode(nodes, null, this);
    if (!bestNode) { Logger.warn("无法选择最佳节点，返回第一个可用节点"); return nodes[0] || null; }
    try { if (this.lruCache && bestNode.id) this.lruCache.set(cacheKey, bestNode.id); } catch (e) { Logger.debug("缓存默认节点选择结果失败:", e.message); }
    return bestNode;
  }

  async getGeoInfo(ip, domain) {
    if (!this.geoInfoCache) this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    if (!ip) return fallbackGeo(domain);
    if (ip === "127.0.0.1" || ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.")) return { country: "Local", region: "Local" };
    const cached = this.geoInfoCache.get(ip);
    if (cached) return cached;

    const primary = await fetchGeoPrimary(ip);
    if (primary) { this.geoInfoCache.set(ip, primary); return primary; }
    const fallback = await fetchGeoFallback(ip);
    if (fallback) { this.geoInfoCache.set(ip, fallback); return fallback; }
    const downgraded = fallbackGeo(domain);
    this.geoInfoCache.set(ip, downgraded, CONSTANTS.GEO_FALLBACK_TTL);
    return downgraded;
  }

  async testNodeMultiMetrics(node) {
    const cacheKey = `nodeMetrics:${node.id}`;
    const cached = this.lruCache.get(cacheKey);
    if (cached) return cached;

    const timeout = CONSTANTS.NODE_TEST_TIMEOUT || 5000;
    const probe = async () => {
      const probeUrl = node.proxyUrl || node.probeUrl || (node.server ? `http://${node.server}` : null);
      let tcpLatencyMs = null;
      if (typeof process !== "undefined" && process.versions?.node && node.server) {
        try {
          const [host, portStr] = node.server.split(":");
          const port = parseInt(portStr || "80", 10) || 80;
          tcpLatencyMs = await this.throughputEstimator.tcpConnectLatency(host, port, timeout);
        } catch { tcpLatencyMs = null; }
      }
      if (!probeUrl) throw new Error("无探测URL，使用模拟测试");
      const start = Date.now();
      let response;
      try { response = await _safeFetch(probeUrl, { method: "GET" }, timeout); }
      catch { return { latency: timeout, loss: 1, jitter: 100, bytes: 0, bps: 0, __hardFail: true }; }
      const latency = Date.now() - start;

      const measure = await this.throughputEstimator.measureResponse(response, timeout);
      const bytes = measure.bytes || 0;
      const jitter = measure.jitter || 0;
      const bps = this.throughputEstimator.bpsFromBytesLatency({ bytes, latency });

      const finalLatency = (typeof tcpLatencyMs === "number" && tcpLatencyMs > 0 && tcpLatencyMs < latency) ? tcpLatencyMs : latency;
      return { latency: finalLatency, loss: 0, jitter, bytes, bps };
    };

    try {
      const result = await Utils.retry(() => probe(), 2, 200);
      try { this.lruCache.set(cacheKey, result, 60000); } catch {}
      return result;
    } catch (e) {
      Logger.debug("真实网络探测失败，使用模拟数据:", e && e.message ? e.message : e);
      return new Promise(resolve => {
        setTimeout(() => {
          const latency = Math.random() * 500 + 50;
          const loss = Math.random() * 0.1;
          const jitter = Math.random() * 50;
          const bytes = Math.floor(Math.random() * 32 * 1024);
          const bps = this.throughputEstimator.bpsFromBytesLatency({ bytes, latency });
          const simulated = { latency, loss, jitter, bytes, bps, __simulated: true };
          try { this.lruCache.set(cacheKey, simulated, 60000); } catch {}
          resolve(simulated);
        }, Math.random() * 500);
      });
    }
  }

  recordRequestMetrics(node, result, req) {
    if (!node || !result) return;
    const metrics = {
      timestamp: Date.now(),
      nodeId: node.id,
      success: result.success,
      latency: result.latency,
      url: req?.url || "",
      method: req?.method || "",
      bytes: result.bytes || 0,
      bps: this.throughputEstimator.bpsFromBytesLatency({ bytes: result.bytes || 0, latency: result.latency || 0 })
    };
    this.successTracker.record(result.success);
    if (result.latency) this.stats.add(result.latency);
    this.metricsManager.append(node.id, metrics);
    const aiScore = this.aiScoreNode(node, metrics);
    this.nodeManager.updateNodeQuality(node.id, aiScore);
  }

  aiScoreNode(node, metrics) {
    const nodeHistory = this.nodeManager.nodeHistory.get(node.id) || [];
    const recentMetrics = this.state.metrics.get(node.id) || [];
    if (recentMetrics.length < CONSTANTS.MIN_SAMPLE_SIZE) return metrics.success ? 2 : -2;
    const features = this.extractNodeFeatures(metrics, recentMetrics, nodeHistory);
    const prediction = this.predictNodeFuturePerformance(features);
    return this.calculateScoreAdjustment(prediction, metrics.success);
  }

  extractNodeFeatures(currentMetrics, recentMetrics, history) {
    const latencies = recentMetrics.map(m => Number(m.latency)).filter(Number.isFinite);
    const losses    = recentMetrics.map(m => Number(m.loss)).filter(Number.isFinite);
    const jitters   = recentMetrics.map(m => Number(m.jitter)).filter(Number.isFinite);
    const successes = recentMetrics.map(m => m.success ? 1 : 0);
    const bpsArr    = recentMetrics.map(m => Number(m.bps) || 0).filter(Number.isFinite);

    const weightedLatency = Utils.calculateWeightedAverage(latencies);
    const weightedLoss = Utils.calculateWeightedAverage(losses);
    const successRate = successes.length ? successes.reduce((a, b) => a + b, 0) / successes.length : 1;

    const avgLatency = latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0;
    const latencyStd = Utils.calculateStdDev(latencies);
    const latencyCV  = (latencyStd / (avgLatency || 1)) || 0;

    return {
      currentLatency: Number.isFinite(currentMetrics.latency) ? currentMetrics.latency : 0,
      currentLoss: Number.isFinite(currentMetrics.loss) ? currentMetrics.loss : 0,
      currentJitter: Number.isFinite(currentMetrics.jitter) ? currentMetrics.jitter : 0,
      currentBps: Number.isFinite(currentMetrics.bps) ? currentMetrics.bps : 0,
      success: currentMetrics.success ? 1 : 0,
      avgLatency,
      p95Latency: Utils.calculatePercentile(latencies, 95),
      weightedLatency,
      latencyStd,
      latencyCV,
      avgLoss: losses.length ? losses.reduce((a, b) => a + b, 0) / losses.length : 0,
      weightedLoss,
      avgJitter: jitters.length ? jitters.reduce((a, b) => a + b, 0) / jitters.length : 0,
      avgBps: bpsArr.length ? bpsArr.reduce((a, b) => a + b, 0) / bpsArr.length : 0,
      successRate,
      latencyTrend: Utils.calculateTrend(latencies),
      lossTrend: Utils.calculateTrend(losses),
      successTrend: Utils.calculateTrend(successes),
      qualityTrend: history && history.length >= 2 ? history[history.length - 1].score - history[history.length - 2].score : 0,
      recentQuality: history && history.length ? history[history.length - 1].score : 50,
      sampleSize: recentMetrics.length
    };
  }

  predictNodeFuturePerformance(features) {
    const weights = this.getDynamicRiskWeights(features);
    let risk = 0;
    risk += Math.min(features.currentLatency / 1000, 1) * weights.latency;
    risk += Math.min(features.currentLoss, 1) * weights.loss;
    risk += Math.min(features.latencyStd / 100, 1) * weights.jitter;
    risk += Math.max(0, (0.8 - features.successRate) / 0.8) * weights.successRate;
    if (features.latencyTrend > 5) risk += 0.1 * weights.trend;
    if (features.lossTrend > 0.1) risk += 0.1 * weights.trend;
    if (features.successTrend < -0.1) risk += 0.1 * weights.trend;
    risk += Math.max(0, (50 - features.recentQuality) / 50) * weights.quality;
    risk *= (1 - features.success * 0.3);
    risk = Math.max(0, Math.min(1, risk));
    const stabilityScore = Math.round((1 - risk) * 100);
    return { risk, expectedLatency: features.weightedLatency + features.latencyTrend * 5, expectedStability: 1 - risk, stabilityScore, confidence: Math.min(1, features.sampleSize / CONSTANTS.FEATURE_WINDOW_SIZE) };
  }

  getDynamicRiskWeights(features) {
    const baseWeights = { latency: 0.25, loss: 0.25, jitter: 0.15, successRate: 0.15, trend: 0.1, quality: 0.1 };
    if (features.successRate < 0.8 || features.latencyStd > 50) {
      baseWeights.successRate = Math.min(0.3, baseWeights.successRate + 0.1);
      baseWeights.jitter = Math.min(0.3, baseWeights.jitter + 0.05);
      baseWeights.latency = Math.max(0.1, baseWeights.latency - 0.1);
      baseWeights.loss = Math.max(0.1, baseWeights.loss - 0.05);
    }
    const total = Object.values(baseWeights).reduce((s, w) => s + w, 0) || 1;
    return Object.fromEntries(Object.entries(baseWeights).map(([k, v]) => [k, v / total]));
  }

  calculateScoreAdjustment(prediction, success) {
    if (!success) return -10;
    if (prediction.risk < 0.3) return 5;
    if (prediction.risk < 0.5) return 2;
    if (prediction.risk > 0.7) return -3;
    return 0;
  }

  async loadAIDBFromFile() {
    try {
      let raw = "";
      let storage = null;
      try {
        if (typeof $persistentStore !== "undefined" && $persistentStore) storage = $persistentStore;
        else if (typeof window !== "undefined" && window.localStorage) storage = window.localStorage;
      } catch {}
      if (storage) {
        try {
          if (typeof storage.getItem === "function") raw = storage.getItem("ai_node_data") || "";
          else if (typeof storage.read === "function") raw = storage.read("ai_node_data") || "";
        } catch {}
      }
      if (raw && typeof raw === "string" && raw.trim()) {
        try {
          const data = JSON.parse(raw);
          if (typeof data === "object" && data !== null && !Array.isArray(data)) {
            Object.entries(data).forEach(([id, stats]) => {
              if (id && typeof id === "string" && stats && typeof stats === "object") {
                try { this.state.metrics.set(id, Array.isArray(stats) ? stats : [stats]); }
                catch {}
              }
            });
          }
        } catch (e) {
          try {
            if (typeof $persistentStore !== "undefined" && $persistentStore.write) $persistentStore.write("", "ai_node_data");
            else if (typeof window !== "undefined" && window.localStorage?.removeItem) window.localStorage.removeItem("ai_node_data");
          } catch {}
        }
      }
    } catch (e) { Logger.error("AI数据加载失败:", e && e.stack ? e.stack : e); }
  }

  saveAIDBToFile() {
    try {
      if (!this.state || !this.state.metrics) return;
      const data = Object.fromEntries(this.state.metrics.entries());
      if (!data || Object.keys(data).length === 0) return;
      const raw = JSON.stringify(data, null, 2);
      if (!raw || raw.length === 0) return;
      let saved = false;
      try {
        if (typeof $persistentStore !== "undefined" && $persistentStore?.write === "function") { $persistentStore.write(raw, "ai_node_data"); saved = true; }
        else if (typeof window !== "undefined" && window.localStorage?.setItem === "function") { window.localStorage.setItem("ai_node_data", raw); saved = true; }
      } catch (e) { Logger.error("AI数据保存到存储失败:", e && e.message ? e.message : e); }
      if (!saved) Logger.warn("无法保存AI数据: 未找到可用的存储接口");
    } catch (e) { Logger.error("AI数据保存失败:", e && e.stack ? e.stack : e); }
  }
}

// ================= SingBox request adapter =================
const setupRequestApi = () => {
  let base = Plugins.APP_TITLE.includes('SingBox') ? 'http://127.0.0.1:20123' : 'http://127.0.0.1:20113';
  let bearer = '';
  const appSettingsStore = Plugins.useAppSettingsStore();
  const profilesStore = Plugins.useProfilesStore();
  const profile = profilesStore.getProfileById(appSettingsStore.app.kernel.profile);
  if (profile) {
    if (Plugins.APP_TITLE.includes('SingBox')) {
      const controller = profile.experimental.clash_api.external_controller || '127.0.0.1:20123';
      const [, port = 20123] = controller.split(':');
      base = `http://127.0.0.1:${port}`;
      bearer = profile.experimental.clash_api.secret;
    } else {
      const controller = profile.advancedConfig['external-controller'] || '127.0.0.1:20113';
      const [, port = 20113] = controller.split(':');
      base = `http://127.0.0.1:${port}`;
      bearer = profile.advancedConfig.secret;
    }
  }
  request.base = base;
  request.bearer = bearer;
};

const request = new Plugins.Request({ beforeRequest: setupRequestApi, timeout: 60 * 1000 });

// ================= Proxy server (扩展以承载移植的指标/可用性) =================
class ProxyServer {
  constructor(id, url, priority, group, options) {
    this.id = id;
    this.url = url;
    this.priority = priority;
    this.group = group;
    this.options = options;

    this.ewmaLatency = null;
    this.failureCount = 0;
    this.lastDelay = '';
    this.penalty = 0;
    this.lastPenaltyUpdate = Date.now();

    this.state = 'CLOSED';
    this.nextAttempt = 0;

    // 兼容中央管理器
    this.metrics = { latency: 0, jitter: 0, loss: 0, bytes: 0, bps: 0, success: false };
    this.availabilityRate = 0;
    this.geoInfo = null;
    this.score = 0;
  }

  recordSuccess(latency) {
    const now = Date.now();
    const alpha = this.options.ewmaAlpha;
    if (this.ewmaLatency === null) this.ewmaLatency = latency;
    else this.ewmaLatency = alpha * latency + (1 - alpha) * this.ewmaLatency;
    this.failureCount = 0;
    this.lastDelay = latency;
    if (this.state === 'HALF_OPEN' || this.state === 'OPEN') this.state = 'CLOSED';
    const dt = (now - this.lastPenaltyUpdate) / 1000;
    this.penalty *= Math.exp(-this.options.penaltyDecayRate * dt);
    this.lastPenaltyUpdate = now;

    // 更新中央指标
    this.metrics.latency = latency;
    this.metrics.success = true;
  }

  recordFailure() {
    const now = Date.now();
    this.failureCount += 1;
    this.lastDelay = '';
    this.penalty += this.options.penaltyIncrement;
    this.lastPenaltyUpdate = now;
    if (this.failureCount >= this.options.failureThreshold) { this.state = 'OPEN'; this.nextAttempt = now + this.options.circuitBreakerTimeout; }
    this.metrics.success = false;
  }

  isAvailable() {
    const now = Date.now();
    if (this.state === 'OPEN') {
      if (now >= this.nextAttempt) { this.state = 'HALF_OPEN'; return true; }
      return false;
    }
    return true;
  }

  getScore() {
    if (!this.isAvailable() || this.ewmaLatency === null) return -Infinity;
    const now = Date.now();
    const dt = (now - this.lastPenaltyUpdate) / 1000;
    const decayedPenalty = this.penalty * Math.exp(-this.options.penaltyDecayRate * dt);
    const pScore = this.options.priorityWeight * this.priority;
    const lScore = this.options.latencyWeight * (1 / this.ewmaLatency);
    const penScore = this.options.penaltyWeight * decayedPenalty;
    return pScore + lScore - penScore;
  }
}

// ================= Proxy manager (融合中央编排器) =================
class ProxyManager {
  constructor(proxyConfigs, options, centralManager, kernelApi) {
    this.options = Object.assign({
      ewmaAlpha: 0.3,
      failureThreshold: 3,
      circuitBreakerTimeout: 360 * 1000,
      penaltyIncrement: 5,
      penaltyDecayRate: 0.1,
      priorityWeight: 1.0,
      latencyWeight: 100.0,
      penaltyWeight: 1.0,
      hysteresisMargin: 0.1,
      monitoringInterval: 60 * 1000,
      requestTimeout: 5000
    }, options);

    this.proxies = proxyConfigs.map((cfg) => new ProxyServer(cfg.id, cfg.url, cfg.priority, cfg.group, this.options));
    this.current = null;
    this.central = centralManager;
    this.kernelApi = kernelApi;
  }

  async start() { await this.central.initialize(); }

  startMonitoring() {
    this.monitoringTimer = Plugins.setIntervalImmediately(() => {
      this.checkAll().then(() => {
        this.evaluateSwitch();
      });
    }, this.options.monitoringInterval);
  }

  stopMonitoring() { clearInterval(this.monitoringTimer); }

  async checkAll() {
    const checkProxy = async (proxy) => {
      if (!proxy.isAvailable()) return;
      try {
        const { delay } = await request.get(proxy.url, { url: Plugin.TestUrl || 'https://www.gstatic.com/generate_204', timeout: Number(Plugin.RequestTimeout) });
        proxy.recordSuccess(delay);

        // 补充中央探测信息
        const nodeDef = this.central.state.config.proxies?.find(p => p.id === proxy.id) || { id: proxy.id, proxyUrl: request.base + proxy.url };
        const metrics = await this.central.testNodeMultiMetrics(nodeDef);
        metrics.latency = delay;
        this.central.metricsManager.append(proxy.id, metrics);
        const availTracker = this.central.availabilityTracker;
        availTracker.ensure(proxy.id);
        availTracker.record(proxy.id, true, { hardFail: false });
        proxy.availabilityRate = availTracker.rate(proxy.id);
        proxy.metrics = { ...proxy.metrics, ...metrics, success: true };
        proxy.score = this.central.calculateNodeQualityScore(metrics);
        this.central.state.updateNodeStatus(proxy.id, { metrics, score: proxy.score, availabilityRate: proxy.availabilityRate });
      } catch (err) {
        proxy.recordFailure();
        const nodeDef = this.central.state.config.proxies?.find(p => p.id === proxy.id) || { id: proxy.id, proxyUrl: request.base + proxy.url };
        const failMetrics = { latency: this.options.requestTimeout, jitter: 100, loss: 1, bytes: 0, bps: 0, __hardFail: true };
        this.central.metricsManager.append(proxy.id, failMetrics);
        this.central.availabilityTracker.record(proxy.id, false, { hardFail: true });
        proxy.availabilityRate = this.central.availabilityTracker.rate(proxy.id);
        proxy.metrics = { ...proxy.metrics, ...failMetrics, success: false };
        proxy.score = this.central.calculateNodeQualityScore(failMetrics);
        this.central.state.updateNodeStatus(proxy.id, { metrics: failMetrics, score: proxy.score, availabilityRate: proxy.availabilityRate });
      }
    };
    await Plugins.asyncPool(Number(Plugin.ConcurrencyLimit), this.proxies, checkProxy);
  }

  evaluateSwitch() {
    let best = null; let bestScore = -Infinity;
    for (const p of this.proxies) { const score = p.getScore(); if (score > bestScore) { bestScore = score; best = p; } }
    if (!best) return;

    if (!this.current) { this.switchTo(best); return; }

    const kernelApi = Plugins.useKernelApiStore();
    const proxyName = kernelApi.proxies[this.current.group].now;
    const proxy = this.proxies.find((v) => v.id === proxyName);
    if (proxy) this.current = proxy;

    const currentScore = this.current.getScore();
    if (best.id !== this.current.id && bestScore >= currentScore + this.options.hysteresisMargin) {
      this.switchTo(best);
    }
  }

  switchTo(proxy) {
    Logger.info(`[切换] 策略组【${proxy.group}】: ${this.current?.id || '无'} -> ${proxy.id}`);
    this.current = proxy;
    const kernelApi = Plugins.useKernelApiStore();
    Plugins.handleUseProxy(kernelApi.proxies[proxy.group], kernelApi.proxies[proxy.id]);

    // 同步至中央管理器的节点切换冷却与历史记录
    this.central.nodeManager.currentNode = proxy.id;
    this.central.nodeManager.switchCooldown.set(proxy.id, Date.now() + this.central.nodeManager._getCooldownTime(proxy.id));
    this.central.nodeManager._recordSwitchEvent(null, proxy.id, proxy.geoInfo || null);
  }
}

// ================= 插件状态与预设 =================
const presetMap = {
  Stable: Plugin.StableMode,
  LatencyFirst: Plugin.LatencyFirstMode,
  Custom: Plugin.CustomMode
};

// 保存插件状态
window[Plugin.id] = window[Plugin.id] || {
  isRunning: false,
  managers: [],
  init() {
    console.log(`[${Plugin.name}]`, 'init');
    const kernelApi = Plugins.useKernelApiStore();
    if (!kernelApi.running) { console.log(`[${Plugin.name}]`, '核心未运行'); return false; }
    if (!presetMap[Plugin.Preset]) { console.log(`[${Plugin.name}]`, '预设使用场景不存在，请检查插件配置'); return false; }
    if (Plugin.IncludeGroup.every((v) => !kernelApi.proxies[v])) { console.log(`[${Plugin.name}]`, '未匹配到任何需要接管的策略组'); return false; }

    const options = { ...JSON.parse(presetMap[Plugin.Preset]), monitoringInterval: Number(Plugin.MonitoringInterval), requestTimeout: Number(Plugin.RequestTimeout) };
    console.log(`[${Plugin.name}]`, `当前智能切换场景为【${Plugin.Preset}】`);
    console.log(`[${Plugin.name}]`, `当前智能切换参数为`, options);

    // 中央管理器实例（一次）
    const central = new CentralManager({
      syncCurrent: (id) => {
        const group = Plugin.IncludeGroup[0];
        const kernelApi = Plugins.useKernelApiStore();
        if (kernelApi.proxies[group] && kernelApi.proxies[id]) Plugins.handleUseProxy(kernelApi.proxies[group], kernelApi.proxies[id]);
      }
    });

    // 应用配置（保持原格式流程）
    try {
      const config = { proxies: Object.values(kernelApi.proxies).map(p => ({ id: p.name, name: p.name, proxyUrl: `${request.base}/proxies/${encodeURIComponent(p.name)}/delay`, server: "", type: "http" })) };
      central.state.config = central.processConfiguration ? central.processConfiguration(config) : config;
    } catch (e) { Logger.warn("初始化配置失败:", e.message); }

    // 初始化/预热
    central.initialize().catch(e => Logger.warn("CentralManager 初始化失败:", e.message));

    this.managers = [];
    Plugin.IncludeGroup.forEach((group) => {
      if (!kernelApi.proxies[group]) return;
      const proxies = kernelApi.proxies[group].all.map((proxy) => ({ id: proxy, url: `/proxies/${encodeURIComponent(proxy)}/delay`, priority: 1, group }));
      const manager = new ProxyManager(proxies, options, central, kernelApi);
      this.managers.push(manager);
      console.log(`[${Plugin.name}]`, `智能切换已接管策略组【${group}】`);
    });

    return true;
  },
  start() {
    console.log(`[${Plugin.name}]`, 'start');
    if (this.isRunning) { console.log(`[${Plugin.name}]`, '已经在运行了'); return true; }
    if (!this.init()) return false;
    this.managers.forEach((manager) => { manager.start(); manager.startMonitoring(); });
    this.isRunning = true;
    return true;
  },
  stop() {
    console.log(`[${Plugin.name}]`, 'stop');
    if (!this.isRunning) { console.log(`[${Plugin.name}]`, '没有在运行'); return true; }
    this.managers.forEach((manager) => manager.stopMonitoring());
    this.isRunning = false;
    return true;
  }
};

/* 触发器 手动触发 */
const onRun = async () => {
  console.log(`[${Plugin.name}]`, 'onRun');
  const kernelApi = Plugins.useKernelApiStore();
  if (!kernelApi.running) { throw '请先启动核心'; }
  const res = window[Plugin.id].start();
  return res ? 1 : 2;
}

/* 触发器 APP就绪后 */
const onReady = async () => {
  console.log(`[${Plugin.name}]`, 'onReady');

  function setPluginStatus(status) {
    const pluginStore = Plugins.usePluginsStore();
    const plugin = pluginStore.getPluginById(Plugin.id);
    plugin.status = status;
    pluginStore.editPlugin(plugin.id, plugin);
  }

  setTimeout(() => {
    const res = window[Plugin.id].start();
    setPluginStatus(res ? 1 : 2);
  }, 3_000);
}

/* 触发器 核心启动后 */
const onCoreStarted = async () => {
  console.log(`[${Plugin.name}]`, 'onCoreStarted');
  window[Plugin.id].stop();
  const res = window[Plugin.id].start();
  return res ? 1 : 2;
}

/* 触发器 核心停止后 */
const onCoreStopped = async () => {
  console.log(`[${Plugin.name}]`, 'onCoreStopped');
  const res = window[Plugin.id].stop();
  return res ? 2 : 1;
}

/* 插件右键 - 启动 */
const Start = () => {
  const kernelApi = Plugins.useKernelApiStore();
  if (!kernelApi.running) { throw '请先启动核心'; }
  const res = window[Plugin.id].start();
  return res ? 1 : 2;
}

/* 右键菜单 - 停止 */
const Stop = () => {
  const res = window[Plugin.id].stop();
  return res ? 2 : 1;
}

/* 右键菜单 - 查看节点状态 */
const ViewStat = async () => {
  function renderState(state) {
    switch (state) {
      case 'CLOSED': return '🟢 正常';
      case 'OPEN': return '🔴 故障';
      case 'HALF_OPEN': return '🟡 检测中';
      default: return '❓未知';
    }
  }

  const groups = window[Plugin.id].managers.map((manager) => {
    const group = manager.proxies[0].group;
    const rows = manager.proxies
      .map((proxy) => {
        const { id, lastDelay, ewmaLatency, failureCount, penalty, state, lastPenaltyUpdate, nextAttempt } = proxy;
        const name = id.replaceAll('|', '\\|');
        return {
          name: manager.current?.id === id ? `\`${name}\`` : name,
          state: renderState(state),
          lastDelay: lastDelay ? lastDelay + 'ms' : '-',
          ewmaLatency: ewmaLatency ? ewmaLatency.toFixed(2) + 'ms' : '-',
          score: proxy.getScore().toFixed(2),
          failureCount,
          penalty: penalty ? penalty.toFixed(2) : penalty,
          isAvailable: lastDelay !== '' ? '✅' : '❌',
          lastPenaltyUpdate,
          nextAttempt
        }
      })
      .sort((a, b) => b.score - a.score);
    return { group, rows, options: manager.options };
  });

  const groups_markdown = groups.map((group) =>
    [
      `## 策略组【${group.group}】`,
      `> 代理数量：${group.rows.length} 监控间隔：${group.options.monitoringInterval}ms\n`,
      '|节点名|分数|当前延迟|EWMA平滑延迟|失败次数|惩罚值|更新时间|下次检测时间|断路器|可用性|',
      '|--|--|--|--|--|--|--|--|--|--|',
      group.rows
        .map(
          (v) =>
            `|${v.name}|${v.score}|${v.lastDelay}|${v.ewmaLatency}|${v.failureCount}|${v.penalty}|${Plugins.formatRelativeTime(v.lastPenaltyUpdate)}|${v.nextAttempt === 0 ? '-' : Plugins.formatRelativeTime(v.nextAttempt)}|${v.state}|${v.isAvailable}|`
        )
        .join('\n')
    ].join('\n')
  );

  const ok = await Plugins.confirm(Plugin.name, groups_markdown.join('\n'), { type: 'markdown', okText: '刷新' }).catch(() => false);
  if (ok) return await ViewStat();
}
