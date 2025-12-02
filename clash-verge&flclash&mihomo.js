"use strict";
/**
 * Central Orchestrator（中央调度架构）
 * - 保留原有 API 与行为，增强稳定性、隐私与跨平台兼容
 * - 智能节点选择，事件驱动，无周期轮询
 * - 指标流/可用性信号/吞吐量测量统一加固
 * - 出站/入站协议与业务感知优化
 * - GitHub 资源统一镜像加速（健康检测 + 原站回退）
 */

/* ===================== GitHub 访问加速（镜像健康检测 + Raw/Release） ===================== */
const GH_MIRRORS = [
  "https://mirror.ghproxy.com/",
  "https://github.moeyy.xyz/",
  "https://ghproxy.com/",
  "" // 原始 GitHub 回退
];
// 短时缓存镜像健康结果，避免频繁探测
let __ghSelected = null;
let __ghLastProbeTs = 0;
const __GH_PROBE_TTL = 10 * 60 * 1000;
async function __probeMirror(url, fetchFn) {
  const testUrl = `${url}https://raw.githubusercontent.com/github/gitignore/main/Node.gitignore`;
  try {
    const resp = await fetchFn(testUrl, { method: "HEAD" });
    return resp && (resp.status >= 200 && resp.status < 400);
  } catch { return false; }
}
async function selectBestMirror(fetchFn) {
  const now = Date.now();
  if (__ghSelected && (now - __ghLastProbeTs) < __GH_PROBE_TTL) return __ghSelected;
  for (const m of GH_MIRRORS) {
    try {
      const ok = m === "" ? true : await __probeMirror(m, fetchFn);
      if (ok) { __ghSelected = m; __ghLastProbeTs = now; return m; }
    } catch {}
  }
  __ghSelected = ""; __ghLastProbeTs = now;
  return "";
}
// 默认先用首选前缀（在运行期被健康探测动态更新）
let GH_PROXY_PREFIX = GH_MIRRORS[0] || "";
const GH_RAW = (path) => `${GH_PROXY_PREFIX}https://raw.githubusercontent.com/${path}`;
const GH_RELEASE = (path) => `${GH_PROXY_PREFIX}https://github.com/${path}`;

/* ===================== 平台检测 ===================== */
const PLATFORM = (() => {
  const isNode = typeof process !== "undefined" && !!process.versions?.node;
  const isBrowser = typeof window !== "undefined" && typeof window.addEventListener === "function";
  return Object.freeze({ isNode, isBrowser });
})();

/* ===================== 常量定义（统一评分权重与上限） ===================== */
const CONSTANTS = Object.freeze({
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

  // 统一权重与分值上限，强调稳定优先
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
  LOSS_CLAMP: 1.0,

  LARGE_PAYLOAD_THRESHOLD_BYTES: 512 * 1024,
  STREAM_HINT_REGEX: /youtube|netflix|stream|video|live|hls|dash/i,
  AI_HINT_REGEX: /openai|claude|gemini|ai|chatgpt|api\.openai|anthropic|googleapis/i,
  GAMING_PORTS: [3074, 27015, 27016, 27017, 27031, 27036, 5000, 5001],
  TLS_PORTS: [443, 8443],
  HTTP_PORTS: [80, 8080, 8880]
});

/* ===================== 日志输出（默认低噪音） ===================== */
class Logger {
  static error(...args) { console.error("[ERROR]", ...args); }
  static info(...args) { console.info("[INFO]", ...args); }
  static debug(...args) { if (CONSTANTS.ENABLE_SCORE_DEBUGGING) console.debug("[DEBUG]", ...args); }
  static warn(...args) { console.warn("[WARN]", ...args); }
}

/* ===================== 错误类型 ===================== */
class ConfigurationError extends Error { constructor(message) { super(message); this.name = "ConfigurationError"; } }
class InvalidRequestError extends Error { constructor(message) { super(message); this.name = "InvalidRequestError"; } }

/* ===================== 事件系统 ===================== */
class EventEmitter {
  constructor() { this.eventListeners = new Map(); }
  on(event, listener) {
    if (!event || typeof listener !== "function") return;
    const arr = this.eventListeners.get(event) || [];
    arr.push(listener);
    this.eventListeners.set(event, arr);
  }
  off(event, listener) {
    if (!this.eventListeners.has(event)) return;
    const arr = this.eventListeners.get(event);
    const idx = arr.indexOf(listener);
    if (idx !== -1) arr.splice(idx, 1);
    if (arr.length === 0) this.eventListeners.delete(event);
  }
  emit(event, ...args) {
    const arr = this.eventListeners.get(event);
    if (!arr || arr.length === 0) return;
    const snapshot = [...arr];
    for (const fn of snapshot) {
      try { fn(...args); } catch (e) { Logger.error(`事件 ${event} 处理失败:`, e.stack || e); }
    }
  }
  removeAllListeners(event) {
    if (event) this.eventListeners.delete(event);
    else this.eventListeners.clear();
  }
}

/* ===================== 应用状态 ===================== */
class AppState {
  constructor() {
    this.nodes = new Map();
    this.metrics = new Map();
    this.config = {};
    this.lastUpdated = Date.now();
  }
  updateNodeStatus(nodeId, status) {
    if (!nodeId || typeof nodeId !== "string") return;
    const prev = this.nodes.get(nodeId) || {};
    this.nodes.set(nodeId, { ...prev, ...status });
    this.lastUpdated = Date.now();
  }
}

/* ===================== LRU 缓存（自适应清理） ===================== */
class LRUCache {
  constructor({ maxSize = CONSTANTS.LRU_CACHE_MAX_SIZE, ttl = CONSTANTS.LRU_CACHE_TTL } = {}) {
    this.cache = new Map();
    this.maxSize = Math.max(1, Number(maxSize) || CONSTANTS.LRU_CACHE_MAX_SIZE);
    this.ttl = Math.max(1, Number(ttl) || CONSTANTS.LRU_CACHE_TTL);
    this.head = { key: null, prev: null, next: null };
    this.tail = { key: null, prev: this.head, next: null };
    this.head.next = this.tail;
  }
  _unlink(node) {
    if (!node || node === this.head || node === this.tail) return;
    const { prev, next } = node;
    if (prev) prev.next = next;
    if (next) next.prev = prev;
    node.prev = null; node.next = null;
  }
  _pushFront(node) {
    if (!node) return;
    node.prev = this.head;
    node.next = this.head.next;
    if (this.head.next) this.head.next.prev = node;
    this.head.next = node;
  }
  _evictTail() {
    const node = this.tail.prev;
    if (!node || node === this.head) return null;
    this._unlink(node);
    this.cache.delete(node.key);
    return node.key;
  }
  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    const expired = (Date.now() - entry.timestamp) > entry.ttl;
    if (expired) {
      this._unlink(entry);
      this.cache.delete(key);
      return null;
    }
    this._unlink(entry);
    entry.timestamp = Date.now();
    this._pushFront(entry);
    return entry.value;
  }
  set(key, value, ttl = this.ttl) {
    if (key == null) return;
    const ratio = this.cache.size / this.maxSize;
    if (ratio > CONSTANTS.CACHE_CLEANUP_THRESHOLD) {
      this._cleanupExpiredEntries(CONSTANTS.CACHE_CLEANUP_BATCH_SIZE);
    }
    const now = Date.now();
    if (this.cache.has(key)) {
      const entry = this.cache.get(key);
      entry.value = value; entry.ttl = Math.max(1, ttl | 0); entry.timestamp = now;
      this._unlink(entry); this._pushFront(entry);
      return;
    }
    if (this.cache.size >= this.maxSize) { this._evictTail(); }
    const newNode = { key, value, ttl: Math.max(1, ttl | 0), timestamp: now, prev: null, next: null };
    this._pushFront(newNode);
    this.cache.set(key, newNode);
  }
  _cleanupExpiredEntries(limit = 100) {
    const now = Date.now(); let cleaned = 0;
    for (const [key, entry] of this.cache) {
      if ((now - entry.timestamp) > entry.ttl) {
        this._unlink(entry);
        this.cache.delete(key);
        if (++cleaned >= limit) break;
      }
    }
  }
  clear() { this.cache.clear(); this.head.next = this.tail; this.tail.prev = this.head; }
  delete(key) {
    const entry = this.cache.get(key);
    if (!entry) return false;
    this._unlink(entry); this.cache.delete(key); return true;
  }
}

/* ===================== 滚动统计 & 成功率追踪 ===================== */
class RollingStats {
  constructor(windowSize = 100) {
    this.windowSize = Math.max(1, windowSize | 0);
    this.data = new Array(this.windowSize).fill(0);
    this.index = 0; this.count = 0; this.sum = 0;
  }
  add(value) {
    const v = Number(value) || 0;
    if (this.count < this.windowSize) { this.data[this.index] = v; this.sum += v; this.count++; }
    else { const prev = this.data[this.index] || 0; this.data[this.index] = v; this.sum += v - prev; }
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

/* ===================== 工具函数（统一并发/重试） ===================== */
const Utils = {
  sleep(ms = 0) { return new Promise(r => setTimeout(r, Math.max(0, ms | 0))); },
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
      while (true) {
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
    const runners = Array(Math.min(validLimit, tasks.length)).fill(0).map(() => next());
    await Promise.all(runners);
    return results;
  },
  async asyncPool(tasks, concurrency = CONSTANTS.CONCURRENCY_LIMIT) {
    if (!Array.isArray(tasks) || tasks.length === 0) return [];
    const validConcurrency = Math.max(1, Math.min(50, Math.floor(concurrency) || CONSTANTS.CONCURRENCY_LIMIT || 3));
    const results = await Utils.runWithConcurrency(tasks, validConcurrency);
    return results.map(r => r && r.status === "fulfilled" ? r.value : { __error: (r && r.reason) || new Error("任务执行失败") });
  },
  calculateWeightedAverage(values, weightFactor = 0.9) {
    if (!Array.isArray(values) || values.length === 0) return 0;
    let sum = 0, weightSum = 0;
    values.forEach((val, idx) => {
      const weight = Math.pow(weightFactor, values.length - idx - 1);
      sum += val * weight; weightSum += weight;
    });
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
    for (let i = 0; i < n; i++) {
      const w = (i + 1) / n; const x = i; const y = values[i];
      sumW += w; sumX += x * w; sumY += y * w; sumXY += x * y * w; sumX2 += x * x * w;
    }
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
  },
  filterProxiesByRegion(proxies, region) {
    if (!Array.isArray(proxies) || !region || !region.regex) return [];
    return proxies
      .filter(p => {
        if (!p || typeof p.name !== "string") return false;
        const m = p.name.match(/(?:[xX✕✖⨉]|倍率)(\d+\.?\d*)/i);
        const mult = m ? parseFloat(m[1]) : 0;
        return p.name.match(region.regex) && mult <= Config.regionOptions.ratioLimit;
      })
      .map(p => p.name);
  },
  createServiceGroups(config, regionGroupNames, ruleProviders, rules) {
    if (!config || !Array.isArray(regionGroupNames) || !(ruleProviders instanceof Map) || !Array.isArray(rules)) return;
    Config.services.forEach(service => {
      if (!Config.ruleOptions[service.id]) return;
      if (Array.isArray(service.rule)) rules.push(...service.rule);
      if (service.ruleProvider) {
        ruleProviders.set(service.ruleProvider.name, {
          ...Config.common.ruleProvider,
          behavior: service.ruleProvider.behavior || "classical",
          format: service.ruleProvider.format || "text",
          url: service.ruleProvider.url,
          path: `./ruleset/${service.ruleProvider.name.split('-')[0]}/${service.ruleProvider.name}.${service.ruleProvider.format || 'list'}`
        });
      }
      const proxies = service.proxies || ["默认节点", ...(service.proxiesOrder || []), ...regionGroupNames, "直连"];
      config["proxy-groups"].push({
        ...Config.common.proxyGroup,
        name: service.name,
        type: "select",
        proxies,
        url: service.url || Config.common.proxyGroup.url,
        icon: service.icon
      });
    });
  }
};

/* ===================== 节点管理器（旁路冷却统一） ===================== */
class NodeManager extends EventEmitter {
  static getInstance() { if (!NodeManager.instance) NodeManager.instance = new NodeManager(); return NodeManager.instance; }
  constructor() {
    super();
    this.currentNode = null;
    this.nodeQuality = new Map();
    this.switchCooldown = new Map();
    this.nodeHistory = new Map();
    this.nodeSuccess = new Map();
  }
  isInCooldown(nodeId) { const end = this.switchCooldown.get(nodeId); return !!(end && Date.now() < end); }
  _getCooldownTime(nodeId) {
    const score = Math.max(0, Math.min(100, this.nodeQuality.get(nodeId) || 0));
    return Math.max(CONSTANTS.MIN_SWITCH_COOLDOWN, Math.min(CONSTANTS.MAX_SWITCH_COOLDOWN, CONSTANTS.BASE_SWITCH_COOLDOWN * (1 + score / 100)));
  }
  _recordSwitchEvent(oldNodeId, newNodeId, targetGeo) {
    const event = {
      timestamp: Date.now(),
      oldNodeId, newNodeId,
      targetGeo: targetGeo ? { country: targetGeo.country, region: targetGeo.regionName || targetGeo.region } : null,
      reason: oldNodeId ? "质量过低" : "初始选择"
    };
    Logger.debug("SwitchEvent", event);
  }
  _updateNodeHistory(nodeId, score) {
    const s = Math.max(0, Math.min(100, Number(score) || 0));
    const history = this.nodeHistory.get(nodeId) || [];
    history.push({ timestamp: Date.now(), score: s });
    this.nodeHistory.set(nodeId, history.length > CONSTANTS.MAX_HISTORY_RECORDS ? history.slice(-CONSTANTS.MAX_HISTORY_RECORDS) : history);
  }
  updateNodeQuality(nodeId, scoreDelta) {
    const delta = Number(scoreDelta) || 0;
    const current = this.nodeQuality.get(nodeId) || 0;
    const newScore = Math.max(0, Math.min(100, current + Math.max(-20, Math.min(20, delta))));
    this.nodeQuality.set(nodeId, newScore);
    this._updateNodeHistory(nodeId, newScore);
  }
  async switchToNode(nodeId, targetGeo) {
    if (!nodeId || typeof nodeId !== "string") { Logger.warn("switchToNode: 无效的节点ID"); return null; }
    if (this.currentNode === nodeId) return { id: nodeId };
    const central = CentralManager.getInstance?.() || null;
    const node = central?.state?.config?.proxies?.find(n => n && n.id === nodeId) || null;
    if (!node) { Logger.warn(`尝试切换到不存在的节点: ${nodeId}`); return null; }
    const oldNodeId = this.currentNode;
    this.currentNode = nodeId;
    this.switchCooldown.set(nodeId, Date.now() + this._getCooldownTime(nodeId));
    this._recordSwitchEvent(oldNodeId, nodeId, targetGeo);
    const nodeStatus = central.state.nodes?.get(nodeId);
    const nodeRegion = nodeStatus?.geoInfo?.regionName || "未知区域";
    Logger.info(`节点已切换: ${oldNodeId || "无"} -> ${nodeId} (区域: ${nodeRegion})`);
    return node;
  }
  _selectBestPerformanceNode(nodes) {
    if (!Array.isArray(nodes) || nodes.length === 0) { Logger.warn("_selectBestPerformanceNode: 节点列表为空"); return null; }
    const central = CentralManager.getInstance?.() || null;
    const scoreFor = (node) => {
      if (!node || !node.id) return 0;
      const quality = this.nodeQuality.get(node.id) || 0;
      const nodeState = (central?.state?.nodes?.get(node.id)) || {};
      const metrics = nodeState.metrics || {};
      const availabilityRate = Number(nodeState.availabilityRate) || 0;
      const availabilityPenalty = availabilityRate < CONSTANTS.AVAILABILITY_MIN_RATE ? -30 : 0;

      const latencyVal = Math.max(0, Math.min(CONSTANTS.LATENCY_CLAMP_MS, Number(metrics.latency) || 1000));
      const jitterVal = Math.max(0, Math.min(CONSTANTS.JITTER_CLAMP_MS, Number(metrics.jitter) || 100));
      const lossVal = Math.max(0, Math.min(CONSTANTS.LOSS_CLAMP, Number(metrics.loss) || 0));
      const bps = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, Number(metrics.bps) || 0));

      const latencyScore = Math.max(0, Math.min(35, 35 - latencyVal / 25));
      const jitterScore  = Math.max(0, Math.min(25, 25 - jitterVal));
      const lossScore    = Math.max(0, Math.min(25, 25 * (1 - lossVal)));
      const throughputScore = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SCORE_MAX, Math.round(Math.log10(1 + bps) * 2)));
      const metricScore = Math.round(latencyScore + jitterScore + lossScore + throughputScore);

      const tracker = this.nodeSuccess.get(node.id);
      const successRatePercent = tracker && typeof tracker.rate === "number" ? Math.max(0, Math.min(100, tracker.rate * 100)) : 0;

      const qw = Math.max(0, Math.min(1, CONSTANTS.QUALITY_WEIGHT));
      const mw = Math.max(0, Math.min(1, CONSTANTS.METRIC_WEIGHT));
      const sw = Math.max(0, Math.min(1, CONSTANTS.SUCCESS_WEIGHT));
      const tw = qw + mw + sw || 1;

      const composite = (
        (quality * (qw / tw)) +
        (metricScore * (mw / tw)) +
        (successRatePercent * (sw / tw)) +
        availabilityPenalty
      );
      return Math.max(0, Math.min(100, composite));
    };

    let best = nodes[0]; if (!best) return null;
    let bestVal = scoreFor(best);
    for (let i = 1; i < nodes.length; i++) {
      const n = nodes[i]; if (!n) continue;
      const val = scoreFor(n);
      if (val > bestVal) { best = n; bestVal = val; }
    }
    return best;
  }
  async getBestNode(nodes, targetGeo) {
    if (!Array.isArray(nodes) || nodes.length === 0) { Logger.warn("getBestNode: 节点列表为空或无效"); return null; }
    const availableNodes = nodes.filter(node => node && node.id && !this.isInCooldown(node.id));
    const pool = availableNodes.length > 0 ? availableNodes : nodes;
    if (targetGeo && typeof targetGeo.regionName === "string") {
      const central = CentralManager.getInstance?.() || null;
      if (central?.state?.nodes) {
        const regionalNodes = pool.filter(node => {
          const ns = central.state.nodes.get(node.id);
          return ns?.geoInfo?.regionName === targetGeo.regionName;
        });
        if (regionalNodes.length > 0) return this._selectBestPerformanceNode(regionalNodes) || pool[0];
      }
    }
    return this._selectBestPerformanceNode(pool) || pool[0];
  }
  async switchToBestNode(nodes, targetGeo) {
    if (!nodes || nodes.length === 0) return null;
    const bestNode = await this.getBestNode(nodes, targetGeo);
    if (!bestNode) return null;
    const oldNodeId = this.currentNode;
    this.currentNode = bestNode.id;
    this.switchCooldown.set(bestNode.id, Date.now() + this._getCooldownTime(bestNode.id));
    this._recordSwitchEvent(oldNodeId, bestNode.id, targetGeo);
    const nodeStatus = CentralManager.getInstance().state.nodes.get(bestNode.id);
    const nodeRegion = nodeStatus?.geoInfo?.regionName || "未知区域";
    Logger.info(`节点已切换: ${oldNodeId || "无"} -> ${bestNode.id} (质量分: ${this.nodeQuality.get(bestNode.id)}, 区域: ${nodeRegion})`);
    return bestNode;
  }
}

/* ===================== 中央管理器（跨平台 fetch 加固 + 镜像动态前缀） ===================== */
class CentralManager extends EventEmitter {
  static getInstance() { if (!CentralManager.instance) CentralManager.instance = new CentralManager(); return CentralManager.instance; }
  constructor() {
    super();
    if (CentralManager.instance) return CentralManager.instance;
    this.state = new AppState();
    this.stats = new RollingStats();
    this.successTracker = new SuccessRateTracker();
    this.nodeManager = NodeManager.getInstance();
    this.lruCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.eventListeners = null;

    this.metricsManager = new MetricsManager(this.state);
    this.availabilityTracker = new AvailabilityTracker(this.state, this.nodeManager);
    this.throughputEstimator = new ThroughputEstimator();

    CentralManager.instance = this;

    Promise.resolve().then(() => {
      this.initialize().catch(err => Logger.error("CentralManager 初始化失败:", err && err.stack ? err.stack : err));
    }).catch(err => Logger.error("CentralManager 初始化调度失败:", err && err.stack ? err.stack : err));
  }

  async _getFetchRuntime() {
    let _fetch = (typeof fetch === "function") ? fetch : null;
    let _AbortController = (typeof AbortController !== "undefined") ? AbortController : null;
    if (!_fetch && PLATFORM.isNode) {
      try { const nf = require("node-fetch"); _fetch = nf.default || nf; } catch {}
      if (!_AbortController) {
        try { const AC = require("abort-controller"); _AbortController = AC.default || AC; } catch {
          if (typeof AbortController !== "undefined") _AbortController = AbortController;
        }
      }
    }
    return { _fetch, _AbortController };
  }

  async _safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
    if (!url || typeof url !== "string") throw new Error("_safeFetch: 无效的URL参数");
    if (timeout && (typeof timeout !== "number" || timeout <= 0)) timeout = CONSTANTS.GEO_INFO_TIMEOUT;

    const { _fetch, _AbortController } = await this._getFetchRuntime();
    if (!_fetch) throw new Error("fetch 不可用于当前运行环境，且未找到可回退的实现");

    // 动态更新镜像前缀（仅在 GH 资源路径时）
    if (url.startsWith("https://raw.githubusercontent.com/") || url.startsWith("https://github.com/")) {
      try {
        const best = await selectBestMirror(_fetch);
        GH_PROXY_PREFIX = best || "";
        if (url.startsWith("https://raw.githubusercontent.com/")) url = `${GH_PROXY_PREFIX}${url}`;
        else if (url.startsWith("https://github.com/")) url = `${GH_PROXY_PREFIX}${url}`;
      } catch {}
    }

    const defaultOptions = { headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT, ...(options.headers || {}) }, ...options };

    // Abort + 超时
    if (_AbortController && timeout > 0) {
      const controller = new _AbortController();
      defaultOptions.signal = controller.signal;
      const tid = setTimeout(() => { try { controller.abort(); } catch {} }, timeout);
      try {
        const resp = await _fetch(url, defaultOptions); clearTimeout(tid); return resp;
      } catch (err) {
        clearTimeout(tid);
        if (err.name === "AbortError" || err.name === "TimeoutError") throw new Error(`请求超时 (${timeout}ms): ${url}`);
        throw err;
      }
    }
    if (timeout > 0) {
      const fp = _fetch(url, defaultOptions);
      const tp = new Promise((_, reject) => setTimeout(() => reject(new Error(`请求超时 (${timeout}ms): ${url}`)), timeout));
      return Promise.race([fp, tp]);
    }
    return _fetch(url, defaultOptions);
  }

  async initialize() {
    await this.loadAIDBFromFile().catch(err => Logger.warn("加载AI数据失败，使用默认值:", err && err.message ? err.message : err));

    if (!this.eventListeners) {
      try { this.setupEventListeners(); } catch (e) { Logger.warn("设置事件监听器失败:", e && e.message ? e.message : e); }
    }

    this.on("requestDetected", (targetIp) => {
      this.handleRequestWithGeoRouting(targetIp).catch(err => Logger.warn("地理路由处理失败:", err && err.message ? err.message : err));
    });

    this.preheatNodes().catch(err => Logger.warn("节点预热失败:", err && err.message ? err.message : err));

    try {
      if (PLATFORM.isNode && process.on) {
        const cleanup = () => { this.destroy().catch(err => Logger.error("清理资源失败:", err && err.message ? err.message : err)); };
        process.on("SIGINT", cleanup); process.on("SIGTERM", cleanup);
      } else if (PLATFORM.isBrowser) {
        window.addEventListener("beforeunload", () => {
          this.destroy().catch(err => Logger.error("清理资源失败:", err && err.message ? err.message : err));
        });
      }
    } catch (e) { Logger.warn("注册清理函数失败:", e && e.message ? e.message : e); }

    Logger.info("CentralManager 初始化完成");
  }

  async destroy() {
    Logger.info("开始清理资源...");
    try { this.cleanupEventListeners(); } catch (e) { Logger.warn("清理事件监听器失败:", e && e.message ? e.message : e); }
    try { await this.saveAIDBToFile(); } catch (e) { Logger.warn("保存AI数据失败:", e && e.message ? e.message : e); }
    try { this.lruCache?.clear(); } catch (e) { Logger.warn("清理LRU缓存失败:", e && e.message ? e.message : e); }
    try { this.geoInfoCache?.clear(); } catch (e) { Logger.warn("清理地理信息缓存失败:", e && e.message ? e.message : e); }
    Logger.info("资源清理完成");
  }

  setupEventListeners() {
    this.eventListeners = {
      configChanged: async () => this.onConfigChanged(),
      networkOnline: async () => this.onNetworkOnline(),
      performanceThresholdBreached: async (nodeId) => this.onPerformanceThresholdBreached(nodeId),
      evaluationCompleted: () => this.onEvaluationCompleted()
    };
    if (typeof Config !== "undefined" && Config.on) { Config.on("configChanged", this.eventListeners.configChanged); }
    if (PLATFORM.isBrowser) { window.addEventListener("online", this.eventListeners.networkOnline); }
    if (this.nodeManager?.on) { this.nodeManager.on("performanceThresholdBreached", this.eventListeners.performanceThresholdBreached); }
    this.on("evaluationCompleted", this.eventListeners.evaluationCompleted);
  }
  cleanupEventListeners() {
    if (!this.eventListeners) return;
    if (typeof Config !== "undefined" && Config.off) { try { Config.off("configChanged", this.eventListeners.configChanged); } catch {} }
    if (PLATFORM.isBrowser && window.removeEventListener) { try { window.removeEventListener("online", this.eventListeners.networkOnline); } catch {} }
    if (this.nodeManager?.off) { try { this.nodeManager.off("performanceThresholdBreached", this.eventListeners.performanceThresholdBreached); } catch {} }
    try { this.off("evaluationCompleted", this.eventListeners.evaluationCompleted); } catch {}
    this.eventListeners = null;
  }

  onNodeUpdate(id, status) { this.nodeManager.updateNodeQuality(id, status.score || 0); }
  async onConfigChanged() { Logger.info("配置变更，触发节点评估..."); await this.evaluateAllNodes(); }
  async onNetworkOnline() { Logger.info("网络恢复，触发节点评估..."); await this.evaluateAllNodes(); }
  async onPerformanceThresholdBreached(nodeId) {
    Logger.info(`节点 ${nodeId} 性能阈值突破，触发单节点评估...`);
    const node = this.state.config.proxies?.find(n => n.id === nodeId);
    if (node) await this.evaluateNodeQuality(node);
    else Logger.warn(`节点 ${nodeId} 不存在，无法评估`);
  }
  onEvaluationCompleted() { Logger.info("节点评估完成，触发数据保存和节点清理..."); this.saveAIDBToFile(); this.autoEliminateNodes(); }

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
    results.forEach((r, idx) => {
      if (r && r.__error) { const node = proxies[idx]; Logger.warn(`节点评估失败: ${node?.id}`, r.__error?.message || r.__error); }
    });
    this.emit("evaluationCompleted");
  }

  async evaluateNodeQuality(node) {
    if (!node || !node.id || typeof node.id !== "string") { Logger.warn("evaluateNodeQuality: 无效的节点对象"); return; }
    let metrics = null;
    try { metrics = await Utils.retry(() => this.testNodeMultiMetrics(node), CONSTANTS.MAX_RETRY_ATTEMPTS, CONSTANTS.RETRY_DELAY_BASE); }
    catch {
      Logger.warn(`节点探测多次失败，使用回退模拟: ${node.id}`);
      try { metrics = await this.testNodeMultiMetrics(node); }
      catch { Logger.error(`节点回退测试也失败: ${node.id}`); metrics = { latency: CONSTANTS.NODE_TEST_TIMEOUT, loss: 1, jitter: 100, bytes: 0, bps: 0, __simulated: true }; }
    }

    if (typeof metrics.bps !== "number") metrics.bps = this.throughputEstimator.bpsFromBytesLatency(metrics);

    this.availabilityTracker.ensure(node.id);
    const isSimulated = metrics && metrics.__simulated === true;
    const latency = Math.max(0, Number(metrics?.latency) || 0);
    const timeoutThreshold = (CONSTANTS.NODE_TEST_TIMEOUT || 5000) * 2;

    const hardFail = !!metrics.__hardFail;
    const success = !!(metrics && !isSimulated && latency > 0 && latency < timeoutThreshold && !hardFail);
    this.availabilityTracker.record(node.id, success, { hardFail });

    let score = 0;
    try { score = Math.max(0, Math.min(100, this.calculateNodeQualityScore(metrics))); } catch (e) { Logger.error(`计算节点质量分失败 (${node.id}):`, e.message); score = 0; }

    let geoInfo = null;
    try {
      const nodeIp = (node.server && typeof node.server === "string") ? node.server.split(":")[0] : null;
      if (nodeIp && /^(\d{1,3}\.){3}\d{1,3}$/.test(nodeIp)) { geoInfo = await this.getGeoInfo(nodeIp); }
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
          if (failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS) { this.nodeManager.switchCooldown.delete(node.id); }
          await this.nodeManager.switchToBestNode(proxies);
        }
      }
    } catch (e) { Logger.warn(`节点切换失败 (${node.id}):`, e.message); }
  }

  async handleRequestWithGeoRouting(targetIp) {
    if (!targetIp || !this.state.config.proxies || this.state.config.proxies.length === 0) { Logger.warn("无法进行地理路由: 缺少目标IP或代理节点"); return; }
    const targetGeo = await this.getGeoInfo(targetIp);
    if (!targetGeo) {
      Logger.warn("无法获取目标IP地理信息，使用默认路由");
      await this.nodeManager.switchToBestNode(this.state.config.proxies);
      return;
    }
    await this.nodeManager.switchToBestNode(this.state.config.proxies, targetGeo);
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

  async onRequestOutbound(reqCtx = {}) {
    if (!this.state || !this.state.config) throw new ConfigurationError("系统配置未初始化");
    const nodes = this.state.config.proxies || [];
    if (!Array.isArray(nodes) || nodes.length === 0) return { mode: "direct" };

    const urlStr = typeof reqCtx.url === "string" ? reqCtx.url : (reqCtx.url?.toString?.() || "");
    let hostname = reqCtx.host;
    let port = reqCtx.port;
    let protocol = reqCtx.protocol;
    try {
      if (urlStr) {
        const u = new URL(urlStr);
        hostname = hostname || u.hostname;
        protocol = protocol || (u.protocol || "").replace(":", "").toLowerCase();
        port = port || (u.port ? Number(u.port) : (protocol === "https" ? 443 : protocol === "http" ? 80 : undefined));
      }
    } catch {}

    const clientIP = reqCtx.clientIP || reqCtx.headers?.["X-Forwarded-For"] || reqCtx.headers?.["Remote-Address"];
    const clientGeo = clientIP ? await this.getGeoInfo(clientIP) : null;

    let targetGeo = null;
    try {
      if (hostname) {
        const targetIP = await this.resolveDomainToIP(hostname);
        if (targetIP) targetGeo = await this.getGeoInfo(targetIP);
      }
    } catch {}

    const isVideo = !!(reqCtx.headers?.["Content-Type"]?.includes("video") || CONSTANTS.STREAM_HINT_REGEX.test(urlStr));
    const isAI = CONSTANTS.AI_HINT_REGEX.test(urlStr || hostname || "");
    const isLarge = (Number(reqCtx.contentLength) || 0) >= CONSTANTS.LARGE_PAYLOAD_THRESHOLD_BYTES;
    const isGaming = CONSTANTS.GAMING_PORTS.includes(Number(port));
    const isTLS = (protocol === "https" || CONSTANTS.TLS_PORTS.includes(Number(port)));
    const isHTTP = (protocol === "http" || CONSTANTS.HTTP_PORTS.includes(Number(port)));
    const preferHighThroughput = isVideo || isLarge;
    const preferLowLatency = isGaming || isAI || isTLS;
    const preferStability = isAI || isVideo;

    const enrichedCandidates = nodes
      .map(n => {
        const status = this.state.nodes.get(n.id);
        const m = status?.metrics || {};
        return {
          node: n,
          score: status?.score || 0,
          availability: status?.availabilityRate || 0,
          latency: Number(m.latency) || Infinity,
          bps: Number(m.bps) || 0,
          jitter: Number(m.jitter) || 0
        };
      })
      .filter(c => c.node && c.node.id);

    const bias = (c) => {
      const base = c.score;
      const availabilityBonus = (c.availability >= CONSTANTS.AVAILABILITY_MIN_RATE) ? 10 : -30;
      const throughputBonus = preferHighThroughput ? Math.min(10, Math.round(Math.log10(1 + c.bps) * 2)) : 0;
      const latencyBonus = preferLowLatency ? Math.max(0, Math.min(15, 15 - (c.latency / 30))) : 0;
      const jitterPenalty = preferStability ? Math.min(10, Math.round(c.jitter / 50)) : 0;
      return base + availabilityBonus + throughputBonus + latencyBonus - jitterPenalty;
    };

    let regionPreferred = null;
    if (targetGeo?.country && Array.isArray(Config.regionOptions?.regions)) {
      regionPreferred = Utils.filterProxiesByRegion(nodes, Config.regionOptions.regions.find(r => {
        return r && ((r.name && r.name.includes(targetGeo.country)) || (r.regex && r.regex.test(targetGeo.country)));
      }) || {});
    }

    let candidates = enrichedCandidates;
    if (regionPreferred && regionPreferred.length > 0) {
      const preferredSet = new Set(regionPreferred);
      const regionCandidates = candidates.filter(c => preferredSet.has(c.node.name));
      if (regionCandidates.length > 0) candidates = regionCandidates;
    }

    const ordered = candidates.sort((a, b) => bias(b) - bias(a)).map(c => c.node);
    const bestNode = await this.nodeManager.getBestNode(ordered.length ? ordered : nodes, targetGeo);
    const selected = bestNode || nodes[0];

    const userStr = typeof reqCtx.user === "string" ? reqCtx.user : "default";
    const country = (clientGeo && clientGeo.country) ? clientGeo.country : "unknown";
    const cacheKey = `${userStr}:${country}:${hostname || "unknown"}`;
    try { if (selected?.id) this.lruCache.set(cacheKey, selected.id); } catch {}

    if (!selected) return { mode: "direct" };
    return { mode: "proxy", node: selected, targetGeo, clientGeo, reason: { preferHighThroughput, preferLowLatency, preferStability, isVideo, isAI, isLarge, isGaming, isTLS, isHTTP } };
  }

  async onResponseInbound(resCtx = {}) {
    const node = resCtx.node;
    if (!node || !node.id) return;

    const result = { success: !!resCtx.success, latency: Number(resCtx.latency) || 0, bytes: Number(resCtx.bytes) || 0 };
    const req = { url: resCtx.url, method: resCtx.method, headers: resCtx.headers };

    this.recordRequestMetrics(node, result, req);

    const status = this.state.nodes.get(node.id) || {};
    const availRate = Number(status.availabilityRate) || 0;
    const failStreak = this.availabilityTracker.hardFailStreak(node.id);
    const proxies = this.state?.config?.proxies || [];

    const isTooSlow = result.latency > CONSTANTS.LATENCY_CLAMP_MS;
    const belowAvail = availRate < CONSTANTS.AVAILABILITY_MIN_RATE;

    if (proxies.length > 0 && (failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS || belowAvail || isTooSlow)) {
      if (failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS) { this.nodeManager.switchCooldown.delete(node.id); }
      await this.nodeManager.switchToBestNode(proxies);
    }
  }

  async handleProxyRequest(req, ...args) {
    if (!this.state || !this.state.config) throw new ConfigurationError("系统配置未初始化");
    if (!req || !req.url) throw new InvalidRequestError("无效的请求对象或URL");

    try {
      const dispatch = await this.onRequestOutbound({
        url: req.url, method: req.method, headers: req.headers, user: req.user,
        protocol: req.protocol, port: req.port, host: req.hostname || req.host,
        contentLength: req.contentLength, clientIP: req.headers?.["X-Forwarded-For"] || req.headers?.["Remote-Address"]
      });

      if (dispatch.mode === "direct") return this.proxyToDirect(...args);

      const current = dispatch.node || (await this.nodeManager.switchToBestNode(this.state.config.proxies, dispatch.targetGeo));
      const result = await this.proxyRequestWithNode(current, ...args);

      await this.onResponseInbound({
        node: current, success: result.success, latency: result.latency, bytes: result.bytes,
        url: req.url, method: req.method, status: result.status, headers: result.headers
      });

      return result;
    } catch (error) {
      Logger.error("代理请求处理失败:", error.stack || error);
      return this.proxyToDirect(...args);
    }
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
          const testTasks = candidates.slice(0, limit * 2).map(node =>
            () => Utils.retry(() => this.testNodeMultiMetrics(node), CONSTANTS.MAX_RETRY_ATTEMPTS, CONSTANTS.RETRY_DELAY_BASE)
          );
          await Utils.asyncPool(testTasks, limit);
          this.emit("batchCompleted", { batchIndex: 0 });

          Logger.info(`筛选出 ${candidates.length} 个符合质量要求的节点`);
          const best = await this.nodeManager.getBestNode(candidates);
          if (best) { try { if (this.lruCache && best.id) this.lruCache.set(cacheKey, best.id); } catch (e) { Logger.debug("缓存节点选择结果失败:", e.message); } return best; }
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
            const regionNodes = Utils.filterProxiesByRegion(nodes, targetRegion);
            if (regionNodes && regionNodes.length > 0) {
              const candidates = nodes.filter(n => n && n.name && regionNodes.includes(n.name));
              if (candidates.length > 0) {
                const bestRegionNode = await this.nodeManager.getBestNode(candidates);
                if (bestRegionNode) { try { if (this.lruCache && bestRegionNode.id) this.lruCache.set(cacheKey, bestRegionNode.id); } catch (e) { Logger.debug("缓存区域节点选择结果失败:", e.message); } return bestRegionNode; }
              }
            }
          }
        }
      } catch (error) { Logger.warn("区域节点选择失败，使用默认策略:", error.message); }
    }

    const bestNode = await this.nodeManager.getBestNode(nodes);
    if (!bestNode) { Logger.warn("无法选择最佳节点，返回第一个可用节点"); return nodes[0] || null; }
    try { if (this.lruCache && bestNode.id) this.lruCache.set(cacheKey, bestNode.id); } catch (e) { Logger.debug("缓存默认节点选择结果失败:", e.message); }
    return bestNode;
  }

  async getGeoInfo(ip, domain) {
    if (!this.geoInfoCache) { Logger.error("地理信息缓存未初始化，使用默认配置"); this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL }); }
    if (!ip) { Logger.warn("获取地理信息失败: IP地址为空"); return this._getFallbackGeoInfo(domain); }
    if (ip === "127.0.0.1" || ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.")) { return { country: "Local", region: "Local" }; }
    const cached = this.geoInfoCache.get(ip); if (cached) { Logger.debug(`使用缓存的地理信息: ${ip} -> ${cached.country}`); return cached; }

    try {
      const primary = await this._fetchGeoFromPrimaryAPI(ip);
      if (primary) { this.geoInfoCache.set(ip, primary); return primary; }
      const fallback = await this._fetchGeoFromFallbackAPI(ip);
      if (fallback) { this.geoInfoCache.set(ip, fallback); return fallback; }

      Logger.warn(`所有地理信息API调用失败，使用降级策略: ${ip}`);
      const downgraded = this._getFallbackGeoInfo(domain);
      this.geoInfoCache.set(ip, downgraded, CONSTANTS.GEO_FALLBACK_TTL);
      return downgraded;
    } catch (error) {
      Logger.error(`获取地理信息失败: ${error.message}`, error.stack);
      return this._getFallbackGeoInfo(domain);
    }
  }

  async getIpGeolocation(ip) { return this.getGeoInfo(ip); }

  async _fetchGeoFromPrimaryAPI(ip) {
    if (!ip || typeof ip !== "string") { Logger.error("无效的IP地址:", ip); return null; }
    try {
      const resp = await this._safeFetch(`https://ipapi.co/${ip}/json/`, { headers: { "User-Agent": "Mozilla/5.0" } }, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
      const data = await resp.json();
      if (data.country_name) return { country: data.country_name, region: data.region || data.city || "Unknown" };
      Logger.warn(`主API返回无效数据: ${JSON.stringify(data)}`); return null;
    } catch (error) { Logger.warn(`主API调用失败: ${error.message}`); return null; }
  }

  async _fetchGeoFromFallbackAPI(ip) {
    try {
      const resp = await this._safeFetch(`https://ipinfo.io/${ip}/json`, {}, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
      const data = await resp.json();
      if (data.country) return { country: data.country, region: data.region || data.city || "Unknown" };
      Logger.warn(`备用API返回无效数据: ${JSON.stringify(data)}`); return null;
    } catch (error) { Logger.warn(`备用API调用失败: ${error.message}`); return null; }
  }

  _getFallbackGeoInfo(domain) {
    if (domain && typeof domain === "string" && /^[a-zA-Z0-9.-]+$/.test(domain)) {
      const tld = domain.split(".").pop().toLowerCase();
      const map = { cn: "China", hk: "Hong Kong", tw: "Taiwan", jp: "Japan", kr: "Korea", us: "United States", uk: "United Kingdom", de: "Germany", fr: "France", ca: "Canada", au: "Australia" };
      if (map[tld]) { Logger.debug(`基于域名推断地理信息: ${domain} -> ${map[tld]}`); return { country: map[tld], region: "Unknown" }; }
    }
    return { country: "Unknown", region: "Unknown" };
  }

  async resolveDomainToIP(domain) {
    if (!domain || typeof domain !== "string") { Logger.error("无效的域名参数"); return null; }
    if (!/^[a-zA-Z0-9.-]+$/.test(domain)) { Logger.error(`无效的域名格式: ${domain}`); return null; }

    const cacheKey = `dns:${domain}`;
    const cachedIP = this.lruCache.get(cacheKey); if (cachedIP) return cachedIP;

    const dohList = [
      "https://1.1.1.1/dns-query",
      "https://8.8.8.8/dns-query",
      "https://9.9.9.9/dns-query"
    ];
    try {
      const queries = dohList.map(doh => this._safeFetch(`${doh}?name=${encodeURIComponent(domain)}&type=A`, { headers: { "Accept": "application/dns-json", "User-Agent": "Mozilla/5.0" } }, CONSTANTS.GEO_INFO_TIMEOUT));
      const resp = await Promise.any(queries).catch(() => null);
      if (!resp) return null;
      const data = await resp.json().catch(() => ({}));
      if (data.Answer && data.Answer.length > 0) {
        const ip = data.Answer[0].data;
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) { this.lruCache.set(cacheKey, ip, 600000); return ip; }
      }
      return null;
    } catch (error) {
      if (error.name !== "AbortError") Logger.error(`域名解析失败: ${error.message}`);
      return null;
    }
  }

  async proxyRequestWithNode(node, ...args) {
    if (!node || typeof node !== "object") throw new InvalidRequestError("代理请求失败: 无效的节点信息");
    if (!node.id || !(node.server || node.proxyUrl)) throw new InvalidRequestError(
      `代理请求失败: 节点缺少必要属性 (id: ${node && node.id}, server: ${node && node.server}, proxyUrl: ${node && node.proxyUrl})`
    );
    try {
      const start = Date.now();
      const fetchOptions = (args && args.length && typeof args[0] === "object") ? args[0] : {};
      const response = await this._safeFetch(node.proxyUrl, fetchOptions, CONSTANTS.NODE_TEST_TIMEOUT);
      const latency = Date.now() - start;
      let bytes = 0;
      try { const len = response.headers?.get?.("Content-Length"); bytes = parseInt(len || "0", 10); } catch {}
      return { success: true, latency, bytes, status: response.status, headers: response.headers };
    } catch (error) {
      Logger.error(`代理请求失败 [${node.id}]: ${error?.message || error}`);
      this.availabilityTracker.record(node.id, false, { hardFail: true });
      return { success: false, error: error?.message || String(error), latency: CONSTANTS.NODE_TEST_TIMEOUT };
    }
  }

  proxyToDirect(...args) { return { success: true, direct: true }; }

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

    const features = this.extractNodeFeatures(node, metrics, recentMetrics, nodeHistory);
    const prediction = this.predictNodeFuturePerformance(features);
    const adjustment = this.calculateScoreAdjustment(prediction, metrics.success);

    if (CONSTANTS.ENABLE_SCORE_DEBUGGING && Math.abs(adjustment) > 3) {
      Logger.debug(`Node ${node.id} score components:`, { risk: prediction.risk, latency: features.currentLatency, loss: features.currentLoss, adjustment });
    }
    return adjustment;
  }

  extractNodeFeatures(node, currentMetrics, recentMetrics, history) {
    const latencies = Array.isArray(recentMetrics) ? recentMetrics.map(m => Number(m.latency)).filter(Number.isFinite) : [];
    const losses    = Array.isArray(recentMetrics) ? recentMetrics.map(m => Number(m.loss)).filter(Number.isFinite) : [];
    const jitters   = Array.isArray(recentMetrics) ? recentMetrics.map(m => Number(m.jitter)).filter(Number.isFinite) : [];
    const successes = Array.isArray(recentMetrics) ? recentMetrics.map(m => m.success ? 1 : 0) : [];
    const bpsArr    = Array.isArray(recentMetrics) ? recentMetrics.map(m => Number(m.bps) || 0).filter(Number.isFinite) : [];

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
    return {
      risk,
      expectedLatency: features.weightedLatency + features.latencyTrend * 5,
      expectedStability: 1 - risk,
      stabilityScore,
      confidence: Math.min(1, features.sampleSize / CONSTANTS.FEATURE_WINDOW_SIZE)
    };
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
}

/* 资源（图标/规则/Geo 数据）统一前缀常量 */
const ICONS = {
  Proxy: GH_RAW("Koolson/Qure/master/IconSet/Color/Proxy.png"),
  WorldMap: GH_RAW("Koolson/Qure/master/IconSet/Color/World_Map.png"),
  HongKong: GH_RAW("Koolson/Qure/master/IconSet/Color/Hong_Kong.png"),
  UnitedStates: GH_RAW("Koolson/Qure/master/IconSet/Color/United_States.png"),
  Japan: GH_RAW("Koolson/Qure/master/IconSet/Color/Japan.png"),
  Korea: GH_RAW("Koolson/Qure/master/IconSet/Color/Korea.png"),
  Singapore: GH_RAW("Koolson/Qure/master/IconSet/Color/Singapore.png"),
  ChinaMap: GH_RAW("Koolson/Qure/master/IconSet/Color/China_Map.png"),
  China: GH_RAW("Koolson/Qure/master/IconSet/Color/China.png"),
  UnitedKingdom: GH_RAW("Koolson/Qure/master/IconSet/Color/United_Kingdom.png"),
  Germany: GH_RAW("Koolson/Qure/master/IconSet/Color/Germany.png"),
  Malaysia: GH_RAW("Koolson/Qure/master/IconSet/Color/Malaysia.png"),
  Turkey: GH_RAW("Koolson/Qure/master/IconSet/Color/Turkey.png"),
  ChatGPT: GH_RAW("Koolson/Qure/master/IconSet/Color/ChatGPT.png"),
  YouTube: GH_RAW("Koolson/Qure/master/IconSet/Color/YouTube.png"),
  Bilibili3: GH_RAW("Koolson/Qure/master/IconSet/Color/bilibili_3.png"),
  Bahamut: GH_RAW("Koolson/Qure/master/IconSet/Color/Bahamut.png"),
  DisneyPlus: GH_RAW("Koolson/Qure/master/IconSet/Color/Disney+.png"),
  Netflix: GH_RAW("Koolson/Qure/master/IconSet/Color/Netflix.png"),
  TikTok: GH_RAW("Koolson/Qure/master/IconSet/Color/TikTok.png"),
  Spotify: GH_RAW("Koolson/Qure/master/IconSet/Color/Spotify.png"),
  Pixiv: GH_RAW("Koolson/Qure/master/IconSet/Color/Pixiv.png"),
  HBO: GH_RAW("Koolson/Qure/master/IconSet/Color/HBO.png"),
  TVB: GH_RAW("Koolson/Qure/master/IconSet/Color/TVB.png"),
  PrimeVideo: GH_RAW("Koolson/Qure/master/IconSet/Color/Prime_Video.png"),
  Hulu: GH_RAW("Koolson/Qure/master/IconSet/Color/Hulu.png"),
  Telegram: GH_RAW("Koolson/Qure/master/IconSet/Color/Telegram.png"),
  Line: GH_RAW("Koolson/Qure/master/IconSet/Color/Line.png"),
  Game: GH_RAW("Koolson/Qure/master/IconSet/Color/Game.png"),
  Reject: GH_RAW("Koolson/Qure/master/IconSet/Color/Reject.png"),
  Advertising: GH_RAW("Koolson/Qure/master/IconSet/Color/Advertising.png"),
  Apple2: GH_RAW("Koolson/Qure/master/IconSet/Color/Apple_2.png"),
  GoogleSearch: GH_RAW("Koolson/Qure/master/IconSet/Color/Google_Search.png"),
  Microsoft: GH_RAW("Koolson/Qure/master/IconSet/Color/Microsoft.png"),
  GitHub: GH_RAW("Koolson/Qure/master/IconSet/Color/GitHub.png"),
  JP: GH_RAW("Koolson/Qure/master/IconSet/Color/JP.png"),
  Download: GH_RAW("Koolson/Qure/master/IconSet/Color/Download.png"),
  StreamingCN: GH_RAW("Koolson/Qure/master/IconSet/Color/StreamingCN.png"),
  StreamingNotCN: GH_RAW("Koolson/Qure/master/IconSet/Color/Streaming!CN.png")
};

const URLS = {
  rulesets: {
    applications: GH_RAW("DustinWin/ruleset_geodata/clash-ruleset/applications.list"),
    ai: GH_RAW("dahaha-365/YaNet/dist/rulesets/mihomo/ai.list"),
    adblock_mihomo_mrs: GH_RAW("217heidai/adblockfilters/main/rules/adblockmihomo.mrs"),
    category_bank_jp_mrs: GH_RAW("MetaCubeX/meta-rules-dat/meta/geo/geosite/category-bank-jp.mrs")
  },
  geox: {
    geoip: GH_RELEASE("MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat"),
    geosite: GH_RELEASE("MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"),
    mmdb: GH_RELEASE("MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb"),
    asn: GH_RELEASE("MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb")
  }
};

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
      { name: "HK香港", regex: /港|🇭🇰|hk|hongkong|hong kong/i, icon: ICONS.HongKong },
      { name: "US美国", regex: /美|🇺🇸|us|united state|america/i, icon: ICONS.UnitedStates },
      { name: "JP日本", regex: /日本|🇯🇵|jp|japan/i, icon: ICONS.Japan },
      { name: "KR韩国", regex: /韩|🇰🇷|kr|korea/i, icon: ICONS.Korea },
      { name: "SG新加坡", regex: /新加坡|🇸🇬|sg|singapore/i, icon: ICONS.Singapore },
      { name: "CN中国大陆", regex: /中国|🇨🇳|cn|china/i, icon: ICONS.ChinaMap },
      { name: "TW台湾省", regex: /台湾|🇹🇼|tw|taiwan|tai wan/i, icon: ICONS.China },
      { name: "GB英国", regex: /英|🇬🇧|uk|united kingdom|great britain/i, icon: ICONS.UnitedKingdom },
      { name: "DE德国", regex: /德国|🇩🇪|de|germany/i, icon: ICONS.Germany },
      { name: "MY马来西亚", regex: /马来|my|malaysia/i, icon: ICONS.Malaysia },
      { name: "TK土耳其", regex: /土耳其|🇹🇷|tk|turkey/i, icon: ICONS.Turkey }
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
    { id: "openai", rule: ["DOMAIN-SUFFIX,grazie.ai,国外AI", "DOMAIN-SUFFIX,grazie.aws.intellij.net,国外AI", "RULE-SET,ai,国外AI"], name: "国外AI", url: "https://chat.openai.com/cdn-cgi/trace", icon: ICONS.ChatGPT, ruleProvider: {name: "ai", url: URLS.rulesets.ai} },
    { id: "youtube", rule: ["GEOSITE,youtube,YouTube"], name: "YouTube", url: "https://www.youtube.com/s/desktop/494dd881/img/favicon.ico", icon: ICONS.YouTube },
    { id: "biliintl", rule: ["GEOSITE,biliintl,哔哩哔哩东南亚"], name: "哔哩哔哩东南亚", url: "https://www.bilibili.tv/", icon: ICONS.Bilibili3, proxiesOrder: ["默认节点", "直连"] },
    { id: "bahamut", rule: ["GEOSITE,bahamut,巴哈姆特"], name: "巴哈姆特", url: "https://ani.gamer.com.tw/ajax/getdeviceid.php", icon: ICONS.Bahamut, proxiesOrder: ["默认节点", "直连"] },
    { id: "disney", rule: ["GEOSITE,disney,Disney+"], name: "Disney+", url: "https://disney.api.edge.bamgrid.com/devices", icon: ICONS.DisneyPlus },
    { id: "netflix", rule: ["GEOSITE,netflix,NETFLIX"], name: "NETFLIX", url: "https://api.fast.com/netflix/speedtest/v2?https=true", icon: ICONS.Netflix },
    { id: "tiktok", rule: ["GEOSITE,tiktok,Tiktok"], name: "Tiktok", url: "https://www.tiktok.com/", icon: ICONS.TikTok },
    { id: "spotify", rule: ["GEOSITE,spotify,Spotify"], name: "Spotify", url: "http://spclient.wg.spotify.com/signup/public/v1/account", icon: ICONS.Spotify },
    { id: "pixiv", rule: ["GEOSITE,pixiv,Pixiv"], name: "Pixiv", url: "https://www.pixiv.net/favicon.ico", icon: ICONS.Pixiv },
    { id: "hbo", rule: ["GEOSITE,hbo,HBO"], name: "HBO", url: "https://www.hbo.com/favicon.ico", icon: ICONS.HBO },
    { id: "tvb", rule: ["GEOSITE,tvb,TVB"], name: "TVB", url: "https://www.tvb.com/logo_b.svg", icon: ICONS.TVB },
    { id: "primevideo", rule: ["GEOSITE,primevideo,Prime Video"], name: "Prime Video", url: "https://m.media-amazon.com/images/G/01/digital/video/web/logo-min-remaster.png", icon: ICONS.PrimeVideo },
    { id: "hulu", rule: ["GEOSITE,hulu,Hulu"], name: "Hulu", url: "https://auth.hulu.com/v4/web/password/authenticate", icon: ICONS.Hulu },
    { id: "telegram", rule: ["GEOIP,telegram,Telegram"], name: "Telegram", url: "http://www.telegram.org/img/website_icon.svg", icon: ICONS.Telegram },
    { id: "whatsapp", rule: ["GEOSITE,whatsapp,WhatsApp"], name: "WhatsApp", url: "https://web.whatsapp.com/data/manifest.json", icon: ICONS.Telegram },
    { id: "line", rule: ["GEOSITE,line,Line"], name: "Line", url: "https://line.me/page-data/app-data.json", icon: ICONS.Line },
    { id: "games", rule: ["GEOSITE,category-games@cn,国内网站", "GEOSITE,category-games,游戏专用"], name: "游戏专用", icon: ICONS.Game },
    { id: "tracker", rule: ["GEOSITE,tracker,跟踪分析"], name: "跟踪分析", icon: ICONS.Reject, proxies: ["REJECT", "直连", "默认节点"] },
    { id: "ads", rule: ["GEOSITE,category-ads-all,广告过滤", "RULE-SET,adblockmihomo,广告过滤"], name: "广告过滤", icon: ICONS.Advertising, proxies: ["REJECT", "直连", "默认节点"], ruleProvider: {name: "adblockmihomo", url: URLS.rulesets.adblock_mihomo_mrs, format: "mrs", behavior: "domain"} },
    { id: "apple", rule: ["GEOSITE,apple-cn,苹果服务"], name: "苹果服务", url: "http://www.apple.com/library/test/success.html", icon: ICONS.Apple2 },
    { id: "google", rule: ["GEOSITE,google,谷歌服务"], name: "谷歌服务", url: "http://www.google.com/generate_204", icon: ICONS.GoogleSearch },
    { id: "microsoft", rule: ["GEOSITE,microsoft@cn,国内网站", "GEOSITE,microsoft,微软服务"], name: "微软服务", url: "http://www.msftconnecttest.com/connecttest.txt", icon: ICONS.Microsoft },
    { id: "github", rule: ["GEOSITE,github,Github"], name: "Github", url: "https://github.com/robots.txt", icon: ICONS.GitHub },
    { id: "japan", rule: ["RULE-SET,category-bank-jp,日本网站", "GEOIP,jp,日本网站,no-resolve"], name: "日本网站", url: "https://r.r10s.jp/com/img/home/logo/touch.png", icon: ICONS.JP, ruleProvider: {name: "category-bank-jp", url: URLS.rulesets.category_bank_jp_mrs, format: "mrs", behavior: "domain"} }
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
      geoip: URLS.geox.geoip,
      geosite: URLS.geox.geosite,
      mmdb: URLS.geox.mmdb,
      asn: URLS.geox.asn
    }
  },
  common: {
    ruleProvider: { type: "http", format: "yaml", interval: 86400 },
    proxyGroup: { interval: 300, timeout: 3000, url: "http://cp.cloudflare.com/generate_204", lazy: true, "max-failed-times": 3, hidden: false },
    defaultProxyGroups: [
      { name: "下载软件", icon: ICONS.Download, proxies: ["直连", "REJECT", "默认节点", "国内网站"] },
      { name: "其他外网", icon: ICONS.StreamingNotCN, proxies: ["默认节点", "国内网站"] },
      { name: "国内网站", url: "http://wifi.vivo.com.cn/generate_204", icon: ICONS.StreamingCN, proxies: ["直连", "默认节点"] }
    ],
    postRules: ["GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve", "GEOSITE,cn,国内网站", "GEOIP,cn,国内网站,no-resolve", "MATCH,其他外网"]
  }
};

/* ===================== 配置处理（生成代理组与规则） ===================== */
CentralManager.prototype.processConfiguration = function (config) {
  if (!config || typeof config !== "object") throw new ConfigurationError("processConfiguration: 配置对象无效");
  let safeConfig;
  try {
    safeConfig = JSON.parse(JSON.stringify(config));
    if (!safeConfig || typeof safeConfig !== "object") throw new Error("深拷贝结果无效");
  } catch (e) {
    throw new ConfigurationError(`配置对象无法深拷贝: ${e?.message || "unknown error"}`);
  }

  try { this.state.config = safeConfig; this.stats?.reset?.(); this.successTracker?.reset?.(); } catch (e) { Logger.warn("重置统计信息失败:", e.message); }

  const proxyCount = Array.isArray(safeConfig?.proxies) ? safeConfig.proxies.length : 0;
  const providerCount = (typeof safeConfig?.["proxy-providers"] === "object" && safeConfig["proxy-providers"] !== null)
    ? Object.keys(safeConfig["proxy-providers"]).length : 0;
  if (proxyCount === 0 && providerCount === 0) throw new ConfigurationError("未检测到任何代理节点或代理提供者");

  try {
    if (Config?.system && typeof Config.system === "object") Object.assign(safeConfig, Config.system);
    if (Config?.dns && typeof Config.dns === "object") safeConfig.dns = Config.dns;
  } catch (e) { Logger.warn("应用系统配置失败:", e.message); }

  if (!Config || !Config.enable) { Logger.info("配置处理已禁用，返回原始配置"); return safeConfig; }

  const regionProxyGroups = [];
  let otherProxyGroups = [];
  try {
    if (Array.isArray(safeConfig.proxies)) { otherProxyGroups = safeConfig.proxies.filter(p => p && typeof p.name === "string").map(p => p.name); }
  } catch (e) { Logger.warn("处理代理列表失败:", e.message); otherProxyGroups = []; }

  try {
    if (Config.regionOptions && Array.isArray(Config.regionOptions.regions)) {
      Config.regionOptions.regions.forEach(region => {
        if (!region || typeof region !== "object") return;
        try {
          const names = Utils.filterProxiesByRegion(safeConfig.proxies || [], region);
          if (Array.isArray(names) && names.length > 0) {
            regionProxyGroups.push({
              ...(Config.common?.proxyGroup || {}), name: region.name || "Unknown",
              type: "url-test", tolerance: 50, icon: region.icon || "", proxies: names
            });
            otherProxyGroups = otherProxyGroups.filter(n => !names.includes(n));
          }
        } catch (e) { Logger.debug(`处理地区 ${region.name || "unknown"} 失败:`, e.message); }
      });
    }
  } catch (e) { Logger.warn("处理地区代理组失败:", e.message); }

  let regionGroupNames = [];
  try {
    regionGroupNames = regionProxyGroups.filter(g => g && g.name).map(g => g.name);
    if (otherProxyGroups.length > 0) regionGroupNames.push("其他节点");
    regionGroupNames = Array.from(new Set(regionGroupNames));
  } catch (e) { Logger.warn("构建区域组名称列表失败:", e.message); regionGroupNames = []; }

  try {
    safeConfig["proxy-groups"] = [{
      ...(Config.common?.proxyGroup || {}), name: "默认节点", type: "select",
      proxies: [...regionGroupNames, "直连"], icon: ICONS.Proxy
    }];
  } catch (e) { Logger.warn("初始化代理组失败:", e.message); safeConfig["proxy-groups"] = []; }

  try {
    safeConfig.proxies = Array.isArray(safeConfig?.proxies) ? safeConfig.proxies : [];
    if (!safeConfig.proxies.some(p => p && p.name === "直连")) { safeConfig.proxies.push({ name: "直连", type: "direct" }); }
  } catch (e) { Logger.warn("添加直连代理失败:", e.message); }

  const ruleProviders = new Map();
  const rules = [];
  try {
    if (Config.common?.ruleProvider && typeof Config.common.ruleProvider === "object") {
      ruleProviders.set("applications", {
        ...Config.common.ruleProvider,
        behavior: "classical", format: "text",
        url: URLS.rulesets.applications,
        path: "./ruleset/DustinWin/applications.list"
      });
    }
    if (Array.isArray(Config.preRules)) rules.push(...Config.preRules);
    if (typeof Utils.createServiceGroups === "function") { Utils.createServiceGroups(safeConfig, regionGroupNames, ruleProviders, rules); }
  } catch (e) { Logger.warn("处理服务规则失败:", e.message); }

  try {
    if (Config.common && Array.isArray(Config.common.defaultProxyGroups)) {
      Config.common.defaultProxyGroups.forEach(group => {
        if (group && typeof group === "object" && group.name) {
          try {
            safeConfig["proxy-groups"].push({
              ...(Config.common?.proxyGroup || {}),
              name: group.name || "Unknown",
              type: "select",
              proxies: [...(Array.isArray(group.proxies) ? group.proxies : []), ...regionGroupNames],
              url: group.url || (Config.common?.proxyGroup?.url || ""),
              icon: group.icon || ""
            });
          } catch (e) { Logger.debug(`添加默认代理组失败 (${group.name}):`, e.message); }
        }
      });
    }
  } catch (e) { Logger.warn("添加默认代理组失败:", e.message); }

  try { if (regionProxyGroups.length > 0) safeConfig["proxy-groups"] = (safeConfig["proxy-groups"] || []).concat(regionProxyGroups); }
  catch (e) { Logger.warn("添加区域代理组失败:", e.message); }

  try {
    if (otherProxyGroups.length > 0) {
      safeConfig["proxy-groups"].push({
        ...(Config.common?.proxyGroup || {}),
        name: "其他节点", type: "select", proxies: otherProxyGroups,
        icon: ICONS.WorldMap
      });
    }
  } catch (e) { Logger.warn("添加其他节点组失败:", e.message); }

  try { if (Config.common && Array.isArray(Config.common.postRules)) rules.push(...Config.common.postRules); safeConfig.rules = rules; }
  catch (e) { Logger.warn("添加后置规则失败:", e.message); safeConfig.rules = rules; }

  try { if (ruleProviders.size > 0) safeConfig["rule-providers"] = Object.fromEntries(ruleProviders); }
  catch (e) { Logger.warn("添加规则提供者失败:", e.message); }

  return safeConfig;
};

/* ===================== AI 数据存取（不持久化敏感IP） ===================== */
CentralManager.prototype.loadAIDBFromFile = function () {
  return new Promise((resolve) => {
    try {
      let raw = ""; let storage = null;
      try {
        if (typeof $persistentStore !== "undefined" && $persistentStore) storage = $persistentStore;
        else if (PLATFORM.isBrowser && window.localStorage) storage = window.localStorage;
      } catch (e) { Logger.debug("存储检测失败:", e.message); }
      if (storage) {
        try {
          if (typeof storage.getItem === "function") raw = storage.getItem("ai_node_data") || "";
          else if (typeof storage.read === "function") raw = storage.read("ai_node_data") || "";
        } catch (e) { Logger.warn("读取存储数据失败:", e.message); raw = ""; }
      }
      if (raw && typeof raw === "string" && raw.trim()) {
        try {
          const data = JSON.parse(raw);
          if (typeof data === "object" && data !== null && !Array.isArray(data)) {
            let loadedCount = 0;
            Object.entries(data).forEach(([id, stats]) => {
              if (id && typeof id === "string" && stats && typeof stats === "object") {
                try { this.state.metrics.set(id, Array.isArray(stats) ? stats : [stats]); loadedCount++; }
                catch (e) { Logger.debug(`加载节点数据失败 (${id}):`, e.message); }
              }
            });
            Logger.info(`成功加载AI节点数据，共${loadedCount}条记录`);
          } else { Logger.warn("AI数据格式无效，预期为对象"); }
        } catch (e) {
          Logger.error("AI数据解析失败:", e?.stack || e);
          try {
            if (typeof $persistentStore !== "undefined" && $persistentStore.write) $persistentStore.write("", "ai_node_data");
            else if (PLATFORM.isBrowser && window.localStorage?.removeItem) window.localStorage.removeItem("ai_node_data");
          } catch (delErr) { Logger.warn("删除损坏数据失败:", delErr.message); }
        }
      }
    } catch (e) { Logger.error("AI数据加载失败:", e?.stack || e); }
    finally { resolve(); }
  });
};

CentralManager.prototype.saveAIDBToFile = function () {
  try {
    if (!this.state || !this.state.metrics) { Logger.warn("无法保存AI数据: state.metrics 未初始化"); return; }
    const data = Object.fromEntries(this.state.metrics.entries());
    if (!data || Object.keys(data).length === 0) { Logger.debug("没有AI数据需要保存"); return; }
    const raw = JSON.stringify(data, null, 2);
    if (!raw || raw.length === 0) { Logger.warn("序列化AI数据失败: 结果为空"); return; }
    let saved = false;
    try {
      if (typeof $persistentStore !== "undefined" && typeof $persistentStore?.write === "function") { $persistentStore.write(raw, "ai_node_data"); saved = true; }
      else if (PLATFORM.isBrowser && typeof window.localStorage?.setItem === "function") { window.localStorage.setItem("ai_node_data", raw); saved = true; }
      if (saved) Logger.debug(`AI数据保存成功，共${Object.keys(data).length}条记录`);
      else Logger.warn("无法保存AI数据: 未找到可用的存储接口");
    } catch (e) { Logger.error("AI数据保存到存储失败:", e?.message || e); }
  } catch (e) { Logger.error("AI数据保存失败:", e?.stack || e); }
};

/* ===================== 节点多指标测试（真实/模拟） ===================== */
CentralManager.prototype.testNodeMultiMetrics = async function (node) {
  const cacheKey = `nodeMetrics:${node.id}`;
  const cached = this.lruCache.get(cacheKey); if (cached) return cached;

  const timeout = CONSTANTS.NODE_TEST_TIMEOUT || 5000;
  const probe = async () => {
    const probeUrl = node.proxyUrl || node.probeUrl || (node.server ? `http://${node.server}` : null);

    let tcpLatencyMs = null;
    if (PLATFORM.isNode && node.server) {
      try {
        const [host, portStr] = node.server.split(":");
        const port = parseInt(portStr || "80", 10) || 80;
        tcpLatencyMs = await this.throughputEstimator.tcpConnectLatency(host, port, timeout);
      } catch { tcpLatencyMs = null; }
    }

    if (!probeUrl) throw new Error("无探测URL，使用模拟测试");
    const start = Date.now();
    let response;
    try { response = await this._safeFetch(probeUrl, { method: "GET" }, timeout); }
    catch (e) { return { latency: timeout, loss: 1, jitter: 100, bytes: 0, bps: 0, __hardFail: true }; }
    const latency = Date.now() - start;

    const measure = await this.throughputEstimator.measureResponse(response, timeout);
    const bytes = measure.bytes || 0;
    const jitter = Math.max(0, Math.min(CONSTANTS.JITTER_CLAMP_MS, measure.jitter || 0));
    const bps = this.throughputEstimator.bpsFromBytesLatency({ bytes, latency });

    const finalLatency = (typeof tcpLatencyMs === "number" && tcpLatencyMs > 0 && tcpLatencyMs < latency) ? tcpLatencyMs : latency;
    return { latency: finalLatency, loss: 0, jitter, bytes, bps };
  };

  try {
    const result = await Utils.retry(() => probe(), 2, 200);
    try { this.lruCache.set(cacheKey, result, 60000); } catch {}
    return result;
  } catch (e) {
    Logger.debug("真实网络探测失败，使用模拟数据:", e?.message || e);
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
};

/* ===================== 指标管理/可用性追踪/吞吐估计 ===================== */
class MetricsManager { constructor(state) { this.state = state; } append(nodeId, metrics) {
  if (!nodeId) return; const arr = this.state.metrics.get(nodeId) || []; arr.push(metrics);
  if (arr.length > CONSTANTS.FEATURE_WINDOW_SIZE) this.state.metrics.set(nodeId, arr.slice(-CONSTANTS.FEATURE_WINDOW_SIZE));
  else this.state.metrics.set(nodeId, arr);
}}

class AvailabilityTracker {
  constructor(state, nodeManager) { this.state = state; this.nodeManager = nodeManager; this.trackers = nodeManager.nodeSuccess; }
  ensure(nodeId) { if (!this.trackers.get(nodeId)) this.trackers.set(nodeId, new SuccessRateTracker()); }
  record(nodeId, success, opts = {}) {
    this.ensure(nodeId);
    const tracker = this.trackers.get(nodeId);
    tracker.record(success, opts);
    const rate = tracker.rate;
    this.state.updateNodeStatus(nodeId, { availabilityRate: rate });
  }
  rate(nodeId) { return (this.trackers.get(nodeId)?.rate) || 0; }
  hardFailStreak(nodeId) { return (this.trackers.get(nodeId)?.hardFailStreak) || 0; }
}

class ThroughputEstimator {
  async tcpConnectLatency(host, port, timeout) {
    if (!PLATFORM.isNode) throw new Error("Not Node");
    const net = require("net");
    return new Promise((resolve, reject) => {
      const start = Date.now();
      const socket = new net.Socket();
      let done = false;
      const cleanup = (err) => { if (done) return; done = true; try { socket.destroy(); } catch {} if (err) reject(err); else resolve(Date.now() - start); };
      socket.setTimeout(timeout, () => cleanup(new Error("TCP connect timeout")));
      socket.once("error", err => cleanup(err));
      socket.connect(port, host, () => cleanup());
    });
  }

  async measureResponse(response, timeoutMs) {
    let bytes = 0; let jitter = 0;
    try {
      if (response?.body?.getReader) {
        const reader = response.body.getReader();
        const maxBytes = 64 * 1024;
        const readStart = Date.now();
        while (true) {
          const chunk = await reader.read();
          if (chunk?.done) break;
          const value = chunk?.value || null;
          if (value) {
            const len = value.byteLength || value.length || 0;
            bytes += len;
            if (bytes >= maxBytes) break;
          }
        }
        const readTime = Math.max(1, Date.now() - readStart);
        const speedKbps = (bytes * 8) / readTime;
        jitter = Math.max(1, 200 - Math.min(200, Math.round(speedKbps / 10)));
        return { bytes, jitter };
      }
      if (typeof response?.arrayBuffer === "function") {
        const buf = await response.arrayBuffer();
        bytes = buf?.byteLength || 0; jitter = 0; return { bytes, jitter };
      }
      if (response?.headers?.get) {
        const len = response.headers.get("Content-Length");
        bytes = parseInt(len || "0", 10); jitter = 0; return { bytes, jitter };
      }
      return { bytes: 0, jitter: 0 };
    } catch { return { bytes: 0, jitter: 0 }; }
  }

  bpsFromBytesLatency({ bytes = 0, latency = 0 }) {
    const ms = Math.max(1, Number(latency) || 1);
    const bps = Math.max(0, Math.round((bytes * 8 / ms) * 1000));
    return Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, bps);
  }
}

/* ===================== 主流程入口 ===================== */
function main(config) {
  const centralManager = CentralManager.getInstance();
  return centralManager.processConfiguration(config);
}

/* ===================== CommonJS/ESM 兼容导出 ===================== */
if (typeof module !== "undefined") {
  module.exports = { main, CentralManager, NodeManager, Config };
}
