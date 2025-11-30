"use strict";
/**
 * Central orchestrator architecture with unified, availability-first node selection.
 * Preserves original APIs and behavior; strengthens metrics flow, availability signals,
 * throughput measurement, modularity, and cross-platform compat.
 */

// ================= Maintenance notice =================
// Event-driven only; no periodic schedulers introduced.
// All new variables, classes, and functions are defined explicitly here.
// ======================================================

// ================= Constants =================
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
  FEATURE_WINDOW_SIZE: 50, // increase window for richer features
  ENABLE_SCORE_DEBUGGING: false,
  QUALITY_WEIGHT: 0.5,
  METRIC_WEIGHT: 0.35,
  SUCCESS_WEIGHT: 0.15,
  // Cache cleanup
  CACHE_CLEANUP_THRESHOLD: 0.1,
  CACHE_CLEANUP_BATCH_SIZE: 50,
  // Retry/backoff
  MAX_RETRY_ATTEMPTS: 3,
  RETRY_DELAY_BASE: 200,
  // Platform compat
  DEFAULT_USER_AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  // Availability thresholds
  AVAILABILITY_MIN_RATE: 0.75,      // below this, node deprioritized
  AVAILABILITY_EMERGENCY_FAILS: 2,  // consecutive hard fails to bypass cooldown
  // Throughput normalization caps (bits/s)
  THROUGHPUT_SOFT_CAP_BPS: 50_000_000, // 50 Mbps soft-cap for scoring
  THROUGHPUT_SCORE_MAX: 15,
  // Metrics clamp
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
class ConfigurationError extends Error {
  constructor(message) {
    super(message); this.name = "ConfigurationError";
  }
}
class InvalidRequestError extends Error {
  constructor(message) {
    super(message); this.name = "InvalidRequestError";
  }
}

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
    [...this.eventListeners.get(event)].forEach(fn => {
      try { fn(...args); } catch (e) { Logger.error(`事件 ${event} 处理失败:`, e.stack || e); }
    });
  }
  removeAllListeners(event) {
    if (event) this.eventListeners.delete(event);
    else this.eventListeners.clear();
  }
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
    const newNode = {
      key, value, ttl, timestamp: Date.now(),
      prev: this.head, next: this.head.next
    };
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
    if (this.count < this.windowSize) {
      this.data[this.index] = value; this.sum += value; this.count++;
    } else {
      const prev = this.data[this.index] || 0;
      this.data[this.index] = value; this.sum += value - prev;
    }
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
        if (typeof task !== "function") {
          results[current] = { status: "rejected", reason: new Error(`任务 ${current} 不是函数`) };
          continue;
        }
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
      while (idx < tasks.length) {
        if (!results[idx]) results[idx] = { status: "rejected", reason: error };
        idx++;
      }
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

// ================= Node manager =================
class NodeManager extends EventEmitter {
  static getInstance() {
    if (!NodeManager.instance) NodeManager.instance = new NodeManager();
    return NodeManager.instance;
  }
  constructor() {
    super();
    this.currentNode = null;
    this.nodeQuality = new Map();        // id -> numeric quality 0-100
    this.switchCooldown = new Map();     // id -> timestamp
    this.nodeHistory = new Map();        // id -> [{timestamp, score}]
    this.nodeSuccess = new Map();        // id -> SuccessRateTracker
  }
  isInCooldown(nodeId) {
    const end = this.switchCooldown.get(nodeId);
    return !!(end && Date.now() < end);
  }
  _getCooldownTime(nodeId) {
    const score = this.nodeQuality.get(nodeId) || 0;
    return Math.max(
      CONSTANTS.MIN_SWITCH_COOLDOWN,
      Math.min(CONSTANTS.MAX_SWITCH_COOLDOWN, CONSTANTS.BASE_SWITCH_COOLDOWN * (1 + score / 100))
    );
  }
  _recordSwitchEvent(oldNodeId, newNodeId, targetGeo) {
    const event = {
      timestamp: Date.now(),
      oldNodeId, newNodeId,
      targetGeo: targetGeo ? { country: targetGeo.country, region: targetGeo.regionName || targetGeo.region } : null,
      reason: oldNodeId ? "质量过低" : "初始选择"
    };
    // ready for external logging integration
  }
  _updateNodeHistory(nodeId, score) {
    const history = this.nodeHistory.get(nodeId) || [];
    history.push({ timestamp: Date.now(), score });
    if (history.length > CONSTANTS.MAX_HISTORY_RECORDS) {
      this.nodeHistory.set(nodeId, history.slice(-CONSTANTS.MAX_HISTORY_RECORDS));
    } else {
      this.nodeHistory.set(nodeId, history);
    }
  }
  updateNodeQuality(nodeId, scoreDelta) {
    const current = this.nodeQuality.get(nodeId) || 0;
    const newScore = Math.max(0, Math.min(100, current + (Number(scoreDelta) || 0)));
    this.nodeQuality.set(nodeId, newScore);
    this._updateNodeHistory(nodeId, newScore);
  }
  async switchToNode(nodeId, targetGeo) {
    if (!nodeId || typeof nodeId !== "string") {
      Logger.warn("switchToNode: 无效的节点ID");
      return null;
    }
    if (this.currentNode === nodeId) return { id: nodeId };
    try {
      const central = (typeof CentralManager !== "undefined" && CentralManager.getInstance) ? CentralManager.getInstance() : null;
      if (!central || !central.state || !central.state.config || !Array.isArray(central.state.config.proxies)) {
        Logger.warn("switchToNode: CentralManager 未初始化或配置无效"); return null;
      }
      const node = central.state.config.proxies.find(n => n && n.id === nodeId) || null;
      if (!node) { Logger.warn(`尝试切换到不存在的节点: ${nodeId}`); return null; }
      const oldNodeId = this.currentNode;
      this.currentNode = nodeId;
      this.switchCooldown.set(nodeId, Date.now() + this._getCooldownTime(nodeId));
      this._recordSwitchEvent(oldNodeId, nodeId, targetGeo);
      const nodeStatus = central.state.nodes?.get(nodeId);
      const nodeRegion = nodeStatus?.geoInfo?.regionName || "未知区域";
      Logger.info(`节点已切换: ${oldNodeId || "无"} -> ${nodeId} (区域: ${nodeRegion})`);
      return node;
    } catch (error) {
      Logger.error(`节点切换失败 (${nodeId}):`, error && error.message ? error.message : error);
      return null;
    }
  }
  _selectBestPerformanceNode(nodes) {
    if (!Array.isArray(nodes) || nodes.length === 0) {
      Logger.warn("_selectBestPerformanceNode: 节点列表为空"); return null;
    }
    try {
      const central = (typeof CentralManager !== "undefined" && CentralManager.getInstance) ? CentralManager.getInstance() : null;
      const scoreFor = (node) => {
        if (!node || !node.id) return 0;
        try {
          const quality = this.nodeQuality.get(node.id) || 0;
          const nodeState = (central?.state?.nodes?.get(node.id)) || {};
          const metrics = nodeState.metrics || {};
          const availabilityRate = Number(nodeState.availabilityRate) || 0;

          // Availability-first: penalize harshly if below threshold
          const availabilityPenalty = availabilityRate < CONSTANTS.AVAILABILITY_MIN_RATE ? -30 : 0;

          // Metric scoring
          const latencyVal = Math.max(0, Math.min(CONSTANTS.LATENCY_CLAMP_MS, Number(metrics.latency) || 1000));
          const jitterVal = Math.max(0, Math.min(CONSTANTS.JITTER_CLAMP_MS, Number(metrics.jitter) || 100));
          const lossVal = Math.max(0, Math.min(CONSTANTS.LOSS_CLAMP, Number(metrics.loss) || 0));
          const bps = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, Number(metrics.bps) || 0));

          const latencyScore = Math.max(0, Math.min(50, 50 - latencyVal / 20));
          const jitterScore  = Math.max(0, Math.min(25, 25 - jitterVal));
          const lossScore    = Math.max(0, Math.min(15, 15 * (1 - lossVal)));
          const throughputScore = Math.max(0, Math.min(CONSTANTS.THROUGHPUT_SCORE_MAX, Math.round(Math.log10(1 + bps) * 2)));
          const metricScore = Math.round(latencyScore + jitterScore + lossScore + throughputScore);

          // Success rate (from trackers)
          let successRatePercent = 0;
          const tracker = this.nodeSuccess.get(node.id);
          if (tracker && typeof tracker.rate === "number") {
            successRatePercent = Math.max(0, Math.min(100, tracker.rate * 100));
          }

          const qw = Math.max(0, Math.min(1, CONSTANTS.QUALITY_WEIGHT || 0.5));
          const mw = Math.max(0, Math.min(1, CONSTANTS.METRIC_WEIGHT || 0.35));
          const sw = Math.max(0, Math.min(1, CONSTANTS.SUCCESS_WEIGHT || 0.15));
          const tw = qw + mw + sw || 1;

          const composite = (
            (quality * (qw / tw)) +
            (metricScore * (mw / tw)) +
            (successRatePercent * (sw / tw)) +
            availabilityPenalty
          );
          return Math.max(0, Math.min(100, composite));
        } catch (e) {
          Logger.debug(`计算节点得分失败 (${node.id}):`, e.message); return 0;
        }
      };

      let best = nodes[0]; if (!best) return null;
      let bestVal = scoreFor(best);
      for (let i = 1; i < nodes.length; i++) {
        const n = nodes[i]; if (!n) continue;
        const val = scoreFor(n);
        if (val > bestVal) { best = n; bestVal = val; }
      }
      return best;
    } catch (error) {
      Logger.error("_selectBestPerformanceNode 执行失败:", error && error.message ? error.message : error);
      return nodes[0] || null;
    }
  }
  async getBestNode(nodes, targetGeo) {
    if (!Array.isArray(nodes) || nodes.length === 0) {
      Logger.warn("getBestNode: 节点列表为空或无效"); return null;
    }
    try {
      const availableNodes = nodes.filter(node => node && node.id && !this.isInCooldown(node.id));
      const pool = availableNodes.length > 0 ? availableNodes : nodes;
      // Region preference if geo given
      if (targetGeo && typeof targetGeo.regionName === "string") {
        try {
          const central = (typeof CentralManager !== "undefined" && CentralManager.getInstance) ? CentralManager.getInstance() : null;
          if (central?.state?.nodes) {
            const regionalNodes = pool.filter(node => {
              try {
                const ns = central.state.nodes.get(node.id);
                return ns?.geoInfo?.regionName === targetGeo.regionName;
              } catch { return false; }
            });
            if (regionalNodes.length > 0) {
              return this._selectBestPerformanceNode(regionalNodes) || pool[0];
            }
          }
        } catch (e) { Logger.warn("获取区域节点失败，使用默认选择策略:", e.message); }
      }
      return this._selectBestPerformanceNode(pool) || pool[0];
    } catch (error) {
      Logger.error("getBestNode 执行失败:", error && error.message ? error.message : error);
      return nodes[0] || null;
    }
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

// ================= Central manager (center) =================
class CentralManager extends EventEmitter {
  static getInstance() { return CentralManager.instance; }
  constructor() {
    super();
    try {
      this.state = new AppState();
      this.stats = new RollingStats();
      this.successTracker = new SuccessRateTracker();
      this.nodeManager = NodeManager.getInstance();
      this.lruCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
      this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
      this.eventListeners = null;

      // Internal submodules (modularization without breaking APIs)
      this.metricsManager = new MetricsManager(this.state);
      this.availabilityTracker = new AvailabilityTracker(this.state, this.nodeManager);
      this.throughputEstimator = new ThroughputEstimator();

      CentralManager.instance = this;

      Promise.resolve().then(() => {
        this.initialize().catch(err => Logger.error("CentralManager 初始化失败:", err && err.stack ? err.stack : err));
      }).catch(err => Logger.error("CentralManager 初始化调度失败:", err && err.stack ? err.stack : err));
    } catch (error) {
      Logger.error("CentralManager 构造失败:", error && error.stack ? error.stack : error);
      throw error;
    }
  }

  async _safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
    if (!url || typeof url !== "string") throw new Error("_safeFetch: 无效的URL参数");
    if (timeout && (typeof timeout !== "number" || timeout <= 0)) timeout = CONSTANTS.GEO_INFO_TIMEOUT;

    let _fetch = (typeof fetch === "function") ? fetch : null;
    let _AbortController = (typeof AbortController !== "undefined") ? AbortController : null;

    // Node fallbacks
    if (!_fetch && typeof process !== "undefined" && process.versions && process.versions.node) {
      try {
        const nf = require("node-fetch");
        _fetch = nf.default || nf;
      } catch {}
      if (!_AbortController) {
        try {
          const AC = require("abort-controller");
          _AbortController = AC.default || AC;
        } catch {
          if (typeof AbortController !== "undefined") _AbortController = AbortController;
        }
      }
    }
    if (!_fetch) throw new Error("fetch 不可用于当前运行环境，且未找到可回退的实现（node-fetch）");

    const defaultOptions = {
      headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT, ...(options.headers || {}) },
      ...options
    };

    const hasAbort = !!_AbortController;
    if (hasAbort && timeout > 0) {
      const controller = new _AbortController();
      defaultOptions.signal = controller.signal;
      const tid = setTimeout(() => { try { controller.abort(); } catch {} }, timeout);
      try {
        const resp = await _fetch(url, defaultOptions);
        clearTimeout(tid);
        return resp;
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
    try {
      await this.loadAIDBFromFile().catch(err => Logger.warn("加载AI数据失败，使用默认值:", err && err.message ? err.message : err));

      try { this.setupEventListeners(); }
      catch (e) { Logger.warn("设置事件监听器失败:", e && e.message ? e.message : e); }

      try {
        this.on("requestDetected", (targetIp) => {
          this.handleRequestWithGeoRouting(targetIp).catch(err => Logger.warn("地理路由处理失败:", err && err.message ? err.message : err));
        });
      } catch (e) { Logger.warn("注册地理路由事件失败:", e && e.message ? e.message : e); }

      this.preheatNodes().catch(err => Logger.warn("节点预热失败:", err && err.message ? err.message : err));

      try {
        if (typeof process !== "undefined" && process.on) {
          const cleanup = () => { this.destroy().catch(err => Logger.error("清理资源失败:", err && err.message ? err.message : err)); };
          process.on("SIGINT", cleanup);
          process.on("SIGTERM", cleanup);
        } else if (typeof window !== "undefined" && window.addEventListener) {
          window.addEventListener("beforeunload", () => {
            this.destroy().catch(err => Logger.error("清理资源失败:", err && err.message ? err.message : err));
          });
        }
      } catch (e) { Logger.warn("注册清理函数失败:", e && e.message ? e.message : e); }

      Logger.info("CentralManager 初始化完成");
    } catch (error) {
      Logger.error("CentralManager 初始化过程中发生错误:", error && error.stack ? error.stack : error);
      throw error;
    }
  }

  async destroy() {
    try {
      Logger.info("开始清理资源...");
      try { this.cleanupEventListeners(); } catch (e) { Logger.warn("清理事件监听器失败:", e && e.message ? e.message : e); }
      try { await this.saveAIDBToFile(); } catch (e) { Logger.warn("保存AI数据失败:", e && e.message ? e.message : e); }
      try { if (this.lruCache) this.lruCache.clear(); } catch (e) { Logger.warn("清理LRU缓存失败:", e && e.message ? e.message : e); }
      try { if (this.geoInfoCache) this.geoInfoCache.clear(); } catch (e) { Logger.warn("清理地理信息缓存失败:", e && e.message ? e.message : e); }
      Logger.info("资源清理完成");
    } catch (error) { Logger.error("资源清理过程中发生错误:", error && error.stack ? error.stack : error); }
  }

  setupEventListeners() {
    this.eventListeners = {
      configChanged: async () => this.onConfigChanged(),
      networkOnline: async () => this.onNetworkOnline(),
      performanceThresholdBreached: async (nodeId) => this.onPerformanceThresholdBreached(nodeId),
      evaluationCompleted: () => this.onEvaluationCompleted()
    };
    if (typeof Config !== "undefined" && Config.on) {
      Config.on("configChanged", this.eventListeners.configChanged);
    }
    if (typeof window !== "undefined" && typeof window.addEventListener === "function") {
      window.addEventListener("online", this.eventListeners.networkOnline);
    }
    if (this.nodeManager && typeof this.nodeManager.on === "function") {
      this.nodeManager.on("performanceThresholdBreached", this.eventListeners.performanceThresholdBreached);
    }
    this.on("evaluationCompleted", this.eventListeners.evaluationCompleted);
  }
  cleanupEventListeners() {
    if (!this.eventListeners) return;
    if (typeof Config !== "undefined" && Config.off) {
      try { Config.off("configChanged", this.eventListeners.configChanged); } catch {}
    }
    if (typeof window !== "undefined" && typeof window.removeEventListener === "function") {
      try { window.removeEventListener("online", this.eventListeners.networkOnline); } catch {}
    }
    if (this.nodeManager && typeof this.nodeManager.off === "function") {
      try { this.nodeManager.off("performanceThresholdBreached", this.eventListeners.performanceThresholdBreached); } catch {}
    }
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
  onEvaluationCompleted() {
    Logger.info("节点评估完成，触发数据保存和节点清理...");
    this.saveAIDBToFile();
    this.autoEliminateNodes();
  }

  async preheatNodes() {
    const proxies = this.state.config.proxies || [];
    if (proxies.length === 0) return;
    const testNodes = proxies.slice(0, CONSTANTS.PREHEAT_NODE_COUNT);
    const tasks = testNodes.map(node => () => Utils.retry(() => this.testNodeMultiMetrics(node), 2, 200));
    const results = await Utils.asyncPool(tasks, CONSTANTS.CONCURRENCY_LIMIT);
    results.forEach((res, i) => {
      const node = testNodes[i];
      if (res && res.__error) {
        Logger.error(`节点预热失败: ${node.id}`, res.__error && res.__error.message ? res.__error.message : res.__error);
        return;
      }
      // compute bps for consistent scoring
      const bps = this.throughputEstimator.bpsFromBytesLatency(res);
      const enriched = { ...res, bps };
      this.state.updateNodeStatus(node.id, { initialMetrics: enriched, lastTested: Date.now() });
      this.metricsManager.append(node.id, enriched);
      this.nodeManager.updateNodeQuality(node.id, this.calculateInitialQualityScore(enriched));
      // initialize availability tracker
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
      if (r && r.__error) {
        const node = proxies[idx];
        Logger.warn(`节点评估失败: ${node?.id}`, r.__error && r.__error.message ? r.__error.message : r.__error);
      }
    });
    this.emit("evaluationCompleted");
  }

  async evaluateNodeQuality(node) {
    if (!node || !node.id || typeof node.id !== "string") {
      Logger.warn("evaluateNodeQuality: 无效的节点对象"); return;
    }

    // probe metrics
    let metrics = null;
    try {
      metrics = await Utils.retry(() => this.testNodeMultiMetrics(node), CONSTANTS.MAX_RETRY_ATTEMPTS, CONSTANTS.RETRY_DELAY_BASE);
    } catch {
      Logger.warn(`节点探测多次失败，使用回退模拟: ${node.id}`);
      try { metrics = await this.testNodeMultiMetrics(node); }
      catch {
        Logger.error(`节点回退测试也失败: ${node.id}`);
        metrics = { latency: CONSTANTS.NODE_TEST_TIMEOUT, loss: 1, jitter: 100, bytes: 0, bps: 0, __simulated: true };
      }
    }

    // compute bps if not present
    if (typeof metrics.bps !== "number") metrics.bps = this.throughputEstimator.bpsFromBytesLatency(metrics);

    // availability record
    this.availabilityTracker.ensure(node.id);
    const isSimulated = metrics && metrics.__simulated === true;
    const latency = Math.max(0, Number(metrics?.latency) || 0);
    const timeoutThreshold = (CONSTANTS.NODE_TEST_TIMEOUT || 5000) * 2;

    // hardFail indicates transport-level failure (set within probe)
    const hardFail = !!metrics.__hardFail;
    const success = !!(metrics && !isSimulated && latency > 0 && latency < timeoutThreshold && !hardFail);
    this.availabilityTracker.record(node.id, success, { hardFail });

    // score
    let score = 0;
    try {
      score = this.calculateNodeQualityScore(metrics);
      score = Math.max(0, Math.min(100, score));
    } catch (e) {
      Logger.error(`计算节点质量分失败 (${node.id}):`, e.message);
      score = 0;
    }

    // geo
    let geoInfo = null;
    try {
      const nodeIp = (node.server && typeof node.server === "string") ? node.server.split(":")[0] : null;
      if (nodeIp && /^(\d{1,3}\.){3}\d{1,3}$/.test(nodeIp)) {
        geoInfo = await this.getGeoInfo(nodeIp);
      }
    } catch (e) { Logger.debug(`获取节点地理信息失败 (${node.id}):`, e.message); }

    // state update
    try {
      this.nodeManager.updateNodeQuality(node.id, score);
      this.metricsManager.append(node.id, metrics);
      const avail = this.availabilityTracker.rate(node.id);
      this.state.updateNodeStatus(node.id, {
        metrics, score, geoInfo, lastEvaluated: Date.now(), availabilityRate: avail
      });
    } catch (e) {
      Logger.error(`更新节点状态失败 (${node.id}):`, e.message);
    }

    // emergency switch: if current node hard fails or availability collapses, bypass cooldown
    try {
      const isCurrent = this.nodeManager.currentNode === node.id;
      const availRate = this.availabilityTracker.rate(node.id);
      const failStreak = this.availabilityTracker.hardFailStreak(node.id);
      if (isCurrent && (hardFail || availRate < CONSTANTS.AVAILABILITY_MIN_RATE || score < CONSTANTS.QUALITY_SCORE_THRESHOLD)) {
        const proxies = this.state?.config?.proxies;
        if (Array.isArray(proxies) && proxies.length > 0) {
          if (failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS) {
            this.nodeManager.switchCooldown.delete(node.id); // bypass cooldown
          }
          await this.nodeManager.switchToBestNode(proxies);
        }
      }
    } catch (e) {
      Logger.warn(`节点切换失败 (${node.id}):`, e.message);
    }
  }

  async handleRequestWithGeoRouting(targetIp) {
    if (!targetIp || !this.state.config.proxies || this.state.config.proxies.length === 0) {
      Logger.warn("无法进行地理路由: 缺少目标IP或代理节点"); return;
    }
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

  async handleProxyRequest(req, ...args) {
    if (!this.state || !this.state.config) throw new ConfigurationError("系统配置未初始化");
    if (!req || !req.url) throw new InvalidRequestError("无效的请求对象或URL");

    try {
      const user = req.user || "default";
      const allNodes = this.state.config.proxies || [];
      if (allNodes.length === 0) {
        Logger.warn("没有可用代理节点，将使用直连模式");
        return this.proxyToDirect(...args);
      }

      let currentNode = this.nodeManager.currentNode ? allNodes.find(n => n.id === this.nodeManager.currentNode) : null;
      if (!currentNode || !this.state.nodes.has(currentNode.id)) {
        currentNode = await this.nodeManager.switchToBestNode(allNodes);
      }

      const clientIP = req.headers["X-Forwarded-For"] || req.headers["Remote-Address"];
      const clientGeo = await this.getGeoInfo(clientIP);

      let targetGeo = null;
      try {
        const targetUrl = new URL(req.url);
        const targetDomain = targetUrl.hostname;
        const targetIP = await this.resolveDomainToIP(targetDomain);
        if (targetIP) targetGeo = await this.getGeoInfo(targetIP);
      } catch (error) { Logger.warn(`解析目标URL失败: ${error.message}`, error.stack); }

      const targetNode = await this.smartDispatchNode(user, allNodes, { clientGeo, targetGeo, req });
      if (targetNode && targetNode.id !== currentNode?.id) {
        const switched = await this.nodeManager.switchToNode(targetNode.id, targetGeo);
        if (switched) currentNode = allNodes.find(n => n.id === targetNode.id) || switched;
      }

      const result = await this.proxyRequestWithNode(currentNode, ...args);
      this.recordRequestMetrics(currentNode, result, req);
      return result;
    } catch (error) {
      Logger.error("代理请求处理失败:", error.stack);
      return this.proxyToDirect(...args);
    }
  }

  async smartDispatchNode(user, nodes, context) {
    if (!Array.isArray(nodes) || nodes.length === 0) throw new InvalidRequestError("smartDispatchNode: 节点列表不能为空");
    if (!context || typeof context !== "object") throw new InvalidRequestError("smartDispatchNode: 无效的上下文信息");

    try {
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

      // streaming preference
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
              this.emit("batchCompleted", { batchIndex: 0 });
            } catch (e) { Logger.warn("节点测试批次处理失败:", e.message); }

            Logger.info(`筛选出 ${candidates.length} 个符合质量要求的节点`);
            const best = await this.nodeManager.getBestNode(candidates);
            if (best) {
              try { if (this.lruCache && best.id) this.lruCache.set(cacheKey, best.id); }
              catch (e) { Logger.debug("缓存节点选择结果失败:", e.message); }
              return best;
            }
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
                  if (bestRegionNode) {
                    try { if (this.lruCache && bestRegionNode.id) this.lruCache.set(cacheKey, bestRegionNode.id); }
                    catch (e) { Logger.debug("缓存区域节点选择结果失败:", e.message); }
                    return bestRegionNode;
                  }
                }
              }
            }
          }
        } catch (error) { Logger.warn("区域节点选择失败，使用默认策略:", error.message); }
      }

      const bestNode = await this.nodeManager.getBestNode(nodes);
      if (!bestNode) { Logger.warn("无法选择最佳节点，返回第一个可用节点"); return nodes[0] || null; }
      try { if (this.lruCache && bestNode.id) this.lruCache.set(cacheKey, bestNode.id); }
      catch (e) { Logger.debug("缓存默认节点选择结果失败:", e.message); }
      return bestNode;
    } catch (error) {
      Logger.error("smartDispatchNode 执行失败:", error && error.message ? error.message : error);
      return nodes[0] || null;
    }
  }

  async getGeoInfo(ip, domain) {
    if (!this.geoInfoCache) {
      Logger.error("地理信息缓存未初始化，使用默认配置");
      this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    }
    if (!ip) {
      Logger.warn("获取地理信息失败: IP地址为空");
      return this._getFallbackGeoInfo(domain);
    }
    if (ip === "127.0.0.1" || ip.startsWith("192.168.") || ip.startsWith("10.") || ip.startsWith("172.16.")) {
      return { country: "Local", region: "Local" };
    }
    const cached = this.geoInfoCache.get(ip);
    if (cached) { Logger.debug(`使用缓存的地理信息: ${ip} -> ${cached.country}`); return cached; }

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

  // unify getIpGeolocation with primary/fallback HTTPS-first
  async getIpGeolocation(ip) { return this.getGeoInfo(ip); }

  async _fetchGeoFromPrimaryAPI(ip) {
    if (!ip || typeof ip !== "string") { Logger.error("无效的IP地址:", ip); return null; }
    try {
      const resp = await this._safeFetch(`https://ipapi.co/${ip}/json/`, { headers: { "User-Agent": "Mozilla/5.0" } }, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
      const data = await resp.json();
      if (data.country_name) {
        return { country: data.country_name, region: data.region || data.city || "Unknown" };
      }
      Logger.warn(`主API返回无效数据: ${JSON.stringify(data)}`); return null;
    } catch (error) { Logger.warn(`主API调用失败: ${error.message}`); return null; }
  }

  async _fetchGeoFromFallbackAPI(ip) {
    try {
      const resp = await this._safeFetch(`https://ipinfo.io/${ip}/json`, {}, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
      const data = await resp.json();
      if (data.country) {
        return { country: data.country, region: data.region || data.city || "Unknown" };
      }
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
    try {
      if (!/^[a-zA-Z0-9.-]+$/.test(domain)) { Logger.error(`无效的域名格式: ${domain}`); return null; }
      const cacheKey = `dns:${domain}`;
      const cachedIP = this.lruCache.get(cacheKey);
      if (cachedIP) return cachedIP;

      const response = await this._safeFetch(
        `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=A`,
        { headers: { "Accept": "application/dns-json", "User-Agent": "Mozilla/5.0" } },
        CONSTANTS.GEO_INFO_TIMEOUT
      );
      if (!response.ok) throw new Error(`DNS query failed: ${response.status}`);
      const data = await response.json();
      if (data.Answer && data.Answer.length > 0) {
        const ip = data.Answer[0].data;
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
          this.lruCache.set(cacheKey, ip);
          return ip;
        }
        Logger.error(`无效的IP地址: ${ip}`);
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
      try {
        const len = response.headers && response.headers.get && response.headers.get("Content-Length");
        bytes = parseInt(len || "0");
      } catch {}
      const result = { success: true, latency, bytes };
      return result;
    } catch (error) {
      Logger.error(`代理请求失败 [${node.id}]: ${error && error.message ? error.message : error}`);
      // mark hard fail for availability
      this.availabilityTracker.record(node.id, false, { hardFail: true });
      return { success: false, error: error && error.message ? error.message : String(error), latency: CONSTANTS.NODE_TEST_TIMEOUT };
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
      Logger.debug(`Node ${node.id} score components:`, {
        risk: prediction.risk, latency: features.currentLatency, loss: features.currentLoss, adjustment
      });
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
    // trend penalties
    if (features.latencyTrend > 5) risk += 0.1 * weights.trend;
    if (features.lossTrend > 0.1) risk += 0.1 * weights.trend;
    if (features.successTrend < -0.1) risk += 0.1 * weights.trend;
    // low recent quality
    risk += Math.max(0, (50 - features.recentQuality) / 50) * weights.quality;
    // success reduces risk
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

  processConfiguration(config) {
    if (!config || typeof config !== "object") throw new ConfigurationError("processConfiguration: 配置对象无效");
    let safeConfig;
    try {
      safeConfig = JSON.parse(JSON.stringify(config));
      if (!safeConfig || typeof safeConfig !== "object") throw new Error("深拷贝结果无效");
    } catch (e) {
      throw new ConfigurationError(`配置对象无法深拷贝: ${e && e.message ? e.message : "unknown error"}`);
    }

    try {
      this.state.config = safeConfig;
      this.stats?.reset?.();
      this.successTracker?.reset?.();
    } catch (e) { Logger.warn("重置统计信息失败:", e.message); }

    const proxyCount = Array.isArray(safeConfig?.proxies) ? safeConfig.proxies.length : 0;
    const providerCount = (typeof safeConfig?.["proxy-providers"] === "object" && safeConfig["proxy-providers"] !== null)
      ? Object.keys(safeConfig["proxy-providers"]).length : 0;
    if (proxyCount === 0 && providerCount === 0) throw new ConfigurationError("未检测到任何代理节点或代理提供者");

    try {
      if (Config?.system && typeof Config.system === "object") Object.assign(safeConfig, Config.system);
      if (Config?.dns && typeof Config.dns === "object") safeConfig.dns = Config.dns;
    } catch (e) { Logger.warn("应用系统配置失败:", e.message); }

    if (!Config || !Config.enable) {
      Logger.info("配置处理已禁用，返回原始配置"); return safeConfig;
    }

    const regionProxyGroups = [];
    let otherProxyGroups = [];
    try {
      if (Array.isArray(safeConfig.proxies)) {
        otherProxyGroups = safeConfig.proxies.filter(p => p && typeof p.name === "string").map(p => p.name);
      }
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
    } catch (e) { Logger.warn("构建区域组名称列表失败:", e.message); regionGroupNames = []; }

    try {
      safeConfig["proxy-groups"] = [{
        ...(Config.common?.proxyGroup || {}), name: "默认节点", type: "select",
        proxies: [...regionGroupNames, "直连"],
        icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Proxy.png"
      }];
    } catch (e) { Logger.warn("初始化代理组失败:", e.message); safeConfig["proxy-groups"] = []; }

    try {
      safeConfig.proxies = Array.isArray(safeConfig?.proxies) ? safeConfig.proxies : [];
      if (!safeConfig.proxies.some(p => p && p.name === "直连")) {
        safeConfig.proxies.push({ name: "直连", type: "direct" });
      }
    } catch (e) { Logger.warn("添加直连代理失败:", e.message); }

    const ruleProviders = new Map();
    const rules = [];
    try {
      if (Config.common?.ruleProvider && typeof Config.common.ruleProvider === "object") {
        ruleProviders.set("applications", {
          ...Config.common.ruleProvider,
          behavior: "classical", format: "text",
          url: "https://fastly.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/applications.list",
          path: "./ruleset/DustinWin/applications.list"
        });
      }
      if (Array.isArray(Config.preRules)) rules.push(...Config.preRules);
      if (typeof Utils.createServiceGroups === "function") {
        Utils.createServiceGroups(safeConfig, regionGroupNames, ruleProviders, rules);
      }
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
          icon: "https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/World_Map.png"
        });
      }
    } catch (e) { Logger.warn("添加其他节点组失败:", e.message); }

    try {
      if (Config.common && Array.isArray(Config.common.postRules)) rules.push(...Config.common.postRules);
      safeConfig.rules = rules;
    } catch (e) { Logger.warn("添加后置规则失败:", e.message); safeConfig.rules = rules; }

    try { if (ruleProviders.size > 0) safeConfig["rule-providers"] = Object.fromEntries(ruleProviders); }
    catch (e) { Logger.warn("添加规则提供者失败:", e.message); }

    return safeConfig;
  }

  loadAIDBFromFile() {
    return new Promise((resolve) => {
      try {
        let raw = "";
        let storage = null;
        try {
          if (typeof $persistentStore !== "undefined" && $persistentStore) storage = $persistentStore;
          else if (typeof window !== "undefined" && window.localStorage) storage = window.localStorage;
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
            Logger.error("AI数据解析失败:", e && e.stack ? e.stack : e);
            try {
              if (typeof $persistentStore !== "undefined" && $persistentStore.write) $persistentStore.write("", "ai_node_data");
              else if (typeof window !== "undefined" && window.localStorage?.removeItem) window.localStorage.removeItem("ai_node_data");
            } catch (delErr) { Logger.warn("删除损坏数据失败:", delErr.message); }
          }
        }
      } catch (e) { Logger.error("AI数据加载失败:", e && e.stack ? e.stack : e); }
      finally { resolve(); }
    });
  }

  saveAIDBToFile() {
    try {
      if (!this.state || !this.state.metrics) { Logger.warn("无法保存AI数据: state.metrics 未初始化"); return; }
      const data = Object.fromEntries(this.state.metrics.entries());
      if (!data || Object.keys(data).length === 0) { Logger.debug("没有AI数据需要保存"); return; }
      const raw = JSON.stringify(data, null, 2);
      if (!raw || raw.length === 0) { Logger.warn("序列化AI数据失败: 结果为空"); return; }
      let saved = false;
      try {
        if (typeof $persistentStore !== "undefined" && $persistentStore?.write === "function") {
          $persistentStore.write(raw, "ai_node_data"); saved = true;
        } else if (typeof window !== "undefined" && window.localStorage?.setItem === "function") {
          window.localStorage.setItem("ai_node_data", raw); saved = true;
        }
        if (saved) Logger.debug(`AI数据保存成功，共${Object.keys(data).length}条记录`);
        else Logger.warn("无法保存AI数据: 未找到可用的存储接口");
      } catch (e) { Logger.error("AI数据保存到存储失败:", e && e.message ? e.message : e); }
    } catch (e) { Logger.error("AI数据保存失败:", e && e.stack ? e.stack : e); }
  }

  async testNodeMultiMetrics(node) {
    const cacheKey = `nodeMetrics:${node.id}`;
    const cached = this.lruCache.get(cacheKey);
    if (cached) return cached;

    const timeout = CONSTANTS.NODE_TEST_TIMEOUT || 5000;
    const probe = async () => {
      // Build a lightweight probe URL
      const probeUrl =
        node.proxyUrl ||
        node.probeUrl ||
        (node.server ? `http://${node.server}` : null);

      // Optional TCP connect latency for Node.js
      let tcpLatencyMs = null;
      if (typeof process !== "undefined" && process.versions?.node && node.server) {
        try {
          const [host, portStr] = node.server.split(":");
          const port = parseInt(portStr || "80", 10) || 80;
          tcpLatencyMs = await this.throughputEstimator.tcpConnectLatency(host, port, timeout);
        } catch (e) { tcpLatencyMs = null; }
      }

      if (!probeUrl) throw new Error("无探测URL，使用模拟测试");
      const start = Date.now();
      let response;
      try { response = await this._safeFetch(probeUrl, { method: "GET" }, timeout); }
      catch (e) {
        // transport-level failure (hard fail)
        return { latency: timeout, loss: 1, jitter: 100, bytes: 0, bps: 0, __hardFail: true };
      }
      const latency = Date.now() - start;

      // Streamed throughput measurement (browser/Node compatible)
      const measure = await this.throughputEstimator.measureResponse(response, timeout);
      const bytes = measure.bytes || 0;
      const jitter = measure.jitter || 0;

      // bps normalized
      const bps = this.throughputEstimator.bpsFromBytesLatency({ bytes, latency });

      // Prefer TCP connect latency if available and reasonable
      const finalLatency = (typeof tcpLatencyMs === "number" && tcpLatencyMs > 0 && tcpLatencyMs < latency)
        ? tcpLatencyMs : latency;

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
}

// ================= Internal submodules =================
class MetricsManager {
  constructor(state) { this.state = state; }
  append(nodeId, metrics) {
    if (!nodeId) return;
    const arr = this.state.metrics.get(nodeId) || [];
    arr.push(metrics);
    // cap window size for scientific features
    if (arr.length > CONSTANTS.FEATURE_WINDOW_SIZE) {
      this.state.metrics.set(nodeId, arr.slice(-CONSTANTS.FEATURE_WINDOW_SIZE));
    } else {
      this.state.metrics.set(nodeId, arr);
    }
  }
}

class AvailabilityTracker {
  constructor(state, nodeManager) {
    this.state = state; this.nodeManager = nodeManager;
    this.trackers = nodeManager.nodeSuccess; // unify with NodeManager's trackers
  }
  ensure(nodeId) {
    if (!this.trackers.get(nodeId)) this.trackers.set(nodeId, new SuccessRateTracker());
  }
  record(nodeId, success, opts = {}) {
    this.ensure(nodeId);
    const tracker = this.trackers.get(nodeId);
    tracker.record(success, opts);
    // reflect on state for selection visibility
    const rate = tracker.rate;
    this.state.updateNodeStatus(nodeId, { availabilityRate: rate });
  }
  rate(nodeId) { return (this.trackers.get(nodeId)?.rate) || 0; }
  hardFailStreak(nodeId) { return (this.trackers.get(nodeId)?.hardFailStreak) || 0; }
}

class ThroughputEstimator {
  // Node-only TCP connect latency (optional). Returns ms or throws.
  async tcpConnectLatency(host, port, timeout) {
    if (!(typeof process !== "undefined" && process.versions?.node)) throw new Error("Not Node");
    const net = require("net");
    return new Promise((resolve, reject) => {
      const start = Date.now();
      const socket = new net.Socket();
      let done = false;
      const cleanup = (err) => {
        if (done) return; done = true;
        try { socket.destroy(); } catch {}
        if (err) reject(err);
      };
      socket.setTimeout(timeout, () => cleanup(new Error("TCP connect timeout")));
      socket.once("error", err => cleanup(err));
      socket.connect(port, host, () => {
        const ms = Date.now() - start;
        cleanup(); resolve(ms);
      });
    });
  }

  // Cross-platform response measurement
  async measureResponse(response, timeoutMs) {
    let bytes = 0; let jitter = 0;
    try {
      // Browser ReadableStream
      if (response?.body && typeof response.body.getReader === "function") {
        const reader = response.body.getReader();
        const maxBytes = 64 * 1024; // limit to 64KB
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
      // Node.js: try arrayBuffer quickly
      if (response?.arrayBuffer) {
        const buf = await response.arrayBuffer();
        bytes = buf.byteLength || 0;
        jitter = 0;
        return { bytes, jitter };
      }
      // Fallback: headers
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

// ================= Config (original shape preserved) =================
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

// ================= Main =================
function main(config) {
  const centralManager = new CentralManager();
  return centralManager.processConfiguration(config);
}
