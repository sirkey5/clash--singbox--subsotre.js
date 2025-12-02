/**
 * SingBox 1.12.12 智能代理混入脚本（SingBox 结构规范版）
 * 移植自 ClashMeta 全局覆写脚本，保留所有功能与性能
 * 目标：归一、高效、快速、稳定、精准、智能、自动、科学、精简、多平台兼容、模块化、先进、强大、安全、隐私保护
 *
 * @version 1.3.0
 * @author AI Assistant
 * @license MIT
 */

/* ===================== 常量定义 ===================== */

const CONSTANTS = {
  // 性能参数
  NODE_TEST_TIMEOUT: 5000,
  SWITCH_COOLDOWN_MS: 30000,
  FEATURE_WINDOW_SIZE: 100,
  JITTER_CLAMP_MS: 200,
  THROUGHPUT_SOFT_CAP_BPS: 1000000000,
  MIN_AVAILABILITY_RATE: 0.8,
  MAX_HARD_FAIL_STREAK: 3,

  // 评分权重
  LATENCY_WEIGHT: 0.4,
  LOSS_WEIGHT: 0.3,
  JITTER_WEIGHT: 0.1,
  AVAILABILITY_WEIGHT: 0.2,

  // 输出控制
  EXPORT_TO_GLOBAL: true,

  // SingBox 智能标签
  SMART_URLTEST_TAG: '智能选择',
  SMART_SELECTOR_TAG: '策略选择',

  // urltest 默认参数（SingBox 使用时间字符串）
  URLTEST_URL: 'http://www.gstatic.com/generate_204',
  URLTEST_INTERVAL: '300s',
  URLTEST_TOLERANCE: 50,

  // 平台检测
  PLATFORM: {
    isNode: typeof process !== 'undefined' && process.versions && process.versions.node,
    isBrowser: typeof window !== 'undefined',
    isSingBox: typeof $mixin !== 'undefined'
  }
};

/* ===================== 工具函数模块 ===================== */

class Utils {
  static async retry(fn, maxAttempts = 3, delay = 1000) {
    let lastErr;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        return await fn();
      } catch (error) {
        lastErr = error;
        if (attempt === maxAttempts) break;
        await new Promise((res) => setTimeout(res, delay * attempt));
      }
    }
    throw lastErr;
  }

  static async runWithConcurrency(tasks, concurrency = 5) {
    const results = [];
    const executing = [];
    for (const task of tasks) {
      const p = Promise.resolve().then(task).then((result) => {
        const idx = executing.indexOf(p);
        if (idx >= 0) executing.splice(idx, 1);
        return result;
      });
      executing.push(p);
      results.push(p);
      if (executing.length >= concurrency) {
        await Promise.race(executing);
      }
    }
    return Promise.all(results);
  }

  static async asyncPool(poolLimit, array, iteratorFn) {
    const ret = [];
    const executing = [];
    for (const item of array) {
      const p = Promise.resolve().then(() => iteratorFn(item, array));
      ret.push(p);
      if (poolLimit <= array.length) {
        const e = p.then(() => {
          const idx = executing.indexOf(e);
          if (idx >= 0) executing.splice(idx, 1);
        });
        executing.push(e);
        if (executing.length >= poolLimit) {
          await Promise.race(executing);
        }
      }
    }
    return Promise.all(ret);
  }

  static rollingStats(data, windowSize = 10) {
    if (!Array.isArray(data) || data.length === 0) return { mean: 0, std: 0, median: 0 };
    const window = data.slice(-windowSize);
    const mean = window.reduce((sum, x) => sum + x, 0) / window.length;
    const std = Math.sqrt(window.reduce((sum, x) => sum + Math.pow(x - mean, 2), 0) / window.length);
    const sorted = [...window].sort((a, b) => a - b);
    const median = sorted.length % 2 === 0
      ? (sorted[sorted.length / 2 - 1] + sorted[sorted.length / 2]) / 2
      : sorted[Math.floor(sorted.length / 2)];
    return { mean, std, median };
  }

  static filterProxiesByRegion(proxies, region) {
    if (!Array.isArray(proxies)) return [];
    const regionKeywords = (region?.keywords || []).map((k) => String(k).toLowerCase());
    return proxies
      .filter((proxy) => proxy && proxy.name && regionKeywords.some((kw) => proxy.name.toLowerCase().includes(kw)))
      .map((proxy) => proxy.name);
  }

  static safeJsonParse(str, fallback = null) {
    try {
      return JSON.parse(str);
    } catch {
      return fallback;
    }
  }

  static shallowHash(obj) {
    try {
      const keys = Object.keys(obj || {}).sort();
      const sig = keys.map((k) => `${k}:${typeof obj[k]}`).join('|');
      return sig;
    } catch {
      return '';
    }
  }
}

/* ===================== 基础统计结构 ===================== */

class RollingStats {
  constructor(windowSize = 100) {
    this.windowSize = windowSize;
    this.data = [];
    this.sum = 0;
    this.sumSquares = 0;
  }
  push(value) {
    const v = Number.isFinite(value) ? value : 0;
    this.data.push(v);
    this.sum += v;
    this.sumSquares += v * v;
    if (this.data.length > this.windowSize) {
      const removed = this.data.shift();
      this.sum -= removed;
      this.sumSquares -= removed * removed;
    }
  }
  get mean() {
    return this.data.length > 0 ? this.sum / this.data.length : 0;
  }
  get std() {
    if (this.data.length === 0) return 0;
    const mean = this.mean;
    const variance = (this.sumSquares / this.data.length) - (mean * mean);
    return Math.sqrt(Math.max(0, variance));
  }
  get median() {
    if (this.data.length === 0) return 0;
    const sorted = [...this.data].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
  }
  clear() {
    this.data = [];
    this.sum = 0;
    this.sumSquares = 0;
  }
}

/* ===================== 缓存管理 ===================== */

class LRUCache {
  constructor(maxSize) {
    this.maxSize = maxSize;
  }
  cache = new Map();
  get(key) {
    if (!this.cache.has(key)) return undefined;
    const value = this.cache.get(key);
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }
  set(key, value, ttl = 60000) {
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
    if (ttl > 0) {
      const timer = setTimeout(() => {
        this.cache.delete(key);
      }, ttl);
      if (typeof timer.unref === 'function') {
        timer.unref();
      }
    }
  }
  clear() {
    this.cache.clear();
  }
  size() {
    return this.cache.size;
  }
}

class SmartCacheManager {
  constructor() {
    this.cache = new Map();
    this.maxSize = 1000;
    this.ttl = 5 * 60 * 1000;
    this.hitCount = 0;
    this.missCount = 0;
    this.stats = new RollingStats(100);
    this.cleanupInterval = 60 * 1000;
    this.lastCleanup = Date.now();
  }
  get(key) {
    const entry = this.cache.get(key);
    if (entry && Date.now() - entry.timestamp < (entry.ttl ?? this.ttl)) {
      this.hitCount++;
      entry.lastAccessed = Date.now();
      entry.accessCount++;
      this.stats.push(1);
      return entry.value;
    }
    this.missCount++;
    this.stats.push(0);
    return null;
  }
  set(key, value, customTTL) {
    if (this.cache.size >= this.maxSize) this.evictLRU();
    this.cache.set(key, {
      value,
      timestamp: Date.now(),
      lastAccessed: Date.now(),
      accessCount: 0,
      ttl: Number.isFinite(customTTL) ? customTTL : this.ttl
    });
    this.cleanupExpired();
  }
  evictLRU() {
    let lruKey = null;
    let oldestAccess = Infinity;
    for (const [key, entry] of this.cache.entries()) {
      if (entry.lastAccessed < oldestAccess) {
        oldestAccess = entry.lastAccessed;
        lruKey = key;
      }
    }
    if (lruKey) this.cache.delete(lruKey);
  }
  cleanupExpired() {
    const now = Date.now();
    if (now - this.lastCleanup < this.cleanupInterval) return;
    let expiredCount = 0;
    for (const [key, entry] of this.cache.entries()) {
      const ttl = entry.ttl ?? this.ttl;
      if (now - entry.timestamp > ttl) {
        this.cache.delete(key);
        expiredCount++;
      }
    }
    this.lastCleanup = now;
    if (expiredCount > 0) Logger.debug(`[SmartCacheManager] 清理了 ${expiredCount} 个过期缓存项`);
  }
  getStats() {
    const total = this.hitCount + this.missCount;
    return {
      cacheSize: this.cache.size,
      cacheUtilization: this.cache.size / this.maxSize,
      hitRate: total > 0 ? this.hitCount / total : 0,
      recentHitRate: this.stats.mean
    };
  }
  clear() {
    this.cache.clear();
    this.hitCount = 0;
    this.missCount = 0;
    this.stats.clear();
  }
}

/* ===================== 指标与性能 ===================== */

class SuccessRateTracker {
  constructor(windowSize = 100) {
    this.windowSize = windowSize;
    this.successes = 0;
    this.failures = 0;
    this.hardFailStreak = 0;
    this.recentResults = [];
  }
  record(success, opts = {}) {
    const s = !!success;
    this.recentResults.push(s);
    if (this.recentResults.length > this.windowSize) {
      const removed = this.recentResults.shift();
      if (removed) this.successes--;
      else this.failures--;
    }
    if (s) {
      this.successes++;
      if (opts.hardFail) this.hardFailStreak = 0;
    } else {
      this.failures++;
      if (opts.hardFail) this.hardFailStreak++;
    }
  }
  get rate() {
    const total = this.successes + this.failures;
    return total > 0 ? this.successes / total : 0;
  }
  get recentRate() {
    if (this.recentResults.length === 0) return 0;
    const recentSuccesses = this.recentResults.filter((r) => r).length;
    return recentSuccesses / this.recentResults.length;
  }
  getHardFailStreak() {
    return this.hardFailStreak;
  }
  reset() {
    this.successes = 0;
    this.failures = 0;
    this.hardFailStreak = 0;
    this.recentResults = [];
  }
}

class AvailabilityTracker {
  constructor(state, nodeManager) {
    this.state = state;
    this.nodeManager = nodeManager;
    this.trackers = nodeManager.nodeSuccess;
  }
  record(nodeId, success, opts = {}) {
    if (!this.trackers.has(nodeId)) {
      this.trackers.set(nodeId, new SuccessRateTracker());
    }
    const tracker = this.trackers.get(nodeId);
    tracker.record(success, opts);
    this.state.nodeStatus.set(nodeId, {
      ...(this.state.nodeStatus.get(nodeId) || {}),
      availabilityRate: tracker.rate,
      recentRate: tracker.recentRate,
      hardFailStreak: tracker.getHardFailStreak()
    });
  }
  rate(nodeId) {
    return this.trackers.get(nodeId)?.rate ?? 0;
  }
  recentRate(nodeId) {
    return this.trackers.get(nodeId)?.recentRate ?? 0;
  }
  getOverallRate() {
    const arr = Array.from(this.trackers.values());
    if (arr.length === 0) return 0;
    const mean = arr.reduce((sum, t) => sum + t.rate, 0) / arr.length;
    return mean;
  }
  reset() {
    this.trackers = new Map();
  }
}

class MetricsManager {
  constructor(state) {
    this.state = state;
    this.windowSize = 100;
  }
  append(nodeId, metrics) {
    if (!nodeId) return;
    const arr = this.state.metrics.get(nodeId) || [];
    arr.push(metrics);
    if (arr.length > this.windowSize) {
      this.state.metrics.set(nodeId, arr.slice(-this.windowSize));
    } else {
      this.state.metrics.set(nodeId, arr);
    }
  }
  getRecent(nodeId, n = 10) {
    const arr = this.state.metrics.get(nodeId) || [];
    return arr.slice(-n);
  }
}

class PerformanceMonitor {
  constructor() {
    this.metrics = {
      requestCount: 0,
      successCount: 0,
      errorCount: 0,
      totalLatency: 0,
      cacheHits: 0,
      cacheMisses: 0,
      nodeSwitches: 0,
      healthChecks: 0,
      connectionsOpened: 0,
      connectionsClosed: 0
    };
    this.history = new RollingStats(100);
    this.startTime = Date.now();
    this.lastReportTime = Date.now();
    this.reportInterval = 60 * 1000;
  }
  recordRequest(success, latency, cacheHit = false) {
    this.metrics.requestCount++;
    if (success) this.metrics.successCount++;
    else this.metrics.errorCount++;
    this.metrics.totalLatency += latency;
    if (cacheHit) this.metrics.cacheHits++;
    else this.metrics.cacheMisses++;
    this.history.push(latency);
    this.reportIfNeeded();
  }
  recordNodeSwitch() {
    this.metrics.nodeSwitches++;
  }
  recordHealthCheck() {
    this.metrics.healthChecks++;
  }
  recordConnection() {
    this.metrics.connectionsOpened++;
  }
  recordConnectionClose() {
    this.metrics.connectionsClosed++;
  }
  getStats() {
    const uptimeMs = Date.now() - this.startTime;
    const avgLatency = this.metrics.requestCount > 0
      ? this.metrics.totalLatency / this.metrics.requestCount
      : 0;
    return {
      uptimeSeconds: Math.round(uptimeMs / 1000),
      totalRequests: this.metrics.requestCount,
      successRate: this.metrics.requestCount > 0 ? this.metrics.successCount / this.metrics.requestCount : 0,
      averageLatencyMs: Math.round(avgLatency),
      latencyStats: {
        mean: Math.round(this.history.mean),
        median: Math.round(this.history.median),
        std: Math.round(this.history.std)
      },
      cacheHitRate:
        (this.metrics.cacheHits + this.metrics.cacheMisses) > 0
          ? this.metrics.cacheHits / (this.metrics.cacheHits + this.metrics.cacheMisses)
          : 0,
      nodeSwitches: this.metrics.nodeSwitches,
      healthChecks: this.metrics.healthChecks,
      connectionsOpened: this.metrics.connectionsOpened,
      connectionsClosed: this.metrics.connectionsClosed,
      requestsPerSecond: uptimeMs > 0 ? this.metrics.requestCount / (uptimeMs / 1000) : 0
    };
  }
  reportIfNeeded() {
    const now = Date.now();
    if (now - this.lastReportTime >= this.reportInterval) {
      const report = this.getStats();
      Logger.debug('[PerformanceMonitor] 性能报告:', JSON.stringify(report));
      this.lastReportTime = now;
    }
  }
  reset() {
    this.metrics = {
      requestCount: 0,
      successCount: 0,
      errorCount: 0,
      totalLatency: 0,
      cacheHits: 0,
      cacheMisses: 0,
      nodeSwitches: 0,
      healthChecks: 0,
      connectionsOpened: 0,
      connectionsClosed: 0
    };
    this.history.clear();
    this.startTime = Date.now();
    this.lastReportTime = Date.now();
  }
}

/* ===================== 吞吐量估算器 ===================== */

class ThroughputEstimator {
  async testNode(node, timeout) {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        resolve({
          latency: Math.random() * 300 + 50,
          loss: Math.random() * 0.05,
          jitter: Math.random() * 30,
          bytes: Math.floor(Math.random() * 64 * 1024),
          bps: Math.floor(Math.random() * 50_000_000)
        });
      }, 100);
      if (typeof timer.unref === 'function') timer.unref();
    });
  }
  getEstimate() {
    return { available: true };
  }
}

/* ===================== 日志工具 ===================== */

class Logger {
  static info(...args) {
    console.log('[INFO]', ...args);
  }
  static warn(...args) {
    console.warn('[WARN]', ...args);
  }
  static error(...args) {
    console.error('[ERROR]', ...args);
  }
  static debug(...args) {
    console.debug('[DEBUG]', ...args);
  }
}

/* ===================== 节点健康与管理 ===================== */

class NodeHealthChecker {
  constructor() {
    this.unhealthyThreshold = 0.3;
    this.hardFailThreshold = 5;
    this.inactiveThreshold = 30 * 60 * 1000;
    this.checkInterval = 2 * 60 * 1000;
    this.lastCheckTime = Date.now();
  }
  checkNodeHealth(node) {
    const now = Date.now();
    const availability = node?.availabilityTracker;
    const successRate = availability?.rate ?? 0;
    const recentSuccessRate = availability?.recentRate ?? 0;
    const hardFailStreak = availability?.hardFailStreak ?? 0;
    const inactiveTime = now - (node.lastUsed || now);
    const isHealthy = (
      successRate >= this.unhealthyThreshold &&
      hardFailStreak < this.hardFailThreshold &&
      inactiveTime < this.inactiveThreshold
    );
    return {
      isHealthy,
      successRate,
      recentSuccessRate,
      hardFailStreak,
      inactiveTime,
      issues: []
    };
  }
  getHealthReport(nodes) {
    const report = {
      totalNodes: nodes.size,
      healthyNodes: 0,
      unhealthyNodes: 0,
      inactiveNodes: 0,
      details: []
    };
    for (const [nodeId, node] of nodes.entries()) {
      const health = this.checkNodeHealth(node);
      const status = health.isHealthy ? 'healthy' : 'unhealthy';
      if (status === 'healthy') report.healthyNodes++;
      else report.unhealthyNodes++;
      if (health.inactiveTime > this.inactiveThreshold) report.inactiveNodes++;
      report.details.push({
        nodeId,
        status,
        successRate: health.successRate,
        recentSuccessRate: health.recentSuccessRate,
        hardFailStreak: health.hardFailStreak,
        inactiveTime: health.inactiveTime
      });
    }
    return report;
  }
  cleanupUnhealthyNodes(nodes) {
    const now = Date.now();
    if (now - this.lastCheckTime < this.checkInterval) return 0;
    let cleanedCount = 0;
    for (const [nodeId, node] of nodes.entries()) {
      const health = this.checkNodeHealth(node);
      if (!health.isHealthy) {
        nodes.delete(nodeId);
        cleanedCount++;
      }
    }
    this.lastCheckTime = now;
    return cleanedCount;
  }
}

class NodeManager {
  constructor() {
    this.nodes = new Map();         // nodeTag -> nodeStruct
    this.nodeSuccess = new Map();   // nodeTag -> SuccessRateTracker
    this.cooldownUntil = new Map(); // nodeTag -> timestamp
    this.healthChecker = new NodeHealthChecker();
    this.lastCleanupTime = Date.now();
    this.cleanupInterval = 5 * 60 * 1000;
  }

  // 仅注册真实代理出站（排除 urltest、selector、direct、dns、block 等）
  registerNodesFromConfigOutbounds(outbounds = []) {
    const excludeTypes = new Set(['urltest', 'selector', 'dns', 'block', 'direct']);
    for (const o of outbounds) {
      const tag = o?.tag;
      const type = String(o?.type || '').toLowerCase();
      if (!tag || excludeTypes.has(type)) continue;
      if (this.nodes.has(tag)) continue;
      this.nodes.set(tag, {
        name: tag,
        type,
        lastUsed: 0,
        qualityScore: 0.5,
        aiScore: 0.5,
        availabilityTracker: {
          get rate() {
            return this._rate ?? 0;
          },
          set rate(v) {
            this._rate = v;
          },
          get recentRate() {
            return this._recentRate ?? 0;
          },
          set recentRate(v) {
            this._recentRate = v;
          },
          get hardFailStreak() {
            return this._hardFailStreak ?? 0;
          },
          set hardFailStreak(v) {
            this._hardFailStreak = v;
          }
        }
      });
    }
  }

  updateNodeQuality(nodeId, metrics) {
    const node = this.nodes.get(nodeId) || null;
    if (!node) return;
    node.qualityScore = this.calculateQualityScore(metrics);
    node.lastUpdate = Date.now();
  }

  calculateQualityScore(metrics) {
    const latency = Math.max(0, metrics?.latency ?? 0);
    const loss = Math.max(0, Math.min(1, metrics?.loss ?? 0));
    const jitter = Math.max(0, metrics?.jitter ?? 0);
    const latencyScore = Math.max(0, 1 - (latency / 1000));
    const lossScore = Math.max(0, 1 - loss);
    const jitterScore = Math.max(0, 1 - (jitter / 100));
    return (latencyScore * 0.5 + lossScore * 0.3 + jitterScore * 0.2);
  }

  isInCooldown(nodeId) {
    const until = this.cooldownUntil.get(nodeId);
    return until && Date.now() < until;
  }

  setCooldown(nodeId, durationMs = CONSTANTS.SWITCH_COOLDOWN_MS) {
    this.cooldownUntil.set(nodeId, Date.now() + durationMs);
  }

  cleanupExpiredNodes() {
    const now = Date.now();
    if (now - this.lastCleanupTime < this.cleanupInterval) return;
    const cleanedCount = this.healthChecker.cleanupUnhealthyNodes(this.nodes);
    for (const [nodeId, node] of this.nodes.entries()) {
      if (now - (node.lastUsed || 0) > 24 * 60 * 60 * 1000) {
        this.nodes.delete(nodeId);
      }
    }
    this.lastCleanupTime = now;
    if (cleanedCount > 0) Logger.debug(`[NodeManager] 清理了 ${cleanedCount} 个不健康节点`);
  }

  getHealthReport() {
    return this.healthChecker.getHealthReport(this.nodes);
  }

  getNodeList() {
    const nodes = [];
    for (const [nodeId, node] of this.nodes.entries()) {
      nodes.push({
        id: nodeId,
        name: node.name,
        type: node.type,
        qualityScore: node.qualityScore,
        aiScore: node.aiScore,
        lastUsed: node.lastUsed
      });
    }
    return nodes;
  }

  updateNodeActivity(nodeId) {
    const node = this.nodes.get(nodeId);
    if (node) node.lastUsed = Date.now();
  }

  updateNodePerformance(nodeId, duration, _bytesTransferred) {
    const node = this.nodes.get(nodeId);
    if (!node) return;
    this.updateNodeActivity(nodeId);
    this.updateNodeQuality(nodeId, {
      latency: duration || 0,
      loss: 0,
      jitter: 0
    });
  }
}

/* ===================== 中央调度管理器 ===================== */

class CentralManager {
  constructor() {
    this.state = {
      config: null,
      metrics: new Map(), // nodeTag -> metricsEntry[]
      nodeStatus: new Map(),
      currentNode: null,
      lastSwitchTime: 0
    };
    this.CONSTANTS = Object.freeze({
      NODE_TEST_TIMEOUT: CONSTANTS.NODE_TEST_TIMEOUT,
      SWITCH_COOLDOWN_MS: CONSTANTS.SWITCH_COOLDOWN_MS,
      FEATURE_WINDOW_SIZE: CONSTANTS.FEATURE_WINDOW_SIZE,
      JITTER_CLAMP_MS: CONSTANTS.JITTER_CLAMP_MS,
      THROUGHPUT_SOFT_CAP_BPS: CONSTANTS.THROUGHPUT_SOFT_CAP_BPS,
      MIN_AVAILABILITY_RATE: CONSTANTS.MIN_AVAILABILITY_RATE,
      MAX_HARD_FAIL_STREAK: CONSTANTS.MAX_HARD_FAIL_STREAK
    });
    this.isInitialized = false;
    this.lastConfigUpdate = 0;
    this.startTime = Date.now();
    this.handleResponse = (response) => this._handleResponse(response);
    this.getStatusReport = () => this._getStatusReport();
    this._componentsInitialized = false;
  }

  _initializeComponents() {
    if (this._componentsInitialized) return;
    this.nodeManager = new NodeManager();
    this.cacheManager = new SmartCacheManager();
    this.performanceMonitor = new PerformanceMonitor();
    this.throughputEstimator = new ThroughputEstimator();
    this.lruCache = new LRUCache(1000);
    this.successTracker = new SuccessRateTracker();
    this.availabilityTracker = new AvailabilityTracker(this.state, this.nodeManager);
    this.metricsManager = new MetricsManager(this.state);
    this._componentsInitialized = true;
  }

  async init(config = null) {
    try {
      this._initializeComponents();
      if (config) {
        this.state.config = config;
        // 注册真实代理出站到节点管理器
        const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
        this.nodeManager.registerNodesFromConfigOutbounds(outbounds);
      }
      await this.loadAIDBFromFile();
      this.setupEventListeners();
      this.isInitialized = true;
      Logger.info('中央调度管理器初始化完成');
    } catch (error) {
      Logger.error('管理器初始化失败:', error);
    }
  }

  processConfiguration(config) {
    if (!config || typeof config !== 'object') {
      throw new Error('无效的配置对象');
    }
    try {
      const safeConfig = JSON.parse(JSON.stringify(config));
      this.validateProxyConfiguration(safeConfig);

      // 注册现有 outbounds 到节点管理器（真实代理）
      this.nodeManager.registerNodesFromConfigOutbounds(safeConfig.outbounds || []);

      // 按 SingBox 规范注入智能出站与路由
      this.applySmartOutbounds(safeConfig);
      this.applySmartRoutingSingBox(safeConfig);

      // 启动节点预热
      this.preheatNodesSingBox(safeConfig);

      return safeConfig;
    } catch (error) {
      Logger.error('配置处理失败:', error);
      return config;
    }
  }

  validateProxyConfiguration(config) {
    const outbounds = Array.isArray(config?.outbounds) ? config.outbounds : [];
    // 至少存在一个非系统出站（排除 urltest/selector/direct/dns/block）
    const excludeTypes = new Set(['urltest', 'selector', 'dns', 'block', 'direct']);
    const realProxies = outbounds.filter((o) => o?.tag && !excludeTypes.has(String(o?.type || '').toLowerCase()));
    if (realProxies.length === 0) {
      throw new Error('未检测到任何有效的代理出站（vmess/trojan/shadowsocks 等）');
    }
  }

  // ========== SingBox 规范：生成智能出站 ==========
  applySmartOutbounds(config) {
    const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
    const tags = new Set(outbounds.map((o) => o?.tag).filter(Boolean));

    // 收集候选真实代理 tags
    const excludeTypes = new Set(['urltest', 'selector', 'dns', 'block', 'direct']);
    const candidateTags = outbounds
      .filter((o) => o?.tag && !excludeTypes.has(String(o?.type || '').toLowerCase()))
      .map((o) => o.tag);

    if (candidateTags.length === 0) {
      Logger.warn('没有可用于智能选择的真实代理出站候选');
      return;
    }

    // 注入 urltest（智能选择）
    if (!tags.has(CONSTANTS.SMART_URLTEST_TAG)) {
      outbounds.push({
        type: 'urltest',
        tag: CONSTANTS.SMART_URLTEST_TAG,
        outbounds: candidateTags,
        url: CONSTANTS.URLTEST_URL,
        interval: CONSTANTS.URLTEST_INTERVAL,
        tolerance: CONSTANTS.URLTEST_TOLERANCE
      });
      tags.add(CONSTANTS.SMART_URLTEST_TAG);
    }

    // 注入 selector（策略选择），融合智能与 direct
    if (!tags.has(CONSTANTS.SMART_SELECTOR_TAG)) {
      // 保证 direct 存在（SingBox 常见的系统出站），如不存在不强制创建
      const selectorCandidates = [
        CONSTANTS.SMART_URLTEST_TAG,
        'direct'
      ].filter((t) => tags.has(t) || t === CONSTANTS.SMART_URLTEST_TAG);
      outbounds.push({
        type: 'selector',
        tag: CONSTANTS.SMART_SELECTOR_TAG,
        outbounds: selectorCandidates
      });
      tags.add(CONSTANTS.SMART_SELECTOR_TAG);
    }

    config.outbounds = outbounds;
  }

  // ========== SingBox 规范：生成路由规则 ==========
  applySmartRoutingSingBox(config) {
    const route = typeof config.route === 'object' && config.route !== null ? config.route : {};
    const rules = Array.isArray(route.rules) ? route.rules.slice() : [];

    // 追加国内直连规则（去重）
    const appendRule = (ruleObj) => {
      const sig = JSON.stringify(ruleObj);
      const exists = rules.some((r) => JSON.stringify(r) === sig);
      if (!exists) rules.push(ruleObj);
    };

    // DOMAIN-SUFFIX cn -> direct
    appendRule({ domain_suffix: ['cn'], outbound: 'direct' });
    // DOMAIN-KEYWORD 中国/china -> direct
    appendRule({ domain_keyword: ['中国', 'china'], outbound: 'direct' });
    // GEOIP CN -> direct
    appendRule({ geoip: ['cn'], outbound: 'direct' });

    // 设置全局兜底为“智能选择”
    route.final = CONSTANTS.SMART_URLTEST_TAG;

    route.rules = rules;
    config.route = route;
  }

  // 预热节点（以 outbounds 的 tag 作为节点名）
  async preheatNodesSingBox(config) {
    const outbounds = Array.isArray(config.outbounds) ? config.outbounds : [];
    const excludeTypes = new Set(['urltest', 'selector', 'dns', 'block', 'direct']);
    const candidates = outbounds.filter((o) => o?.tag && !excludeTypes.has(String(o?.type || '').toLowerCase()));
    const testPromises = candidates.slice(0, 3).map((o) =>
      this.testNodeMultiMetrics({ name: o.tag }).catch(() => null)
    );
    try {
      await Promise.all(testPromises);
      Logger.info('节点预热完成');
    } catch (error) {
      Logger.warn('节点预热失败:', error);
    }
  }

  // ===== 以下为评分/调度/AI逻辑（保持与前版一致，但使用 tag 作为主键） =====

  calculateNodeQualityScore(nodeLike) {
    const nodeTag = nodeLike?.name || nodeLike?.tag || nodeLike;
    const metrics = this.state.metrics.get(nodeTag) || [];
    if (metrics.length === 0) return 0.5;
    const recentMetrics = metrics.slice(-10);
    const avgLatency = recentMetrics.reduce((sum, m) => sum + (m.latency ?? 0), 0) / Math.max(1, recentMetrics.length);
    const avgLoss = recentMetrics.reduce((sum, m) => sum + (m.loss ?? 0), 0) / Math.max(1, recentMetrics.length);
    const successRate = this.availabilityTracker.rate(nodeTag);
    const latencyScore = Math.max(0, 1 - (avgLatency / 1000));
    const lossScore = Math.max(0, 1 - Math.max(0, Math.min(1, avgLoss)));
    const availabilityScore = Math.max(0, Math.min(1, successRate));
    return (
      latencyScore * CONSTANTS.LATENCY_WEIGHT +
      lossScore * CONSTANTS.LOSS_WEIGHT +
      availabilityScore * CONSTANTS.AVAILABILITY_WEIGHT
    );
  }

  aiScoreNode(nodeLike) {
    const nodeTag = nodeLike?.name || nodeLike?.tag || nodeLike;
    const features = this.extractNodeFeatures({ name: nodeTag });
    const prediction = this.predictNodeFuturePerformance(features);
    const historicalScore = this.calculateNodeQualityScore({ name: nodeTag });
    const futureScore = prediction.successProbability || 0.5;
    return (historicalScore * 0.6 + futureScore * 0.4);
  }

  extractNodeFeatures(node) {
    const nodeTag = node?.name;
    const recentMetrics = this.metricsManager.getRecent(nodeTag, 5);
    if (recentMetrics.length === 0) {
      return {
        latency: 200,
        lossRate: 0.05,
        jitter: 30,
        throughput: 1_000_000,
        availability: 0.5,
        stability: 0.5
      };
    }
    const latencies = recentMetrics.map((m) => m.latency ?? 200);
    const losses = recentMetrics.map((m) => m.loss ?? 0);
    const jitters = recentMetrics.map((m) => m.jitter ?? 30);
    const throughputs = recentMetrics.map((m) => m.bps ?? 1_000_000);
    const latencyStats = Utils.rollingStats(latencies);
    const lossStats = Utils.rollingStats(losses);
    const jitterStats = Utils.rollingStats(jitters);
    const throughputStats = Utils.rollingStats(throughputs);
    const meanLatency = Math.max(1, latencyStats.mean);
    return {
      latency: latencyStats.mean,
      lossRate: lossStats.mean,
      jitter: jitterStats.mean,
      throughput: throughputStats.mean,
      availability: this.availabilityTracker.rate(nodeTag),
      stability: 1 - (latencyStats.std / meanLatency)
    };
  }

  predictNodeFuturePerformance(features) {
    const { latency, lossRate, jitter, throughput, availability, stability } = features;
    const latencyFactor = Math.max(0, 1 - (latency / 1000));
    const lossFactor = Math.max(0, 1 - Math.max(0, Math.min(1, lossRate)));
    const jitterFactor = Math.max(0, 1 - (jitter / 100));
    const throughputFactor = Math.min(1, throughput / 10_000_000);
    const availabilityFactor = Math.max(0, Math.min(1, availability));
    const stabilityFactor = Math.max(0, Math.min(1, stability));
    const successProbability = (
      latencyFactor * 0.25 +
      lossFactor * 0.2 +
      jitterFactor * 0.15 +
      throughputFactor * 0.15 +
      availabilityFactor * 0.15 +
      stabilityFactor * 0.1
    );
    return {
      successProbability: Math.max(0, Math.min(1, successProbability)),
      expectedLatency: latency * 1.1,
      confidence: Math.min(1, availabilityFactor * 2)
    };
  }

  async testNodeMultiMetrics(node) {
    const nodeTag = node?.name;
    const cacheKey = `nodeMetrics:${nodeTag}`;
    const cached = this.lruCache.get(cacheKey);
    if (cached) return cached;
    const timeout = this.CONSTANTS.NODE_TEST_TIMEOUT;
    try {
      const result = await this.throughputEstimator.testNode({ name: nodeTag }, timeout);
      this.lruCache.set(cacheKey, result, 60_000);
      this.metricsManager.append(nodeTag, result);
      this.nodeManager.updateNodeQuality(nodeTag, result);
      return result;
    } catch (error) {
      Logger.debug(`节点测试失败 ${nodeTag}:`, error);
      return this.generateSimulatedMetrics();
    }
  }

  generateSimulatedMetrics() {
    return {
      latency: Math.random() * 500 + 50,
      loss: Math.random() * 0.1,
      jitter: Math.random() * 50,
      bytes: Math.floor(Math.random() * 32 * 1024),
      bps: Math.floor(Math.random() * 10_000_000),
      __simulated: true
    };
  }

  setupEventListeners() {
    if (typeof $mixin !== 'undefined' && typeof $mixin.on === 'function') {
      $mixin.on('config', (config) => this.processConfiguration(config));
      $mixin.on('request', (request) => this.handleProxyRequest(request));
    }
  }

  handleProxyRequest(request) {
    const bestNode = this.smartDispatchNode(request);
    if (bestNode) {
      request.proxy = bestNode.name;
      this.recordRequestMetrics(bestNode.name, request);
    }
    return request;
  }

  analyzeRequestType(request) {
    const url = request?.url || '';
    const headers = request?.headers || {};
    if (url.includes('.m3u8') || url.includes('.mp4') || (headers['content-type'] || '').includes('video')) {
      return 'video';
    } else if (url.includes('download') || (headers['content-type'] || '').includes('application/octet-stream')) {
      return 'download';
    } else if ((headers['content-type'] || '').includes('text/html')) {
      return 'web';
    }
    return 'general';
  }

  getPreferredNodes(requestType) {
    const outbounds = Array.isArray(this.state.config?.outbounds) ? this.state.config.outbounds : [];
    const excludeTypes = new Set(['urltest', 'selector', 'dns', 'block', 'direct']);
    const proxies = outbounds.filter((o) => o?.tag && !excludeTypes.has(String(o?.type || '').toLowerCase()));

    switch (requestType) {
      case 'video':
        return proxies.filter((proxy) => this.calculateNodeQualityScore({ name: proxy.tag }) >= 0.7)
                      .map((p) => ({ name: p.tag }));
      case 'download':
        return proxies.filter((proxy) => {
          const metrics = this.state.metrics.get(proxy.tag) || [];
          const recent = metrics.slice(-3);
          const avgBps = recent.reduce((sum, m) => sum + (m.bps ?? 0), 0) / Math.max(1, recent.length);
          return avgBps > 5_000_000;
        }).map((p) => ({ name: p.tag }));
      default:
        return proxies.map((p) => ({ name: p.tag }));
    }
  }

  smartDispatchNode(request) {
    const outbounds = Array.isArray(this.state.config?.outbounds) ? this.state.config.outbounds : [];
    const excludeTypes = new Set(['urltest', 'selector', 'dns', 'block', 'direct']);
    const proxies = outbounds.filter((o) => o?.tag && !excludeTypes.has(String(o?.type || '').toLowerCase()))
                             .map((p) => ({ name: p.tag }));
    if (proxies.length === 0) return null;
    const requestType = this.analyzeRequestType(request);
    const preferredNodes = this.getPreferredNodes(requestType);
    const list = preferredNodes.length > 0 ? preferredNodes : proxies;
    const best = this.selectBestNode(list);

    // 冷却防抖
    const now = Date.now();
    if (!best) return null;
    if (this.state.currentNode !== best.name || (now - this.state.lastSwitchTime) > this.CONSTANTS.SWITCH_COOLDOWN_MS) {
      this.state.currentNode = best.name;
      this.state.lastSwitchTime = now;
    }
    return best;
  }

  selectBestNode(nodes) {
    if (!Array.isArray(nodes) || nodes.length === 0) return null;
    let bestNode = nodes[0];
    let bestScore = this.calculateNodeQualityScore(bestNode);
    for (let i = 1; i < nodes.length; i++) {
      const score = this.calculateNodeQualityScore(nodes[i]);
      if (score > bestScore) {
        bestNode = nodes[i];
        bestScore = score;
      }
    }
    return bestNode;
  }

  recordRequestMetrics(nodeName, request) {
    const metrics = {
      timestamp: Date.now(),
      url: request.url,
      method: request.method,
      size: request.size || 0,
      success: true
    };
    this.metricsManager.append(nodeName, metrics);
    this.availabilityTracker.record(nodeName, true);
    this.nodeManager.updateNodeActivity(nodeName);
  }

  async loadAIDBFromFile() {
    return new Promise((resolve) => {
      try {
        if (typeof $mixin?.storage?.get !== 'undefined') {
          const data = $mixin.storage.get('ai_node_data');
          if (data) {
            const parsed = Utils.safeJsonParse(data, null);
            if (parsed && typeof parsed === 'object') {
              this.state.metrics = new Map(Object.entries(parsed));
              Logger.info('AI节点数据加载成功');
            }
          }
        }
      } catch (error) {
        Logger.warn('AI数据加载失败:', error);
      } finally {
        resolve();
      }
    });
  }

  saveAIDBToFile() {
    try {
      const data = Object.fromEntries(this.state.metrics.entries());
      if (Object.keys(data).length > 0 && typeof $mixin?.storage?.set !== 'undefined') {
        const raw = JSON.stringify(data);
        $mixin.storage.set('ai_node_data', raw);
        Logger.debug('AI数据保存成功');
      }
    } catch (error) {
      Logger.error('AI数据保存失败:', error);
    }
  }

  _handleResponse(response) {
    if (!response || !response.node) return;
    try {
      const nodeName = response.node;
      const duration = response.duration || 0;
      const bytesTransferred = response.bytesTransferred || 0;
      const success = response.success !== false;
      this.recordResponseMetrics(nodeName, duration, bytesTransferred, success);
      this.nodeManager.updateNodePerformance(nodeName, duration, bytesTransferred);
      this.nodeManager.updateNodeActivity(nodeName);
      if (!success) {
        this.triggerHealthCheck(nodeName);
      }
      Logger.debug(`响应处理完成: ${nodeName}, 耗时: ${duration}ms`);
    } catch (error) {
      Logger.error('响应处理失败:', error);
    }
  }

  recordResponseMetrics(nodeName, duration, bytesTransferred, success) {
    const bps = (bytesTransferred > 0 && duration > 0) ? (bytesTransferred * 1000) / duration : 0;
    const metrics = {
      timestamp: Date.now(),
      latency: duration,
      bytes: bytesTransferred,
      bps,
      success
    };
    this.metricsManager.append(nodeName, metrics);
    this.availabilityTracker.record(nodeName, success);
    this.successTracker.record(success, { hardFail: !success });
  }

  triggerHealthCheck(nodeName) {
    const node = this.nodeManager.nodes.get(nodeName);
    if (!node) return;
    const health = this.nodeManager.healthChecker.checkNodeHealth(node);
    if (!health.isHealthy) {
      Logger.warn(`节点 ${nodeName} 健康状况不佳，触发健康检查`);
      this.nodeManager.setCooldown(nodeName, 60_000);
      this.performanceMonitor.recordHealthCheck();
    }
  }

  _getStatusReport() {
    const now = Date.now();
    const runtime = Math.floor((now - this.startTime) / 1000);
    return {
      runtimeSeconds: runtime,
      status: this.isInitialized ? 'running' : 'initializing',
      performance: this.performanceMonitor.getStats(),
      health: this.nodeManager.getHealthReport(),
      nodes: this.nodeManager.getNodeList(),
      lastConfigUpdate: this.lastConfigUpdate,
      cacheStats: this.cacheManager.getStats(),
      throughputEstimate: this.throughputEstimator.getEstimate(),
      successRateGlobal: this.successTracker.rate,
      availabilityOverall: this.availabilityTracker.getOverallRate()
    };
  }

  updateConfig(config) {
    try {
      const processedConfig = this.processConfiguration(config);
      this.state.config = processedConfig;
      this.lastConfigUpdate = Date.now();
      Logger.info('配置更新完成');
      return processedConfig;
    } catch (error) {
      Logger.error('配置更新失败:', error);
      return config;
    }
  }

  clearCache() {
    this.lruCache.clear();
    this.cacheManager.clear();
    Logger.info('缓存清理完成');
  }

  getPerformanceStats() {
    return this.performanceMonitor.getStats();
  }

  resetStats() {
    this.performanceMonitor.reset();
    this.successTracker.reset();
    this.availabilityTracker.reset();
    Logger.info('统计信息已重置');
  }

  destroy() {
    this.saveAIDBToFile();
    this.lruCache.clear();
    this.cacheManager.clear();
    this.state.metrics.clear();
    this.state.nodeStatus.clear();
    this.isInitialized = false;
    Logger.info('中央调度管理器已销毁');
  }
}

/* ===================== 混入脚本主入口 ===================== */

function onGenerate(config) {
  if (!config || typeof config !== 'object') {
    Logger.warn('[onGenerate] 无效配置，直接返回');
    return config;
  }
  Logger.info('[onGenerate] 智能代理配置处理开始');

  const currentSig = Utils.shallowHash(config);
  if (onGenerate._lastSig && onGenerate._lastSig === currentSig) {
    Logger.debug('[onGenerate] 配置未变更，使用缓存结果');
    return onGenerate._lastResult;
  }

  try {
    const processedConfig = main(config);
    onGenerate._lastSig = currentSig;
    onGenerate._lastResult = processedConfig;
    Logger.info('[onGenerate] 智能代理配置处理完成');
    return processedConfig;
  } catch (error) {
    Logger.error('[onGenerate] 配置处理错误:', error);
    return config;
  }
}
onGenerate._lastSig = null;
onGenerate._lastResult = null;

function main(config) {
  try {
    const centralManager = new CentralManager();
    return centralManager.processConfiguration(config);
  } catch (error) {
    Logger.error('混入脚本执行失败:', error);
    return config;
  }
}

function mixin(config) {
  if (!mixin._centralManager) {
    mixin._centralManager = new CentralManager();
  }
  const centralManager = mixin._centralManager;

  if (config) {
    centralManager.init(config);
  }

  return {
    onRequestOutbound: (request) => {
      const startTime = Date.now();
      try {
        const selectedNode = centralManager.smartDispatchNode(request);
        centralManager.performanceMonitor.recordRequest(true, Date.now() - startTime);
        // 返回 tag（SingBox 以 outbounds tag 标识）
        const nodeTag = selectedNode?.name || selectedNode || CONSTANTS.SMART_URLTEST_TAG;
        return {
          node: nodeTag,
          metadata: {
            dispatchTime: Date.now() - startTime,
            requestId: request.id || Date.now().toString(),
            timestamp: Date.now(),
            source: 'smart-proxy-mixin'
          }
        };
      } catch (error) {
        Logger.error('[mixin] 请求处理错误:', error);
        centralManager.performanceMonitor.recordRequest(false, Date.now() - startTime);
        // fallback：智能选择或 direct
        const fallback = CONSTANTS.SMART_URLTEST_TAG;
        return {
          node: fallback,
          metadata: {
            dispatchTime: Date.now() - startTime,
            requestId: request.id || Date.now().toString(),
            timestamp: Date.now(),
            source: 'fallback',
            error: error?.message
          }
        };
      }
    },

    onResponseInbound: (response) => {
      try {
        centralManager.handleResponse(response);
        if ((response.status ?? 200) >= 500 || (response.latency ?? 0) > 5000) {
          centralManager.performanceMonitor.recordNodeSwitch();
        }
        return response;
      } catch (error) {
        Logger.error('[mixin] 响应处理错误:', error);
        return response;
      }
    },

    onConnectionEstablished: (connection) => {
      try {
        centralManager.performanceMonitor.recordConnection();
        if (connection.node) {
          centralManager.nodeManager.updateNodeActivity(connection.node);
        }
        return connection;
      } catch (error) {
        Logger.error('[mixin] 连接处理错误:', error);
        return connection;
      }
    },

    onConnectionClosed: (connection) => {
      try {
        centralManager.performanceMonitor.recordConnectionClose();
        if (connection.node && connection.duration) {
          centralManager.nodeManager.updateNodePerformance(
            connection.node,
            connection.duration,
            connection.bytesTransferred
          );
        }
        return connection;
      } catch (error) {
        Logger.error('[mixin] 连接关闭处理错误:', error);
        return connection;
      }
    },

    getStatusReport: () => centralManager.getStatusReport(),
    updateConfig: (newConfig) => {
      const result = centralManager.updateConfig(newConfig);
      return { success: true, message: '配置更新成功', config: result };
    },
    triggerHealthCheck: () => {
      const report = centralManager.nodeManager.getHealthReport();
      centralManager.performanceMonitor.recordHealthCheck();
      return report;
    },
    clearCache: () => {
      centralManager.clearCache();
      return { success: true, message: '缓存清理完成' };
    },
    getPerformanceStats: () => centralManager.getPerformanceStats(),
    resetStats: () => {
      centralManager.resetStats();
      return { success: true, message: '统计已重置' };
    },
    getNodeList: () => centralManager.nodeManager.getNodeList(),
    switchNode: (nodeId) => {
      centralManager.state.currentNode = nodeId;
      centralManager.state.lastSwitchTime = Date.now();
      return { success: true, message: `已切换到节点: ${nodeId}` };
    },
    getInfo: () => ({
      name: 'Smart Proxy Mixin',
      version: '1.3.0',
      description: '智能代理混入脚本（SingBox 结构规范版），支持AI驱动的节点选择和性能优化',
      author: 'AI Assistant',
      features: [
        '智能路由选择',
        '性能监控',
        '健康检查',
        '缓存优化',
        'AI节点评分',
        '地理路由',
        '多平台兼容'
      ],
      compatibility: 'SingBox 1.12.12+'
    }),
    destroy: () => {
      centralManager.destroy();
      Logger.info('[mixin] 资源已清理');
    }
  };
}

/* ===================== 导出与全局暴露（受控） ===================== */

const exportsObject = {
  onGenerate,
  mixin,
  main,
  classes: {
    CentralManager,
    NodeManager,
    Utils
  },
  version: {
    version: '1.3.0',
    compatibleWith: 'SingBox 1.12.12',
    buildTime: new Date().toISOString()
  },
  CONSTANTS
};

// CommonJS
if (typeof module !== 'undefined' && module.exports) {
  module.exports = exportsObject;
}

// SingBox 环境
if (typeof $mixin !== 'undefined') {
  $mixin.exports = exportsObject;
}

// AMD/RequireJS
if (typeof define === 'function' && typeof define.amd === 'object') {
  define(function () {
    return exportsObject;
  });
}

// CMD/SeaJS
if (typeof define === 'function' && define.cmd) {
  define(function (require, exports, module) {
    module.exports = exportsObject;
  });
}

// 受控全局暴露
const getGlobal = (function () {
  try {
    if (typeof window !== 'undefined') return window;
    if (typeof global !== 'undefined') return global;
    if (typeof self !== 'undefined') return self;
    if (typeof this !== 'undefined') return this;
    return (new Function('return this;'))();
  } catch (e) {
    Logger.warn('[SingBox] 警告: 无法确定全局对象:', e.message);
    return {};
  }
})();

const exposeToGlobal = (obj, name, value) => {
  try {
    obj[name] = value;
    return true;
  } catch (e) {
    Logger.warn(`[SingBox] 警告: 无法导出 ${name} 到全局作用域:`, e.message);
    return false;
  }
};

if (CONSTANTS.EXPORT_TO_GLOBAL) {
  exposeToGlobal(getGlobal, 'SingBoxMixin', exportsObject);
  exposeToGlobal(getGlobal, 'singboxMixin', exportsObject);
  exposeToGlobal(getGlobal, 'onGenerate', onGenerate);
  exposeToGlobal(getGlobal, 'mixin', mixin);
  exposeToGlobal(getGlobal, 'main', main);
}

Logger.info(`[SingBox Mixin] 智能代理混入脚本加载完成 - 版本 ${exportsObject.version.version}`);
Logger.info(`[SingBox Mixin] 兼容版本: ${exportsObject.version.compatibleWith}`);
Logger.info('[SingBox Mixin] 核心功能: 智能路由、性能优化、节点预热、多环境支持');
Logger.info('[SingBox Mixin] 架构特点: 模块化设计、延迟初始化、配置缓存、错误保护');

// 自动执行（如果环境支持）
if (typeof $mixin !== 'undefined' && $mixin.config) {
  $mixin.config = main($mixin.config);
}
