"use strict";
// ========== 重要维护提示 ==========
// 所有后续新增的变量、函数、类、常量等，必须在本文件中显式定义，严禁未定义直接调用，防止ReferenceError: not defined等运行时错误。
// 如有跨文件依赖，需在本文件顶部或相关位置补充声明或导入。
// 本文件采用事件触发驱动机制，禁制使用使用定时机制和逻辑。
// ===================================

// 全局常量定义 - 集中管理所有常量，提高可维护性
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
  FEATURE_WINDOW_SIZE: 10,
  ENABLE_SCORE_DEBUGGING: false // 可调试开关
  ,QUALITY_WEIGHT: 0.5,
  METRIC_WEIGHT: 0.35,
  SUCCESS_WEIGHT: 0.15
};


// 事件发射器基类 - 提供事件监听和触发功能
class EventEmitter {
  constructor() {
    this.eventListeners = new Map(); // 使用Map确保方法兼容性
  }

  /**
   * 添加事件监听
   * @param {string} event - 事件名称
   * @param {Function} listener - 监听器函数
   */
  on(event, listener) {
    if (!this.eventListeners.has(event)) {
      this.eventListeners.set(event, []);
    }
    this.eventListeners.get(event).push(listener);
  }

  /**
   * 移除事件监听
   * @param {string} event - 事件名称
   * @param {Function} listener - 监听器函数
   */
  off(event, listener) {
    if (!this.eventListeners.has(event)) return;
    const listeners = this.eventListeners.get(event);
    const index = listeners.indexOf(listener);
    if (index !== -1) listeners.splice(index, 1);
    if (listeners.length === 0) this.eventListeners.delete(event);
  }

  /**
   * 触发事件
   * @param {string} event - 事件名称
   * @param {...*} args - 传递给监听器的参数
   */
  emit(event, ...args) {
    if (!this.eventListeners.has(event)) return;
    // 创建监听器副本以防止在触发过程中修改数组
    [...this.eventListeners.get(event)].forEach(listener => {
      try {
        listener(...args);
      } catch (error) {
        Logger.error(`事件 ${event} 处理失败:`, error.stack);
      }
    });
  }

  /**
   * 移除所有事件监听
   * @param {string} [event] - 可选的事件名称，如果提供，则只移除该事件的所有监听器
   */
  removeAllListeners(event) {
    if (event) {
      this.eventListeners.delete(event);
    } else {
      this.eventListeners.clear();
    }
  }
}

class AppState {
  constructor() {
    this.nodes = new Map();
    this.metrics = new Map();
    this.config = {};
    this.lastUpdated = Date.now();
  }

  /**
   * 更新节点状态
   * @param {string} nodeId - 节点ID
   * @param {Object} status - 节点状态
   */
  updateNodeStatus(nodeId, status) {
    this.nodes.set(nodeId, { ...this.nodes.get(nodeId), ...status });
    this.lastUpdated = Date.now();
  }
}

// 注意：工具函数集合在文件下方以 `const Utils = { ... }` 形式定义，
// 这里不再定义重复的 `Utils` 类，后续已将并发/重试功能合并到该对象中以保持兼容性。

class LRUCache {
  // 增强：添加默认值和动态调整逻辑
  constructor({ maxSize = CONSTANTS.LRU_CACHE_MAX_SIZE, ttl = CONSTANTS.LRU_CACHE_TTL } = {}) { // 添加定时清理机制
    this.cache = new Map();
    this.maxSize = maxSize;
    this.ttl = ttl;
    this.head = { key: null, value: null, prev: null, next: null };
    this.tail = { key: null, value: null, prev: this.head, next: null };
    this.head.next = this.tail;
  }

  /**
   * 从双向链表中移除指定条目（不负责从 Map 中删除）
   */
  _removeEntry(node) {
    if (!node) return;
    try {
      if (node.prev) node.prev.next = node.next;
      if (node.next) node.next.prev = node.prev;
      node.prev = null;
      node.next = null;
    } catch (e) {
      // 忽略链表修正错误，防止抛出
    }
  }

  _moveToFront(node) {
    if (!node) return;
    // 如果节点尚未在链表中则忽略
    if (!node.prev || !node.next) return;
    try {
      node.prev.next = node.next;
      node.next.prev = node.prev;
      node.next = this.head.next;
      node.prev = this.head;
      if (this.head.next) this.head.next.prev = node;
      this.head.next = node;
    } catch (e) {
      // 忽略链表重排的异常，保持缓存稳定性
    }
  }

  _removeTail() {
    const node = this.tail.prev;
    if (!node || node === this.head) return null;
    // 使用统一移除方法
    this._removeEntry(node);
    const key = node.key;
    this.cache.delete(key);
    return key;
  }

  /**
   * 获取缓存
   * @param {string} key - 缓存键
   * @returns {*} 缓存值
   */
  get(key) {
    const entry = this.cache.get(key);
    if (!entry || Date.now() - entry.timestamp > entry.ttl) {
      if (entry) {
        // 从链表中安全移除并删除缓存项
        this._removeEntry(entry);
        this.cache.delete(key);
      }
      return null;
    }
    this._moveToFront(entry);
    entry.timestamp = Date.now();
    return entry.value;
  }

  /**
   * 设置缓存
   * @param {string} key - 缓存键
   * @param {*} value - 缓存值
   * @param {number} [ttl=this.ttl] - 缓存时间
   */
  set(key, value, ttl = this.ttl) {
    this._cleanupExpiredEntries(); // 事件驱动清理：添加新条目时清理过期项
    if (this.cache.has(key)) {
      const entry = this.cache.get(key);
      entry.value = value;
      entry.timestamp = Date.now();
      this._moveToFront(entry);
      return;
    }

    if (this.cache.size >= this.maxSize) {
      const removedKey = this._removeTail();
      if (removedKey) Logger.debug(`LRU 移除键: ${removedKey}`);
    }

    const newNode = {
      key,
      value,
      timestamp: Date.now(),
      ttl: ttl,
      prev: this.head,
      next: this.head.next
    };
    this.head.next.prev = newNode;
    this.head.next = newNode;
    this.cache.set(key, newNode);
  }

  _cleanupExpiredEntries(limit = 100) {
    const now = Date.now();
    let cleaned = 0;
    let iterations = 0;
    const maxIterations = Math.min(this.cache.size, limit * 2); // 限制最大迭代次数
    const keysToDelete = [];
    for (const [key, entry] of this.cache) {
      iterations++;
      if (now - entry.timestamp > entry.ttl) {
        keysToDelete.push(key);
        cleaned++;
        if (cleaned >= limit) break; // 达到清理上限，退出循环
      }
      if (iterations >= maxIterations) break; // 达到最大迭代次数，退出循环
    }

    // 安全移除缓存项并修正链表
    for (const key of keysToDelete) {
      const entry = this.cache.get(key);
      if (entry) this._removeEntry(entry);
      this.cache.delete(key);
    }
    
    if (cleaned > 0) Logger.debug(`清理了 ${cleaned} 个过期缓存项`);
  }

  /**
   * 清空缓存
   */
  clear() {
    this.cache.clear();
    this.head.next = this.tail;
    this.tail.prev = this.head;
  }

  /**
   * 删除指定键
   * @param {string} key
   */
  delete(key) {
    const entry = this.cache.get(key);
    if (!entry) return false;
    this._removeEntry(entry);
    this.cache.delete(key);
    return true;
  }
}
class RollingStats {
  constructor(windowSize = 100) {
    this.windowSize = windowSize;
    this.data = new Array(windowSize).fill(0);
    this.index = 0;
    this.count = 0;
    this.sum = 0;
  }

  /**
   * 添加数据（保持 O(1) 平均计算）
   * @param {number} value - 数值
   */
  add(value) {
    value = Number(value) || 0;
    if (this.count < this.windowSize) {
      this.data[this.index] = value;
      this.sum += value;
      this.count++;
    } else {
      const prev = this.data[this.index] || 0;
      this.data[this.index] = value;
      this.sum += value - prev;
    }
    this.index = (this.index + 1) % this.windowSize;
  }

  /**
   * 获取平均值
   * @returns {number} 平均值
   */
  get average() {
    return this.count ? this.sum / this.count : 0;
  }

  /**
   * 重置
   */
  reset() {
    this.data.fill(0);
    this.index = 0;
    this.count = 0;
    this.sum = 0;
  }
}

class SuccessRateTracker {
  constructor() {
    this.successCount = 0;
    this.totalCount = 0;
  }

  /**
   * 记录成功或失败
   * @param {boolean} success - 是否成功
   */
  record(success) {
    this.totalCount++;
    if (success) this.successCount++;
  }

  /**
   * 获取成功率
   * @returns {number} 成功率
   */
  get rate() {
    return this.totalCount ? this.successCount / this.totalCount : 0;
  }

  /**
   * 重置
   */
  reset() {
    this.successCount = 0;
    this.totalCount = 0;
  }
}

// 日志工具类 - 提供基础日志功能，防止全局依赖缺失
class Logger {
  static error(...args) { console.error(...args); }
  static info(...args) { console.info(...args); }
  static debug(...args) { if (CONSTANTS.ENABLE_SCORE_DEBUGGING) console.debug(...args); }
  static warn(...args) { console.warn(...args); }
}

// 自定义错误类
class ConfigurationError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ConfigurationError';
  }
}

class InvalidRequestError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidRequestError';
  }
}

class NodeManager extends EventEmitter {
  static getInstance() {
    if (!NodeManager.instance) NodeManager.instance = new NodeManager();
    return NodeManager.instance;
  }

  constructor() {
    super();
    this.currentNode = null;
    this.nodeQuality = new Map();
    this.switchCooldown = new Map();
    this.nodeHistory = new Map(); // 节点历史记录
    this.nodeSuccess = new Map(); // 每个节点的成功率跟踪器
  }
  /**
   * 按指定节点切换（保留 switchToBestNode 作为选择器）
   * @param {string} nodeId
   * @param {Object} [targetGeo]
   */
  async switchToNode(nodeId, targetGeo) {
    if (!nodeId) return null;
    // 如果已经是当前节点，则直接返回
    if (this.currentNode === nodeId) return { id: nodeId };

    const central = typeof CentralManager !== 'undefined' && CentralManager.getInstance ? CentralManager.getInstance() : null;
    const node = central?.state?.config?.proxies?.find(n => n.id === nodeId) || null;
    if (!node) {
      Logger.warn(`尝试切换到不存在的节点: ${nodeId}`);
      return null;
    }

    const oldNodeId = this.currentNode;
    this.currentNode = nodeId;
    this.switchCooldown.set(nodeId, Date.now() + this._getCooldownTime(nodeId));
    this._recordSwitchEvent(oldNodeId, nodeId, targetGeo);
    const nodeStatus = central?.state?.nodes?.get(nodeId);
    const nodeRegion = nodeStatus?.geoInfo?.regionName || '未知区域';
    Logger.info(`节点已切换: ${oldNodeId || '无'} -> ${nodeId} (区域: ${nodeRegion})`);
    return node;
  }
  /**
   * 根据性能和地理信息选择最佳节点
   * @param {Array} nodes - 节点列表
   * @param {Object} [targetGeo] - 目标IP的地理信息
   * @returns {Object} 最佳节点
   */
  async getBestNode(nodes, targetGeo) {
    // 过滤掉冷却期内的节点
    const availableNodes = Array.isArray(nodes) ? nodes.filter(node => !this.isInCooldown(node.id)) : [];
    if (availableNodes.length === 0) return nodes[0];

    // 1. 如果有目标地理信息，优先选择同区域节点
    if (targetGeo && targetGeo.regionName) {
      const central = (typeof CentralManager !== 'undefined' && CentralManager.getInstance) ? CentralManager.getInstance() : null;
      const regionalNodes = availableNodes.filter(node => {
        const nodeStatus = central?.state?.nodes?.get(node.id);
        return nodeStatus?.geoInfo?.regionName === targetGeo.regionName;
      });

      if (regionalNodes.length > 0) {
        // 在同区域节点中选择性能最佳
        return this._selectBestPerformanceNode(regionalNodes);
      }
    }

    // 2. 无地理信息或无同区域节点，按性能选择
    return this._selectBestPerformanceNode(availableNodes);
  }

  /**
   * 仅根据性能指标选择最佳节点
   * @param {Array} nodes - 节点列表
   * @returns {Object} 性能最佳的节点
   */
  _selectBestPerformanceNode(nodes) {
    const central = (typeof CentralManager !== 'undefined' && CentralManager.getInstance) ? CentralManager.getInstance() : null;
    const scoreFor = (node) => {
      const quality = this.nodeQuality.get(node.id) || 0;

      // 从状态中提取最近一次探测指标
      const nodeState = central?.state?.nodes?.get(node.id) || {};
      const metrics = nodeState.metrics || {};

      // 计算一个 0-100 的度量得分 (基于延迟 / 丢包 / 抖动 / 吞吐)
      let metricScore = 0;
      try {
        const latencyVal = Number(metrics.latency) || 1000;
        const jitterVal = Number(metrics.jitter) || 100;
        const lossVal = Number(metrics.loss) || 1;
        const bytes = Number(metrics.bytes) || 0;

        const latencyScore = Math.max(0, Math.min(50, 50 - latencyVal / 20));
        const jitterScore = Math.max(0, Math.min(25, 25 - jitterVal));
        const lossScore = Math.max(0, Math.min(15, 15 * (1 - lossVal)));
        const throughputScore = Math.max(0, Math.min(10, Math.round(Math.log10(1 + (bytes * 8) / Math.max(1, latencyVal)) * 2)));
        metricScore = Math.round(latencyScore + jitterScore + lossScore + throughputScore);
      } catch (e) {
        metricScore = 0;
      }

      // 成功率
      const tracker = this.nodeSuccess.get(node.id);
      const successRate = tracker ? (tracker.rate * 100) : 0;

      // 复合得分
      const composite = (
        (quality * (CONSTANTS.QUALITY_WEIGHT || 0.5)) +
        (metricScore * (CONSTANTS.METRIC_WEIGHT || 0.35)) +
        (successRate * (CONSTANTS.SUCCESS_WEIGHT || 0.15))
      );
      return composite;
    };

    let best = nodes[0];
    let bestVal = scoreFor(best);
    for (let i = 1; i < nodes.length; i++) {
      const n = nodes[i];
      const val = scoreFor(n);
      if (val > bestVal) {
        best = n;
        bestVal = val;
      }
    }
    return best;
  }

  /**
   * 更新节点质量
   * @param {string} nodeId - 节点ID
   * @param {number} score - 质量分
   */
  updateNodeQuality(nodeId, score) {
    const current = this.nodeQuality.get(nodeId) || 0;
    // 限制分数范围在0-100
    const newScore = Math.max(0, Math.min(100, current + score));
    this.nodeQuality.set(nodeId, newScore);

    // 更新历史记录
    this._updateNodeHistory(nodeId, newScore);
  }

  /**
   * 切换到最佳节点
   * @param {Array} nodes - 节点列表
   * @param {Object} [targetGeo] - 目标IP的地理信息
   * @returns {Object} 最佳节点
   */
  async switchToBestNode(nodes, targetGeo) {
    if (!nodes || nodes.length === 0) return null;

    const bestNode = await this.getBestNode(nodes, targetGeo);
    if (!bestNode) return null;

    // 记录切换前的节点
    const oldNodeId = this.currentNode;

    // 应用新节点
    this.currentNode = bestNode.id;

    // 设置冷却期
    this.switchCooldown.set(bestNode.id, Date.now() + this._getCooldownTime(bestNode.id));

    // 记录切换事件，增加地理信息
    this._recordSwitchEvent(oldNodeId, bestNode.id, targetGeo);

    const nodeStatus = CentralManager.getInstance().state.nodes.get(bestNode.id);
    const nodeRegion = nodeStatus?.geoInfo?.regionName || '未知区域';
    Logger.info(`节点已切换: ${oldNodeId || '无'} -> ${bestNode.id} (质量分: ${this.nodeQuality.get(bestNode.id)}, 区域: ${nodeRegion})`);
    return bestNode;
  }

  /**
   * 记录切换事件
   * @param {string} oldNodeId - 旧节点ID
   * @param {string} newNodeId - 新节点ID
   * @param {Object} targetGeo - 目标地理信息
   */
  _recordSwitchEvent(oldNodeId, newNodeId, targetGeo) {
    // 增强事件记录，包含地理信息
    const event = {
      timestamp: Date.now(),
      oldNodeId,
      newNodeId,
      targetGeo: targetGeo ? {
        country: targetGeo.country,
        region: targetGeo.regionName
      } : null,
      reason: oldNodeId ? '质量过低' : '初始选择'
    };
    // 实际应用中可以将切换事件存储到日志系统
  }

  /**
   * 判断节点是否在冷却期
   * @param {string} nodeId - 节点ID
   * @returns {boolean} 是否在冷却期
   */
  isInCooldown(nodeId) {
    const cooldownEnd = this.switchCooldown.get(nodeId);
    return cooldownEnd && Date.now() < cooldownEnd;
  }

  _getCooldownTime(nodeId) {
    // 根据节点质量动态调整冷却时间
    const score = this.nodeQuality.get(nodeId) || 0;
    // 质量越高冷却时间越长，使用全局常量确保一致性
    return Math.max(
      CONSTANTS.MIN_SWITCH_COOLDOWN,
      Math.min(
        CONSTANTS.MAX_SWITCH_COOLDOWN,
        CONSTANTS.BASE_SWITCH_COOLDOWN * (1 + score / 100)
      )
    );
  }

  _updateNodeHistory(nodeId, score) {
    const history = this.nodeHistory.get(nodeId) || [];
    history.push({ timestamp: Date.now(), score });
    // 保留最近记录，使用全局常量
    if (history.length > CONSTANTS.MAX_HISTORY_RECORDS) {
      // 使用slice而非shift提高性能（O(n) -> O(k)）
      this.nodeHistory.set(nodeId, history.slice(-CONSTANTS.MAX_HISTORY_RECORDS));
    } else {
      this.nodeHistory.set(nodeId, history);
    }
  }
}

class CentralManager extends EventEmitter {
  static getInstance() {
    return CentralManager.instance;
  }
  constructor() {
    super();
    this.state = new AppState();
    this.stats = new RollingStats();
    this.successTracker = new SuccessRateTracker();
    this.nodeManager = NodeManager.getInstance();
    this.lruCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.eventListeners = null;
    // 注册单例引用，方便外部安全访问（在构造完成后）
    CentralManager.instance = this;
    // 延迟初始化以避免在构造期间依赖尚未定义的外部符号
    // 保持异常捕获，防止未处理的 Promise 拒绝
    try {
      Promise.resolve().then(() => this.initialize()).catch(err => Logger.error('CentralManager 初始化失败:', err && err.stack ? err.stack : err));
    } catch (e) {
      Logger.error('CentralManager 初始化调度失败:', e && e.stack ? e.stack : e);
    }
  }
  
  /**
   * 安全的 fetch 封装，支持超时和在没有 AbortController 的环境中回退
   * @param {string} url
   * @param {Object} [options]
   * @param {number} [timeout]
   */
  async _safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
    // 兼容浏览器与 Node 环境：优先使用全局 fetch
    let _fetch = (typeof fetch === 'function') ? fetch : null;
    let _AbortController = (typeof AbortController === 'undefined') ? null : AbortController;

    // 在 Node 环境中尝试回退到 node-fetch（若已安装）并引入 AbortController
    if (!_fetch && typeof process !== 'undefined' && process.versions && process.versions.node) {
      try {
        // 尝试动态 require，若模块不存在则继续让调用方处理错误
        // eslint-disable-next-line global-require
        const nf = require('node-fetch');
        // node-fetch v3 是 ESM，require 可能返回 a default 属性
        _fetch = nf.default || nf;
      } catch (e) {
        // 无 node-fetch 可用，保留 _fetch 为 null
      }

      try {
        // 尝试引入 abort-controller
        // eslint-disable-next-line global-require
        const AC = require('abort-controller');
        _AbortController = AC.default || AC;
      } catch (e) {
        // 忽略，可能运行在 Node 18+ 自带 AbortController
        if (typeof AbortController !== 'undefined') _AbortController = AbortController;
      }
    }

    if (!_fetch) throw new Error('fetch 不可用于当前运行环境，且未找到可回退的实现（node-fetch）');

    const hasAbort = !!_AbortController;
    if (hasAbort) {
      const controller = new _AbortController();
      options = { ...options, signal: controller.signal };
      const timeoutId = setTimeout(() => controller.abort(), timeout);
      try {
        const resp = await _fetch(url, options);
        clearTimeout(timeoutId);
        return resp;
      } catch (err) {
        clearTimeout(timeoutId);
        throw err;
      }
    }

    // 无 AbortController 时直接调用 fetch（无法超时）
    return _fetch(url, options);
  }
  /**
   * 查询IP地址的地理信息
   * @param {string} ip - 要查询的IP地址
   * @returns {Promise<Object|null>} 包含国家、地区等信息的地理数据或null
   */
  async getIpGeolocation(ip) {
    // 1. 优先查缓存
    const cached = this.geoInfoCache.get(ip);
    if (cached) return cached;
    
    // 2. 调用GeoIP服务 (使用ip-api.com的免费API)
    try {
      const response = await this._safeFetch(`http://ip-api.com/json/${ip}?fields=country,regionName,city,lat,lon,isp,org,as,name`, {}, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!response.ok) throw new Error(`HTTP错误: ${response.status}`);
      const data = await response.json();
      if (data.status !== 'success') throw new Error(`查询失败: ${data.message}`);
      
      // 3. 缓存结果
      this.geoInfoCache.set(ip, data, CONSTANTS.GEO_FALLBACK_TTL);
      return data;
    } catch (error) {
      Logger.error(`IP地理查询失败 (${ip}):`, error.message);
      return null;
    }
  }

  /**
   * 初始化
   */
  async initialize() {
    await this.loadAIDBFromFile();
    this.setupEventListeners();
    // 添加地理感知分流事件监听
    this.on('requestDetected', (targetIp) => this.handleRequestWithGeoRouting(targetIp));
    await this.preheatNodes();
    // 移除定时任务，完全采用事件驱动模式 - 符合维护提示要求
    // 注册进程退出时的清理函数
    if (typeof process !== 'undefined') {
      process.on('SIGINT', () => this.destroy());
      process.on('SIGTERM', () => this.destroy());
    } else if (typeof window !== 'undefined') {
      window.addEventListener('beforeunload', () => this.destroy());
    }
  }

  /**
   * 销毁实例并释放所有资源
   */
  async destroy() {
    Logger.info('开始清理资源...');
    this.cleanupEventListeners();
    // 移除对 stopScheduledEvaluation 的调用，因为在事件驱动模型下不再需要定时评估
    await this.saveAIDBToFile();
    this.lruCache.clear();
    this.geoInfoCache.clear();
    Logger.info('资源清理完成');
  }

  /**
   * 从持久化存储加载AI节点数据
   * @returns {Promise<void>} 加载完成Promise
   */
  loadAIDBFromFile() {
    return new Promise((resolve) => {
      try {
        let raw = '';
        // 尝试从不同环境的存储中读取数据
        // 环境兼容的存储访问
        const storage = typeof $persistentStore !== 'undefined' ? $persistentStore :
                       (typeof window !== 'undefined' && window.localStorage ? window.localStorage : null);
        if (storage) {
          raw = storage.getItem ? storage.getItem('ai_node_data') || '' :
                                 (storage.read ? storage.read('ai_node_data') || '' : '');
        }

        if (raw) {
          try {
            const data = JSON.parse(raw);
            // 验证数据格式
            if (typeof data === 'object' && data !== null) {
              Object.entries(data).forEach(([id, stats]) => {
                this.state.metrics.set(id, stats);
              });
              Logger.info(`成功加载AI节点数据，共${this.state.metrics.size}条记录`);
            } else {
              Logger.error('AI数据格式无效，预期为对象');
            }
          } catch (parseError) {
            Logger.error('AI数据解析失败:', parseError.stack);
            // 尝试删除损坏的数据
            if (typeof $persistentStore !== 'undefined') {
              $persistentStore.write('', 'ai_node_data');
            } else if (typeof window !== 'undefined' && window.localStorage) {
              window.localStorage.removeItem('ai_node_data');
            }
          }
        }
      } catch (e) {
        Logger.error('AI数据加载失败:', e.stack);
      } finally {
        resolve();
      }
    });
  }

  /**
   * 保存AI节点数据到持久化存储
   */
  saveAIDBToFile() {
    try {
      const data = Object.fromEntries(this.state.metrics.entries());
      const raw = JSON.stringify(data, null, 2);
      if (typeof $persistentStore !== 'undefined') {
        $persistentStore.write(raw, 'ai_node_data');
      } else if (typeof window !== 'undefined' && window.localStorage) {
        window.localStorage.setItem('ai_node_data', raw);
      }
    } catch (e) {
      Logger.error('AI数据保存失败:', e.stack);
    }
  }
  /**
   * 设置事件监听器并保存引用以便后续清理
   */
  setupEventListeners() {
    // 存储事件监听器引用以便清理（不对 state.nodes 中普通对象进行事件绑定）
    this.eventListeners = {
      configChanged: async () => this.onConfigChanged(),
      networkOnline: async () => this.onNetworkOnline(),
      performanceThresholdBreached: async (nodeId) => this.onPerformanceThresholdBreached(nodeId),
      evaluationCompleted: () => this.onEvaluationCompleted()
    };

    // 配置变更事件（如果 Config 提供事件接口）
    if (typeof Config !== 'undefined' && Config.on) {
      Config.on('configChanged', this.eventListeners.configChanged);
    }

    // 网络状态变更事件（浏览器环境）
    if (typeof window !== 'undefined' && typeof window.addEventListener === 'function') {
      window.addEventListener('online', this.eventListeners.networkOnline);
    }

    // 监听 NodeManager 相关事件（如果有）
    if (this.nodeManager && typeof this.nodeManager.on === 'function') {
      this.nodeManager.on('performanceThresholdBreached', this.eventListeners.performanceThresholdBreached);
    }

    // 评估完成事件（CentralManager 本身的事件）
    this.on('evaluationCompleted', this.eventListeners.evaluationCompleted);
  }

  /**
   * 清理所有事件监听器
   */
  cleanupEventListeners() {
    if (!this.eventListeners) return;

    // 移除配置变更事件监听
    if (typeof Config !== 'undefined' && Config.off) {
      try { Config.off('configChanged', this.eventListeners.configChanged); } catch (e) { /* ignore */ }
    }

    // 移除网络状态变更事件监听
    if (typeof window !== 'undefined' && typeof window.removeEventListener === 'function') {
      try { window.removeEventListener('online', this.eventListeners.networkOnline); } catch (e) { /* ignore */ }
    }

    // 移除 NodeManager 事件监听
    if (this.nodeManager && typeof this.nodeManager.off === 'function') {
      try { this.nodeManager.off('performanceThresholdBreached', this.eventListeners.performanceThresholdBreached); } catch (e) { /* ignore */ }
    }

    // 移除 CentralManager 自身的事件监听
    try { this.off('evaluationCompleted', this.eventListeners.evaluationCompleted); } catch (e) { /* ignore */ }

    this.eventListeners = null;
  }

  /**
   * 节点更新事件处理函数
   * @param {string} id - 节点ID
   * @param {Object} status - 节点状态
   */
  onNodeUpdate(id, status) {
    this.nodeManager.updateNodeQuality(id, status.score || 0);
  }

  /**
   * 配置变更事件处理函数
   */
  async onConfigChanged() {
    Logger.info('配置变更，触发节点评估...');
    await this.evaluateAllNodes();
  }

  /**
   * 网络恢复事件处理函数
   */
  async onNetworkOnline() {
    Logger.info('网络恢复，触发节点评估...');
    await this.evaluateAllNodes();
  }

  /**
   * 节点性能阈值突破事件处理函数
   * @param {string} nodeId - 节点ID
   */
  async onPerformanceThresholdBreached(nodeId) {
    Logger.info(`节点 ${nodeId} 性能阈值突破，触发单节点评估...`);
    const node = this.state.config.proxies?.find(n => n.id === nodeId);
    if (node) {
      await this.evaluateNodeQuality(node);
    } else {
      Logger.warn(`节点 ${nodeId} 不存在，无法评估`);
    }
  }

  /**
   * 评估完成事件处理函数
   */
  onEvaluationCompleted() {
    Logger.info('节点评估完成，触发数据保存和节点清理...');
    this.saveAIDBToFile();
    this.autoEliminateNodes();
  }

  /**
   * 预热节点
   */
  async preheatNodes() {
    const proxies = this.state.config.proxies || [];
    if (proxies.length === 0) return;

    const testNodes = proxies.slice(0, CONSTANTS.PREHEAT_NODE_COUNT);
    const results = [];

    // 使用并发控制器处理节点测试
    const testTasks = testNodes.map(node => () => Utils.retry(() => this.testNodeMultiMetrics(node), 2, 200));
    const batchResults = await Utils.asyncPool(testTasks, CONSTANTS.CONCURRENCY_LIMIT);
    results.push(...batchResults);

    results.forEach((result, index) => {
      if (result && result.__error) {
        Logger.error(`节点预热失败: ${testNodes[index].id}`, result.__error && result.__error.message ? result.__error.message : result.__error);
        return;
      }
      const node = testNodes[index];
      this.state.updateNodeStatus(node.id, {
        initialMetrics: result,
        lastTested: Date.now()
      });
      this.nodeManager.updateNodeQuality(node.id, this.calculateInitialQualityScore(result));
    });
  }

  /**
   * 计算初始质量分
   * @param {Object} metrics - 指标
   * @returns {number} 初始质量分
   */
  calculateInitialQualityScore(metrics) {
    // 基于多维度指标计算初始质量分，增加默认值保护以防止NaN
    metrics = metrics || {};
    const latency = Number(metrics.latency) || 0;
    const loss = Number(metrics.loss) || 0;
    const jitter = Number(metrics.jitter) || 0;
    const raw = Math.round(
      (100 - latency / 20) +
      (1 - loss) * 50 +
      (1 - jitter / 100) * 30
    );
    return Math.max(0, Math.min(100, raw));
  }

  // 重命名方法，移除periodic前缀
  async evaluateAllNodes() {
    const proxies = this.state.config.proxies || [];
    if (proxies.length === 0) return;
    // 使用并发池评估节点，保证单个失败不会中断整体
    const evalTasks = proxies.map(node => () => this.evaluateNodeQuality(node));
    const results = await Utils.asyncPool(evalTasks, CONSTANTS.CONCURRENCY_LIMIT);
    // 记录失败项以便后续分析
    results.forEach((r, idx) => {
      if (r && r.__error) {
        const node = proxies[idx];
        Logger.warn(`节点评估失败: ${node?.id}`, r.__error && r.__error.message ? r.__error.message : r.__error);
      }
    });

    // 触发评估完成事件
    this.emit('evaluationCompleted');
  }

  /**
   * 评估节点质量并获取地理信息
   * @param {Object} node - 要评估的节点对象
   */
  async evaluateNodeQuality(node) {
    let metrics = null;
    try {
      metrics = await Utils.retry(() => this.testNodeMultiMetrics(node), 2, 200);
    } catch (e) {
      Logger.warn(`节点探测多次失败，使用回退模拟: ${node?.id}`, e && e.message ? e.message : e);
      // 即使探测失败，也保持后续逻辑使用模拟值
      metrics = await this.testNodeMultiMetrics(node);
    }
    // 记录成功率：非模拟且延迟合理视为一次成功
    try {
      const tracker = this.nodeSuccess.get(node.id) || new SuccessRateTracker();
      const isSimulated = metrics && metrics.__simulated;
      const success = !!(metrics && !isSimulated && Number(metrics.latency) > 0 && Number(metrics.latency) < (CONSTANTS.NODE_TEST_TIMEOUT * 2));
      tracker.record(success);
      this.nodeSuccess.set(node.id, tracker);
    } catch (e) {
      // 不影响核心流程
    }
    const score = this.calculateNodeQualityScore(metrics);
    
    // 获取节点IP并查询地理信息
    const nodeIp = node.server?.split(':')[0]; // 假设server格式为"ip:port"
    let geoInfo = null;
    if (nodeIp) {
      geoInfo = await this.getIpGeolocation(nodeIp);
    }

    this.nodeManager.updateNodeQuality(node.id, score);
    this.state.updateNodeStatus(node.id, {
      metrics,
      score,
      geoInfo,
      lastEvaluated: Date.now()
    });

    // 如果是当前节点且质量过低，触发切换
    if (this.nodeManager.currentNode === node.id && score < CONSTANTS.QUALITY_SCORE_THRESHOLD) {
      await this.nodeManager.switchToBestNode(this.state.config.proxies);
    }
  }

  /**
   * 处理请求并应用地理感知路由
   * @param {string} targetIp - 目标请求的IP地址
   */
  async handleRequestWithGeoRouting(targetIp) {
    if (!targetIp || !this.state.config.proxies || this.state.config.proxies.length === 0) {
      Logger.warn('无法进行地理路由: 缺少目标IP或代理节点');
      return;
    }

    // 获取目标IP地理信息
    const targetGeo = await this.getIpGeolocation(targetIp);
    if (!targetGeo) {
      Logger.warn('无法获取目标IP地理信息，使用默认路由');
      await this.nodeManager.switchToBestNode(this.state.config.proxies);
      return;
    }

    // 根据地理信息选择最佳节点
    await this.nodeManager.switchToBestNode(this.state.config.proxies, targetGeo);
  }

  /**
   * 计算节点质量分
   * @param {Object} metrics - 指标
   * @returns {number} 质量分
   */
  calculateNodeQualityScore(metrics) {
    // 综合多维度指标计算质量分 (0-100)
    metrics = metrics || {};
    const latencyVal = Number(metrics.latency) || 0;
    const jitterVal = Number(metrics.jitter) || 0;
    const lossVal = Number(metrics.loss) || 0;
    const latencyScore = Math.max(0, Math.min(35, 35 - latencyVal / 25));
    const jitterScore = Math.max(0, Math.min(25, 25 - jitterVal));
    const lossScore = Math.max(0, Math.min(25, 25 * (1 - lossVal)));
    // 基于探测下载字节数估算吞吐得分（优先考虑真实连网速率）
    let throughputScore = 0;
    try {
      const bytes = metrics.bytes || 0;
      const latency = Math.max(1, metrics.latency || 1);
      const bps = (bytes * 8) / latency * 1000; // 近似比特率 (bits/s)
      // 将 bps 映射到 0-15 分
      throughputScore = Math.max(0, Math.min(15, Math.round(Math.log10(1 + bps) * 2)));
    } catch (e) {
      throughputScore = 0;
    }

    const total = Math.round(latencyScore + jitterScore + lossScore + throughputScore);
    return Math.max(0, Math.min(100, total));
  }

  /**
   * 自动淘汰节点
   */
  autoEliminateNodes() {
    const proxies = this.state.config.proxies || [];
    const thresholdTime = Date.now() - CONSTANTS.NODE_EVALUATION_THRESHOLD; // 3小时未评估

    proxies.forEach(node => {
      const status = this.state.nodes.get(node.id);
      if (!status || status.lastEvaluated < thresholdTime || status.score < 20) {
        this.state.nodes.delete(node.id);
        this.state.metrics.delete(node.id);
        this.nodeManager.nodeQuality.delete(node.id);
        Logger.info(`已清理异常节点: ${node.id}`);
      }
    });
  }

  /**
   * 处理代理请求，实现智能节点选择和请求转发
   * @param {Request} req - HTTP请求对象
   * @param {...*} args - 剩余参数（包含res和next）
   * @throws {ConfigurationError} 当系统配置未初始化时抛出
   * @throws {InvalidRequestError} 当请求对象或URL无效时抛出
   */
  async handleProxyRequest(req, ...args) {
    // 验证配置和输入
    if (!this.state || !this.state.config) {
      throw new ConfigurationError('系统配置未初始化');
    }
    if (!req || !req.url) {
      throw new InvalidRequestError('无效的请求对象或URL');
    }

    try {
      // 已在函数入口完成必要的校验，进入处理逻辑
      // 获取当前用户和可用节点
      const user = req.user || 'default';
      const allNodes = this.state.config.proxies || [];
      if (allNodes.length === 0) {
        Logger.warn('没有可用代理节点，将使用直连模式');
        return this.proxyToDirect(...args);
      }

      // 确保有活跃节点
      let currentNode = this.nodeManager.currentNode ? 
        allNodes.find(n => n.id === this.nodeManager.currentNode) : null;

      // 如果没有当前节点或当前节点不可用，选择最佳节点
      if (!currentNode || !this.state.nodes.has(currentNode.id)) {
        currentNode = await this.nodeManager.switchToBestNode(allNodes);
      }

      // 采集客户端地理信息
      const clientIP = req.headers['X-Forwarded-For'] || req.headers['Remote-Address'];
      const clientGeo = await this.getGeoInfo(clientIP);

      // 获取目标地址地理信息
      let targetGeo = null;
      try {
        const targetUrl = new URL(req.url);
        const targetDomain = targetUrl.hostname;
        const targetIP = await this.resolveDomainToIP(targetDomain);
        if (targetIP) {
          targetGeo = await this.getGeoInfo(targetIP);
        }
      } catch (error) {
        Logger.warn(`解析目标URL失败: ${error.message}`, error.stack);
      }

      // 智能分流决策
      const targetNode = await this.smartDispatchNode(user, allNodes, { clientGeo, targetGeo, req });

      // 如果需要切换到目标节点
      if (targetNode && targetNode.id !== currentNode?.id) {
        const switched = await this.nodeManager.switchToNode(targetNode.id, targetGeo);
        // 如果成功切换，则更新 currentNode 引用
        if (switched) {
          currentNode = allNodes.find(n => n.id === targetNode.id) || switched;
        }
      }

      // 执行代理请求并记录指标
      const result = await this.proxyRequestWithNode(currentNode, ...args);
      this.recordRequestMetrics(currentNode, result, req);

      return result;
    } catch (error) {
      Logger.error('代理请求处理失败:', error.stack);
      return this.proxyToDirect(...args);
    }
  }

  /**
   * 智能选择最佳代理节点
   * @param {string} user - 用户名
   * @param {Array} nodes - 候选节点列表
   * @param {Object} context - 上下文信息，包含客户端和目标地理信息
   * @returns {Object} 最佳节点
   * @throws {InvalidRequestError} 当节点列表为空或上下文无效时抛出
   */
  async smartDispatchNode(user, nodes, context) {
    if (!nodes || !nodes.length) {
      throw new InvalidRequestError('节点列表不能为空');
    }
    if (!context || !context.clientGeo) {
      throw new InvalidRequestError('无效的上下文信息，缺少客户端地理信息');
    }
    // 基于用户、地理信息和请求特征智能选择节点
    const cacheKey = `${user}:${context.clientGeo?.country || 'unknown'}:${context.req?.url?.hostname || 'unknown'}`;
    const cachedNode = this.lruCache.get(cacheKey);

    if (cachedNode) {
      const node = nodes.find(n => n.id === cachedNode);
      if (node) return node;
      // 缓存节点不存在时立刻移除无效缓存
      try { this.lruCache.delete(cacheKey); } catch (e) { /* ignore */ }
    }

    // 基于内容类型的分流策略
    const contentType = context.req?.headers['Content-Type'] || '';
    const url = context.req?.url || '';

    // 视频流优先选择低延迟节点
    if (contentType.includes('video') || url.match(/youtube|netflix|stream/i)) {
      // 使用更高效的节点筛选算法
      // 从状态中挑选满足质量阈值的节点 id，然后映射到配置中完整的节点对象
      const candidateIds = Array.from(this.state.nodes.entries())
        .filter(([_, node]) => (node && node.score) > CONSTANTS.QUALITY_SCORE_THRESHOLD)
        .map(([id]) => id);
      const candidates = candidateIds
        .map(id => this.state.config.proxies?.find(p => p.id === id))
        .filter(Boolean);
      // 限制并发测试数量，避免资源耗尽
      const concurrencyLimit = CONSTANTS.CONCURRENCY_LIMIT;
      const results = [];
      for (let i = 0; i < candidates.length; i += concurrencyLimit) {
        const batch = candidates.slice(i, i + concurrencyLimit);
        const tasks = batch.map(node => () => Utils.retry(() => this.testNodeMultiMetrics(node), 2, 200));
        await Utils.asyncPool(tasks, concurrencyLimit);
        // 移除固定延迟，通过事件触发下一批处理
        this.emit('batchCompleted', { batchIndex: i / concurrencyLimit });
      }
      if (candidates.length > 0) {
        Logger.info(`筛选出 ${candidates.length} 个符合质量要求的节点`);
        const best = await this.nodeManager.getBestNode(candidates);
        this.lruCache.set(cacheKey, best.id);
        return best;
      }
    }

    // 根据目标地理信息筛选节点
    if (context.targetGeo && context.targetGeo.country && Config && Config.regionOptions && Array.isArray(Config.regionOptions.regions)) {
      const targetRegion = Config.regionOptions.regions.find(
        r => r.name.includes(context.targetGeo.country) || (r.regex && context.targetGeo.country.match(r.regex))
      );

      if (targetRegion) {
        const regionNodes = Utils.filterProxiesByRegion(nodes, targetRegion);
        if (regionNodes.length > 0) {
          const candidates = nodes.filter(n => regionNodes.includes(n.name));
          const bestRegionNode = await this.nodeManager.getBestNode(candidates);
          this.lruCache.set(cacheKey, bestRegionNode.id);
          return bestRegionNode;
        }
      }
    }

    // 默认返回最佳节点
    const bestNode = await this.nodeManager.getBestNode(nodes);
    this.lruCache.set(cacheKey, bestNode.id);
    return bestNode;
  }

  /**
   * 获取IP地址的地理信息，包含多级降级策略
   * @param {string} ip - 要查询的IP地址
   * @param {string} [domain] - 可选的域名，用于在IP查询失败时进行地理推断
   * @returns {Promise<{country: string, region: string}>} 地理信息对象
   */
  async getGeoInfo(ip, domain) {
    // 初始化地理信息缓存（如果不存在）
    // 确保地理信息缓存已初始化
    if (!this.geoInfoCache) {
      Logger.error('地理信息缓存未初始化，使用默认配置');
      this.geoInfoCache = new LRUCache({
        maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE,
        ttl: CONSTANTS.LRU_CACHE_TTL
      });
    }

    // 检查IP是否为空
    if (!ip) {
      Logger.warn('获取地理信息失败: IP地址为空');
      return this._getFallbackGeoInfo(domain);
    }

    // 本地IP处理
    if (ip === '127.0.0.1' || ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.')) {
      return { country: 'Local', region: 'Local' };
    }

    // 检查缓存
    const cachedGeo = this.geoInfoCache.get(ip);
    if (cachedGeo) {
      Logger.debug(`使用缓存的地理信息: ${ip} -> ${cachedGeo.country}`);
      return cachedGeo;
    }

    try {
      // 主API: ipapi.co
      const result = await this._fetchGeoFromPrimaryAPI(ip);
      if (result) {
        this.geoInfoCache.set(ip, result);
        return result;
      }

      // 备用API: ipinfo.io
      const fallbackResult = await this._fetchGeoFromFallbackAPI(ip);
      if (fallbackResult) {
        this.geoInfoCache.set(ip, fallbackResult);
        return fallbackResult;
      }

      // 所有API都失败，使用降级策略
      Logger.warn(`所有地理信息API调用失败，使用降级策略: ${ip}`);
      const fallbackGeo = this._getFallbackGeoInfo(domain);
      this.geoInfoCache.set(ip, fallbackGeo, CONSTANTS.GEO_FALLBACK_TTL); // 使用较短的TTL缓存降级结果
      return fallbackGeo;

    } catch (error) {
      Logger.error(`获取地理信息失败: ${error.message}`, error.stack);
      return this._getFallbackGeoInfo(domain);
    }
  }

  /**
   * 从主API获取地理信息
   * @param {string} ip - 要查询的IP地址
   * @returns {Promise<{country: string, region: string}|null>} 地理信息对象或null
   */
  async _fetchGeoFromPrimaryAPI(ip) {
    if (!ip || typeof ip !== 'string') {
      Logger.error('无效的IP地址:', ip);
      return null;
    }
    try {
      const response = await this._safeFetch(`https://ipapi.co/${ip}/json/`, { headers: { 'User-Agent': 'Mozilla/5.0' } }, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      const data = await response.json();
      if (data.country_name) {
        return {
          country: data.country_name,
          region: data.region || data.city || 'Unknown'
        };
      }
      Logger.warn(`主API返回无效数据: ${JSON.stringify(data)}`);
      return null;
    } catch (error) {
      Logger.warn(`主API调用失败: ${error.message}`);
      return null;
    }
  }

  /**
   * 从备用API获取地理信息
   * @param {string} ip - 要查询的IP地址
   * @returns {Promise<{country: string, region: string}|null>} 地理信息对象或null
   */
  async _fetchGeoFromFallbackAPI(ip) {
    try {
      const response = await this._safeFetch(`https://ipinfo.io/${ip}/json`, {}, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
      const data = await response.json();
      if (data.country) {
        return {
          country: data.country,
          region: data.region || data.city || 'Unknown'
        };
      }
      Logger.warn(`备用API返回无效数据: ${JSON.stringify(data)}`);
      return null;
    } catch (error) {
      Logger.warn(`备用API调用失败: ${error.message}`);
      return null;
    }
  }

  /**
   * 获取降级的地理信息
   * @param {string} [domain] - 可选的域名，用于地理推断
   * @returns {{country: string, region: string}} 降级的地理信息
   */
  _getFallbackGeoInfo(domain) {
    // 基于域名后缀的地理推断 - 增加域名验证
  if (domain && typeof domain === 'string' && /^[a-zA-Z0-9.-]+$/.test(domain)) {
      const tld = domain.split('.').pop().toLowerCase();
      const countryMap = {
        'cn': 'China', 'hk': 'Hong Kong', 'tw': 'Taiwan', 'jp': 'Japan',
        'kr': 'Korea', 'us': 'United States', 'uk': 'United Kingdom',
        'de': 'Germany', 'fr': 'France', 'ca': 'Canada', 'au': 'Australia'
      };

      if (countryMap[tld]) {
        Logger.debug(`基于域名推断地理信息: ${domain} -> ${countryMap[tld]}`);
        return { country: countryMap[tld], region: 'Unknown' };
      }
    }

    // 最后的默认值
    return { country: 'Unknown', region: 'Unknown' };
  }

  /**
   * 解析域名到IP地址
   * @param {string} domain - 要解析的域名
   * @returns {Promise<string|null>} IP地址或null
   */
  async resolveDomainToIP(domain) {
    if (!domain || typeof domain !== 'string') {
      Logger.error('无效的域名参数');
      return null;
    }

    try {
      // 验证域名格式
      if (!/^[a-zA-Z0-9.-]+$/.test(domain)) {
        Logger.error(`无效的域名格式: ${domain}`);
        return null;
      }

      const cacheKey = `dns:${domain}`;
      const cachedIP = this.lruCache.get(cacheKey);
      if (cachedIP) return cachedIP;

      const response = await this._safeFetch(
        `https://1.1.1.1/dns-query?name=${encodeURIComponent(domain)}&type=A`,
        { headers: { 'Accept': 'application/dns-json', 'User-Agent': 'Mozilla/5.0' } },
        CONSTANTS.GEO_INFO_TIMEOUT
      );
      if (!response.ok) throw new Error(`DNS query failed: ${response.status}`);
      const data = await response.json();

      if (data.Answer && data.Answer.length > 0) {
        const ip = data.Answer[0].data;
        // 验证IP格式
        if (/^\d+\.\d+\.\d+\.\d+$/.test(ip)) {
          this.lruCache.set(cacheKey, ip);
          return ip;
        }
        Logger.error(`无效的IP地址: ${ip}`);
      }
      return null;
    } catch (error) {
      if (error.name !== 'AbortError') {
        Logger.error(`域名解析失败: ${error.message}`);
      }
      return null;
    }
  }

  /**
   * 使用指定节点执行代理请求
   * @param {Object} node - 代理节点配置，必须包含id、server和port属性
   * @param {...*} args - 传递给fetch的参数
   * @returns {Promise<Object>} 请求结果，包含success、latency等信息
   * @throws {InvalidRequestError} 当节点配置无效时抛出
   */
  async proxyRequestWithNode(node, ...args) {
    if (!node || typeof node !== 'object') {
      throw new InvalidRequestError('代理请求失败: 无效的节点信息');
    }
    // 兼容不同的节点配置：允许使用 server 或 proxyUrl
    if (!node.id || !(node.server || node.proxyUrl)) {
      throw new InvalidRequestError(`代理请求失败: 节点缺少必要属性 (id: ${node && node.id}, server: ${node && node.server}, proxyUrl: ${node && node.proxyUrl})`);
    }
    try {
      const startTime = Date.now();
      const fetchOptions = (args && args.length && typeof args[0] === 'object') ? args[0] : {};
      const response = await this._safeFetch(node.proxyUrl, fetchOptions, CONSTANTS.NODE_TEST_TIMEOUT);
      const result = {
        success: true,
        latency: Date.now() - startTime,
        bytes: parseInt(response.headers.get && response.headers.get('Content-Length') || '0')
      };
      return result;
    } catch (error) {
      Logger.error(`代理请求失败 [${node.id}]: ${error && error.message ? error.message : error}`);
      return {
        success: false,
        error: error && error.message ? error.message : String(error),
        latency: CONSTANTS.NODE_TEST_TIMEOUT
      };
    }

  }

  /**
   * 直连处理
   * @param {...*} args - 剩余参数
   * @returns {Object} 直连结果
   */
  proxyToDirect(...args) {
    // 直连处理
    return { success: true, direct: true };
  }

  /**
   * 记录请求指标
   * @param {Object} node - 节点
   * @param {Object} result - 请求结果
   * @param {Request} req - HTTP请求对象
   */
  recordRequestMetrics(node, result, req) {
    if (!node || !result) return;

    // 记录请求指标用于后续分析
    const metrics = {
      timestamp: Date.now(),
      nodeId: node.id,
      success: result.success,
      latency: result.latency,
      url: req?.url || '',
      method: req?.method || '',
      bytes: result.bytes || 0
    };

    // 简单的成功/失败记录
    this.successTracker.record(result.success);
    if (result.latency) this.stats.add(result.latency);

    // AI节点评分
    const aiScore = this.aiScoreNode(node, metrics);
    this.nodeManager.updateNodeQuality(node.id, aiScore);
  }

  /**
   * AI节点评分模型 - 基于多维度指标预测节点未来表现
   * @param {Object} node - 节点对象
   * @param {Object} metrics - 当前请求指标
   * @returns {number} 评分调整值 (-10 到 +10)
   * 
   * 评分逻辑:
   * 1. 提取节点特征(当前指标、统计特征、趋势特征、历史质量分特征)
   * 2. 预测节点未来表现(风险评估、预期延迟、稳定性)
   * 3. 计算评分调整值，引导节点选择策略
   */
  aiScoreNode(node, metrics) {
    // 基于多维度指标的AI评分模型
    const nodeHistory = this.nodeManager.nodeHistory.get(node.id) || [];
    const recentMetrics = this.state.metrics.get(node.id) || [];

    // 如果数据样本不足，返回默认调整值
    if (recentMetrics.length < CONSTANTS.MIN_SAMPLE_SIZE) {
      return metrics.success ? 2 : -2;
    }

    // 特征提取 - 从历史数据中提取关键性能指标
    const features = this.extractNodeFeatures(node, metrics, recentMetrics, nodeHistory);

    // 预测未来表现 - 使用特征数据预测节点稳定性和延迟
    const prediction = this.predictNodeFuturePerformance(features);

    // 计算评分调整值 (-10 到 +10)
    const adjustment = this.calculateScoreAdjustment(prediction, metrics.success);

    // 记录评分组件用于调试和优化
    // 优化：仅在调试模式且分数变化显著时记录
    if (CONSTANTS.ENABLE_SCORE_DEBUGGING && Math.abs(adjustment) > 3) {
      Logger.debug(`Node ${node.id} score components:`, {
        risk: prediction.risk,
        latency: features.currentLatency,
        loss: features.currentLoss,
        adjustment
      });
    }

    return adjustment;
  }

  /**
   * 提取节点特征
   * @param {Object} node - 节点
   * @param {Object} currentMetrics - 当前指标
   * @param {Array} recentMetrics - 最近指标
   * @param {Array} history - 历史记录
   * @returns {Object} 节点特征
   */
  extractNodeFeatures(node, currentMetrics, recentMetrics, history) {
    // 健壮性处理
    const latencies = Array.isArray(recentMetrics) ? recentMetrics.map(m => m.latency).filter(Number.isFinite) : [];
    const losses = Array.isArray(recentMetrics) ? recentMetrics.map(m => m.loss).filter(Number.isFinite) : [];
    const jitters = Array.isArray(recentMetrics) ? recentMetrics.map(m => m.jitter).filter(Number.isFinite) : [];
    const successes = Array.isArray(recentMetrics) ? recentMetrics.map(m => m.success ? 1 : 0) : [];
    const featureWindow = Array.isArray(recentMetrics) ? recentMetrics : [];
    const weightedLatency = Utils.calculateWeightedAverage(latencies);
    const weightedLoss = Utils.calculateWeightedAverage(losses);
    const successRate = successes.length ? successes.reduce((a, b) => a + b, 0) / successes.length : 1;
    return {
      currentLatency: Number.isFinite(currentMetrics.latency) ? currentMetrics.latency : 0,
      currentLoss: Number.isFinite(currentMetrics.loss) ? currentMetrics.loss : 0,
      currentJitter: Number.isFinite(currentMetrics.jitter) ? currentMetrics.jitter : 0,
      success: currentMetrics.success ? 1 : 0,
      avgLatency: latencies.length ? latencies.reduce((a, b) => a + b, 0) / latencies.length : 0,
      p95Latency: Utils.calculatePercentile(latencies, 95),
      weightedLatency: weightedLatency,
      latencyStd: Utils.calculateStdDev(latencies),
      latencyCV: (Utils.calculateStdDev(latencies) / (latencies.length ? (latencies.reduce((a, b) => a + b, 0) / latencies.length) : 1)) || 0,
      avgLoss: losses.length ? losses.reduce((a, b) => a + b, 0) / losses.length : 0,
      weightedLoss: weightedLoss,
      avgJitter: jitters.length ? jitters.reduce((a, b) => a + b, 0) / jitters.length : 0,
      successRate: successRate,
      latencyTrend: Utils.calculateTrend(latencies),
      lossTrend: Utils.calculateTrend(losses),
      successTrend: Utils.calculateTrend(successes),
      qualityTrend: history && history.length >= 2 ? history[history.length - 1].score - history[history.length - 2].score : 0,
      recentQuality: history && history.length ? history[history.length - 1].score : 50,
      sampleSize: featureWindow.length
    };
  }

  /**
   * 预测节点未来表现
   * @param {Object} features - 节点特征
   * @returns {Object} 预测结果
   */
  predictNodeFuturePerformance(features) {
    // 动态权重配置 - 根据当前网络状况调整各因素权重
    const weights = this.getDynamicRiskWeights(features);

    // 基于特征计算风险分数 (0-1)
    let risk = 0;

    // 高延迟增加风险
    risk += Math.min(features.currentLatency / 1000, 1) * weights.latency;

    // 高丢包增加风险
    risk += features.currentLoss * weights.loss;

    // 延迟标准差高增加风险（不稳定）
    risk += Math.min(features.latencyStd / 100, 1) * weights.jitter;

    // 成功率低增加风险
    risk += Math.max(0, (0.8 - features.successRate) / 0.8) * weights.successRate;

    // 负面趋势增加风险
    if (features.latencyTrend > 5) risk += 0.1 * weights.trend;
    if (features.lossTrend > 0.1) risk += 0.1 * weights.trend;
    if (features.successTrend < -0.1) risk += 0.1 * weights.trend;

    // 低质量分增加风险
    risk += Math.max(0, (50 - features.recentQuality) / 50) * weights.quality;

    // 成功状态降低风险
    risk *= (1 - features.success * 0.3);

    // 确保风险在0-1之间
    risk = Math.max(0, Math.min(1, risk));

    // 计算预期稳定性评分 (0-100)
    const stabilityScore = Math.round((1 - risk) * 100);

    return {
      risk,
      expectedLatency: features.weightedLatency + features.latencyTrend * 5,
      expectedStability: 1 - risk,
      stabilityScore: stabilityScore,
      confidence: Math.min(1, features.sampleSize / CONSTANTS.FEATURE_WINDOW_SIZE) // 基于样本量的置信度
    };
  }

  /**
   * 获取动态风险权重，根据当前网络状况调整各因素权重
   * @param {Object} features - 节点特征
   * @returns {Object} 各因素权重
   */
  // 优化：基于网络状况动态调整风险权重
  getDynamicRiskWeights(features) {
    // 高延迟环境下降低延迟权重，提高稳定性权重
    // 基础权重配置
    const baseWeights = {
      latency: 0.25,
      loss: 0.25,
      jitter: 0.15,
      successRate: 0.15,
      trend: 0.1,
      quality: 0.1
    };

    // 如果网络不稳定，增加稳定性相关权重
    if (features.successRate < 0.8 || features.latencyStd > 50) {
      baseWeights.successRate = Math.min(0.3, baseWeights.successRate + 0.1);
      baseWeights.jitter = Math.min(0.3, baseWeights.jitter + 0.05);
      baseWeights.latency = Math.max(0.1, baseWeights.latency - 0.1);
      baseWeights.loss = Math.max(0.1, baseWeights.loss - 0.05);
    }

    // 归一化权重确保总和为1
    const total = Object.values(baseWeights).reduce((sum, w) => sum + w, 0);
    // 防止除零错误
    if (total <= 0) return { latency: 0.25, loss: 0.25, jitter: 0.15, successRate: 0.15, trend: 0.1, quality: 0.1 };
    return Object.fromEntries(
      Object.entries(baseWeights).map(([k, v]) => [k, v / total])
    );
  }

  /**
   * 计算评分调整值
   * @param {Object} prediction - 预测结果
   * @param {boolean} success - 是否成功
   * @returns {number} 评分调整值
   */
  calculateScoreAdjustment(prediction, success) {
    // 基于预测结果计算评分调整值
    if (!success) return -10; // 失败大幅扣分

    // 根据风险预测调整分数
    if (prediction.risk < 0.3) return 5;  // 低风险加分
    if (prediction.risk < 0.5) return 2;  // 中低风险小幅加分
    if (prediction.risk > 0.7) return -3; // 高风险扣分
    return 0; // 中等风险不调整
  }

  /**
   * 处理配置对象，生成最终的代理配置
   * @param {Object} config - 原始配置对象
   * @returns {Object} 处理后的配置对象
   */
  processConfiguration(config) {
    // 深拷贝，防止污染
    let safeConfig;
    try {
      safeConfig = JSON.parse(JSON.stringify(config));
    } catch (e) {
      throw new Error('配置对象无法深拷贝，可能包含循环引用或不可序列化内容');
    }
    this.state.config = safeConfig;
    this.stats.reset();
    this.successTracker.reset();
    // 验证代理配置
    const proxyCount = safeConfig?.proxies?.length ?? 0;
    const proxyProviderCount = typeof safeConfig?.['proxy-providers'] === 'object' ? Object.keys(safeConfig['proxy-providers']).length : 0;
    if (proxyCount === 0 && proxyProviderCount === 0) {
      throw new Error('未检测到任何代理节点或代理提供者');
    }
    // 应用系统配置
    Object.assign(safeConfig, Config.system);
    safeConfig.dns = Config.dns;
    if (!Config.enable) return safeConfig;
    // 处理地区代理组
    const regionProxyGroups = [];
    let otherProxyGroups = safeConfig.proxies.map(proxy => proxy.name);
    Config.regionOptions.regions.forEach(region => {
      const proxies = Utils.filterProxiesByRegion(safeConfig.proxies, region);
      if (proxies.length > 0) {
        regionProxyGroups.push({
          ...Config.common.proxyGroup,
          name: region.name,
          type: 'url-test',
          tolerance: 50,
          icon: region.icon,
          proxies: proxies
        });
        // 从其他节点中移除已分类的代理
        otherProxyGroups = otherProxyGroups.filter(name => !proxies.includes(name));
      }
    });
    const regionGroupNames = regionProxyGroups.map(group => group.name);
    if (otherProxyGroups.length > 0) {
      regionGroupNames.push('其他节点');
    }
    // 初始化代理组
    safeConfig['proxy-groups'] = [{
      ...Config.common.proxyGroup,
      name: '默认节点',
      type: 'select',
      proxies: [...regionGroupNames, '直连'],
      icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Proxy.png'
    }];
    // 添加直连代理
    safeConfig.proxies = safeConfig?.proxies || [];
    if (!safeConfig.proxies.some(p => p.name === '直连')) {
      safeConfig.proxies.push({ name: '直连', type: 'direct' });
    }
    // 处理服务规则和代理组
    const ruleProviders = new Map();
    ruleProviders.set('applications', {
      ...Config.common.ruleProvider,
      behavior: 'classical',
      format: 'text',
      url: 'https://fastly.jsdelivr.net/gh/DustinWin/ruleset_geodata@clash-ruleset/applications.list',
      path: './ruleset/DustinWin/applications.list'
    });
    const rules = [...Config.preRules];
    Utils.createServiceGroups(safeConfig, regionGroupNames, ruleProviders, rules);
    Config.common.defaultProxyGroups.forEach(group => {
      safeConfig['proxy-groups'].push({
        ...Config.common.proxyGroup,
        name: group.name,
        type: 'select',
        proxies: [...group.proxies, ...regionGroupNames],
        url: group.url || Config.common.proxyGroup.url,
        icon: group.icon
      });
    });
    safeConfig['proxy-groups'] = safeConfig['proxy-groups'].concat(regionProxyGroups);
    if (otherProxyGroups.length > 0) {
      safeConfig['proxy-groups'].push({
        ...Config.common.proxyGroup,
        name: '其他节点',
        type: 'select',
        proxies: otherProxyGroups,
        icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/World_Map.png'
      });
    }
    rules.push(...Config.common.postRules);
    safeConfig.rules = rules;
    safeConfig['rule-providers'] = Object.fromEntries(ruleProviders);
    return safeConfig;
  }

  /**
   * 模拟节点多指标测试
   * @param {Object} node - 节点对象
   * @returns {Promise<Object>} 包含延迟、丢包、抖动等指标
   * @description 这是一个模拟函数，实际应替换为真实的节点测试逻辑，例如通过外部工具或API进行测试。
   */
  async testNodeMultiMetrics(node) {
    // 优化：使用缓存、重试和真实网络测试以测量延迟和带宽；在不可用时退回到模拟值
    const cacheKey = `nodeMetrics:${node.id}`;
    const cached = this.lruCache.get(cacheKey);
    if (cached) return cached;

    const timeout = CONSTANTS.NODE_TEST_TIMEOUT || 5000;

    const probe = async () => {
      const probeUrl = node.proxyUrl || node.probeUrl || (node.server ? `http://${node.server}` : null);
      if (!probeUrl || typeof fetch === 'undefined') {
        throw new Error('无探测URL或环境不支持 fetch，使用模拟测试');
      }

      const start = Date.now();
      const response = await this._safeFetch(probeUrl, { method: 'GET' }, timeout);
      const latency = Date.now() - start;

      let bytes = 0;
      let loss = 0; // 无法精确测量丢包，使用0或后续扩展API
      let jitter = 0;

      // 尝试使用流读取并限制读取大小以测量吞吐
      try {
        if (response && response.body && typeof response.body.getReader === 'function') {
          const reader = response.body.getReader();
          const maxBytes = 32 * 1024; // 32KB
          let readStart = Date.now();
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            bytes += value.byteLength || value.length || 0;
            if (bytes >= maxBytes) break;
          }
          const readEnd = Date.now();
          const readTime = Math.max(1, readEnd - readStart);
          const speedKbps = (bytes * 8) / readTime; // kb/s
          jitter = Math.max(1, 200 - Math.min(200, Math.round(speedKbps / 10)));
        } else {
          const buf = await response.arrayBuffer();
          bytes = buf.byteLength || 0;
        }
      } catch (e) {
        bytes = parseInt(response.headers && response.headers.get ? response.headers.get('Content-Length') || '0' : '0') || 0;
      }

      return { latency, loss, jitter, bytes };
    };

    try {
      const result = await Utils.retry(() => probe(), 2, 200);
      // 缓存短期结果以减少重复探测
      try { this.lruCache.set(cacheKey, result, 60000); } catch (e) { /* ignore cache set errors */ }
      return result;
    } catch (e) {
      Logger.debug('真实网络探测失败，使用模拟数据:', e && e.message ? e.message : e);
      // 退回到原有的模拟逻辑，保持兼容性与性能
      return new Promise(resolve => {
        setTimeout(() => {
          const latency = Math.random() * 500 + 50; // 50-550ms
          const loss = Math.random() * 0.1; // 0-10%
          const jitter = Math.random() * 50; // 0-50ms
          const bytes = Math.floor(Math.random() * 32 * 1024);
          const simulated = { latency, loss, jitter, bytes, __simulated: true };
          try { this.lruCache.set(cacheKey, simulated, 60000); } catch (e) {}
          resolve(simulated);
        }, Math.random() * 500);
      });
    }
  }
}

const Config = {
  // 总开关
  enable: true,

  // 分流规则配置
  ruleOptions: {
    apple: true,       // 苹果服务
    microsoft: true,  // 微软服务
    github: true,     // Github服务
    google: true,     // Google服务
    openai: true,     // 国外AI和GPT
    spotify: true,    // Spotify
    youtube: true,    // YouTube
    bahamut: true,    // 巴哈姆特/动画疯
    netflix: true,    // Netflix网飞
    tiktok: true,     // 国际版抖音
    disney: true,     // 迪士尼
    pixiv: true,      // Pixiv
    hbo: true,        // HBO
    biliintl: true,   // 哔哩哔哩东南亚
    tvb: true,        // TVB
    hulu: true,       // Hulu
    primevideo: true, // 亚马逊prime video
    telegram: true,   // Telegram通讯软件
    line: true,       // Line通讯软件
    whatsapp: true,   // Whatsapp
    games: true,      // 游戏策略组
    japan: true,      // 日本网站策略组
    tracker: true,    // 网络分析和跟踪服务
    ads: true         // 常见的网络广告
  },

  // 前置规则
  preRules: [
    'RULE-SET,applications,下载软件',
    'PROCESS-NAME,SunloginClient,DIRECT',
    'PROCESS-NAME,SunloginClient.exe,DIRECT',
    'PROCESS-NAME,AnyDesk,DIRECT',
    'PROCESS-NAME,AnyDesk.exe,DIRECT'
  ],

  // 地区配置
  regionOptions: {
    excludeHighPercentage: true,
    ratioLimit: 2, // 统一倍率限制
    regions: [
      { name: 'HK香港', regex: /港|🇭🇰|hk|hongkong|hong kong/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Hong_Kong.png' },
      { name: 'US美国', regex: /美|🇺🇸|us|united state|america/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/United_States.png' },
      { name: 'JP日本', regex: /日本|🇯🇵|jp|japan/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Japan.png' },
      { name: 'KR韩国', regex: /韩|🇰🇷|kr|korea/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Korea.png' },
      { name: 'SG新加坡', regex: /新加坡|🇸🇬|sg|singapore/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Singapore.png' },
      { name: 'CN中国大陆', regex: /中国|🇨🇳|cn|china/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/China_Map.png' },
      { name: 'TW台湾省', regex: /台湾|🇹🇼|tw|taiwan|tai wan/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/China.png' },
      { name: 'GB英国', regex: /英|🇬🇧|uk|united kingdom|great britain/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/United_Kingdom.png' },
      { name: 'DE德国', regex: /德国|🇩🇪|de|germany/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Germany.png' },
      { name: 'MY马来西亚', regex: /马来|my|malaysia/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Malaysia.png' }, // 修复国旗表情错误
      { name: 'TK土耳其', regex: /土耳其|🇹🇷|tk|turkey/i, icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Turkey.png' }
    ]
  },

  // DNS配置
  dns: {
    enable: true,
    listen: ':1053',
    ipv6: true,
    'prefer-h3': true,
    'use-hosts': true,
    'use-system-hosts': true,
    'respect-rules': true,
    'enhanced-mode': 'fake-ip',
    'fake-ip-range': '198.18.0.1/16',
    'fake-ip-filter': ['*', '+.lan', '+.local', '+.market.xiaomi.com'],
    nameserver: ['https://120.53.53.53/dns-query', 'https://223.5.5.5/dns-query'],
    'proxy-server-nameserver': ['https://120.53.53.53/dns-query', 'https://223.5.5.5/dns-query'],
    'nameserver-policy': {
      'geosite:private': 'system',
      'geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn': ['119.29.29.29', '223.5.5.5']
    }
  },

  // 服务配置 - 数据驱动定义所有服务
  services: [
    { id: 'openai', rule: ['DOMAIN-SUFFIX,grazie.ai,国外AI', 'DOMAIN-SUFFIX,grazie.aws.intellij.net,国外AI', 'RULE-SET,ai,国外AI'], name: '国外AI', url: 'https://chat.openai.com/cdn-cgi/trace', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/ChatGPT.png', ruleProvider: {name: 'ai', url: 'https://github.com/dahaha-365/YaNet/raw/refs/heads/dist/rulesets/mihomo/ai.list'} },
    { id: 'youtube', rule: ['GEOSITE,youtube,YouTube'], name: 'YouTube', url: 'https://www.youtube.com/s/desktop/494dd881/img/favicon.ico', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/YouTube.png' },
    { id: 'biliintl', rule: ['GEOSITE,biliintl,哔哩哔哩东南亚'], name: '哔哩哔哩东南亚', url: 'https://www.bilibili.tv/', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/bilibili_3.png', proxiesOrder: ['默认节点', '直连'] },
    { id: 'bahamut', rule: ['GEOSITE,bahamut,巴哈姆特'], name: '巴哈姆特', url: 'https://ani.gamer.com.tw/ajax/getdeviceid.php', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Bahamut.png', proxiesOrder: ['默认节点', '直连'] },
    { id: 'disney', rule: ['GEOSITE,disney,Disney+'], name: 'Disney+', url: 'https://disney.api.edge.bamgrid.com/devices', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Disney+.png' },
    { id: 'netflix', rule: ['GEOSITE,netflix,NETFLIX'], name: 'NETFLIX', url: 'https://api.fast.com/netflix/speedtest/v2?https=true', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Netflix.png' },
    { id: 'tiktok', rule: ['GEOSITE,tiktok,Tiktok'], name: 'Tiktok', url: 'https://www.tiktok.com/', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/TikTok.png' },
    { id: 'spotify', rule: ['GEOSITE,spotify,Spotify'], name: 'Spotify', url: 'http://spclient.wg.spotify.com/signup/public/v1/account', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Spotify.png' },
    { id: 'pixiv', rule: ['GEOSITE,pixiv,Pixiv'], name: 'Pixiv', url: 'https://www.pixiv.net/favicon.ico', icon: 'https://play-lh.googleusercontent.com/8pFuLOHF62ADcN0ISUAyEueA5G8IF49mX_6Az6pQNtokNVHxIVbS1L2NM62H-k02rLM=w240-h480-rw' }, // 修复错误的URL
    { id: 'hbo', rule: ['GEOSITE,hbo,HBO'], name: 'HBO', url: 'https://www.hbo.com/favicon.ico', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/HBO.png' },
    { id: 'tvb', rule: ['GEOSITE,tvb,TVB'], name: 'TVB', url: 'https://www.tvb.com/logo_b.svg', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/TVB.png' },
    { id: 'primevideo', rule: ['GEOSITE,primevideo,Prime Video'], name: 'Prime Video', url: 'https://m.media-amazon.com/images/G/01/digital/video/web/logo-min-remaster.png', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Prime_Video.png' },
    { id: 'hulu', rule: ['GEOSITE,hulu,Hulu'], name: 'Hulu', url: 'https://auth.hulu.com/v4/web/password/authenticate', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Hulu.png' },
    { id: 'telegram', rule: ['GEOIP,telegram,Telegram'], name: 'Telegram', url: 'http://www.telegram.org/img/website_icon.svg', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Telegram.png' },
    { id: 'whatsapp', rule: ['GEOSITE,whatsapp,WhatsApp'], name: 'WhatsApp', url: 'https://web.whatsapp.com/data/manifest.json', icon: 'https://static.whatsapp.net/rsrc.php/v3/yP/r/rYZqPCBaG70.png' },
    { id: 'line', rule: ['GEOSITE,line,Line'], name: 'Line', url: 'https://line.me/page-data/app-data.json', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Line.png' },
    { id: 'games', rule: ['GEOSITE,category-games@cn,国内网站', 'GEOSITE,category-games,游戏专用'], name: '游戏专用', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Game.png' },
    { id: 'tracker', rule: ['GEOSITE,tracker,跟踪分析'], name: '跟踪分析', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Reject.png', proxies: ['REJECT', '直连', '默认节点'] },
    { id: 'ads', rule: ['GEOSITE,category-ads-all,广告过滤', 'RULE-SET,adblockmihomo,广告过滤'], name: '广告过滤', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Advertising.png', proxies: ['REJECT', '直连', '默认节点'], ruleProvider: {name: 'adblockmihomo', url: 'https://github.com/217heidai/adblockfilters/raw/refs/heads/main/rules/adblockmihomo.mrs', format: 'mrs', behavior: 'domain'} },
    { id: 'apple', rule: ['GEOSITE,apple-cn,苹果服务'], name: '苹果服务', url: 'http://www.apple.com/library/test/success.html', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Apple_2.png' },
    { id: 'google', rule: ['GEOSITE,google,谷歌服务'], name: '谷歌服务', url: 'http://www.google.com/generate_204', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Google_Search.png' },
    { id: 'microsoft', rule: ['GEOSITE,microsoft@cn,国内网站', 'GEOSITE,microsoft,微软服务'], name: '微软服务', url: 'http://www.msftconnecttest.com/connecttest.txt', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Microsoft.png' },
    { id: 'github', rule: ['GEOSITE,github,Github'], name: 'Github', url: 'https://github.com/robots.txt', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/GitHub.png' },
    { id: 'japan', rule: ['RULE-SET,category-bank-jp,日本网站', 'GEOIP,jp,日本网站,no-resolve'], name: '日本网站', url: 'https://r.r10s.jp/com/img/home/logo/touch.png', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/JP.png', ruleProvider: {name: 'category-bank-jp', url: 'https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/category-bank-jp.mrs', format: 'mrs', behavior: 'domain'} }
  ],

  // 系统配置
  system: {
    'allow-lan': true,
    'bind-address': '*',
    mode: 'rule',
    profile: { 'store-selected': true, 'store-fake-ip': true },
    'unified-delay': true,
    'tcp-concurrent': true,
    'keep-alive-interval': 1800,
    'find-process-mode': 'strict',
    'geodata-mode': true,
    'geodata-loader': 'memconservative',
    'geo-auto-update': true,
    'geo-update-interval': 24,
    sniffer: {
      enable: true,
      'force-dns-mapping': true,
      'parse-pure-ip': false,
      'override-destination': true,
      sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, '8080-8880'] }, QUIC: { ports: [443, 8443] } },
      'skip-src-address': ['127.0.0.0/8', '192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
      'force-domain': ['+.google.com', '+.googleapis.com', '+.googleusercontent.com', '+.youtube.com', '+.facebook.com', '+.messenger.com', '+.fbcdn.net', 'fbcdn-a.akamaihd.net'],
      'skip-domain': ['Mijia Cloud', '+.oray.com']
    },
    ntp: { enable: true, 'write-to-system': false, server: 'cn.ntp.org.cn' },
    'geox-url': {
      geoip: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat',
      geosite: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat',
      mmdb: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb',
      asn: 'https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb'
    }
  },

  // 通用配置
  common: {
    ruleProvider: { type: 'http', format: 'yaml', interval: 86400 },
    proxyGroup: { interval: 300, timeout: 3000, url: 'http://cp.cloudflare.com/generate_204', lazy: true, 'max-failed-times': 3, hidden: false },
    defaultProxyGroups: [
      { name: '下载软件', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Download.png', proxies: ['直连', 'REJECT', '默认节点', '国内网站'] },
      { name: '其他外网', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/Streaming!CN.png', proxies: ['默认节点', '国内网站'] },
      { name: '国内网站', url: 'http://wifi.vivo.com.cn/generate_204', icon: 'https://fastly.jsdelivr.net/gh/Koolson/Qure/IconSet/Color/StreamingCN.png', proxies: ['直连', '默认节点'] }
    ],
    postRules: ['GEOSITE,private,DIRECT', 'GEOIP,private,DIRECT,no-resolve', 'GEOSITE,cn,国内网站', 'GEOIP,cn,国内网站,no-resolve', 'MATCH,其他外网']
  }
};

/**
 * 工具函数模块 - 提供通用功能
 */
const Utils = {
  /**
   * 根据地区过滤代理
   * @param {Array} proxies - 代理列表
   * @param {Object} region - 地区
   * @returns {Array} 过滤后的代理名称列表
   */
  filterProxiesByRegion(proxies, region) {
    if (!Array.isArray(proxies) || !region || !region.regex) return [];
    return proxies
      .filter(proxy => {
        if (!proxy || typeof proxy.name !== 'string') return false;
        const multiplierMatch = proxy.name.match(/(?:[xX✕✖⨉]|倍率)(\d+\.?\d*)/i);
        const multiplier = multiplierMatch ? parseFloat(multiplierMatch[1]) : 0;
        return proxy.name.match(region.regex) && multiplier <= Config.regionOptions.ratioLimit;
      })
      .map(proxy => proxy.name);
  },
  /**
   * 创建服务组
   * @param {Object} config - 配置
   * @param {Array} regionGroupNames - 地区组名称
   * @param {Map} ruleProviders - 规则提供者
   * @param {Array} rules - 规则
   */
  createServiceGroups(config, regionGroupNames, ruleProviders, rules) {
    if (!config || !Array.isArray(regionGroupNames) || !(ruleProviders instanceof Map) || !Array.isArray(rules)) return;
    Config.services.forEach(service => {
      if (!Config.ruleOptions[service.id]) return;
      if (Array.isArray(service.rule)) rules.push(...service.rule);
      if (service.ruleProvider) {
        ruleProviders.set(service.ruleProvider.name, {
          ...Config.common.ruleProvider,
          behavior: service.ruleProvider.behavior || 'classical',
          format: service.ruleProvider.format || 'text',
          url: service.ruleProvider.url,
          path: `./ruleset/${service.ruleProvider.name.split('-')[0]}/${service.ruleProvider.name}.${service.ruleProvider.format || 'list'}`
        });
      }
      const proxies = service.proxies || [
        '默认节点',
        ...(service.proxiesOrder || []),
        ...regionGroupNames,
        '直连'
      ];
      config['proxy-groups'].push({
        ...Config.common.proxyGroup,
        name: service.name,
        type: 'select',
        proxies: proxies,
        url: service.url || Config.common.proxyGroup.url,
        icon: service.icon
      });
    });
  },
  /**
   * 并发执行任务
   * @param {Array<Function>} tasks - 任务列表
   * @param {number} limit - 并发限制
   * @returns {Promise<Array>} 任务结果
   */
  async runWithConcurrency(tasks, limit = 5) {
    if (!Array.isArray(tasks) || tasks.length === 0) return [];
    if (typeof limit !== 'number' || limit < 1) limit = 5;
    const results = [];
    let idx = 0;
    async function next() {
      if (idx >= tasks.length) return;
      const current = idx++;
      try {
        results[current] = { status: 'fulfilled', value: await tasks[current]() };
      } catch (e) {
        results[current] = { status: 'rejected', reason: e };
      }
      await next();
    }
    const runners = Array(Math.min(limit, tasks.length)).fill(0).map(() => next());
    await Promise.all(runners);
    return results;
  },
  /**
   * 并发池：兼容返回原始值的任务数组
   * @param {Array<Function|Promise>} tasks
   * @param {number} concurrency
   */
  async asyncPool(tasks, concurrency = CONSTANTS.CONCURRENCY_LIMIT) {
    if (!Array.isArray(tasks) || tasks.length === 0) return [];
    // 复用现有 runWithConcurrency（它返回 {status, value/reason} 对象）
    const results = await this.runWithConcurrency(tasks, concurrency);
    return results.map(r => (r && r.status === 'fulfilled' ? r.value : { __error: r && r.reason }));
  },
  /**
   * 简单重试（指数退避）
   * @param {Function} fn - 异步函数
   * @param {number} attempts
   * @param {number} delay
   */
  async retry(fn, attempts = 3, delay = 200) {
    let lastErr;
    for (let i = 0; i < attempts; i++) {
      try {
        return await fn();
      } catch (e) {
        lastErr = e;
        if (i < attempts - 1) await new Promise(r => setTimeout(r, delay * Math.pow(2, i)));
      }
    }
    throw lastErr;
  },
  sleep(ms = 0) { return new Promise(r => setTimeout(r, ms)); },
  /**
   * 计算加权平均值
   * @param {Array<number>} values - 数值列表
   * @param {number} [weightFactor=0.9] - 权重因子
   * @returns {number} 加权平均值
   */
  calculateWeightedAverage(values, weightFactor = 0.9) {
    if (!Array.isArray(values) || values.length === 0) return 0;
    let sum = 0, weightSum = 0;
    values.forEach((val, idx) => {
      const weight = Math.pow(weightFactor, values.length - idx - 1);
      sum += val * weight;
      weightSum += weight;
    });
    return weightSum === 0 ? 0 : sum / weightSum;
  },
  /**
   * 计算标准差
   * @param {Array<number>} values - 数值列表
   * @returns {number} 标准差
   */
  calculateStdDev(values) {
    if (!Array.isArray(values) || values.length === 0) return 0;
    const avg = values.reduce((a, b) => a + b, 0) / values.length;
    return Math.sqrt(values.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / values.length);
  },
  /**
   * 计算趋势
   * @param {Array<number>} values - 数值列表
   * @returns {number} 趋势
   */
  calculateTrend(values) {
    const n = Array.isArray(values) ? values.length : 0;
    if (n < 2) return 0;
    let sumX = 0, sumY = 0, sumXY = 0, sumX2 = 0, sumWeights = 0;
    for (let i = 0; i < n; i++) {
      const weight = (i + 1) / n;
      const x = i;
      const y = values[i];
      sumWeights += weight;
      sumX += x * weight;
      sumY += y * weight;
      sumXY += x * y * weight;
      sumX2 += x * x * weight;
    }
    const numerator = sumWeights * sumXY - sumX * sumY;
    const denominator = sumWeights * sumX2 - sumX * sumX;
    if (denominator === 0) return 0;
    return numerator / denominator;
  },
  /**
   * 计算百分位数
   * @param {Array<number>} values - 数值列表
   * @param {number} percentile - 百分位
   * @returns {number} 百分位数
   */
  calculatePercentile(values, percentile) {
    if (!Array.isArray(values) || values.length === 0) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const index = (percentile / 100) * (sorted.length - 1);
    if (Math.floor(index) === index) {
      return sorted[index];
    }
    const i = Math.floor(index);
    const fraction = index - i;
    return sorted[i] + (sorted[i + 1] - sorted[i]) * fraction;
  }
};

/**
 * 主函数
 * @param {Object} config - 原始配置对象
 * @returns {Object} 处理后的配置对象
 */
function main(config) {
  const centralManager = new CentralManager();
  return centralManager.processConfiguration(config);
}
