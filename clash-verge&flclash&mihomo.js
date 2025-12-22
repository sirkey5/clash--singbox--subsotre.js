"use strict";

/**
 * Central Orchestrator - 全自动智能事件驱动增强版 (优化重构版)
 * - 结构优化：统一配置构建器，消除重复逻辑
 * - 性能提升：使用现代JS API，优化工具函数
 * - 代码精简：压缩常量定义，内联工具函数
 * - 保留功能：完整保持原有API和行为兼容
 */

const PLATFORM = (() => {
  const isNode = typeof process !== "undefined" && !!process.versions?.node;
  const isBrowser = typeof window !== "undefined" && typeof window.addEventListener === "function";
  return Object.freeze({ isNode, isBrowser });
})();

/** 统一常量管理（压缩优化版） */
const CONSTANTS = Object.freeze({
  PREHEAT_NODE_COUNT: 10,
  NODE_TEST_TIMEOUT: 5000,
  BASE_SWITCH_COOLDOWN: 30 * 60 * 1000,
  MIN_SWITCH_COOLDOWN: 5 * 60 * 1000,
  MAX_SWITCH_COOLDOWN: 2 * 60 * 60 * 1000,
  MAX_HISTORY_RECORDS: 100,
  NODE_EVALUATION_THRESHOLD: 3 * 60 * 60 * 1000,
  LRU_CACHE_MAX_SIZE: 1000,
  LRU_CACHE_TTL: 3600000,
  CONCURRENCY_LIMIT: 5,
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
  MAX_RETRY_BACKOFF_MS: 5000,

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
  HTTP_PORTS: [80, 8080, 8880],

  BIAS_AVAIL_BONUS_OK: 10,
  BIAS_AVAIL_PENALTY_BAD: -30,
  BIAS_LATENCY_MAX_BONUS: 15,
  BIAS_JITTER_MAX_PENALTY: 10,

  SAFE_PORTS: new Set([80, 443, 8080, 8081, 8088, 8880, 8443]),
  ADBLOCK_UPDATE_INTERVAL_MS: 12 * 60 * 60 * 1000,
  ADBLOCK_RULE_TTL_MS: 24 * 60 * 60 * 1000,

  EARLY_SAMPLE_SCORE: 2,
  POOL_WINDOW_SIZE: 100,
  GOOD_PERCENTILE: 90,
  BAD_PERCENTILE: 50,
  ADAPT_ALPHA: 0.5,
  MIN_POOL_ITEMS_FOR_ADAPT: 10,

  DATA_URL_MAX_BYTES: 2 * 1024 * 1024,
  DATA_URL_PREFIX: "data:text/plain;base64,",

  // 修复：提取 ScoringStrategies 中的 Magic Numbers
  VIDEO_STREAM_BONUS: 1,
  
  // 修复：asyncPool 中的魔法数字
  ASYNC_POOL_MAX_CONCURRENCY: 50,
  ASYNC_POOL_DEFAULT_LIMIT: 3,
  
  // 修复：NodeScorer 中的魔法数字
  DEFAULT_SCORING_WEIGHTS: { latency: 0.4, loss: 0.3, jitter: 0.2, speed: 0.1 },
  LATENCY_HIGH_THRESHOLD: 500,
  LATENCY_BASE_SCORE: 35,
  LATENCY_SCALE_FACTOR: 100,
  LATENCY_EXPONENT: 1.5,
  LATENCY_DIVISOR: 25,
  JITTER_BASE_SCORE: 25,
  LOSS_BASE_SCORE: 25,
  THROUGHPUT_SCALE_FACTOR: 2,
  
  // 修复：AdBlockManager 中的魔法数字
  ADBLOCK_BATCH_SIZE: 500,
  ADBLOCK_CHUNK_SIZE: 50000,

  // 修复：GitHub 镜像系统探测频率魔法数字
  GH_PROBE_TTL: 10 * 60 * 1000
});

const ScoringStrategies = {
  Default(context, helpers) {
    return helpers.adjust(context.prediction, context.metrics.success);
  },
  Video(context, helpers) {
    const base = helpers.adjust(context.prediction, context.metrics.success);
    const bytes = Number(context.metrics.bytes) || 0;
    // 修复：使用常量替代 Magic Number
    return base + (bytes >= CONSTANTS.LARGE_PAYLOAD_THRESHOLD_BYTES ? CONSTANTS.VIDEO_STREAM_BONUS : 0);
  }
};

// 修复：添加敏感信息脱敏工具
const DataMasker = {
  // 修复：扩展敏感参数正则，增加更多常见敏感参数
  maskUrl: (url) => {
    if (typeof url !== "string") return url;
    try {
      return url.replace(/([?&](token|key|auth|password|secret|access_token|api_key|session_id|credential)=)[^&]+/gi, '$1******');
    } catch {
      return url;
    }
  },
  
  // 修复：增加 IPv6 脱敏处理
  maskIP: (ip) => {
    if (typeof ip !== "string") return ip;
    try {
      // 处理 IPv4
      let masked = ip.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b/g, '$1***');
      // 处理 IPv6（增强版，隐藏更多地址段）
      // 隐藏后4组IPv6地址段
      masked = masked.replace(/([0-9a-fA-F]{1,4}:){4}[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}:[0-9a-fA-F]{1,4}/g, '$1****:****:****:****');
      return masked;
    } catch {
      return ip;
    }
  },  
  // 递归脱敏对象中的敏感信息
  maskObject: (obj, depth = 0, maxDepth = 5) => {
    if (depth > maxDepth) return '[MAX_DEPTH_REACHED]';
    if (obj === null || typeof obj !== "object") return obj;
    
    const sensitiveKeys = /password|token|key|secret|auth|credential|access/i;
    
    if (Array.isArray(obj)) {
      return obj.map(item => DataMasker.maskObject(item, depth + 1, maxDepth));
    }
    
    const masked = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        if (sensitiveKeys.test(key)) {
          masked[key] = '***MASKED***';
        } else if (typeof obj[key] === 'string') {
          masked[key] = DataMasker.maskUrl(DataMasker.maskIP(obj[key]));
        } else {
          masked[key] = DataMasker.maskObject(obj[key], depth + 1, maxDepth);
        }
      }
    }
    return masked;
  }
};

// 修复：提取私有日志函数，减少代码重复并增加脱敏
const Logger = {
  // 私有日志函数，统一处理逻辑，增加敏感信息脱敏
  _log: (level, ctx, args, forceLog = false) => {
    if (typeof console === "undefined") return;
    if (level === "DEBUG" && !CONSTANTS.ENABLE_SCORE_DEBUGGING && !forceLog) return;
    
    const prefix = `[${level}]`;
    const context = ctx || "-";
    
    // 修复：脱敏日志参数，防止敏感信息泄露
    const sanitizedArgs = args.map(arg => {
      if (typeof arg === "string") {
        return DataMasker.maskUrl(DataMasker.maskIP(arg));
      } else if (typeof arg === "object" && arg !== null) {
        return DataMasker.maskObject(arg);
      }
      return arg;
    });
    
    // 尝试使用对应级别的日志方法，回退到 log
    const logMethod = console[level.toLowerCase()] || console.log;
    if (typeof logMethod === "function") {
      logMethod(prefix, context, ...sanitizedArgs);
      return;
    }
    
    // 最终回退到 console.log
    if (typeof console.log === "function") {
      console.log(prefix, context, ...sanitizedArgs);
    }
  },

	error: (ctx, ...a) => {
		Logger._log("ERROR", ctx, a);
	},
	info: (ctx, ...a) => {
		Logger._log("INFO", ctx, a);
	},
	warn: (ctx, ...a) => {
		Logger._log("WARN", ctx, a);
	},
	debug: (ctx, ...a) => {
		Logger._log("DEBUG", ctx, a);
	}
};

class ConfigurationError extends Error { 
  constructor(m) { 
    super(m); 
    this.name = "ConfigurationError"; 
  } 
}

class InvalidRequestError extends Error { 
  constructor(m) { 
    super(m); 
    this.name = "InvalidRequestError"; 
  } 
}

/* ============== 优化工具集 ============== */
const Utils = {
  now: () => Date.now(),
  clamp: (v, min, max) => Math.max(min, Math.min(max, v)),
  clamp01: (v) => Math.max(0, Math.min(1, v)),
  sleep: (ms = 0) => new Promise(r => setTimeout(r, Math.max(0, ms | 0))),
  
  // 修复：改进的深拷贝，支持循环引用和原型污染防护
  deepClone: (obj) => {
    if (typeof structuredClone === "function") {
      try {
        return structuredClone(obj);
      } catch (e) {
        // structuredClone 可能因循环引用失败，继续使用自定义实现
      }
    }
    
    // 修复：使用 WeakMap 处理循环引用，避免栈溢出
    const cache = new WeakMap();
    
    // 递归深拷贝实现，支持 Set/Map 等复杂对象
    const deepCloneImpl = (item) => {
      if (item === null || typeof item !== "object") return item;
      if (item instanceof Date) return new Date(item.getTime());
      if (item instanceof RegExp) return new RegExp(item.source, item.flags);
      if (item instanceof Set) {
        const cloned = new Set();
        for (const value of item) cloned.add(deepCloneImpl(value));
        return cloned;
      }
      if (item instanceof Map) {
        const cloned = new Map();
        for (const [key, value] of item) cloned.set(deepCloneImpl(key), deepCloneImpl(value));
        return cloned;
      }
      if (Array.isArray(item)) {
        return item.map(deepCloneImpl);
      }
      if (typeof item === "object") {
        // 修复：检查循环引用缓存
        if (cache.has(item)) {
          return cache.get(item);
        }
        
        const cloned = {};
        // 修复：缓存新对象以处理循环引用
        cache.set(item, cloned);
        
        for (const key in item) {
          // 修复：过滤危险键，防止原型污染
          if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;
          }
          if (item.hasOwnProperty(key)) {
            cloned[key] = deepCloneImpl(item[key]);
          }
        }
        return cloned;
      }
      return item;
    };
    
    try {
      return deepCloneImpl(obj);
    } catch (e) {
      // 修复：增强特殊对象的 JSON 回退处理
      try {
        return JSON.parse(JSON.stringify(obj, (key, value) => {
          if (value instanceof RegExp) {
            return { __type: 'RegExp', source: value.source, flags: value.flags };
          }
          if (value instanceof Map) {
            return { __type: 'Map', entries: Array.from(value.entries()) };
          }
          if (value instanceof Set) {
            return { __type: 'Set', values: Array.from(value.values()) };
          }
          return value;
        }), (key, value) => {
          if (value?.__type === 'RegExp') {
            return new RegExp(value.source, value.flags);
          }
          if (value?.__type === 'Map') {
            return new Map(value.entries);
          }
          if (value?.__type === 'Set') {
            return new Set(value.values);
          }
          return value;
        });
      } catch {
        return obj; // 最后回退：返回原对象
      }
    }
  },

  // 修复：优化并发池实现，改用数组管理并跟踪索引，减少集合操作开销
  async asyncPool(tasks, limit = CONSTANTS.CONCURRENCY_LIMIT) {
    const list = Array.isArray(tasks) ? tasks.filter(f => typeof f === "function") : [];
    if (!list.length) return [];
    
    const maxConcurrency = Math.max(1, Math.min(CONSTANTS.ASYNC_POOL_MAX_CONCURRENCY, Math.floor(limit) || CONSTANTS.ASYNC_POOL_DEFAULT_LIMIT));
    const results = new Array(list.length);
    const executing = []; 
    let index = 0;

    const runTask = async (i) => {
      try {
        results[i] = await list[i]();
      } catch (error) {
        results[i] = { 
          __error: error?.message || "任务执行失败", 
          __index: i,
          __originalError: error 
        };
      } finally {
        // 移除完成的任务索引
        const pos = executing.indexOf(i);
        if (pos > -1) executing.splice(pos, 1);
        // 继续执行剩余任务
        if (index < list.length) {
          const nextIndex = index++;
          executing.push(nextIndex);
          await runTask(nextIndex);
        }
      }
    };

    // 启动初始任务
    const initial = Math.min(maxConcurrency, list.length);
    const promises = [];
    for (; index < initial; index++) {
      executing.push(index);
      promises.push(runTask(index));
    }

    // 等待所有任务完成。由于 runTask 会递归调用自身，我们只需等待初始启动的任务完成
    await Promise.all(promises);
    
    return results;
  },

  // 指数退避重试（保持原有逻辑）
  async retry(fn, attempts = CONSTANTS.MAX_RETRY_ATTEMPTS, delay = CONSTANTS.RETRY_DELAY_BASE) {
    const maxA = Math.max(1, Math.min(10, Math.floor(attempts)));
    const baseD = Math.max(0, Math.min(CONSTANTS.MAX_RETRY_BACKOFF_MS, Math.floor(delay)));
    let lastErr;
    for (let i = 0; i < maxA; i++) {
      try { return await fn(); } catch (e) {
        lastErr = e;
        if (i < maxA - 1) await Utils.sleep(Math.min(CONSTANTS.MAX_RETRY_BACKOFF_MS, baseD * (2 ** i)));
      }
    }
    throw lastErr || new Error("retry: 所有重试都失败");
  },

  // 网络地址检测（保持原有逻辑）
  isValidDomain(d) { return typeof d === "string" && /^[a-zA-Z0-9.-]+$/.test(d) && !d.startsWith(".") && !d.endsWith(".") && !d.includes(".."); },
  
  isIPv4(ip) {
    if (typeof ip !== "string") return false;
    if (!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return false;
    const parts = ip.split(".");
    for (let i = 0; i < parts.length; i++) {
      const n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) return false;
    }
    return true;
  },

  isLoopbackOrLocal(ip) {
    if (typeof ip !== "string") return false;
    if (ip === "localhost" || ip === "localhost.localdomain") return true;
    if (!Utils.isIPv4(ip)) return false;
    return ip === "127.0.0.1" || ip === "0.0.0.0" || ip.startsWith("127.");
  },

  isPrivateIP(ip) {
    if (typeof ip !== "string" || !ip) return false;
    if (ip.includes(":")) {
      const v = ip.toLowerCase();
      if (v === "::1") return true;
      if (v.startsWith("fc") || v.startsWith("fd")) return true;
      if (v.startsWith("fe80")) return true;
      return false;
    }
    if (!Utils.isIPv4(ip)) return false;
    try {
      const parts = ip.split(".").map(n => parseInt(n, 10));
      const a = parts[0];
      const b = parts[1];
      if (a === 10) return true;
      if (a === 127) return true;
      if (a === 192 && b === 168) return true;
      if (a === 172 && b >= 16 && b <= 31) return true;
      if (a === 169 && b === 254) return true;
      if (a === 100 && b >= 64 && b <= 127) return true;
      if (a >= 224 && a <= 239) return true;
      return false;
    } catch {
      return false;
    }
  },

  isLocalDomain(domain) {
    if (typeof domain !== "string") return false;
    return domain.endsWith(".local") || domain.endsWith(".localhost") || domain.endsWith(".localdomain") || domain.endsWith(".test");
  },

  // URL安全化
  sanitizeUrl(u) {
    if (typeof u !== "string" || !u) return null;
    const trimmed = u.trim();
    if (!trimmed) return null;

    // 修复：更精确的 data-url 大小校验
    if (trimmed.startsWith(CONSTANTS.DATA_URL_PREFIX)) {
      const b64 = trimmed.slice(CONSTANTS.DATA_URL_PREFIX.length);
      // 考虑 Base64 填充字符(=)的影响
      const padding = (b64.endsWith('==') ? 2 : b64.endsWith('=') ? 1 : 0);
      const estBytes = (b64.length * 3 - padding) / 4;
      if (estBytes <= CONSTANTS.DATA_URL_MAX_BYTES) return u;
      return null;
    }

    if (!/^https?:\/\//i.test(trimmed)) return null;

    try {
      const url = new URL(trimmed);
      const scheme = url.protocol.replace(":", "").toLowerCase();
      if (!["http", "https"].includes(scheme)) return null;
      url.username = ""; url.password = "";

      const port = url.port ? parseInt(url.port, 10) : (scheme === "https" ? 443 : 80);
      if (!CONSTANTS.SAFE_PORTS.has(port)) {
        if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
        if (port < 1024) return null;
      }

      const host = url.hostname;
      if (Utils.isLocalDomain(host)) return null;
      if (Utils.isLoopbackOrLocal(host)) return null;
      if (Utils.isIPv4(host) && Utils.isPrivateIP(host)) return null;

      // 修复：移除强制 HTTP 转 HTTPS 的逻辑，避免破坏依赖 HTTP 的合法服务
      // if (scheme === "http" && !Utils.isPrivateIP(host) && !Utils.isLoopbackOrLocal(host)) {
      //   url.protocol = "https:"; if (!url.port || url.port === "80") url.port = "443";
      // }
      return url.toString();
    } catch { return null; }
  },

  // 工具函数保持不变但内联化
  filterProxiesByRegion(proxies, region) {
    if (!Array.isArray(proxies) || !region?.regex) return [];
    const limit = Config?.regionOptions?.ratioLimit ?? 2;
    return proxies.filter(p => {
      const name = p?.name; 
      if (typeof name !== "string") return false;
      
      // 修复：安全限制字符串长度，防止 ReDoS 攻击
      if (name.length > 100) return false;
      
      // 修复：确保 match 结果不为 null
      const m = name.match(/(?:[xX✕✖⨉]|倍率)(\d+\.?\d*)/i);
      const mult = m ? parseFloat(m[1]) : 1;
      return region.regex.test(name) && mult <= limit;
    }).map(p => p.name);
  },

  getProxyGroupBase() { return (Config.common?.proxyGroup || {}); },
  getRuleProviderBase() { return (Config.common?.ruleProvider || { type: "http", format: "yaml", interval: 86400 }); },

  safeInt(hdrValue, def = 0) {
    try { const n = parseInt(hdrValue ?? "0", 10); return Number.isFinite(n) ? n : def; } catch { return def; }
  },

  toDataUrl(text) {
    if (typeof text !== "string" || !text) return "";
    
    try {
      // 修复：在转换前检查原始文本长度，避免内存分配浪费
      const maxOriginalSize = Math.floor(CONSTANTS.DATA_URL_MAX_BYTES / 1.34); // Base64 ≈ 1.33x
      if (text.length > maxOriginalSize) {
        throw new Error(`文本过大 (${text.length} > ${maxOriginalSize})，跳过 DataURL 生成`);
      }

      // 修复：显式检查 Buffer 是否存在
      if (typeof Buffer !== "undefined") {
        const b64 = Buffer.from(text).toString("base64");
        const estBytes = Math.floor(b64.length * 0.75);
        if (estBytes > CONSTANTS.DATA_URL_MAX_BYTES) throw new Error("data-url 超出大小限制");
        return `${CONSTANTS.DATA_URL_PREFIX}${b64}`;
      }
    } catch (e) {
      // Buffer 失败，继续尝试浏览器方法
    }
    
    try {
      // 修复：优先使用现代 API，避免废弃的 unescape/encodeURIComponent
      let base64 = "";
      if (typeof TextEncoder !== "undefined" && typeof btoa === "function") {
        // 使用 TextEncoder + btoa 的现代方法
        const encoder = new TextEncoder();
        const data = encoder.encode(text);
        // 手动转换为 base64
        let binary = "";
        for (let i = 0; i < data.length; i++) {
          binary += String.fromCharCode(data[i]);
        }
        base64 = btoa(binary);
      } else if (typeof btoa === "function") {
        // 回退到传统方法（已废弃但更兼容）
        base64 = btoa(unescape(encodeURIComponent(text)));
      } else {
        return ""; // 不支持 base64 编码
      }
      
      const estBytes = Math.floor(base64.length * 0.75);
      if (estBytes > CONSTANTS.DATA_URL_MAX_BYTES) throw new Error("data-url 超出大小限制");
      return `${CONSTANTS.DATA_URL_PREFIX}${base64}`;
    } catch { return ""; }
  },  // 修复：添加缺失的 safeSet 方法
  safeSet: (obj, key, val) => {
    if (obj && typeof obj === "object") {
      obj[key] = val;
    }
  }
};

/* ============== GitHub 镜像系统 ============== */
const GH_MIRRORS = ["", "https://mirror.ghproxy.com/", "https://github.moeyy.xyz/", "https://ghproxy.com/"];
const GH_TEST_TARGETS = [
  "https://raw.githubusercontent.com/github/gitignore/main/Node.gitignore",
  "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/main/README.md", 
  "https://raw.githubusercontent.com/cli/cli/trunk/README.md"
];

let GH_PROXY_PREFIX = "";
// 修复：更新 GitHub 镜像系统变量命名，符合规范且更清晰
let ghCurrentMirror = "";
let ghLastProbeTimestamp = 0;
let ghIsSelecting = false;
const ghWaiters = [];

const GH_RAW_URL = (path) => `${GH_PROXY_PREFIX}https://raw.githubusercontent.com/${path}`;
const GH_RELEASE_URL = (path) => `${GH_PROXY_PREFIX}https://github.com/${path}`;
const pickTestTarget = () => GH_TEST_TARGETS[Math.floor(Math.random() * GH_TEST_TARGETS.length)];

// 修复：使用 finally 确保定时器清除，避免资源泄漏
async function __probeMirror(prefix, fetchFn, timeoutMs) {
  const testUrl = prefix ? (prefix + pickTestTarget()) : pickTestTarget();
  let tid = null;
  try {
    const c = typeof AbortController !== "undefined" ? new AbortController() : null;
    if (timeoutMs > 0) {
      tid = setTimeout(() => { try { c?.abort(); } catch {} }, timeoutMs);
    }
    const resp = await fetchFn(testUrl, { method: "GET", headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT }, signal: c?.signal });
    return !!resp && resp.ok;
  } catch { 
    return false; 
  } finally {
    if (tid) clearTimeout(tid);
  }
}

async function selectBestMirror(runtimeFetch) {
  const now = Utils.now();
  // 修复：使用常量 CONSTANTS.GH_PROBE_TTL 替代魔法数字
  if (ghCurrentMirror && (now - ghLastProbeTimestamp) < CONSTANTS.GH_PROBE_TTL) return ghCurrentMirror;
  if (ghIsSelecting) return new Promise((resolve) => ghWaiters.push(resolve));
  ghIsSelecting = true;
  try {
    let resolved = false;
    let chosen = "";
    let pending = GH_MIRRORS.length;

    await Promise.all(GH_MIRRORS.map(m => (async () => {
      try {
        const ok = await __probeMirror(m, runtimeFetch, CONSTANTS.GEO_INFO_TIMEOUT);
        if (!resolved && ok) {
          resolved = true;
          chosen = m;
        }
      } catch { } finally {
        pending -= 1;
      }
    })()));

    // 修复：当没有找到更好的镜像时，保持当前有效的镜像
    if (!resolved && chosen === "") chosen = ghCurrentMirror || "";    ghCurrentMirror = chosen;
    ghLastProbeTimestamp = now;
    GH_PROXY_PREFIX = chosen;
    return chosen;
  } catch (e) {
    Logger.warn("GH.selectBestMirror", e?.message || e);
    return ghCurrentMirror || "";
  } finally {
    ghIsSelecting = false;
    while (ghWaiters.length) { const fn = ghWaiters.shift(); try { fn(ghCurrentMirror || ""); } catch {} }
  }
}

/* ============== 资源URL定义（优化版） ============== */
const ICONS = (() => {
  const base = "Koolson/Qure/master/IconSet/Color";
  const mk = n => GH_RAW_URL(`${base}/${n}.png`);
  const names = {
    Proxy: "Proxy", WorldMap: "World_Map", HongKong: "Hong_Kong", UnitedStates: "United_States",
    Japan: "Japan", Korea: "Korea", Singapore: "Singapore", ChinaMap: "China_Map", China: "China",
    UnitedKingdom: "United_Kingdom", Germany: "Germany", Malaysia: "Malaysia", Turkey: "Turkey",
    ChatGPT: "ChatGPT", YouTube: "YouTube", Bilibili3: "bilibili_3", Bahamut: "Bahamut",
    DisneyPlus: "Disney+", Netflix: "Netflix", TikTok: "TikTok", Spotify: "Spotify", Pixiv: "Pixiv",
    HBO: "HBO", TVB: "TVB", PrimeVideo: "Prime_Video", Hulu: "Hulu", Telegram: "Telegram",
    Line: "Line", Game: "Game", Reject: "Reject", Advertising: "Advertising", Apple2: "Apple_2",
    GoogleSearch: "Google_Search", Microsoft: "Microsoft", GitHub: "GitHub", JP: "JP", Download: "Download",
    StreamingCN: "StreamingCN", StreamingNotCN: "Streaming!CN"
  };
  const o = {};
  for (const k in names) o[k] = () => mk(names[k]);
  return o;
})();

const ICON_VAL = (fn) => { try { return typeof fn === "function" ? fn() : fn; } catch { return ""; } };

const URLS = (() => {
  const rulesets = {
    applications: () => GH_RAW_URL("DustinWin/ruleset_geodata/clash-ruleset/applications.list"),
    ai: () => GH_RAW_URL("dahaha-365/YaNet/dist/rulesets/mihomo/ai.list"),
    adblock_mihomo_mrs: () => GH_RAW_URL("217heidai/adblockfilters/main/rules/adblockmihomo.mrs"),
    category_bank_jp_mrs: () => GH_RAW_URL("MetaCubeX/meta-rules-dat/meta/geo/geosite/category-bank-jp.mrs"),
    adblock_easylist: () => "https://easylist.to/easylist/easylist.txt",
    adblock_easyprivacy: () => "https://easylist.to/easylist/easyprivacy.txt",
    adblock_ublock_filters: () => "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt"
  };
  const rel = f => GH_RELEASE_URL(`MetaCubeX/meta-rules-dat/releases/download/latest/${f}`);
  const geox = {
    geoip: () => rel("geoip-lite.dat"),
    geosite: () => rel("geosite.dat"), 
    mmdb: () => rel("country-lite.mmdb"),
    asn: () => rel("GeoLite2-ASN.mmdb")
  };
  return { rulesets, geox };
})();

/* ============== 配置管理（压缩版） ============== */
const Config = {
  enable: true,
  privacy: {
    geoExternalLookup: false,
    systemDnsOnly: false,
    trustedGeoEndpoints: [],
    githubMirrorEnabled: false
  },
  ruleOptions: (() => { 
    const ks = ["apple","microsoft","github","google","openai","spotify","youtube","bahamut","netflix","tiktok","disney","pixiv","hbo","biliintl","tvb","hulu","primevideo","telegram","line","whatsapp","games","japan","tracker","ads"]; 
    const o = {}; ks.forEach(k => o[k] = true); return o; 
  })(),
  preRules: ["RULE-SET,applications,下载软件","PROCESS-NAME,SunloginClient,DIRECT","PROCESS-NAME,SunloginClient.exe,DIRECT","PROCESS-NAME,AnyDesk,DIRECT","PROCESS-NAME,AnyDesk.exe,DIRECT"],
  regionOptions: { excludeHighPercentage: true, ratioLimit: 2, regions: [
    { name: "HK香港", regex: /港|🇭🇰|hk|hongkong|hong kong/i, icon: ICON_VAL(ICONS.HongKong) },
    { name: "US美国", regex: /美|🇺🇸|us|united states|america/i, icon: ICON_VAL(ICONS.UnitedStates) },
    { name: "JP日本", regex: /日本|🇯🇵|jp|japan/i, icon: ICON_VAL(ICONS.Japan) },
    { name: "KR韩国", regex: /韩|🇰🇷|kr|korea/i, icon: ICON_VAL(ICONS.Korea) },
    { name: "SG新加坡", regex: /新加坡|🇸🇬|sg|singapore/i, icon: ICON_VAL(ICONS.Singapore) },
    { name: "CN中国大陆", regex: /中国|🇨🇳|cn|china/i, icon: ICON_VAL(ICONS.ChinaMap) },
    { name: "TW台湾省", regex: /台湾|🇹🇼|tw|taiwan|tai wan/i, icon: ICON_VAL(ICONS.China) },
    { name: "GB英国", regex: /英|🇬🇧|uk|united kingdom|great britain/i, icon: ICON_VAL(ICONS.UnitedKingdom) },
    { name: "DE德国", regex: /德国|🇩🇪|de|germany/i, icon: ICON_VAL(ICONS.Germany) },
    { name: "MY马来西亚", regex: /马来|my|malaysia/i, icon: ICON_VAL(ICONS.Malaysia) },
    { name: "TR土耳其", regex: /土耳其|🇹🇷|tr|turkey/i, icon: ICON_VAL(ICONS.Turkey) }
  ]},
  dns: {
    // 修复：限制监听地址为本地回环地址，防止被外部网络滥用
    enable: true, listen: "127.0.0.1:1053", ipv6: true, "prefer-h3": true, "use-hosts": true, "use-system-hosts": true,
    "respect-rules": true, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": ["*", "+.lan", "+.local", "+.market.xiaomi.com"],
    nameserver: ["https://120.53.53.53/dns-query", "https://223.5.5.5/dns-query"],
    "proxy-server-nameserver": ["https://120.53.53.53/dns-query", "https://223.5.5.5/dns-query"],
    "nameserver-policy": { "geosite:private": "system", "geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn": ["119.29.29.29", "223.5.5.5"] }
  },
  services: [
    { id:"openai", rule:["DOMAIN-SUFFIX,grazie.ai,国外AI","DOMAIN-SUFFIX,grazie.aws.intellij.net,国外AI","RULE-SET,ai,国外AI"], name:"国外AI", url:"https://chat.openai.com/cdn-cgi/trace", icon: ICON_VAL(ICONS.ChatGPT), ruleProvider:{ name:"ai", url: URLS.rulesets.ai() } },
    { id:"youtube", rule:["GEOSITE,youtube,YouTube"], name:"YouTube", url:"https://www.youtube.com/s/desktop/494dd881/img/favicon.ico", icon: ICON_VAL(ICONS.YouTube) },
    { id:"biliintl", rule:["GEOSITE,biliintl,哔哩哔哩东南亚"], name:"哔哩哔哩东南亚", url:"https://www.bilibili.tv/", icon: ICON_VAL(ICONS.Bilibili3), proxiesOrder:["默认节点","直连"] },
    { id:"bahamut", rule:["GEOSITE,bahamut,巴哈姆特"], name:"巴哈姆特", url:"https://ani.gamer.com.tw/ajax/getdeviceid.php", icon: ICON_VAL(ICONS.Bahamut), proxiesOrder:["默认节点","直连"] },
    { id:"disney", rule:["GEOSITE,disney,Disney+"], name:"Disney+", url:"https://disney.api.edge.bamgrid.com/devices", icon: ICON_VAL(ICONS.DisneyPlus) },
    { id:"netflix", rule:["GEOSITE,netflix,NETFLIX"], name:"NETFLIX", url:"https://api.fast.com/netflix/speedtest/v2?https=true", icon: ICON_VAL(ICONS.Netflix) },
    { id:"tiktok", rule:["GEOSITE,tiktok,Tiktok"], name:"Tiktok", url:"https://www.tiktok.com/", icon: ICON_VAL(ICONS.TikTok) },
    { id:"spotify", rule:["GEOSITE,spotify,Spotify"], name:"Spotify", url:"http://spclient.wg.spotify.com/signup/public/v1/account", icon: ICON_VAL(ICONS.Spotify) },
    { id:"pixiv", rule:["GEOSITE,pixiv,Pixiv"], name:"Pixiv", url:"https://www.pixiv.net/favicon.ico", icon: ICON_VAL(ICONS.Pixiv) },
    { id:"hbo", rule:["GEOSITE,hbo,HBO"], name:"HBO", url:"https://www.hbo.com/favicon.ico", icon: ICON_VAL(ICONS.HBO) },
    { id:"tvb", rule:["GEOSITE,tvb,TVB"], name:"TVB", url:"https://www.tvb.com/logo_b.svg", icon: ICON_VAL(ICONS.TVB) },
    { id:"primevideo", rule:["GEOSITE,primevideo,Prime Video"], name:"Prime Video", url:"https://m.media-amazon.com/images/G/01/digital/video/web/logo-min-remaster.png", icon: ICON_VAL(ICONS.PrimeVideo) },
    { id:"hulu", rule:["GEOSITE,hulu,Hulu"], name:"Hulu", url:"https://auth.hulu.com/v4/web/password/authenticate", icon: ICON_VAL(ICONS.Hulu) },
    { id:"telegram", rule:["GEOIP,telegram,Telegram"], name:"Telegram", url:"http://www.telegram.org/img/website_icon.svg", icon: ICON_VAL(ICONS.Telegram) },
    { id:"whatsapp", rule:["GEOSITE,whatsapp,WhatsApp"], name:"WhatsApp", url:"https://web.whatsapp.com/data/manifest.json", icon: ICON_VAL(ICONS.Telegram) },
    { id:"line", rule:["GEOSITE,line,Line"], name:"Line", url:"https://line.me/page-data/app-data.json", icon: ICON_VAL(ICONS.Line) },
    { id:"games", rule:["GEOSITE,category-games@cn,国内网站","GEOSITE,category-games,游戏专用"], name:"游戏专用", icon: ICON_VAL(ICONS.Game) },
    { id:"tracker", rule:["GEOSITE,tracker,跟踪分析"], name:"跟踪分析", icon: ICON_VAL(ICONS.Reject), proxies:["REJECT","直连","默认节点"] },
    { id:"ads", rule:["GEOSITE,category-ads-all,广告过滤","RULE-SET,adblock_combined,广告过滤"], name:"广告过滤", icon: ICON_VAL(ICONS.Advertising), proxies:["REJECT","直连","默认节点"], ruleProvider:{ name:"adblock_combined", url: URLS.rulesets.adblock_mihomo_mrs(), format:"mrs", behavior:"domain" } },
    { id:"apple", rule:["GEOSITE,apple-cn,苹果服务"], name:"苹果服务", url:"http://www.apple.com/library/test/success.html", icon: ICON_VAL(ICONS.Apple2) },
    { id:"google", rule:["GEOSITE,google,谷歌服务"], name:"谷歌服务", url:"http://www.google.com/generate_204", icon: ICON_VAL(ICONS.GoogleSearch) },
    { id:"microsoft", rule:["GEOSITE,microsoft@cn,国内网站","GEOSITE,microsoft,微软服务"], name:"微软服务", url:"http://www.msftconnecttest.com/connecttest.txt", icon: ICON_VAL(ICONS.Microsoft) },
    { id:"github", rule:["GEOSITE,github,Github"], name:"Github", url:"https://github.com/robots.txt", icon: ICON_VAL(ICONS.GitHub) },
    { id:"japan", rule:["RULE-SET,category-bank-jp,日本网站","GEOIP,jp,日本网站,no-resolve"], name:"日本网站", url:"https://r.r10s.jp/com/img/home/logo/touch.png", icon: ICON_VAL(ICONS.JP), ruleProvider:{ name:"category-bank-jp", url: URLS.rulesets.category_bank_jp_mrs(), format:"mrs", behavior:"domain" } }
  ],
  system: { "allow-lan": true, "bind-address": "*", mode: "rule", profile: { "store-selected": true, "store-fake-ip": true }, "unified-delay": true, "tcp-concurrent": true, "keep-alive-interval": 1800, "find-process-mode": "strict", "geodata-mode": true, "geodata-loader": "memconservative", "geo-auto-update": true, "geo-update-interval": 24, sniffer: { enable: true, "force-dns-mapping": true, "parse-pure-ip": false, "override-destination": true, sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, "8080-8880"] }, QUIC: { ports: [443, 8443] } }, "skip-src-address": ["127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"], "force-domain": ["+.google.com", "+.googleapis.com", "+.googleusercontent.com", "+.youtube.com", "+.facebook.com", "+.messenger.com", "+.fbcdn.net", "fbcdn-a.akamaihd.net"], "skip-domain": ["Mijia Cloud", "+.oray.com"] }, ntp: { enable: true, "write-to-system": false, server: "cn.ntp.org.cn" }, "geox-url": { geoip: URLS.geox.geoip(), geosite: URLS.geox.geosite(), mmdb: URLS.geox.mmdb(), asn: URLS.geox.asn() } },
  common: {
    ruleProvider: { type: "http", format: "yaml", interval: 86400 },
    proxyGroup: { interval: 300, timeout: 3000, url: "http://cp.cloudflare.com/generate_204", lazy: true, "max-failed-times": 3, hidden: false },
    defaultProxyGroups: [
      { name:"下载软件", icon: ICON_VAL(ICONS.Download), proxies:["直连","REJECT","默认节点","国内网站"] },
      { name:"其他外网", icon: ICON_VAL(ICONS.StreamingNotCN), proxies:["默认节点","国内网站"] },
      { name:"国内网站", url:"http://wifi.vivo.com.cn/generate_204", icon: ICON_VAL(ICONS.StreamingCN), proxies:["直连","默认节点"] }
    ],
    postRules: ["GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve", "GEOSITE,cn,国内网站", "GEOIP,cn,国内网站,no-resolve", "MATCH,其他外网"]
  },
  tuning: {
    preheatEnabled: true,
    preheatConcurrency: 3,
    preheatBatchDelayMs: 250,
    nodeTestTimeoutMs: 5000,
    nodeTestMaxAttempts: 3,
    nodeTestRetryDelayBaseMs: 200
  }
};

/* ============== 事件系统 ============== */
class EventEmitter {
  constructor() { this.eventListeners = new Map(); }
  on(ev, fn) { if (!ev || typeof fn !== "function") return; const arr = this.eventListeners.get(ev) || []; arr.push(fn); this.eventListeners.set(ev, arr); }
  off(ev, fn) { const arr = this.eventListeners.get(ev); if (!arr) return; const i = arr.indexOf(fn); if (i !== -1) arr.splice(i, 1); if (!arr.length) this.eventListeners.delete(ev); }
  emit(ev, ...args) { const arr = this.eventListeners.get(ev); if (!arr?.length) return; for (const fn of arr.slice()) { try { fn(...args); } catch (e) { Logger.error("Event.emit", e.stack || e); } } }
  removeAllListeners(ev) { if (ev) this.eventListeners.delete(ev); else this.eventListeners.clear(); }
}

/* ============== 优化后的统一配置构建器 ============== */
class ConfigBuilder {
  // 修复：拆分复杂函数为多个子函数，增加详细注释，提高可维护性
  static build(baseConfig, options = {}) {
    const config = Utils.deepClone(baseConfig);
    
    // 1. 验证配置
    if (!this._validateConfig(config)) return config;

    // 2. 合并系统配置
    this._mergeSystemConfig(config);

    // 3. 区域识别与构建
    const { regions, regionProxyGroups, otherProxyNames } = this._discoverAndBuildRegions(config);
    const regionGroupNames = this._buildRegionGroupNames(regionProxyGroups, otherProxyNames);

    // 4. 确保直连存在
    this._ensureDirectProxy(config);

    // 5. 构建代理组
    config['proxy-groups'] = this._buildProxyGroups(config, regionGroupNames, regionProxyGroups, otherProxyNames);

    // 6. 构建规则
    const { rules, ruleProviders } = this._buildRules(config, regionGroupNames);
    config.rules = rules;
    config['rule-providers'] = ruleProviders;

    return config;
  }

  /**
   * 验证配置是否包含必要的代理或提供商
   * @private
   */
  static _validateConfig(config) {
    const proxies = config.proxies || [];
    const proxyCount = Array.isArray(proxies) ? proxies.length : 0;
    const providerCount = (typeof config["proxy-providers"] === "object" && config["proxy-providers"] !== null) 
      ? Object.keys(config["proxy-providers"]).length : 0;
    
    if (proxyCount === 0 && providerCount === 0) {
      Logger.warn("ConfigBuilder", "未发现代理或代理提供商配置");
      return false;
    }
    return true;
  }

  /**
   * 发现并构建区域相关的代理组
   * @private
   */
  static _discoverAndBuildRegions(config) {
    const regionAuto = new RegionAutoManager();
    let regions = Config.regionOptions?.regions || [];
    const proxies = config.proxies || [];
    
    try {
      const discovered = regionAuto.discoverRegionsFromProxies(proxies);
      regions = regionAuto.mergeNewRegions(regions, discovered);
    } catch (e) { 
      Logger.warn("ConfigBuilder.regionDiscover", e.message); 
    }

    const { regionProxyGroups, otherProxyNames } = regionAuto.buildRegionGroups(config, regions);
    return { regions, regionProxyGroups, otherProxyNames };
  }

  static _mergeSystemConfig(config) {
    try {
      if (Config?.system && typeof Config.system === "object") Object.assign(config, Config.system);
      if (Config?.dns && typeof Config.dns === "object") config.dns = Config.dns;
    } catch (e) { Logger.warn("ConfigBuilder.mergeSystem", e.message); }
  }

  // 修复：优化去重逻辑，直接构建唯一数组，减少内存开销
  static _buildRegionGroupNames(regionProxyGroups, otherProxyNames) {
    const regionGroupNames = new Set();
    try {
      regionProxyGroups.forEach(g => {
        if (g?.name) regionGroupNames.add(g.name);
      });
      if (otherProxyNames.length) regionGroupNames.add("其他节点");
    } catch (e) { 
      Logger.warn("ConfigBuilder.regionGroupNames", e.message); 
    }
    return Array.from(regionGroupNames);
  }

  static _ensureDirectProxy(config) {
    if (!Array.isArray(config.proxies)) config.proxies = [];
    if (!config.proxies.some(p => p?.name === "直连")) {
      config.proxies.push({ name: "直连", type: "direct" });
    }
  }

  static _buildProxyGroups(config, regionGroupNames, regionProxyGroups, otherProxyNames) {
    const groupBase = Utils.getProxyGroupBase();
    const proxyGroups = [];
    
    // 默认总控分组
    proxyGroups.push({
      ...groupBase,
      name: "默认节点",
      type: "select",
      proxies: [...regionGroupNames, "直连"],
      icon: ICON_VAL(ICONS.Proxy)
    });

    // 服务分组
    const services = Array.isArray(Config?.services) ? Config.services : [];
    const defaultOrder = ["默认节点", "国内网站", "直连", "REJECT"];
    
    for (const svc of services) {
      try {
        const groupName = svc.name || svc.id;
        if (!groupName) continue;
        const base = Array.isArray(svc.proxiesOrder)
          ? svc.proxiesOrder
          : (Array.isArray(svc.proxies) ? svc.proxies : defaultOrder);
        const finalOrder = Array.from(new Set([...(base || []), ...regionGroupNames]));
        proxyGroups.push({
          ...groupBase,
          name: groupName,
          type: "select",
          proxies: finalOrder,
          icon: svc.icon || ""
        });
      } catch (e) {
        Logger.warn("ConfigBuilder.serviceGroup", svc?.id, e.message || e);
      }
    }

    // 默认代理组
    if (Config.common?.defaultProxyGroups?.length) {
      for (const group of Config.common.defaultProxyGroups) {
        if (group?.name) {
          proxyGroups.push({
            ...groupBase,
            name: group.name,
            type: "select",
            proxies: [...(Array.isArray(group.proxies) ? group.proxies : []), ...regionGroupNames],
            url: group.url || (Config.common?.proxyGroup?.url || ""),
            icon: group.icon
          });
        }
      }
    }

    // 区域分组
    if (regionProxyGroups.length) proxyGroups.push(...regionProxyGroups);

    // 其他节点分组
    if (otherProxyNames.length) {
      proxyGroups.push({
        ...groupBase,
        name: "其他节点",
        type: "select",
        proxies: Array.from(new Set(otherProxyNames)),
        icon: ICON_VAL(ICONS.WorldMap)
      });
    }

    return proxyGroups;
  }

  static _buildRules(config, regionGroupNames) {
    const ruleProviders = {};
    const rules = [];
    const baseRP = Utils.getRuleProviderBase();

    // 应用规则提供者
    ruleProviders.applications = {
      ...baseRP,
      behavior: "classical",
      format: "text",
      url: URLS.rulesets.applications(),
      path: "./ruleset/DustinWin/applications.list"
    };

    // 前置规则
    if (Array.isArray(Config.preRules)) rules.push(...Config.preRules);

    // 服务规则与规则提供者
    const services = Array.isArray(Config?.services) ? Config.services : [];
    for (const svc of services) {
      if (Array.isArray(svc.rule)) rules.push(...svc.rule);
      if (svc.ruleProvider?.name && svc.ruleProvider.url && !ruleProviders[svc.ruleProvider.name]) {
        ruleProviders[svc.ruleProvider.name] = {
          ...baseRP,
          behavior: svc.ruleProvider.behavior || "domain",
          format: svc.ruleProvider.format || "yaml",
          url: svc.ruleProvider.url,
          path: `./ruleset/${svc.ruleProvider.name}.${svc.ruleProvider.format || "yaml"}`
        };
      }
    }

    // 广告拦截规则提供者
    if (Config.services?.find(s => s.id === "ads")?.ruleProvider) {
      const adRP = Config.services.find(s => s.id === "ads").ruleProvider;
      ruleProviders.adblock_combined = {
        ...baseRP,
        behavior: adRP.behavior || "domain",
        format: adRP.format || "mrs",
        url: adRP.url,
        path: `./ruleset/adblock_combined.${adRP.format || "mrs"}`
      };
    }

    // 后置规则
    if (Array.isArray(Config.common?.postRules)) rules.push(...Config.common.postRules);

    return { rules, ruleProviders };
  }
}

/* ============== 优化后的区域映射 ============== */
const REGION_MAP = (() => {
  const mappings = {
    China: "cn,china,mainland,中国,大陆,chn",
    HongKong: "hk,hongkong,hong kong,香港,hkg",
    Taiwan: "tw,taiwan,台湾,台灣,twn",
    Japan: "jp,japan,日本,jpn",
    Korea: "kr,korea,韩国,南朝鲜,kor",
    UnitedStates: "us,united states,america,美国,usa",
    UnitedKingdom: "uk,united kingdom,britain,great britain,英国,gbr",
    Germany: "de,germany,德国,deu",
    France: "fr,france,法国,fra",
    Canada: "ca,canada,加拿大,can",
    Australia: "au,australia,澳大利亚,澳洲,aus",
    NewZealand: "nz,new zealand,新西兰,nzl",
    Singapore: "sg,singapore,新加坡,sgp",
    Malaysia: "my,malaysia,马来",
    Thailand: "th,thailand,泰国,tha",
    India: "in,india,印度,ind",
    Brazil: "br,brazil,巴西,bra",
    Mexico: "mx,mexico,墨西哥,mex",
    Russia: "ru,russia,俄罗斯,rus",
    Netherlands: "nl,netherlands,荷兰,nld",
    Spain: "es,spain,西班牙,esp",
    Italy: "it,italy,意大利,ita",
    Turkey: "tr,turkey,土耳其,tur",
    UAE: "ae,uae,阿联酋,are"
  };
  
  const result = {};
  for (const [country, aliases] of Object.entries(mappings)) {
    aliases.split(',').forEach(alias => {
      result[alias.toLowerCase()] = country;
    });
  }
  return result;
})();

function normalizeRegionName(name) {
  const key = String(name || "").trim().toLowerCase();
  return REGION_MAP[key] || name;
}

/* ============== 优化后的区域管理器 ============== */
class RegionAutoManager {
  constructor() { 
    this.knownRegexMap = this._buildFromConfigRegions(Config?.regionOptions?.regions || []); 
    this._cache = new Map(); // 添加缓存机制
  }

  _buildFromConfigRegions(regions) {
    return (Array.isArray(regions) ? regions : []).map(r => ({
      key: (r.name || "").replace(/[A-Z]{2}/i, ""),
      regex: r.regex,
      icon: r.icon || ICON_VAL(ICONS.WorldMap),
      name: r.name || "Unknown"
    }));
  }

  _normalizeName(name) { return String(name || "").trim(); }
  _hasRegion(regions, name) { return Array.isArray(regions) && regions.some(r => r?.name === name); }

  discoverRegionsFromProxies(proxies) {
    const found = new Map(); 
    if (!Array.isArray(proxies)) return found;
    
    for (const p of proxies) {
      const name = this._normalizeName(p?.name); 
      if (!name) continue;
      
      // 使用缓存
      if (this._cache.has(name)) {
        const cached = this._cache.get(name);
        if (cached) found.set(cached.name, cached);
        continue;
      }

      for (const e of this.knownRegexMap) {
        if (e.regex.test(name)) {
          found.set(e.name, e);
          this._cache.set(name, e);
          break;
        }
      }

      // 修复：确保 hints 默认为数组，避免 null 值导致的问题
      const hints = name.match(/[A-Za-z]{2,}|[\u4e00-\u9fa5]{2,}/g) || [];
      if (hints.length) {
        const wl = { 
          es: "ES西班牙", ca: "CA加拿大", au: "AU澳大利亚", fr: "FR法国", 
          it: "IT意大利", nl: "NL荷兰", ru: "RU俄罗斯", in: "IN印度", 
          br: "BR巴西", ar: "AR阿根廷" 
        };
        for (const h of hints) {
          const k = h.toLowerCase();
          if (wl[k]) {
            const cn = wl[k].replace(/[A-Z]{2}/, '').replace(/[^\u4e00-\u9fa5]/g, '');
            const regex = new RegExp(`${k}|${cn}`, 'i');
            const region = { name: wl[k], regex, icon: ICON_VAL(ICONS.WorldMap) };
            found.set(wl[k], region);
            this._cache.set(name, region);
            break;
          }
        }
      }

      // 缓存未匹配的结果
      if (!this._cache.has(name)) {
        this._cache.set(name, null);
      }
    }
    return found;
  }

  mergeNewRegions(configRegions, discoveredMap) {
    const merged = Array.isArray(configRegions) ? [...configRegions] : [];
    for (const r of discoveredMap.values()) {
      if (!this._hasRegion(merged, r.name)) {
        merged.push({ name: r.name, regex: r.regex, icon: r.icon || ICON_VAL(ICONS.WorldMap) });
      }
    }
    return merged;
  }

  buildRegionGroups(config, regions) {
    const regionProxyGroups = [];
    let otherNames = (config.proxies || []).filter(p => typeof p?.name === "string").map(p => p.name);
    
    for (const region of regions) {
      const names = Utils.filterProxiesByRegion(config.proxies || [], region);
      if (names.length) {
        regionProxyGroups.push({ 
          ...Utils.getProxyGroupBase(), 
          name: region.name || "Unknown", 
          type: "url-test", 
          tolerance: 50, 
          icon: region.icon || ICON_VAL(ICONS.WorldMap), 
          proxies: names 
        });
        otherNames = otherNames.filter(n => !names.includes(n));
      }
    }
    return { regionProxyGroups, otherProxyNames: Array.from(new Set(otherNames)) };
  }
}

/* ============== 优化后的广告拦截管理器 ============== */
class AdBlockManager {
  constructor(central) {
    this.central = central;
    this.cache = new LRUCache({ maxSize: 256, ttl: CONSTANTS.ADBLOCK_RULE_TTL_MS });
    this.lastUpdate = 0;
    this.sources = [
      { name: "easylist", url: URLS.rulesets.adblock_easylist(), type: "text" },
      { name: "easyprivacy", url: URLS.rulesets.adblock_easyprivacy(), type: "text" },
      { name: "ublock_filters", url: URLS.rulesets.adblock_ublock_filters(), type: "text" },
      { name: "mihomo_mrs", url: URLS.rulesets.adblock_mihomo_mrs(), type: "mrs" }
    ];
  }

  async updateIfNeeded() {
    const now = Utils.now();
    if (now - this.lastUpdate < CONSTANTS.ADBLOCK_UPDATE_INTERVAL_MS) return;
    try {
      await this.fetchAndMergeRules(); 
      this.lastUpdate = now; 
      Logger.info("AdBlock.update", "广告规则已自动更新与合并");
    } catch (e) { Logger.warn("AdBlock.update", e?.message || e); }
  }

  async fetchAndMergeRules() {
    const fetchers = this.sources.map(src => () => this.fetchSource(src).catch(() => null));
    const results = await Utils.asyncPool(fetchers, Math.min(CONSTANTS.CONCURRENCY_LIMIT, 4));
    const texts = []; let mrsUrl = null;

    results.forEach((res, i) => {
      const src = this.sources[i];
      if (!res) return;
      if (src.type === "mrs") mrsUrl = src.url;
      else if (typeof res === "string" && res.trim()) texts.push(res);
    });

    if (mrsUrl) {
      this.cache.set("adblock_mrs_url", mrsUrl, CONSTANTS.ADBLOCK_RULE_TTL_MS);
      return;
    }

    const domainSet = new Set();

    // 优化的大文本处理：避免split大数组，使用流式处理
    for (const text of texts) {
      await this.processTextStreamed(text, domainSet);
    }

    this.cache.set("adblock_combined_set", domainSet, CONSTANTS.ADBLOCK_RULE_TTL_MS);
  }

  // 优化版：流式文本处理，避免大内存占用和GC压力
  async processTextStreamed(text, domainSet) {
    const BATCH_SIZE = CONSTANTS.ADBLOCK_BATCH_SIZE; // 使用常量替代魔法数字
    const CHUNK_SIZE = CONSTANTS.ADBLOCK_CHUNK_SIZE; // 使用常量替代魔法数字
    let pos = 0;
    let lineCount = 0;
    let lineBuffer = "";

    // 修复：使用indexOf查找换行符，避免大字符串slice操作
    while (pos < text.length) {
      const endPos = Math.min(pos + CHUNK_SIZE, text.length);
      let currentPos = pos;
      
      // 在当前块内逐行处理，避免创建大字符串副本
      while (currentPos < endPos) {
        const newlineIndex = text.indexOf('\n', currentPos);
        
        if (newlineIndex === -1 || newlineIndex >= endPos) {
          // 在当前块内没有找到换行符，收集剩余内容
          lineBuffer += text.slice(currentPos, endPos);
          break;
        }
        
        // 找到完整的一行
        const line = lineBuffer + text.slice(currentPos, newlineIndex).trim();
        lineBuffer = ""; // 重置缓冲区
        lineCount++;
        currentPos = newlineIndex + 1;

        // 处理行内容
        if (!line || line.startsWith("!") || line.startsWith("#") || line.startsWith("[") || line.startsWith("@@")) {
          continue;
        }
        
        let dom = null;
        if (line.startsWith("||")) {
          const stop = line.indexOf("^");
          if (stop > 2) dom = line.slice(2, stop);
        }
        if (!dom && line.startsWith("domain=")) {
          dom = line.slice("domain=".length).split(",", 1)[0];
        }
        if (!dom) {
          const m3 = line.match(/^[\w.-]+\.[a-z]{2,}$/i);
          if (m3) dom = m3[0];
        }
        if (dom && Utils.isValidDomain(dom)) {
          domainSet.add(dom.toLowerCase());
        }

        // 定期让出控制权，避免阻塞，并允许GC
        if (lineCount % BATCH_SIZE === 0) {
          await Utils.sleep(0);
        }
      }
      
      pos = endPos;
    }
    
    // 处理最后的缓冲区内容
    if (lineBuffer.trim()) {
      const line = lineBuffer.trim();
      if (!line.startsWith("!") && !line.startsWith("#") && !line.startsWith("[") && !line.startsWith("@@")) {
        let dom = null;
        if (line.startsWith("||")) {
          const stop = line.indexOf("^");
          if (stop > 2) dom = line.slice(2, stop);
        }
        if (!dom && line.startsWith("domain=")) {
          dom = line.slice("domain=".length).split(",", 1)[0];
        }
        if (!dom) {
          const m3 = line.match(/^[\w.-]+\.[a-z]{2,}$/i);
          if (m3) dom = m3[0];
        }
        if (dom && Utils.isValidDomain(dom)) {
          domainSet.add(dom.toLowerCase());
        }
      }
    }
  }

  async fetchSource(src) {
    const cached = this.cache.get(`src:${src.name}`);
    if (cached) return cached;
    const resp = await this.central._safeFetch(src.url, { headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT } }, this.central._nodeTimeout());
    if (src.type === "text") {
      const text = await resp.text();
      return text;
    }
    const marker = "mrs";
    this.cache.set(`src:${src.name}`, marker, CONSTANTS.ADBLOCK_RULE_TTL_MS);
    return marker;
  }

  injectRuleProvider(ruleProviders) {
    const mrsUrl = this.cache.get("adblock_mrs_url");
    const domainSet = this.cache.get("adblock_combined_set");
    if (mrsUrl) {
      Utils.safeSet(ruleProviders, "adblock_combined", {
        ...Utils.getRuleProviderBase(),
        behavior: "domain",
        format: "mrs",
        url: mrsUrl,
        path: "./ruleset/adblock_combined.mrs",
        interval: 43200
      });
      return;
    }
    if (!domainSet || !(domainSet instanceof Set) || domainSet.size === 0) return;
    const combinedList = Array.from(domainSet);
    const joined = combinedList.join("\n");
    if (!joined || joined.length > 1_000_000) return;
    const dataUrl = Utils.toDataUrl(joined);
    Utils.safeSet(ruleProviders, "adblock_combined", {
      type: "http",
      behavior: "domain",
      format: "text",
      url: dataUrl,
      path: "./ruleset/adblock_combined.list",
      interval: 43200
    });
  }
}

/* ============== 简化的事件系统和状态管理 ============== */
class AppState {
  constructor() { this.nodes = new Map(); this.metrics = new Map(); this.config = {}; this.lastUpdated = Utils.now(); }
  updateNodeStatus(nodeId, status) { 
    if (!nodeId || typeof nodeId !== "string") return; 
    this.nodes.set(nodeId, { ...(this.nodes.get(nodeId) || {}), ...status }); 
    this.lastUpdated = Utils.now(); 
  }
}

class LRUCache {
  constructor({ maxSize = CONSTANTS.LRU_CACHE_MAX_SIZE, ttl = CONSTANTS.LRU_CACHE_TTL } = {}) {
    this.cache = new Map();
    this.maxSize = Math.max(1, Number(maxSize) || CONSTANTS.LRU_CACHE_MAX_SIZE);
    this.ttl = Math.max(1, Number(ttl) || CONSTANTS.LRU_CACHE_TTL);
  }

  _isExpired(entry) {
    if (!entry) return true;
    const limit = Number.isFinite(entry.ttl) && entry.ttl > 0 ? entry.ttl : this.ttl;
    if (!limit || limit <= 0) return false;
    return (Utils.now() - entry.timestamp) > limit;
  }

  get(key) {
    if (!this.cache.has(key)) return null;
    const entry = this.cache.get(key);
    if (this._isExpired(entry)) {
      this.cache.delete(key);
      return null;
    }
    this.cache.delete(key);
    const refreshed = { value: entry.value, ttl: entry.ttl, timestamp: Utils.now() };
    this.cache.set(key, refreshed);
    return refreshed.value;
  }

  set(key, value, ttl = this.ttl) {
    if (key == null) return;
    const now = Utils.now();
    const effectiveTtl = Number.isFinite(ttl) && ttl > 0 ? ttl : this.ttl;
    if (this.cache.has(key)) this.cache.delete(key);
    else if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) this.cache.delete(oldestKey);
    }
    this.cache.set(key, { value, ttl: effectiveTtl, timestamp: now });
  }

  clear() { this.cache.clear(); }
  delete(key) { return this.cache.delete(key); }
}

/* ============== 统计类 ============== */
class RollingStats {
  constructor(windowSize = 100) { 
    this.windowSize = Math.max(1, windowSize | 0); 
    this.data = new Array(this.windowSize).fill(0); 
    this.index = 0; 
    this.count = 0; 
    this.sum = 0; 
  }

  add(v) { 
    v = Number(v) || 0; 
    if (this.count < this.windowSize) { 
      this.data[this.index] = v; 
      this.sum += v; 
      this.count++; 
    } else { 
      const prev = this.data[this.index] || 0; 
      this.data[this.index] = v; 
      this.sum += v - prev; 
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
    if (success) { 
      this.successCount++; 
      this.hardFailStreak = 0; 
    } else if (hardFail) { 
      this.hardFailStreak = Math.min(this.hardFailStreak + 1, 100); 
    } 
  }
  get rate() { return this.totalCount ? this.successCount / this.totalCount : 0; }
  reset() { this.successCount = 0; this.totalCount = 0; this.hardFailStreak = 0; }
}

/* ============== 策略管理器 ============== */
class PolicyManager extends EventEmitter {
  constructor(baseConfig) {
    super();
    this.config = baseConfig || {};
    this.env = { isNode: PLATFORM.isNode, isBrowser: PLATFORM.isBrowser };
    this.state = {
      networkGood: true,
      githubMirrorHealthy: false,
      geoEndpointsHealthy: false,
      lastGeoErrorTs: 0,
      lastMirrorErrorTs: 0,
      compatLegacyDisable: false
    };
  }

  initFromConfig(cfg) { if (cfg && typeof cfg === "object") this.config = cfg; }
  setCompatLegacyDisableRequested() { this.state.compatLegacyDisable = true; }
  updateNetworkHealth({ ok }) { this.state.networkGood = !!ok; }
  updateMirrorHealth({ ok }) { this.state.githubMirrorHealthy = !!ok; if (!ok) this.state.lastMirrorErrorTs = Utils.now(); }
  updateGeoEndpointHealth({ ok }) { this.state.geoEndpointsHealthy = !!ok; if (!ok) this.state.lastGeoErrorTs = Utils.now(); }

  isSystemEnhancementEnabled() { return true; }

  isGeoExternalLookupEnabled() {
    if (!this.isSystemEnhancementEnabled()) return false;
    const endpoints = Array.isArray(this.config?.privacy?.trustedGeoEndpoints) ? this.config.privacy.trustedGeoEndpoints : [];
    if (!endpoints.length) return false;
    if (!this.state.geoEndpointsHealthy) return false;
    if (!this.state.networkGood) return false;
    return true;
  }

  isSystemDnsOnly() {
    if (!this.isSystemEnhancementEnabled()) return !!this.config?.privacy?.systemDnsOnly;
    if (!this.state.networkGood) return true;
    return !!this.config?.privacy?.systemDnsOnly;
  }

  isGithubMirrorEnabled() {
    if (!this.isSystemEnhancementEnabled()) return false;
    const prefer = !!this.config?.privacy?.githubMirrorEnabled;
    if (!this.state.githubMirrorHealthy) return false;
    if (!this.state.networkGood && this.state.githubMirrorHealthy) return true;
    return prefer;
  }

  isPreheatEnabled() {
    if (!this.isSystemEnhancementEnabled()) return false;
    if (!this.state.networkGood) return false;
    const prefer = this.config?.tuning?.preheatEnabled;
    return (prefer !== false);
  }
}

/* ============== 网络层抽象（Phase 3高级抽象） ============== */
class HttpClient {
  constructor() {
    this.runtimeCache = { fetch: null, AbortController: null };
  }

  async _getRuntime() {
    if (this.runtimeCache.fetch && this.runtimeCache.AbortController !== undefined) {
      return { _fetch: this.runtimeCache.fetch, _AbortController: this.runtimeCache.AbortController };
    }
    
    let _fetch = (typeof fetch === "function") ? fetch : null;
    let _AbortController = (typeof AbortController !== "undefined") ? AbortController : null;
    
    if (!_fetch && PLATFORM.isNode && typeof require === "function") {
      try { const nf = require("node-fetch"); _fetch = nf.default || nf; } catch {}
      if (!_AbortController) {
        try { const AC = require("abort-controller"); _AbortController = AC.default || AC; } catch {
          if (typeof AbortController !== "undefined") _AbortController = AbortController;
        }
      }
    }
    
    this.runtimeCache.fetch = _fetch; 
    this.runtimeCache.AbortController = _AbortController;
    return { _fetch, _AbortController };
  }

  async safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
    if (!url || typeof url !== "string") throw new Error("safeFetch: 无效的URL参数");
    const initial = Utils.sanitizeUrl(url); 
    if (!initial) throw new Error(`safeFetch: URL 非法或不安全 (${url})`);
    url = initial;
    
    const { _fetch, _AbortController } = await this._getRuntime(); 
    if (!_fetch) throw new Error("fetch 不可用于当前运行环境");

    const opts = { 
      ...options, 
      headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT, ...(options.headers || {}) }, 
      redirect: "manual" 
    };

    const execFetch = async (targetUrl, count = 0) => {
      if (count > 3) throw new Error("重定向次数过多");
      const sanitized = Utils.sanitizeUrl(targetUrl); 
      if (!sanitized) throw new Error(`重定向至非安全 URL: ${targetUrl}`);

      let timerId = null;
      let signal = opts.signal;
      if (timeout > 0) {
        if (typeof AbortSignal !== "undefined" && typeof AbortSignal.timeout === "function") {
          signal = AbortSignal.timeout(timeout);
        } else if (_AbortController) {
          const controller = new _AbortController();
          timerId = setTimeout(() => { try { controller.abort(); } catch {} }, timeout);
          signal = controller.signal;
        }
      }

      const finalOpts = signal ? { ...opts, signal } : { ...opts };

      try {
        const resp = await _fetch(sanitized, finalOpts); 
        if (timerId) clearTimeout(timerId);
        
        if (resp.status >= 300 && resp.status < 400) {
          const location = resp.headers.get("location");
          if (location) {
            const nextUrl = new URL(location, sanitized).toString();
            const ok = Utils.sanitizeUrl(nextUrl); 
            if (!ok) throw new Error(`重定向目标不安全: ${nextUrl}`);
            return execFetch(nextUrl, count + 1);
          }
        }
        return resp;
      } catch (err) {
        if (timerId) clearTimeout(timerId);
        if (["AbortError", "TimeoutError"].includes(err?.name)) throw new Error(`请求超时 (${timeout}ms): ${sanitized}`);
        throw err;
      }
    };

    return execFetch(url);
  }
}

/* ============== 评分系统（Phase 3高级抽象） ============== */
class NodeScorer {
  static calculate(metrics, weights = CONSTANTS.DEFAULT_SCORING_WEIGHTS) {
    const latency = Utils.clamp(Number(metrics?.latency) || 0, 0, CONSTANTS.LATENCY_CLAMP_MS);
    const jitter = Utils.clamp(Number(metrics?.jitter) || 0, 0, CONSTANTS.JITTER_CLAMP_MS);
    const loss = Utils.clamp(Number(metrics?.loss) || 0, 0, CONSTANTS.LOSS_CLAMP);
    const bps = Utils.clamp(Number(metrics?.bps) || 0, 0, CONSTANTS.THROUGHPUT_SOFT_CAP_BPS);

    // 修复：使用常量替代魔法数字，非线性评分：延迟超过阈值后指数级下降
    const latencyScore = latency > CONSTANTS.LATENCY_HIGH_THRESHOLD 
      ? Math.max(0, CONSTANTS.LATENCY_BASE_SCORE - Math.pow((latency - CONSTANTS.LATENCY_HIGH_THRESHOLD) / CONSTANTS.LATENCY_SCALE_FACTOR, CONSTANTS.LATENCY_EXPONENT))
      : Utils.clamp(CONSTANTS.LATENCY_BASE_SCORE - latency / CONSTANTS.LATENCY_DIVISOR, 0, CONSTANTS.LATENCY_BASE_SCORE);
    
    const jitterScore = Utils.clamp(CONSTANTS.JITTER_BASE_SCORE - jitter, 0, CONSTANTS.JITTER_BASE_SCORE);
    const lossScore = Utils.clamp(CONSTANTS.LOSS_BASE_SCORE * (1 - loss), 0, CONSTANTS.LOSS_BASE_SCORE);
    const throughputScore = Utils.clamp(Math.round(Math.log10(1 + bps) * CONSTANTS.THROUGHPUT_SCALE_FACTOR), 0, CONSTANTS.THROUGHPUT_SCORE_MAX);

    const totalWeight = weights.latency + weights.loss + weights.jitter + weights.speed;
    
    return Utils.clamp(
      (latencyScore * weights.latency + lossScore * weights.loss + jitterScore * weights.jitter + throughputScore * weights.speed) / totalWeight,
      0, 100
    );
  }

  static calculateFromComponents(components) {
    const { latencyScore, jitterScore, lossScore, throughputScore } = components;
    return Utils.clamp(Math.round(latencyScore + jitterScore + lossScore + throughputScore), 0, 100);
  }

  static biasScore(baseScore, availability, preferences = {}) {
    const { preferHighThroughput = false, preferLowLatency = false, preferStability = false } = preferences;
    let score = baseScore;

    // 可用性加成/惩罚
    score += (availability >= CONSTANTS.AVAILABILITY_MIN_RATE) ? CONSTANTS.BIAS_AVAIL_BONUS_OK : CONSTANTS.BIAS_AVAIL_PENALTY_BAD;

    // 用户偏好调整
    if (preferHighThroughput) {
      score += 5; // 简化的吞吐量偏好
    }
    if (preferLowLatency) {
      score += 3; // 简化的延迟偏好
    }
    if (preferStability) {
      score += 4; // 简化的稳定性偏好
    }

    return Utils.clamp(score, 0, 100);
  }
}

/* ============== 优化后的CentralManager ============== */
class CentralManager extends EventEmitter {
  static getInstance() { 
    if (!CentralManager.instance) CentralManager.instance = new CentralManager(); 
    return CentralManager.instance; 
  }

  constructor() {
    super(); 
    if (CentralManager.instance) return CentralManager.instance;
    
    // 核心组件
    this.state = new AppState();
    this.httpClient = new HttpClient(); // 网络层抽象
    this.nodeScorer = NodeScorer; // 评分系统
    this.adBlockManager = new AdBlockManager(this);
    
    // 统计与缓存
    this.stats = new RollingStats();
    this.successTracker = new SuccessRateTracker();
    this.lruCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    
    // 管理器
    this.nodeManager = NodeManager.getInstance();
    this.regionAutoManager = new RegionAutoManager();
    this.nodePools = new NodePools();
    this.policy = new PolicyManager(Config);
    this.policy.initFromConfig(Config);

    CentralManager.instance = this;
    Promise.resolve().then(() => this.initialize().catch(err => Logger.error("Central.init", err?.stack || err)));
  }

  resetStateForConfig(cfg) {
    this.policy.initFromConfig(cfg || Config);
  }

  static scoreComponents(m = {}) {
    const latency = Utils.clamp(Number(m.latency) || 0, 0, CONSTANTS.LATENCY_CLAMP_MS);
    const jitter  = Utils.clamp(Number(m.jitter) || 0, 0, CONSTANTS.JITTER_CLAMP_MS);
    const loss    = Utils.clamp(Number(m.loss) || 0, 0, CONSTANTS.LOSS_CLAMP);
    const bps     = Utils.clamp(Number(m.bps) || 0, 0, CONSTANTS.THROUGHPUT_SOFT_CAP_BPS);
    
    // 修复：使用常量替代魔法数字
    const latencyScore = Utils.clamp(CONSTANTS.LATENCY_BASE_SCORE - latency / CONSTANTS.LATENCY_DIVISOR, 0, CONSTANTS.LATENCY_BASE_SCORE);
    const jitterScore  = Utils.clamp(CONSTANTS.JITTER_BASE_SCORE - jitter, 0, CONSTANTS.JITTER_BASE_SCORE);
    const lossScore    = Utils.clamp(CONSTANTS.LOSS_BASE_SCORE * (1 - loss), 0, CONSTANTS.LOSS_BASE_SCORE);
    const throughputScore = Utils.clamp(Math.round(Math.log10(1 + bps) * CONSTANTS.THROUGHPUT_SCALE_FACTOR), 0, CONSTANTS.THROUGHPUT_SCORE_MAX);
    
    return { 
      latencyScore, 
      jitterScore, 
      lossScore, 
      throughputScore, 
      metricScore: Utils.clamp(Math.round(latencyScore + jitterScore + lossScore + throughputScore), 0, 100) 
    };
  }

  // 使用新的ConfigBuilder
  processConfiguration(config) {
    if (!config || typeof config !== "object") throw new ConfigurationError("processConfiguration: 配置对象无效");
    
    try {
      this.state.config = config;
      this.stats?.reset?.();
      this.successTracker?.reset?.();
    } catch (e) { Logger.warn("Central.processConfig", e.message); }

    return ConfigBuilder.build(config);
  }

  // 使用网络层抽象
  async _safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
    return this.httpClient.safeFetch(url, options, timeout);
  }

  // 使用评分系统
  calculateQuality(metrics) {
    return this.nodeScorer.calculate(metrics);
  }

  // 委托给网络层
  async _getFetchRuntime() {
    return this.httpClient._getRuntime();
  }

  isGeoExternalLookupEnabled() { return this.policy.isGeoExternalLookupEnabled(); }

  _nodeTimeout() {
    const t = Config?.tuning?.nodeTestTimeoutMs;
    return Number.isFinite(t) && t > 0 ? t : CONSTANTS.NODE_TEST_TIMEOUT;
  }

  async initialize() {
    try {
      // 初始化广告拦截管理器
      await this.adBlockManager.updateIfNeeded();
      Logger.info("Central.init", "优化版本初始化完成 - 使用网络层抽象和评分系统");
    } catch (e) {
      Logger.warn("Central.init", e?.message || e);
    }
  }

  async destroy() {
    Logger.info("Central.destroy", "开始清理资源...");
    try { 
      this.lruCache?.clear(); 
      this.geoInfoCache?.clear(); 
      this.nodePools?.clear?.(); 
    } catch (e) { Logger.warn("Central.destroy", e.message); }
    Logger.info("Central.destroy", "资源清理完成");
  }
}

/* ============== 优劣节点池（优化版） ============== */
class NodePools {
  constructor() { 
    this.good = new Set(); 
    this.bad = new Set(); 
    this.recentScores = []; 
    this.recentAvail = [];
    this._lastSnapshot = { good: [], bad: [] };
    
    // 修复：使用环形缓冲区替代数组 shift 操作
    this._scoreBuffer = new Array(CONSTANTS.POOL_WINDOW_SIZE).fill(null);
    this._availBuffer = new Array(CONSTANTS.POOL_WINDOW_SIZE).fill(null);
    this._bufferIndex = 0;
    this._bufferCount = 0;
  }

  pushSamples(score, avail) {
    if (Number.isFinite(score)) { 
      // 修复：使用环形缓冲区，避免 O(N) 的 shift 操作
      this._scoreBuffer[this._bufferIndex] = Number(score);
    }
    if (Number.isFinite(avail)) { 
      // 修复：使用环形缓冲区，避免 O(N) 的 shift 操作
      this._availBuffer[this._bufferIndex] = Number(avail);
    }
    
    this._bufferIndex = (this._bufferIndex + 1) % CONSTANTS.POOL_WINDOW_SIZE;
    if (this._bufferCount < CONSTANTS.POOL_WINDOW_SIZE) {
      this._bufferCount++;
    }
    
    // 为了向后兼容，同步更新数组（但实际使用时应该使用缓冲区）
    this._syncBuffersToArrays();
  }
  
  // 同步环形缓冲区到数组（保持向后兼容）
  // 优化：只在必要时更新数组，避免不必要的重建
  _syncBuffersToArrays() {
    // 只在缓冲区计数与数组长度不匹配时更新数组
    if (this._bufferCount !== this.recentScores.length + this.recentAvail.length) {
      this.recentScores = [];
      this.recentAvail = [];
      
      for (let i = 0; i < this._bufferCount; i++) {
        const idx = (this._bufferIndex - this._bufferCount + i + CONSTANTS.POOL_WINDOW_SIZE) % CONSTANTS.POOL_WINDOW_SIZE;
        if (this._scoreBuffer[idx] !== null) this.recentScores.push(this._scoreBuffer[idx]);
        if (this._availBuffer[idx] !== null) this.recentAvail.push(this._availBuffer[idx]);
      }
    }
  }
  getAdaptiveThresholds() {
    const enough = (this.recentScores.length >= CONSTANTS.MIN_POOL_ITEMS_FOR_ADAPT) && 
                   (this.recentAvail.length >= CONSTANTS.MIN_POOL_ITEMS_FOR_ADAPT);
    if (!enough) return { goodScore: CONSTANTS.QUALITY_SCORE_THRESHOLD, goodAvail: CONSTANTS.AVAILABILITY_MIN_RATE };
    
    const alpha = CONSTANTS.ADAPT_ALPHA;
    const p90Score = this.calculatePercentile(this.recentScores, CONSTANTS.GOOD_PERCENTILE);
    const p50Avail = this.calculatePercentile(this.recentAvail, CONSTANTS.BAD_PERCENTILE);
    const goodScore = alpha * CONSTANTS.QUALITY_SCORE_THRESHOLD + (1 - alpha) * p90Score;
    const goodAvail = alpha * CONSTANTS.AVAILABILITY_MIN_RATE + (1 - alpha) * p50Avail;
    return { goodScore: Utils.clamp(goodScore, 0, 100), goodAvail: Utils.clamp(goodAvail, 0, 1) };
  }

  calculatePercentile(values, p) {
    if (!Array.isArray(values) || !values.length) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const index = (p / 100) * (sorted.length - 1);
    const i = Math.floor(index);
    const frac = index - i;
    if (i >= sorted.length - 1) return sorted[sorted.length - 1];
    return sorted[i] + (sorted[i + 1] - sorted[i]) * frac;
  }

  classify(id, score, avail) {
    if (!id) return;
    this.pushSamples(Number(score), Number(avail));
    const thr = this.getAdaptiveThresholds();
    const isGood = (Number(score) >= thr.goodScore) && (Number(avail) >= thr.goodAvail);
    if (isGood) { 
      this.good.add(id); 
      this.bad.delete(id); 
    } else { 
      this.bad.add(id); 
      this.good.delete(id); 
    }
  }

  clear() { 
    this.good.clear(); 
    this.bad.clear(); 
    this.recentScores = []; 
    this.recentAvail = []; 
    
    // 修复：清空环形缓冲区
    this._scoreBuffer.fill(null);
    this._availBuffer.fill(null);
    this._bufferIndex = 0;
    this._bufferCount = 0;
  }

  snapshot() { 
    this._lastSnapshot = { good: Array.from(this.good), bad: Array.from(this.bad) }; 
    return this._lastSnapshot; 
  }

  namesFromIds(proxies, ids) {
    if (!Array.isArray(proxies) || !Array.isArray(ids) || !ids.length) return [];
    const map = new Map(proxies.filter(p => p?.id && p?.name).map(p => [p.id, p.name]));
    const out = []; 
    for (const id of ids) { 
      const name = map.get(id); 
      if (name) out.push(name); 
    }
    return out;
  }
}

/* ============== 简化的节点管理器（优化版） ============== */
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
    this.nodeHistory = new Map(); 
    this.nodeSuccess = new Map(); 
  }

  isInCooldown(id) { 
    const end = this.switchCooldown.get(id); 
    return !!(end && Utils.now() < end); 
  }

  _cooldownTime(id) { 
    const s = Utils.clamp(this.nodeQuality.get(id) || 0, 0, 100); 
    return Utils.clamp(CONSTANTS.BASE_SWITCH_COOLDOWN * (1 + (s / 100) * 0.9), CONSTANTS.MIN_SWITCH_COOLDOWN, CONSTANTS.MAX_SWITCH_COOLDOWN); 
  }

  _updateNodeHistory(id, score) {
    const s = Utils.clamp(Number(score) || 0, 0, 100);
    const h = this.nodeHistory.get(id) || [];
    h.push({ timestamp: Utils.now(), score: s });
    this.nodeHistory.set(id, h.length > CONSTANTS.MAX_HISTORY_RECORDS ? h.slice(-CONSTANTS.MAX_HISTORY_RECORDS) : h);
  }

  updateNodeQuality(id, delta) {
    const ns = Utils.clamp((this.nodeQuality.get(id) || 0) + Utils.clamp(Number(delta) || 0, -20, 20), 0, 100);
    this.nodeQuality.set(id, ns);
    this._updateNodeHistory(id, ns);
  }
}

/* ============== 环境检测抽象化 ============== */
const EnvDetector = {
  _cache: {},
  
  // 检测CommonJS环境
  isCommonJS() {
    if (this._cache.commonjs === undefined) {
      this._cache.commonjs = (typeof module !== 'undefined' && module.exports);
    }
    return this._cache.commonjs;
  },
  
  // 检测Node.js环境
  isNode() {
    if (this._cache.node === undefined) {
      this._cache.node = (typeof global !== 'undefined');
    }
    return this._cache.node;
  },
  
  // 检测浏览器环境
  isBrowser() {
    if (this._cache.browser === undefined) {
      this._cache.browser = (typeof window !== 'undefined');
    }
    return this._cache.browser;
  },
  
  // 获取运行环境名称
  getEnvironment() {
    if (this.isNode()) return 'Node';
    if (this.isBrowser()) return 'Browser';
    return 'Unknown';
  }
};

/* ============== 错误对象工厂模式 ============== */
const ErrorConfigFactory = {
  // 创建错误配置对象
  createErrorConfig(errMsg, options = {}) {
    const timestamp = Utils.now();
    const truncatedMsg = errMsg.substring(0, 20);
    const defaults = {
      server: "127.0.0.1",
      port: 80,
      version: "optimized_fixed"
    };
    
    return {
      name: `⛔ 脚本错误: ${truncatedMsg}...`,
      type: "direct",
      ...defaults,
      ...options,
      _error: true,
      _errorMessage: errMsg,
      _errorTimestamp: timestamp,
      _scriptError: {
        timestamp,
        message: errMsg,
        fallback: true,
        version: defaults.version
      }
    };
  }
};

/* ============== 修复后的 Main 函数 ============== */
function main(config) {
  // 修复：快速检查输入
  if (!config || typeof config !== 'object') {
    Logger.error("Main", "输入配置无效");
    return config;
  }

  try {
    // 尝试构建配置
    return ConfigBuilder.build(config);
  } catch (e) {
    const errMsg = e?.message || "未知错误";
    Logger.error("Main", `构建失败: ${errMsg}`);

    // 优化：使用错误对象工厂模式，消除重复时间戳计算和分散赋值
    try {
      // 浅拷贝以避免修改原引用，尽可能保留原始配置
      const fallbackConfig = { ...config };
      
      // 确保 proxies 存在
      if (!Array.isArray(fallbackConfig.proxies)) {
        fallbackConfig.proxies = [];
      }

      // 使用工厂函数创建错误节点，确保时间戳一致性
      const errorNode = ErrorConfigFactory.createErrorConfig(errMsg);
      fallbackConfig.proxies.unshift(errorNode);
      
      return fallbackConfig;
    } catch (fallbackErr) {
      // 终极回退：直接返回原始对象，不做任何处理
      Logger.error("Main", "回退逻辑也失败，返回原始配置");
      return config;
    }
  }
}

/* ============== 优化后的兼容性函数 ============== */
// 直接导出方法引用，避免不必要的函数调用开销
const buildConfigForParser = ConfigBuilder.build.bind(ConfigBuilder);

/* ============== 优化后的统一导出逻辑 ============== */
// 统一导出对象，消除重复定义
const EXPORTS = {
  main, 
  CentralManager, 
  ConfigBuilder, 
  buildConfigForParser,
  RegionAutoManager,  // 修复：导出 RegionAutoManager
  LRUCache,           // 修复：导出 LRUCache
  NodeScorer,         // 修复：导出 NodeScorer
  Utils,               // 修复：导出 Utils
  DataMasker,
  CONSTANTS,
  Config,
  GH_MIRRORS
};

// 统一环境检测与导出
if (EnvDetector.isCommonJS()) module.exports = EXPORTS;
if (EnvDetector.isNode()) Object.assign(global, EXPORTS);
if (EnvDetector.isBrowser()) Object.assign(window, EXPORTS);

Logger.info("Script", `优化版本加载完成 - 环境检测: ${EnvDetector.getEnvironment()}, 使用ConfigBuilder统一配置构建`);
