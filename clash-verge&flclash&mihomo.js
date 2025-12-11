"use strict";

/**
 * Central Orchestrator - 优化版（功能等效 / 安全增强 / 结构归一 / 更强广告拦截）
 * 保留原有 API：main, CentralManager, NodeManager, Config
 * 兼容范围：Node.js >= 14（推荐 16+）、现代浏览器（支持 fetch/AbortController）
 * 设计目标：零人工干预、自动化、隐私可配置、全平台适配
 */

/* ===================== 平台与工具 ===================== */
const PLATFORM = (() => {
  const isNode = typeof process !== "undefined" && !!process.versions?.node;
  const isBrowser = typeof window !== "undefined" && typeof window.addEventListener === "function";
  return Object.freeze({ isNode, isBrowser });
})();

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

  // 早期样本权重（影响 aiScoreNode 的 ±2）
  EARLY_SAMPLE_SCORE: 2
});

const Logger = {
  error: (...a) => console.error("[ERROR]", ...a),
  info:  (...a) => console.info("[INFO]", ...a),
  warn:  (...a) => console.warn("[WARN]", ...a),
  debug: (...a) => { if (CONSTANTS.ENABLE_SCORE_DEBUGGING) console.debug("[DEBUG]", ...a); }
};

class ConfigurationError extends Error { constructor(m) { super(m); this.name = "ConfigurationError"; } }
class InvalidRequestError extends Error { constructor(m) { super(m); this.name = "InvalidRequestError"; } }

/* ===================== 工具与安全 ===================== */
const Utils = {
  now: () => Date.now(),
  clamp: (v, min, max) => Math.max(min, Math.min(max, v)),
  clamp01: (v) => Math.max(0, Math.min(1, v)),
  isFunc: (f) => typeof f === "function",
  sleep(ms = 0) { return new Promise(r => setTimeout(r, Math.max(0, ms | 0))); },

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

  async asyncPool(tasks, limit = CONSTANTS.CONCURRENCY_LIMIT) {
    const list = Array.isArray(tasks) ? tasks.filter(Utils.isFunc) : [];
    if (!list.length) return [];
    const n = Math.max(1, Math.min(50, Math.floor(limit) || 3));
    const res = new Array(list.length);
    let idx = 0;
    async function runner() {
      while (idx < list.length) {
        const cur = idx++, t = list[cur];
        try { const v = t(); res[cur] = (v && typeof v.then === "function") ? await v : v; }
        catch (e) { res[cur] = { __error: e?.message || "任务执行失败" }; }
      }
    }
    await Promise.all(Array(Math.min(n, list.length)).fill(0).map(runner));
    return res;
  },

  // 统计工具
  calculateWeightedAverage(values, weightFactor = 0.9) {
    if (!Array.isArray(values) || !values.length) return 0;
    let sum = 0, wsum = 0, n = values.length;
    for (let i = 0; i < n; i++) { const w = Math.pow(weightFactor, n - i - 1); sum += values[i] * w; wsum += w; }
    return wsum ? sum / wsum : 0;
  },
  calculateStdDev(values) {
    if (!Array.isArray(values) || !values.length) return 0;
    const avg = values.reduce((a, b) => a + b, 0) / values.length;
    return Math.sqrt(values.reduce((a, b) => a + Math.pow(b - avg, 2), 0) / values.length);
  },
  calculateTrend(values) {
    const n = Array.isArray(values) ? values.length : 0; if (n < 2) return 0;
    let sx = 0, sy = 0, sxy = 0, sx2 = 0, sw = 0;
    for (let i = 0; i < n; i++) { const w = (i + 1) / n, x = i, y = values[i]; sw += w; sx += x * w; sy += y * w; sxy += x * y * w; sx2 += x * x * w; }
    const den = sw * sx2 - sx * sx; return den === 0 ? 0 : (sw * sxy - sx * sy) / den;
  },
  calculatePercentile(values, p) {
    if (!Array.isArray(values) || !values.length) return 0;
    const s = [...values].sort((a, b) => a - b), index = (p / 100) * (s.length - 1), i = Math.floor(index), f = index - i;
    return (i === index) ? s[index] : s[i] + (s[i + 1] - s[i]) * f;
  },

  // 域名/IP 校验
  isValidDomain(d) { return typeof d === "string" && /^[a-zA-Z0-9.-]+$/.test(d) && !d.startsWith(".") && !d.endsWith(".") && !d.includes(".."); },
  isIPv4(ip) { return typeof ip === "string" && /^(\d{1,3}\.){3}\d{1,3}$/.test(ip); },
  isLoopbackOrLocal(ip) { return ip === "127.0.0.1" || ip === "0.0.0.0"; },
  isPrivateIP(ip) {
    if (!Utils.isIPv4(ip)) return false;
    try {
      const [a, b] = ip.split(".").map(n => parseInt(n, 10));
      return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
    } catch { return false; }
  },

  // 统一 URL 校验（仅允许 http/https；端口白名单；禁止凭据；私网/环路拦截；允许 data:text/plain;base64）
  sanitizeUrl(u) {
    if (typeof u !== "string" || !u) return null;
    if (u.startsWith("data:text/plain;base64,")) return u;
    try {
      const url = new URL(u);
      let scheme = url.protocol.replace(":", "").toLowerCase();
      if (!["http", "https"].includes(scheme)) return null;
      // 禁止认证信息
      url.username = ""; url.password = "";

      // 端口白名单
      const port = url.port ? parseInt(url.port, 10) : (scheme === "https" ? 443 : 80);
      if (!CONSTANTS.SAFE_PORTS.has(port)) return null;

      // 私网/环路拦截
      const host = url.hostname;
      if (Utils.isIPv4(host) && (Utils.isPrivateIP(host) || Utils.isLoopbackOrLocal(host))) return null;

      // 外部资源尽量强制 https（若源为 http）
      if (scheme === "http" && !Utils.isPrivateIP(host) && !Utils.isLoopbackOrLocal(host)) {
        url.protocol = "https:";
        if (!url.port || url.port === "80") url.port = "443";
      }
      return url.toString();
    } catch { return null; }
  },

  // 代理区域过滤（倍率限制）
  filterProxiesByRegion(proxies, region) {
    if (!Array.isArray(proxies) || !region?.regex) return [];
    const limit = Config?.regionOptions?.ratioLimit ?? 2;
    return proxies.filter(p => {
      const name = p?.name; if (typeof name !== "string") return false;
      const m = name.match(/(?:[xX✕✖⨉]|倍率)(\d+\.?\d*)/i);
      const mult = m ? parseFloat(m[1]) : 1;
      return region.regex.test(name) && mult <= limit;
    }).map(p => p.name);
  },

  // 基础模板
  getProxyGroupBase() { return (Config.common?.proxyGroup || {}); },
  getRuleProviderBase() { return (Config.common?.ruleProvider || { type: "http", format: "yaml", interval: 86400 }); },

  /**
   * 服务定义转 Clash/Mihomo 代理组与规则
   * - service: { id,name,rule[],icon,url,proxiesOrder?,proxies?,ruleProvider? }
   * - 输出：修改 safe["proxy-groups"] 与 safe["rules"]、safe["rule-providers"]
   */
  createServiceGroups(safe, regionGroupNames, ruleProviders, rules) {
    const services = Array.isArray(Config?.services) ? Config.services : [];
    const pg = safe["proxy-groups"] || [];
    const groupBase = Utils.getProxyGroupBase();
    const defaultOrder = ["默认节点", "国内网站", "直连", "REJECT"];

    services.forEach(svc => {
      try {
        const groupName = svc.name || svc.id;
        const proxiesOrder = Array.isArray(svc.proxiesOrder) ? svc.proxiesOrder : (Array.isArray(svc.proxies) ? svc.proxies : defaultOrder);
        const finalOrder = Array.from(new Set([...(proxiesOrder || []), ...regionGroupNames])).filter(Boolean);

        pg.push({ ...groupBase, name: groupName, type: "select", proxies: finalOrder, icon: svc.icon || "" });

        const svcRules = Array.isArray(svc.rule) ? svc.rule : [];
        svcRules.forEach(r => rules.push(r));

        if (svc.ruleProvider?.name && svc.ruleProvider.url) {
          ruleProviders.set(svc.ruleProvider.name, {
            ...Utils.getRuleProviderBase(),
            behavior: svc.ruleProvider.behavior || "domain",
            format: svc.ruleProvider.format || "yaml",
            url: svc.ruleProvider.url,
            path: `./ruleset/${svc.ruleProvider.name}.${(svc.ruleProvider.format || "yaml")}`
          });
        }
      } catch (e) { Logger.warn("服务组构建失败:", svc?.id, e?.message || e); }
    });

    safe["proxy-groups"] = pg;
  }
};

/* ===================== 事件系统 ===================== */
class EventEmitter {
  constructor() { this.eventListeners = new Map(); }
  on(ev, fn) { if (!ev || !Utils.isFunc(fn)) return; const arr = this.eventListeners.get(ev) || []; arr.push(fn); this.eventListeners.set(ev, arr); }
  off(ev, fn) { const arr = this.eventListeners.get(ev); if (!arr) return; const i = arr.indexOf(fn); if (i !== -1) arr.splice(i, 1); if (!arr.length) this.eventListeners.delete(ev); }
  emit(ev, ...args) {
    const arr = this.eventListeners.get(ev); if (!arr?.length) return;
    for (const fn of (arr.length > 1 ? [...arr] : arr)) { try { fn(...args); } catch (e) { Logger.error(`事件 ${ev} 处理失败:`, e.stack || e); } }
  }
  removeAllListeners(ev) { if (ev) this.eventListeners.delete(ev); else this.eventListeners.clear(); }
}

/* ===================== 状态与缓存 ===================== */
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
    this.head = { key: null }; this.tail = { key: null, prev: this.head }; this.head.next = this.tail;
    this._lastCleanup = 0;
  }
  _unlink(n) { if (!n || n === this.head || n === this.tail) return; const { prev, next } = n; if (prev) prev.next = next; if (next) next.prev = prev; n.prev = n.next = null; }
  _pushFront(n) { if (!n) return; n.prev = this.head; n.next = this.head.next; if (this.head.next) this.head.next.prev = n; this.head.next = n; }
  _evictTail() { const n = this.tail.prev; if (!n || n === this.head) return null; this._unlink(n); this.cache.delete(n.key); return n.key; }
  get(key) {
    const e = this.cache.get(key); if (!e) return null;
    if ((Utils.now() - e.timestamp) > e.ttl) { this._unlink(e); this.cache.delete(key); return null; }
    this._unlink(e); e.timestamp = Utils.now(); this._pushFront(e); return e.value;
  }
  set(key, value, ttl = this.ttl) {
    if (key == null) return;
    const now = Utils.now();
    if (this.cache.size / this.maxSize > CONSTANTS.CACHE_CLEANUP_THRESHOLD && now - this._lastCleanup > 500) {
      this._cleanupExpiredEntries(CONSTANTS.CACHE_CLEANUP_BATCH_SIZE); this._lastCleanup = now;
    }
    if (this.cache.has(key)) {
      const e = this.cache.get(key);
      e.value = value; e.ttl = Math.max(1, ttl | 0); e.timestamp = now;
      this._unlink(e); this._pushFront(e); return;
    }
    if (this.cache.size >= this.maxSize) this._evictTail();
    const e = { key, value, ttl: Math.max(1, ttl | 0), timestamp: now, prev: null, next: null };
    this._pushFront(e); this.cache.set(key, e);
  }
  _cleanupExpiredEntries(limit = CONSTANTS.CACHE_CLEANUP_BATCH_SIZE) {
    const now = Utils.now(); let cleaned = 0;
    for (const [k, e] of this.cache) {
      if ((now - e.timestamp) > e.ttl) { this._unlink(e); this.cache.delete(k); if (++cleaned >= limit) break; }
    }
  }
  clear() { this.cache.clear(); this.head.next = this.tail; this.tail.prev = this.head; }
  delete(key) { const e = this.cache.get(key); if (!e) return false; this._unlink(e); this.cache.delete(key); return true; }
}

/* ===================== 统计与成功率 ===================== */
class RollingStats {
  constructor(windowSize = 100) { this.windowSize = Math.max(1, windowSize | 0); this.data = new Array(this.windowSize).fill(0); this.index = 0; this.count = 0; this.sum = 0; }
  add(v) { v = Number(v) || 0; if (this.count < this.windowSize) { this.data[this.index] = v; this.sum += v; this.count++; } else { const prev = this.data[this.index] || 0; this.data[this.index] = v; this.sum += v - prev; } this.index = (this.index + 1) % this.windowSize; }
  get average() { return this.count ? this.sum / this.count : 0; }
  reset() { this.data.fill(0); this.index = 0; this.count = 0; this.sum = 0; }
}
class SuccessRateTracker {
  constructor() { this.successCount = 0; this.totalCount = 0; this.hardFailStreak = 0; }
  record(success, { hardFail = false } = {}) { this.totalCount++; if (success) { this.successCount++; this.hardFailStreak = 0; } else if (hardFail) this.hFailInc(); }
  hFailInc() { this.hardFailStreak = Math.min(this.hardFailStreak + 1, 100); }
  get rate() { return this.totalCount ? this.successCount / this.totalCount : 0; }
  reset() { this.successCount = 0; this.totalCount = 0; this.hardFailStreak = 0; }
}

/* ===================== GitHub 镜像选择（单例与探测） ===================== */
const GH_MIRRORS = ["", "https://mirror.ghproxy.com/", "https://github.moeyy.xyz/", "https://ghproxy.com/"];
const GH_TEST_TARGETS = [
  "https://raw.githubusercontent.com/github/gitignore/main/Node.gitignore",
  "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/main/README.md",
  "https://raw.githubusercontent.com/cli/cli/trunk/README.md"
];
let GH_PROXY_PREFIX = "";
let __ghSelected = "";
let __ghLastProbeTs = 0;
const __GH_PROBE_TTL = 10 * 60 * 1000;
let __ghSelecting = false;
let __ghSelectWaiters = [];

const GH_RAW_URL = (path) => `${GH_PROXY_PREFIX}https://raw.githubusercontent.com/${path}`;
const GH_RELEASE_URL = (path) => `${GH_PROXY_PREFIX}https://github.com/${path}`;
const pickTestTarget = () => GH_TEST_TARGETS[Math.floor(Math.random() * GH_TEST_TARGETS.length)];

async function __probeMirror(prefix, fetchFn, timeoutMs) {
  const testUrl = prefix ? (prefix + pickTestTarget()) : pickTestTarget();
  try {
    const c = typeof AbortController !== "undefined" ? new AbortController() : null;
    const tid = timeoutMs > 0 ? setTimeout(() => { try { c?.abort(); } catch {} }, timeoutMs) : null;
    const resp = await fetchFn(testUrl, { method: "GET", headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT }, signal: c?.signal });
    if (tid) clearTimeout(tid);
    return !!resp && resp.ok;
  } catch { return false; }
}
async function selectBestMirror(runtimeFetch) {
  const now = Utils.now();
  if (__ghSelected && (now - __ghLastProbeTs) < __GH_PROBE_TTL) return __ghSelected;
  if (__ghSelecting) return new Promise((resolve) => __ghSelectWaiters.push(resolve));

  __ghSelecting = true;
  try {
    const results = await Promise.all(GH_MIRRORS.map(m =>
      __probeMirror(m, runtimeFetch, CONSTANTS.GEO_INFO_TIMEOUT).then(ok => ({ m, ok })).catch(() => ({ m, ok: false }))
    ));
    const healthy = results.filter(r => r.ok).map(r => r.m);
    const chosen = healthy.includes("") ? "" : (healthy[0] || __ghSelected || "");
    __ghSelected = chosen; __ghLastProbeTs = now; GH_PROXY_PREFIX = chosen;
    return chosen;
  } catch (e) {
    Logger.warn("selectBestMirror 失败，保持现有前缀:", e?.message || e);
    return __ghSelected || "";
  } finally {
    __ghSelecting = false;
    while (__ghSelectWaiters.length) { const fn = __ghSelectWaiters.shift(); try { fn(__ghSelected || ""); } catch {} }
  }
}

/* ===================== 资源与图标/规则 URL ===================== */
const ICONS = {
  Proxy: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Proxy.png"),
  WorldMap: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/World_Map.png"),
  HongKong: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Hong_Kong.png"),
  UnitedStates: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/United_States.png"),
  Japan: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Japan.png"),
  Korea: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Korea.png"),
  Singapore: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Singapore.png"),
  ChinaMap: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/China_Map.png"),
  China: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/China.png"),
  UnitedKingdom: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/United_Kingdom.png"),
  Germany: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Germany.png"),
  Malaysia: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Malaysia.png"),
  Turkey: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Turkey.png"),
  ChatGPT: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/ChatGPT.png"),
  YouTube: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/YouTube.png"),
  Bilibili3: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/bilibili_3.png"),
  Bahamut: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Bahamut.png"),
  DisneyPlus: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Disney+.png"),
  Netflix: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Netflix.png"),
  TikTok: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/TikTok.png"),
  Spotify: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Spotify.png"),
  Pixiv: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Pixiv.png"),
  HBO: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/HBO.png"),
  TVB: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/TVB.png"),
  PrimeVideo: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Prime_Video.png"),
  Hulu: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Hulu.png"),
  Telegram: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Telegram.png"),
  Line: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Line.png"),
  Game: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Game.png"),
  Reject: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Reject.png"),
  Advertising: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Advertising.png"),
  Apple2: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Apple_2.png"),
  GoogleSearch: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Google_Search.png"),
  Microsoft: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Microsoft.png"),
  GitHub: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/GitHub.png"),
  JP: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/JP.png"),
  Download: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Download.png"),
  StreamingCN: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/StreamingCN.png"),
  StreamingNotCN: () => GH_RAW_URL("Koolson/Qure/master/IconSet/Color/Streaming!CN.png")
};
const ICON_VAL = (fn) => { try { return Utils.isFunc(fn) ? fn() : fn; } catch { return ""; } };

const URLS = {
  rulesets: {
    applications: () => GH_RAW_URL("DustinWin/ruleset_geodata/clash-ruleset/applications.list"),
    ai: () => GH_RAW_URL("dahaha-365/YaNet/dist/rulesets/mihomo/ai.list"),
    adblock_mihomo_mrs: () => GH_RAW_URL("217heidai/adblockfilters/main/rules/adblockmihomo.mrs"),
    category_bank_jp_mrs: () => GH_RAW_URL("MetaCubeX/meta-rules-dat/meta/geo/geosite/category-bank-jp.mrs"),
    adblock_easylist: () => "https://easylist.to/easylist/easylist.txt",
    adblock_easyprivacy: () => "https://easylist.to/easylist/easyprivacy.txt",
    adblock_ublock_filters: () => "https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt"
  },
  geox: {
    geoip: () => GH_RELEASE_URL("MetaCubeX/meta-rules-dat/releases/download/latest/geoip-lite.dat"),
    geosite: () => GH_RELEASE_URL("MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"),
    mmdb: () => GH_RELEASE_URL("MetaCubeX/meta-rules-dat/releases/download/latest/country-lite.mmdb"),
    asn: () => GH_RELEASE_URL("MetaCubeX/meta-rules-dat/releases/download/latest/GeoLite2-ASN.mmdb")
  }
};

/* ===================== 基础配置 ===================== */
const Config = {
  enable: true,
  privacy: {
    geoExternalLookup: true,
    systemDnsOnly: false
  },
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
    { id: "openai", rule: ["DOMAIN-SUFFIX,grazie.ai,国外AI", "DOMAIN-SUFFIX,grazie.aws.intellij.net,国外AI", "RULE-SET,ai,国外AI"], name: "国外AI", url: "https://chat.openai.com/cdn-cgi/trace", icon: ICON_VAL(ICONS.ChatGPT), ruleProvider: {name: "ai", url: URLS.rulesets.ai()} },
    { id: "youtube", rule: ["GEOSITE,youtube,YouTube"], name: "YouTube", url: "https://www.youtube.com/s/desktop/494dd881/img/favicon.ico", icon: ICON_VAL(ICONS.YouTube) },
    { id: "biliintl", rule: ["GEOSITE,biliintl,哔哩哔哩东南亚"], name: "哔哩哔哩东南亚", url: "https://www.bilibili.tv/", icon: ICON_VAL(ICONS.Bilibili3), proxiesOrder: ["默认节点", "直连"] },
    { id: "bahamut", rule: ["GEOSITE,bahamut,巴哈姆特"], name: "巴哈姆特", url: "https://ani.gamer.com.tw/ajax/getdeviceid.php", icon: ICON_VAL(ICONS.Bahamut), proxiesOrder: ["默认节点", "直连"] },
    { id: "disney", rule: ["GEOSITE,disney,Disney+"], name: "Disney+", url: "https://disney.api.edge.bamgrid.com/devices", icon: ICON_VAL(ICONS.DisneyPlus) },
    { id: "netflix", rule: ["GEOSITE,netflix,NETFLIX"], name: "NETFLIX", url: "https://api.fast.com/netflix/speedtest/v2?https=true", icon: ICON_VAL(ICONS.Netflix) },
    { id: "tiktok", rule: ["GEOSITE,tiktok,Tiktok"], name: "Tiktok", url: "https://www.tiktok.com/", icon: ICON_VAL(ICONS.TikTok) },
    { id: "spotify", rule: ["GEOSITE,spotify,Spotify"], name: "Spotify", url: "http://spclient.wg.spotify.com/signup/public/v1/account", icon: ICON_VAL(ICONS.Spotify) },
    { id: "pixiv", rule: ["GEOSITE,pixiv,Pixiv"], name: "Pixiv", url: "https://www.pixiv.net/favicon.ico", icon: ICON_VAL(ICONS.Pixiv) },
    { id: "hbo", rule: ["GEOSITE,hbo,HBO"], name: "HBO", url: "https://www.hbo.com/favicon.ico", icon: ICON_VAL(ICONS.HBO) },
    { id: "tvb", rule: ["GEOSITE,tvb,TVB"], name: "TVB", url: "https://www.tvb.com/logo_b.svg", icon: ICON_VAL(ICONS.TVB) },
    { id: "primevideo", rule: ["GEOSITE,primevideo,Prime Video"], name: "Prime Video", url: "https://m.media-amazon.com/images/G/01/digital/video/web/logo-min-remaster.png", icon: ICON_VAL(ICONS.PrimeVideo) },
    { id: "hulu", rule: ["GEOSITE,hulu,Hulu"], name: "Hulu", url: "https://auth.hulu.com/v4/web/password/authenticate", icon: ICON_VAL(ICONS.Hulu) },
    { id: "telegram", rule: ["GEOIP,telegram,Telegram"], name: "Telegram", url: "http://www.telegram.org/img/website_icon.svg", icon: ICON_VAL(ICONS.Telegram) },
    { id: "whatsapp", rule: ["GEOSITE,whatsapp,WhatsApp"], name: "WhatsApp", url: "https://web.whatsapp.com/data/manifest.json", icon: ICON_VAL(ICONS.Telegram) },
    { id: "line", rule: ["GEOSITE,line,Line"], name: "Line", url: "https://line.me/page-data/app-data.json", icon: ICON_VAL(ICONS.Line) },
    { id: "games", rule: ["GEOSITE,category-games@cn,国内网站", "GEOSITE,category-games,游戏专用"], name: "游戏专用", icon: ICON_VAL(ICONS.Game) },
    { id: "tracker", rule: ["GEOSITE,tracker,跟踪分析"], name: "跟踪分析", icon: ICON_VAL(ICONS.Reject), proxies: ["REJECT", "直连", "默认节点"] },
    { id: "ads", rule: ["GEOSITE,category-ads-all,广告过滤", "RULE-SET,adblock_combined,广告过滤"], name: "广告过滤", icon: ICON_VAL(ICONS.Advertising), proxies: ["REJECT", "直连", "默认节点"], ruleProvider: {name: "adblock_combined", url: URLS.rulesets.adblock_mihomo_mrs(), format: "mrs", behavior: "domain"} },
    { id: "apple", rule: ["GEOSITE,apple-cn,苹果服务"], name: "苹果服务", url: "http://www.apple.com/library/test/success.html", icon: ICON_VAL(ICONS.Apple2) },
    { id: "google", rule: ["GEOSITE,google,谷歌服务"], name: "谷歌服务", url: "http://www.google.com/generate_204", icon: ICON_VAL(ICONS.GoogleSearch) },
    { id: "microsoft", rule: ["GEOSITE,microsoft@cn,国内网站", "GEOSITE,microsoft,微软服务"], name: "微软服务", url: "http://www.msftconnecttest.com/connecttest.txt", icon: ICON_VAL(ICONS.Microsoft) },
    { id: "github", rule: ["GEOSITE,github,Github"], name: "Github", url: "https://github.com/robots.txt", icon: ICON_VAL(ICONS.GitHub) },
    { id: "japan", rule: ["RULE-SET,category-bank-jp,日本网站", "GEOIP,jp,日本网站,no-resolve"], name: "日本网站", url: "https://r.r10s.jp/com/img/home/logo/touch.png", icon: ICON_VAL(ICONS.JP), ruleProvider: {name: "category-bank-jp", url: URLS.rulesets.category_bank_jp_mrs(), format: "mrs", behavior: "domain"} }
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
    "geox-url": { geoip: URLS.geox.geoip(), geosite: URLS.geox.geosite(), mmdb: URLS.geox.mmdb(), asn: URLS.geox.asn() }
  },
  common: {
    ruleProvider: { type: "http", format: "yaml", interval: 86400 },
    proxyGroup: { interval: 300, timeout: 3000, url: "http://cp.cloudflare.com/generate_204", lazy: true, "max-failed-times": 3, hidden: false },
    defaultProxyGroups: [
      { name: "下载软件", icon: ICON_VAL(ICONS.Download), proxies: ["直连", "REJECT", "默认节点", "国内网站"] },
      { name: "其他外网", icon: ICON_VAL(ICONS.StreamingNotCN), proxies: ["默认节点", "国内网站"] },
      { name: "国内网站", url: "http://wifi.vivo.com.cn/generate_204", icon: ICON_VAL(ICONS.StreamingCN), proxies: ["直连", "默认节点"] }
    ],
    postRules: ["GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve", "GEOSITE,cn,国内网站", "GEOIP,cn,国内网站,no-resolve", "MATCH,其他外网"]
  }
};

/* ===================== 节点管理器 ===================== */
class NodeManager extends EventEmitter {
  static getInstance() { if (!NodeManager.instance) NodeManager.instance = new NodeManager(); return NodeManager.instance; }
  constructor() { super(); this.currentNode = null; this.nodeQuality = new Map(); this.switchCooldown = new Map(); this.nodeHistory = new Map(); this.nodeSuccess = new Map(); }
  isInCooldown(id) { const end = this.switchCooldown.get(id); return !!(end && Utils.now() < end); }
  _cooldownTime(id) {
    const s = Utils.clamp(this.nodeQuality.get(id) || 0, 0, 100);
    return Utils.clamp(CONSTANTS.BASE_SWITCH_COOLDOWN * (1 + (s / 100) * 0.9), CONSTANTS.MIN_SWITCH_COOLDOWN, CONSTANTS.MAX_SWITCH_COOLDOWN);
  }
  _recordSwitchEvent(oldId, newId, targetGeo) {
    Logger.debug("SwitchEvent", { timestamp: Utils.now(), oldNodeId: oldId, newNodeId: newId, targetGeo: targetGeo ? { country: targetGeo.country, region: targetGeo.regionName || targetGeo.region } : null, reason: oldId ? "质量过低" : "初始选择" });
  }
  _updateNodeHistory(id, score) {
    const s = Utils.clamp(Number(score) || 0, 0, 100);
    const h = this.nodeHistory.get(id) || [];
    h.push({ timestamp: Utils.now(), score: s });
    this.nodeHistory.set(id, h.length > CONSTANTS.MAX_HISTORY_RECORDS ? h.slice(-CONSTANTS.MAX_HISTORY_RECORDS) : h);
  }
  updateNodeQuality(id, delta) {
    const ns = Utils.clamp((this.nodeQuality.get(id) || 0) + Utils.clamp(Number(delta) || 0, -20, 20), 0, 100);
    this.nodeQuality.set(id, ns); this._updateNodeHistory(id, ns);
  }
  _scoreNode(node, central) {
    if (!node?.id) return 0;
    const quality = this.nodeQuality.get(node.id) || 0;
    const st = central?.state?.nodes?.get(node.id) || {};
    const m = st.metrics || {};
    const avail = Number(st.availabilityRate) || 0;
    const { metricScore } = CentralManager.scoreComponents(m);
    const successRate = Utils.clamp((this.nodeSuccess.get(node.id)?.rate || 0) * 100, 0, 100);
    const qw = CONSTANTS.QUALITY_WEIGHT, mw = CONSTANTS.METRIC_WEIGHT, sw = CONSTANTS.SUCCESS_WEIGHT, tw = qw + mw + sw || 1;
    return Utils.clamp((quality * (qw / tw)) + (metricScore * (mw / tw)) + (successRate * (sw / tw)) + (avail < CONSTANTS.AVAILABILITY_MIN_RATE ? CONSTANTS.BIAS_AVAIL_PENALTY_BAD : 0), 0, 100);
  }
  _best(nodes) {
    const central = CentralManager.getInstance?.();
    return nodes.reduce((best, n) => (this._scoreNode(n, central) > this._scoreNode(best, central) ? n : best), nodes[0]);
  }
  async getBestNode(nodes, targetGeo) {
    if (!Array.isArray(nodes) || !nodes.length) { Logger.warn("getBestNode: 节点列表为空或无效"); return null; }
    const candidates = nodes.filter(n => n?.id && !this.isInCooldown(n.id));
    const pool = candidates.length ? candidates : nodes;
    const st = CentralManager.getInstance?.().state?.nodes;
    const regionName = targetGeo?.regionName || targetGeo?.region;
    if (st && regionName) {
      const regional = pool.filter(n => { const g = st.get(n.id)?.geoInfo; return g && (g.regionName === regionName || g.region === regionName); });
      if (regional.length) return this._best(regional) || pool[0];
    }
    return this._best(pool) || pool[0];
  }
  async switchToBestNode(nodes, targetGeo) {
    if (!nodes?.length) return null;
    const best = await this.getBestNode(nodes, targetGeo); if (!best) return null;
    const oldId = this.currentNode; this.currentNode = best.id;
    this.switchCooldown.set(best.id, Utils.now() + this._cooldownTime(best.id));
    this._recordSwitchEvent(oldId, best.id, targetGeo);
    const st = CentralManager.getInstance().state.nodes.get(best.id); const region = st?.geoInfo?.region || st?.geoInfo?.regionName || "未知区域";
    Logger.info(`节点已切换: ${oldId || "无"} -> ${best.id} (质量分: ${this.nodeQuality.get(best.id)}, 区域: ${region})`);
    return best;
  }
  async switchToNode(id, targetGeo) {
    if (!id || typeof id !== "string") { Logger.warn("switchToNode: 无效的节点ID"); return null; }
    if (this.currentNode === id) return { id };
    const central = CentralManager.getInstance?.(); const node = central?.state?.config?.proxies?.find(n => n?.id === id);
    if (!node) { Logger.warn(`尝试切换到不存在的节点: ${id}`); return null; }
    const oldId = this.currentNode; this.currentNode = id;
    this.switchCooldown.set(id, Utils.now() + this._cooldownTime(id));
    this._recordSwitchEvent(oldId, id, targetGeo);
    const st = central.state.nodes?.get(id); const region = st?.geoInfo?.region || st?.geoInfo?.regionName || "未知区域";
    Logger.info(`节点已切换: ${oldId || "无"} -> ${id} (区域: ${region})`);
    return node;
  }
}

/* ===================== 区域自动分组（归一化） ===================== */
class RegionAutoManager {
  constructor() { this.knownRegexMap = this._buildFromConfigRegions(Config?.regionOptions?.regions || []); }

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
    const found = new Map(); if (!Array.isArray(proxies)) return found;
    proxies.forEach(p => {
      const name = this._normalizeName(p?.name); if (!name) return;
      for (const e of this.knownRegexMap) if (e.regex.test(name)) found.set(e.name, { name: e.name, regex: e.regex, icon: e.icon });
      const hints = name.match(/[A-Za-z]{2,}|[\u4e00-\u9fa5]{2,}/g);
      if (hints?.length) {
        const wl = { es: "ES西班牙", ca: "CA加拿大", au: "AU澳大利亚", fr: "FR法国", it: "IT意大利", nl: "NL荷兰", ru: "RU俄罗斯", in: "IN印度", br: "BR巴西", ar: "AR阿根廷" };
        hints.forEach(h => { const k = h.toLowerCase(); if (wl[k]) { const cn = wl[k].replace(/[A-Z]{2}/, '').replace(/[^\u4e00-\u9fa5]/g, ''); const regex = new RegExp(`${k}|${cn}`, 'i'); found.set(wl[k], { name: wl[k], regex, icon: ICON_VAL(ICONS.WorldMap) }); } });
      }
    });
    return found;
  }

  mergeNewRegions(configRegions, discoveredMap) {
    const merged = Array.isArray(configRegions) ? [...configRegions] : [];
    for (const r of discoveredMap.values()) if (!this._hasRegion(merged, r.name)) merged.push({ name: r.name, regex: r.regex, icon: r.icon || ICON_VAL(ICONS.WorldMap) });
    return merged;
  }

  buildRegionGroups(config, regions) {
    const regionProxyGroups = []; let otherNames = (config.proxies || []).filter(p => typeof p?.name === "string").map(p => p.name);
    regions.forEach(region => {
      const names = Utils.filterProxiesByRegion(config.proxies || [], region);
      if (names.length) {
        regionProxyGroups.push({ ...Utils.getProxyGroupBase(), name: region.name || "Unknown", type: "url-test", tolerance: 50, icon: region.icon || ICON_VAL(ICONS.WorldMap), proxies: names });
        otherNames = otherNames.filter(n => !names.includes(n));
      }
    });
    return { regionProxyGroups, otherProxyNames: Array.from(new Set(otherNames)) };
  }
}

/* ===================== 广告拦截管理器（全平台自动） ===================== */
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
      Logger.info("广告规则已自动更新与合并");
    } catch (e) { Logger.warn("广告规则自动更新失败，使用缓存或静态源:", e?.message || e); }
  }

  async fetchAndMergeRules() {
    const fetchers = this.sources.map(src => () => this.fetchSource(src).catch(() => null));
    const results = await Utils.asyncPool(fetchers, Math.min(CONSTANTS.CONCURRENCY_LIMIT, 4));
    const texts = [];
    let mrsUrl = null;

    results.forEach((res, i) => {
      const src = this.sources[i];
      if (!res) return;
      if (src.type === "mrs") mrsUrl = src.url;
      else if (typeof res === "string" && res.trim()) texts.push(res);
    });

    const domainSet = new Set();
    texts.forEach(t => {
      t.split("\n").forEach(line => {
        line = line.trim();
        if (!line || line.startsWith("!") || line.startsWith("#") || line.startsWith("[") || line.startsWith("@@")) return;
        const m1 = line.match(/^\|\|([a-z0-9.-]+)\^/i);
        const m2 = line.match(/^domain=([a-z0-9.-]+)/i);
        const m3 = line.match(/^([\w.-]+\.[a-z]{2,})$/i);
        const dom = m1?.[1] || m2?.[1] || m3?.[1] || null;
        if (dom && Utils.isValidDomain(dom)) domainSet.add(dom.toLowerCase());
      });
    });

    const combinedList = Array.from(domainSet);
    this.cache.set("adblock_combined_list", combinedList, CONSTANTS.ADBLOCK_RULE_TTL_MS);
    if (mrsUrl) this.cache.set("adblock_mrs_url", mrsUrl, CONSTANTS.ADBLOCK_RULE_TTL_MS);
  }

  async fetchSource(src) {
    const cached = this.cache.get(`src:${src.name}`);
    if (cached) return cached;
    const resp = await this.central._safeFetch(src.url, { headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT } }, CONSTANTS.NODE_TEST_TIMEOUT);
    let text;
    if (src.type === "text") text = await resp.text();
    else if (src.type === "mrs") text = "mrs";
    this.cache.set(`src:${src.name}`, text, CONSTANTS.ADBLOCK_RULE_TTL_MS);
    return text;
  }

  injectRuleProvider(ruleProviders) {
    const mrsUrl = this.cache.get("adblock_mrs_url");
    const list = this.cache.get("adblock_combined_list") || [];
    if (mrsUrl) {
      ruleProviders.set("adblock_combined", {
        ...Utils.getRuleProviderBase(),
        behavior: "domain", format: "mrs", url: mrsUrl, path: "./ruleset/adblock_combined.mrs", interval: 43200
      });
      return;
    }
    const blob = list.join("\n");
    ruleProviders.set("adblock_combined", {
      type: "http", behavior: "domain", format: "text",
      url: `data:text/plain;base64,${Buffer.from(blob).toString("base64")}`,
      path: "./ruleset/adblock_combined.list", interval: 43200
    });
  }
}

/* ===================== 中央管理器 ===================== */
const __runtimeCache = { fetch: null, AbortController: null };

class CentralManager extends EventEmitter {
  static getInstance() { if (!CentralManager.instance) CentralManager.instance = new CentralManager(); return CentralManager.instance; }
  constructor() {
    super(); if (CentralManager.instance) return CentralManager.instance;
    this.state = new AppState(); this.stats = new RollingStats(); this.successTracker = new SuccessRateTracker();
    this.nodeManager = NodeManager.getInstance(); this.lruCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.metricsManager = new MetricsManager(this.state); this.availabilityTracker = new AvailabilityTracker(this.state, this.nodeManager);
    this.throughputEstimator = new ThroughputEstimator(); this.regionAutoManager = new RegionAutoManager();
    this.adBlockManager = new AdBlockManager(this);
    this.eventListeners = null; this._listenersRegistered = false; CentralManager.instance = this;

    Promise.resolve().then(() => this.initialize().catch(err => Logger.error("CentralManager 初始化失败:", err?.stack || err)));
  }

  static scoreComponents(m = {}) {
    const latency = Utils.clamp(Number(m.latency) || 0, 0, CONSTANTS.LATENCY_CLAMP_MS);
    const jitter  = Utils.clamp(Number(m.jitter) || 0, 0, CONSTANTS.JITTER_CLAMP_MS);
    const loss    = Utils.clamp(Number(m.loss) || 0, 0, CONSTANTS.LOSS_CLAMP);
    const bps     = Utils.clamp(Number(m.bps) || 0, 0, CONSTANTS.THROUGHPUT_SOFT_CAP_BPS);
    const latencyScore = Utils.clamp(35 - latency / 25, 0, 35);
    const jitterScore  = Utils.clamp(25 - jitter, 0, 25);
    const lossScore    = Utils.clamp(25 * (1 - loss), 0, 25);
    const throughputScore = Utils.clamp(Math.round(Math.log10(1 + bps) * 2), 0, CONSTANTS.THROUGHPUT_SCORE_MAX);
    return { latencyScore, jitterScore, lossScore, throughputScore, metricScore: Utils.clamp(Math.round(latencyScore + jitterScore + lossScore + throughputScore), 0, 100) };
  }

  async _getFetchRuntime() {
    if (__runtimeCache.fetch && __runtimeCache.AbortController !== undefined) {
      return { _fetch: __runtimeCache.fetch, _AbortController: __runtimeCache.AbortController };
    }
    let _fetch = (typeof fetch === "function") ? fetch : null;
    let _AbortController = (typeof AbortController !== "undefined") ? AbortController : null;
    if (!_fetch && PLATFORM.isNode) {
      try { const nf = require("node-fetch"); _fetch = nf.default || nf; } catch {}
      if (!_AbortController) { try { const AC = require("abort-controller"); _AbortController = AC.default || AC; } catch { if (typeof AbortController !== "undefined") _AbortController = AbortController; } }
    }
    __runtimeCache.fetch = _fetch; __runtimeCache.AbortController = _AbortController;
    return { _fetch, _AbortController };
  }
  isGeoExternalLookupEnabled() { return !(Config?.privacy && Config.privacy.geoExternalLookup === false); }

  async _safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
    if (!url || typeof url !== "string") throw new Error("_safeFetch: 无效的URL参数");
    const sanitized = Utils.sanitizeUrl(url);
    if (!sanitized) throw new Error(`_safeFetch: URL 非法或不安全 (${url})`);
    url = sanitized;

    const { _fetch, _AbortController } = await this._getFetchRuntime(); if (!_fetch) throw new Error("fetch 不可用于当前运行环境，且未找到可回退的实现");

    if (url.startsWith("https://raw.githubusercontent.com/") || url.startsWith("https://github.com/")) {
      try { const best = await selectBestMirror(_fetch); GH_PROXY_PREFIX = best || ""; url = `${GH_PROXY_PREFIX}${url}`; }
      catch (e) { Logger.warn("GH 镜像选择失败，使用原始URL:", e?.message || e); }
    }

    const opts = { ...options, headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT, ...(options.headers || {}) }, redirect: options.redirect || "follow" };
    if (_AbortController && timeout > 0) {
      const c = new _AbortController(), tid = setTimeout(() => { try { c.abort(); } catch {} }, timeout);
      try { const resp = await _fetch(url, { ...opts, signal: c.signal }); clearTimeout(tid); return resp; }
      catch (err) { clearTimeout(tid); if (["AbortError", "TimeoutError"].includes(err?.name)) throw new Error(`请求超时 (${timeout}ms): ${url}`); throw err; }
    }
    if (timeout > 0) return Promise.race([_fetch(url, opts), new Promise((_, rej) => setTimeout(() => rej(new Error(`请求超时 (${timeout}ms): ${url}`)), timeout)) ]);
    return _fetch(url, opts);
  }

  async initialize() {
    try { const { _fetch } = await this._getFetchRuntime(); if (_fetch) await selectBestMirror(_fetch); } catch (e) { Logger.warn("初始化阶段 GH 镜像预选失败:", e?.message || e); }
    await this.loadAIDBFromFile().catch(err => Logger.warn("加载AI数据失败，使用默认值:", err?.message || err));
    if (!this._listenersRegistered) { try { this.setupEventListeners(); this._listenersRegistered = true; } catch (e) { Logger.warn("设置事件监听器失败:", e?.message || e); } }
    this.on("requestDetected", (ip) => this.handleRequestWithGeoRouting(ip).catch(err => Logger.warn("地理路由处理失败:", err?.message || err)));
    this.preheatNodes().catch(err => Logger.warn("节点预热失败:", err?.message || err));

    try { await this.adBlockManager.updateIfNeeded(); } catch (e) { Logger.warn("广告模块初始化更新失败:", e?.message || e); }

    try {
      if (PLATFORM.isNode && process.on) {
        const cleanup = () => this.destroy().catch(err => Logger.error("清理资源失败:", err?.message || err));
        process.on("SIGINT", cleanup); process.on("SIGTERM", cleanup);
      } else if (PLATFORM.isBrowser) {
        window.addEventListener("beforeunload", () => this.destroy().catch(err => Logger.error("清理资源失败:", err?.message || err)));
      }
    } catch (e) { Logger.warn("注册清理函数失败:", e?.message || e); }

    Logger.info("CentralManager 初始化完成");
  }

  async destroy() {
    Logger.info("开始清理资源...");
    try { this.cleanupEventListeners(); this._listenersRegistered = false; } catch (e) { Logger.warn("清理事件监听器失败:", e?.message || e); }
    try { await this.saveAIDBToFile(); } catch (e) { Logger.warn("保存AI数据失败:", e?.message || e); }
    try { this.lruCache?.clear(); this.geoInfoCache?.clear(); } catch (e) { Logger.warn("清理缓存失败:", e?.message || e); }
    Logger.info("资源清理完成");
  }

  setupEventListeners() {
    this.eventListeners = {
      configChanged: async () => this.onConfigChanged(),
      networkOnline: async () => this.onNetworkOnline(),
      performanceThresholdBreached: async (nodeId) => this.onPerformanceThresholdBreached(nodeId),
      evaluationCompleted: () => this.onEvaluationCompleted()
    };
    try { if (typeof Config !== "undefined" && Config.on) Config.on("configChanged", this.eventListeners.configChanged); } catch {}
    try { if (PLATFORM.isBrowser) window.addEventListener("online", this.eventListeners.networkOnline); } catch {}
    try { if (this.nodeManager?.on) this.nodeManager.on("performanceThresholdBreached", this.eventListeners.performanceThresholdBreached); } catch {}
    this.on("evaluationCompleted", this.eventListeners.evaluationCompleted);
  }
  cleanupEventListeners() {
    if (!this.eventListeners) return;
    try { if (typeof Config !== "undefined" && Config.off) Config.off("configChanged", this.eventListeners.configChanged); } catch {}
    try { if (PLATFORM.isBrowser && window.removeEventListener) window.removeEventListener("online", this.eventListeners.networkOnline); } catch {}
    try { if (this.nodeManager?.off) this.nodeManager.off("performanceThresholdBreached", this.eventListeners.performanceThresholdBreached); } catch {}
    try { this.off("evaluationCompleted", this.eventListeners.evaluationCompleted); } catch {}
    this.eventListeners = null;
  }

  onNodeUpdate(id, status) { this.nodeManager.updateNodeQuality(id, status.score || 0); }
  async onConfigChanged() { Logger.info("配置变更，触发节点评估..."); await this.evaluateAllNodes(); }
  async onNetworkOnline() { Logger.info("网络恢复，触发节点评估..."); await this.evaluateAllNodes(); }
  async onPerformanceThresholdBreached(nodeId) {
    Logger.info(`节点 ${nodeId} 性能阈值突破，触发单节点评估...`);
    const node = this.state.config.proxies?.find(n => n?.id === nodeId);
    if (node) await this.evaluateNodeQuality(node); else Logger.warn(`节点 ${nodeId} 不存在，无法评估`);
  }
  onEvaluationCompleted() { Logger.info("节点评估完成，触发数据保存和节点清理..."); this.saveAIDBToFile(); this.autoEliminateNodes(); }

  async preheatNodes() {
    const proxies = this.state.config.proxies || []; if (!proxies.length) return;
    const testNodes = proxies.slice(0, CONSTANTS.PREHEAT_NODE_COUNT);
    const tasks = testNodes.map(node => () => Utils.retry(() => this.testNodeMultiMetrics(node), 2, 200));
    const results = await Utils.asyncPool(tasks, CONSTANTS.CONCURRENCY_LIMIT);
    results.forEach((res, i) => {
      const node = testNodes[i];
      if (res?.__error) { Logger.error(`节点预热失败: ${node.id}`, res.__error); return; }
      const bps = this.throughputEstimator.bpsFromBytesLatency(res); const enriched = { ...res, bps };
      this.state.updateNodeStatus(node.id, { initialMetrics: enriched, lastTested: Utils.now() });
      this.metricsManager.append(node.id, enriched);
      this.nodeManager.updateNodeQuality(node.id, this.calculateQuality(enriched));
      this.availabilityTracker.ensure(node.id);
    });
  }

  calculateQuality(metrics) { return CentralManager.scoreComponents(metrics || {}).metricScore; }

  async evaluateAllNodes() {
    const proxies = this.state.config.proxies || []; if (!proxies.length) return;
    const tasks = proxies.map(node => () => this.evaluateNodeQuality(node));
    const results = await Utils.asyncPool(tasks, CONSTANTS.CONCURRENCY_LIMIT);
    results.forEach((r, idx) => { if (r?.__error) { const node = proxies[idx]; Logger.warn(`节点评估失败: ${node?.id}`, r.__error); } });
    this.emit("evaluationCompleted");
  }

  async evaluateNodeQuality(node) {
    if (!node?.id || typeof node.id !== "string") { Logger.warn("evaluateNodeQuality: 无效的节点对象"); return; }
    let metrics;
    try { metrics = await Utils.retry(() => this.testNodeMultiMetrics(node), CONSTANTS.MAX_RETRY_ATTEMPTS, CONSTANTS.RETRY_DELAY_BASE); }
    catch { Logger.warn(`节点探测多次失败，使用回退模拟: ${node.id}`); try { metrics = await this.testNodeMultiMetrics(node); } catch { Logger.error(`节点回退测试也失败: ${node.id}`); metrics = { latency: CONSTANTS.NODE_TEST_TIMEOUT, loss: 1, jitter: 100, bytes: 0, bps: 0, __simulated: true }; } }
    if (typeof metrics.bps !== "number") metrics.bps = this.throughputEstimator.bpsFromBytesLatency(metrics);

    this.availabilityTracker.ensure(node.id);
    const isSim = metrics?.__simulated === true;
    const latency = Math.max(0, Number(metrics?.latency) || 0);
    const hardFail = !!metrics.__hardFail;
    const success = !!(metrics && !hardFail && latency > 0 && latency < (CONSTANTS.NODE_TEST_TIMEOUT * 2) && !isSim);
    this.availabilityTracker.record(node.id, success, { hardFail });

    let score = 0; try { score = Utils.clamp(this.calculateQuality(metrics), 0, 100); } catch (e) { Logger.error(`计算节点质量分失败 (${node.id}):`, e.message); }

    let geoInfo = null;
    try {
      const ip = (node.server && typeof node.server === "string") ? node.server.split(":")[0] : null;
      if (Utils.isIPv4(ip) && !Utils.isPrivateIP(ip) && !Utils.isLoopbackOrLocal(ip)) {
        geoInfo = this.isGeoExternalLookupEnabled() ? await this.getGeoInfo(ip) : this._getFallbackGeoInfo();
      }
    } catch (e) { Logger.debug(`获取节点地理信息失败 (${node.id}):`, e.message); }

    try {
      this.nodeManager.updateNodeQuality(node.id, score);
      this.metricsManager.append(node.id, metrics);
      const avail = this.availabilityTracker.rate(node.id);
      this.state.updateNodeStatus(node.id, { metrics, score, geoInfo, lastEvaluated: Utils.now(), availabilityRate: avail });
    } catch (e) { Logger.error(`更新节点状态失败 (${node.id}):`, e.message); }

    try {
      const isCurrent = this.nodeManager.currentNode === node.id;
      const availRate = this.availabilityTracker.rate(node.id);
      const failStreak = this.availabilityTracker.hardFailStreak(node.id);
      if (isCurrent && (hardFail || availRate < CONSTANTS.AVAILABILITY_MIN_RATE || score < CONSTANTS.QUALITY_SCORE_THRESHOLD)) {
        const proxies = this.state?.config?.proxies;
        if (Array.isArray(proxies) && proxies.length) { if (failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS) this.nodeManager.switchCooldown.delete(node.id); await this.nodeManager.switchToBestNode(proxies); }
      }
    } catch (e) { Logger.warn(`节点切换失败 (${node.id}):`, e.message); }
  }

  async handleRequestWithGeoRouting(targetIp) {
    const nodes = this.state.config.proxies || []; if (!targetIp || !nodes.length) { Logger.warn("无法进行地理路由: 缺少目标IP或代理节点"); return; }
    const targetGeo = this.isGeoExternalLookupEnabled() ? await this.getGeoInfo(targetIp) : this._getFallbackGeoInfo();
    if (!targetGeo) { Logger.warn("无法获取目标IP地理信息，使用默认路由"); await this.nodeManager.switchToBestNode(nodes); return; }
    await this.nodeManager.switchToBestNode(nodes, targetGeo);
  }

  autoEliminateNodes() {
    const proxies = this.state.config.proxies || []; const threshold = Utils.now() - CONSTANTS.NODE_EVALUATION_THRESHOLD;
    proxies.forEach(node => {
      const st = this.state.nodes.get(node.id); const samples = (this.state.metrics.get(node.id) || []).length;
      if (samples < CONSTANTS.MIN_SAMPLE_SIZE) return;
      if ((!st || st.lastEvaluated < threshold) || (st?.score < CONSTANTS.NODE_CLEANUP_THRESHOLD)) {
        this.state.nodes.delete(node.id); this.state.metrics.delete(node.id); this.nodeManager.nodeQuality.delete(node.id);
        Logger.info(`已清理异常节点: ${node.id}`);
      }
    });
  }

  _biasScore(c, prefers) {
    const { preferHighThroughput, preferLowLatency, preferStability } = prefers;
    return c.score
      + ((c.availability >= CONSTANTS.AVAILABILITY_MIN_RATE) ? CONSTANTS.BIAS_AVAIL_BONUS_OK : CONSTANTS.BIAS_AVAIL_PENALTY_BAD)
      + (preferHighThroughput ? Math.min(10, Math.round(Math.log10(1 + c.bps) * 2)) : 0)
      + (preferLowLatency ? Utils.clamp(CONSTANTS.BIAS_LATENCY_MAX_BONUS - (c.latency / 30), 0, CONSTANTS.BIAS_LATENCY_MAX_BONUS) : 0)
      - (preferStability ? Math.min(CONSTANTS.BIAS_JITTER_MAX_PENALTY, Math.round(c.jitter / 50)) : 0);
  }

  async onRequestOutbound(reqCtx = {}) {
    if (!this.state?.config) throw new ConfigurationError("系统配置未初始化");
    const nodes = this.state.config.proxies || []; if (!nodes.length) return { mode: "direct" };

    const urlStr = typeof reqCtx.url === "string" ? reqCtx.url : (reqCtx.url?.toString?.() || "");
    let hostname = reqCtx.host, port = reqCtx.port, protocol = reqCtx.protocol;
    try {
      if (urlStr) {
        const u = new URL(urlStr);
        hostname = hostname || u.hostname;
        protocol = protocol || (u.protocol || "").replace(":", "").toLowerCase();
        port = port || (u.port ? Number(u.port) : (protocol === "https" ? 443 : protocol === "http" ? 80 : undefined));
      }
    } catch {}

    const clientIP = reqCtx.clientIP || reqCtx.headers?.["X-Forwarded-For"] || reqCtx.headers?.["Remote-Address"];
    const clientGeo = clientIP ? (this.isGeoExternalLookupEnabled() ? await this.getGeoInfo(clientIP) : this._getFallbackGeoInfo(hostname)) : null;

    let targetGeo = null;
    try {
      if (hostname && Utils.isValidDomain(hostname)) {
        if (Config.privacy?.systemDnsOnly) { targetGeo = this._getFallbackGeoInfo(hostname); }
        else {
          const targetIP = await this.resolveDomainToIP(hostname);
          if (targetIP) targetGeo = this.isGeoExternalLookupEnabled() ? await this.getGeoInfo(targetIP) : this._getFallbackGeoInfo(hostname);
        }
      }
    } catch {}

    const isVideo = !!(reqCtx.headers?.["Content-Type"]?.includes("video") || CONSTANTS.STREAM_HINT_REGEX.test(urlStr));
    const isAI = CONSTANTS.AI_HINT_REGEX.test(urlStr || hostname || "");
    const isLarge = (Number(reqCtx.contentLength) || 0) >= CONSTANTS.LARGE_PAYLOAD_THRESHOLD_BYTES;
    const isGaming = CONSTANTS.GAMING_PORTS.includes(Number(port));
    const isTLS = (protocol === "https" || CONSTANTS.TLS_PORTS.includes(Number(port)));
    const isHTTP = (protocol === "http" || CONSTANTS.HTTP_PORTS.includes(Number(port)));
    const preferHighThroughput = isVideo || isLarge, preferLowLatency = isGaming || isAI || isTLS, preferStability = isAI || isVideo;

    const enriched = nodes.map(n => {
      const st = this.state.nodes.get(n.id) || {}; const m = st.metrics || {};
      return { node: n, score: st.score || 0, availability: st.availabilityRate || 0, latency: Number(m.latency) || Infinity, bps: Number(m.bps) || 0, jitter: Number(m.jitter) || 0 };
    }).filter(c => c.node?.id);

    let candidates = enriched;
    const regionPreferred = (targetGeo?.country && Array.isArray(Config.regionOptions?.regions))
      ? Utils.filterProxiesByRegion(nodes, Config.regionOptions.regions.find(r => r && ((r.name?.includes(targetGeo.country)) || (r.regex?.test(targetGeo.country)))))
      : null;
    if (regionPreferred?.length) {
      const set = new Set(regionPreferred);
      const regionCandidates = candidates.filter(c => set.has(c.node.name));
      if (regionCandidates.length) candidates = regionCandidates;
    }

    const prefers = { preferHighThroughput, preferLowLatency, preferStability };
    const ordered = (candidates.length ? candidates : enriched).sort((a, b) => this._biasScore(b, prefers) - this._biasScore(a, prefers)).map(c => c.node);
    const bestNode = await this.nodeManager.getBestNode(ordered.length ? ordered : nodes, targetGeo);
    const selected = bestNode || nodes[0];

    const cacheKey = `${typeof reqCtx.user === "string" ? reqCtx.user : "default"}:${clientGeo?.country || "unknown"}:${hostname || "unknown"}`;
    try { if (selected?.id) this.lruCache.set(cacheKey, selected.id); } catch {}

    if (!selected) return { mode: "direct" };
    return { mode: "proxy", node: selected, targetGeo, clientGeo, reason: { preferHighThroughput, preferLowLatency, preferStability, isVideo, isAI, isLarge, isGaming, isTLS, isHTTP } };
  }

  async onResponseInbound(resCtx = {}) {
    const node = resCtx.node; if (!node?.id) return;
    const result = { success: !!resCtx.success, latency: Number(resCtx.latency) || 0, bytes: Number(resCtx.bytes) || 0 };
    const req = { url: resCtx.url, method: resCtx.method, headers: resCtx.headers };
    this.recordRequestMetrics(node, result, req);

    const st = this.state.nodes.get(node.id) || {}; const availRate = Number(st.availabilityRate) || 0; const failStreak = this.availabilityTracker.hardFailStreak(node.id);
    const proxies = this.state?.config?.proxies || []; const isTooSlow = result.latency > CONSTANTS.LATENCY_CLAMP_MS; const belowAvail = availRate < CONSTANTS.AVAILABILITY_MIN_RATE;
    if (proxies.length && (failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS || belowAvail || isTooSlow)) {
      if (failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS) this.nodeManager.switchCooldown.delete(node.id);
      await this.nodeManager.switchToBestNode(proxies);
    }
  }

  async handleProxyRequest(req, ...args) {
    if (!this.state?.config) throw new ConfigurationError("系统配置未初始化");
    if (!req?.url) throw new InvalidRequestError("无效的请求对象或URL");
    try {
      const dispatch = await this.onRequestOutbound({
        url: req.url, method: req.method, headers: req.headers, user: req.user,
        protocol: req.protocol, port: req.port, host: req.hostname || req.host,
        contentLength: req.contentLength, clientIP: req.headers?.["X-Forwarded-For"] || req.headers?.["Remote-Address"]
      });
      if (dispatch.mode === "direct") return this.proxyToDirect(...args);
      const current = dispatch.node || (await this.nodeManager.switchToBestNode(this.state.config.proxies, dispatch.targetGeo));
      const result = await this.proxyRequestWithNode(current, ...args);
      await this.onResponseInbound({ node: current, success: result.success, latency: result.latency, bytes: result.bytes, url: req.url, method: req.method, status: result.status, headers: result.headers });
      return result;
    } catch (error) { Logger.error("代理请求处理失败:", error.stack || error); return this.proxyToDirect(...args); }
  }

  async smartDispatchNode(user, nodes, context) {
    if (!Array.isArray(nodes) || !nodes.length) throw new InvalidRequestError("smartDispatchNode: 节点列表不能为空");
    if (!context || typeof context !== "object") throw new InvalidRequestError("smartDispatchNode: 无效的上下文信息");

    const userStr = typeof user === "string" ? user : "default";
    const country = context.clientGeo?.country || "unknown";
    const hostname = context.req?.url ? (typeof context.req.url === "string" ? new URL(context.req.url).hostname : (context.req.url.hostname || "unknown")) : "unknown";
    const cacheKey = `${userStr}:${country}:${hostname}`;

    let cached = null; try { cached = this.lruCache?.get(cacheKey); } catch (e) { Logger.debug("缓存查询失败:", e.message); }
    if (cached) {
      try { const node = nodes.find(n => n?.id === cached); if (node) return node; } catch (e) { Logger.debug("缓存节点查找失败:", e.message); }
      try { this.lruCache?.delete(cacheKey); } catch (e) { Logger.debug("清理无效缓存失败:", e.message); }
    }

    const contentType = typeof context.req?.headers?.["Content-Type"] === "string" ? context.req.headers["Content-Type"] : "";
    const url = context.req?.url ? (typeof context.req.url === "string" ? context.req.url : context.req.url.toString()) : "";

    if (contentType.includes("video") || (url && /youtube|netflix|stream/i.test(url))) {
      try {
        const candidateIds = Array.from(this.state.nodes.entries()).filter(([_, node]) => typeof node?.score === "number" && node.score > CONSTANTS.QUALITY_SCORE_THRESHOLD).map(([id]) => id);
        const candidates = candidateIds.map(id => { try { return this.state.config?.proxies?.find(p => p?.id === id); } catch { return null; } }).filter(Boolean);
        const limit = CONSTANTS.CONCURRENCY_LIMIT || 3;
        if (candidates.length) {
          const tests = candidates.slice(0, limit * 2).map(n => () => Utils.retry(() => this.testNodeMultiMetrics(n), CONSTANTS.MAX_RETRY_ATTEMPTS, CONSTANTS.RETRY_DELAY_BASE));
          await Utils.asyncPool(tests, limit);
          const best = await this.nodeManager.getBestNode(candidates);
          if (best) { try { this.lruCache?.set(cacheKey, best.id); } catch (e) { Logger.debug("缓存节点选择结果失败:", e.message); } return best; }
        }
      } catch (error) { Logger.warn("视频流节点选择失败，使用默认策略:", error.message); }
    }

    if (context.targetGeo?.country && Array.isArray(Config.regionOptions?.regions)) {
      try {
        const targetRegion = Config.regionOptions.regions.find(r => r && ((r.name?.includes(context.targetGeo.country)) || (r.regex?.test(context.targetGeo.country))));
        if (targetRegion) {
          const regionNodes = Utils.filterProxiesByRegion(nodes, targetRegion);
          if (regionNodes?.length) {
            const candidates = nodes.filter(n => n?.name && regionNodes.includes(n.name));
            if (candidates.length) {
              const bn = await this.nodeManager.getBestNode(candidates);
              if (bn) { try { this.lruCache?.set(cacheKey, bn.id); } catch (e) { Logger.debug("缓存区域节点选择结果失败:", e.message); } return bn; }
            }
          }
        }
      } catch (error) { Logger.warn("区域节点选择失败，使用默认策略:", error.message); }
    }

    const bestNode = await this.nodeManager.getBestNode(nodes);
    if (!bestNode) { Logger.warn("无法选择最佳节点，返回第一个可用节点"); return nodes[0] || null; }
    try { this.lruCache?.set(cacheKey, bestNode.id); } catch (e) { Logger.debug("缓存默认节点选择结果失败:", e.message); }
    return bestNode;
  }

  async getGeoInfo(ip, domain) {
    if (!this.geoInfoCache) this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    if (!ip) return this._getFallbackGeoInfo(domain);
    if (Utils.isPrivateIP(ip) || Utils.isLoopbackOrLocal(ip)) return { country: "Local", region: "Local" };
    const cached = this.geoInfoCache.get(ip); if (cached) return cached;

    if (!this.isGeoExternalLookupEnabled()) {
      const d = this._getFallbackGeoInfo(domain); this.geoInfoCache.set(ip, d, CONSTANTS.GEO_FALLBACK_TTL); return d;
    }
    try {
      const primary = await this._fetchGeoFromPrimaryAPI(ip); if (primary) { this.geoInfoCache.set(ip, primary); return primary; }
      const fallback = await this._fetchGeoFromFallbackAPI(ip); if (fallback) { this.geoInfoCache.set(ip, fallback); return fallback; }
      const d = this._getFallbackGeoInfo(domain); this.geoInfoCache.set(ip, d, CONSTANTS.GEO_FALLBACK_TTL); return d;
    } catch (error) { Logger.error(`获取地理信息失败: ${error.message}`, error.stack); return this._getFallbackGeoInfo(domain); }
  }
  async getIpGeolocation(ip) { return this.getGeoInfo(ip); }

  async _fetchGeoFromPrimaryAPI(ip) {
    if (!Utils.isIPv4(ip)) return null;
    try {
      const resp = await this._safeFetch(`https://ipapi.co/${ip}/json/`, { headers: { "User-Agent": "Mozilla/5.0" } }, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
      const data = await resp.json();
      const country = data.country_name || data.country || "Unknown";
      const region = data.region || data.city || "Unknown";
      if (country) return { country, region };
      return null;
    } catch { return null; }
  }
  async _fetchGeoFromFallbackAPI(ip) {
    try {
      const resp = await this._safeFetch(`https://ipinfo.io/${ip}/json`, {}, CONSTANTS.GEO_INFO_TIMEOUT);
      if (!resp.ok) throw new Error(`HTTP error! status: ${resp.status}`);
      const data = await resp.json();
      const country = data.country || data.country_name || "Unknown";
      const region = data.region || data.city || "Unknown";
      if (country) return { country, region };
      return null;
    } catch { return null; }
  }
  _getFallbackGeoInfo(domain) {
    if (domain && typeof domain === "string" && Utils.isValidDomain(domain)) {
      const tld = domain.split(".").pop().toLowerCase();
      const map = { cn: "China", hk: "Hong Kong", tw: "Taiwan", jp: "Japan", kr: "Korea", us: "United States", uk: "United Kingdom", de: "Germany", fr: "France", ca: "Canada", au: "Australia" };
      if (map[tld]) return { country: map[tld], region: "Unknown" };
    }
    return { country: "Unknown", region: "Unknown" };
  }

  async resolveDomainToIP(domain) {
    if (!Utils.isValidDomain(domain)) { Logger.error(`无效的域名参数或格式: ${domain}`); return null; }
    if (Config.privacy?.systemDnsOnly) return null;
    const cacheKey = `dns:${domain}`; const cachedIP = this.lruCache.get(cacheKey); if (cachedIP) return cachedIP;
    const doh = ["https://1.1.1.1/dns-query", "https://8.8.8.8/dns-query", "https://9.9.9.9/dns-query"];
    try {
      const queries = doh.map(u => this._safeFetch(`${u}?name=${encodeURIComponent(domain)}&type=A`, { headers: { "Accept": "application/dns-json", "User-Agent": "Mozilla/5.0" } }, CONSTANTS.GEO_INFO_TIMEOUT).catch(() => null));
      let resp = null;
      for (const p of queries) { const r = await p; if (r && r.ok) { resp = r; break; } }
      if (!resp) return null;
      const data = await resp.json().catch(() => ({}));
      const answers = Array.isArray(data.Answer) ? data.Answer : [];
      const ans = answers.find(a => /^\d+\.\d+\.\d+\.\d+$/.test(a?.data));
      if (ans?.data) { this.lruCache.set(cacheKey, ans.data, 600000); return ans.data; }
      return null;
    } catch (error) { if (error.name !== "AbortError") Logger.error(`域名解析失败: ${error.message}`); return null; }
  }

  async proxyRequestWithNode(node, ...args) {
    if (!node || typeof node !== "object") throw new InvalidRequestError("代理请求失败: 无效的节点信息");
    if (!node.id || !(node.server || node.proxyUrl)) throw new InvalidRequestError(`代理请求失败: 节点缺少必要属性 (id: ${node?.id}, server: ${node?.server}, proxyUrl: ${node?.proxyUrl})`);

    const probeUrl = node.proxyUrl || (node.server ? `http://${node.server}` : "");
    const safeUrl = Utils.sanitizeUrl(probeUrl);
    if (!safeUrl) {
      Logger.warn(`代理请求阻断（不安全URL或私网）[${node.id}]: ${probeUrl}`);
      this.availabilityTracker.record(node.id, false, { hardFail: true });
      return { success: false, error: "不安全URL或私网地址", latency: CONSTANTS.NODE_TEST_TIMEOUT };
    }

    try {
      const start = Utils.now(); const fetchOptions = (args && args.length && typeof args[0] === "object") ? args[0] : {};
      const response = await this._safeFetch(safeUrl, fetchOptions, CONSTANTS.NODE_TEST_TIMEOUT);
      const latency = Utils.now() - start; let bytes = 0; try { bytes = parseInt(response.headers?.get?.("Content-Length") || "0", 10); } catch {}
      return { success: true, latency, bytes, status: response.status, headers: response.headers };
    } catch (error) {
      Logger.error(`代理请求失败 [${node.id}]: ${error?.message || error}`); this.availabilityTracker.record(node.id, false, { hardFail: true });
      return { success: false, error: error?.message || String(error), latency: CONSTANTS.NODE_TEST_TIMEOUT };
    }
  }

  proxyToDirect() { return { success: true, direct: true }; }

  recordRequestMetrics(node, result, req) {
    if (!node || !result) return;
    const metrics = {
      timestamp: Utils.now(), nodeId: node.id, success: result.success, latency: result.latency,
      url: req?.url || "", method: req?.method || "", bytes: result.bytes || 0,
      bps: this.throughputEstimator.bpsFromBytesLatency({ bytes: result.bytes || 0, latency: result.latency || 0 })
    };
    this.successTracker.record(result.success);
    if (result.latency) this.stats.add(result.latency);
    this.metricsManager.append(node.id, metrics);
    const aiScore = this.aiScoreNode(node, metrics);
    this.nodeManager.updateNodeQuality(node.id, aiScore);
  }

  aiScoreNode(node, metrics) {
    const history = this.nodeManager.nodeHistory.get(node.id) || [];
    const recents = this.state.metrics.get(node.id) || [];
    if (recents.length < CONSTANTS.MIN_SAMPLE_SIZE) return metrics.success ? CONSTANTS.EARLY_SAMPLE_SCORE : -CONSTANTS.EARLY_SAMPLE_SCORE;
    const f = this.extractNodeFeatures(node, metrics, recents, history);
    const p = this.predictNodeFuturePerformance(f);
    const adj = this.calculateScoreAdjustment(p, metrics.success);
    if (CONSTANTS.ENABLE_SCORE_DEBUGGING && Math.abs(adj) > 3) Logger.debug(`Node ${node.id} score components:`, { risk: p.risk, latency: f.currentLatency, loss: f.currentLoss, adjustment: adj });
    return adj;
  }

  extractNodeFeatures(node, currentMetrics, recentMetrics, history) {
    const lat = recentMetrics.map(m => Number(m.latency)).filter(Number.isFinite);
    const loss = recentMetrics.map(m => Number(m.loss)).filter(Number.isFinite);
    const jit = recentMetrics.map(m => Number(m.jitter)).filter(Number.isFinite);
    const suc = recentMetrics.map(m => m.success ? 1 : 0);
    const bps = recentMetrics.map(m => Number(m.bps) || 0).filter(Number.isFinite);

    const weightedLatency = Utils.calculateWeightedAverage(lat);
    const weightedLoss = Utils.calculateWeightedAverage(loss);
    const successRate = suc.length ? suc.reduce((a, b) => a + b, 0) / suc.length : 1;

    const avgLatency = lat.length ? lat.reduce((a, b) => a + b, 0) / lat.length : 0;
    const latencyStd = Utils.calculateStdDev(lat);
    const latencyCV = (latencyStd / (avgLatency || 1)) || 0;

    return {
      currentLatency: Number.isFinite(currentMetrics.latency) ? currentMetrics.latency : 0,
      currentLoss: Number.isFinite(currentMetrics.loss) ? currentMetrics.loss : 0,
      currentJitter: Number.isFinite(currentMetrics.jitter) ? currentMetrics.jitter : 0,
      currentBps: Number.isFinite(currentMetrics.bps) ? currentMetrics.bps : 0,
      success: currentMetrics.success ? 1 : 0,
      avgLatency,
      p95Latency: Utils.calculatePercentile(lat, 95),
      weightedLatency,
      latencyStd,
      latencyCV,
      avgLoss: loss.length ? loss.reduce((a, b) => a + b, 0) / loss.length : 0,
      weightedLoss,
      avgJitter: jit.length ? jit.reduce((a, b) => a + b, 0) / jit.length : 0,
      avgBps: bps.length ? bps.reduce((a, b) => a + b, 0) / bps.length : 0,
      successRate,
      latencyTrend: Utils.calculateTrend(lat),
      lossTrend: Utils.calculateTrend(loss),
      successTrend: Utils.calculateTrend(suc),
      qualityTrend: history?.length >= 2 ? history[history.length - 1].score - history[history.length - 2].score : 0,
      recentQuality: history?.length ? history[history.length - 1].score : 50,
      sampleSize: recentMetrics.length
    };
  }

  predictNodeFuturePerformance(f) {
    const w = this.getDynamicRiskWeights(f); let risk = 0;
    risk += Utils.clamp01(f.currentLatency / 1000) * w.latency;
    risk += Utils.clamp01(f.currentLoss) * w.loss;
    risk += Utils.clamp01(f.latencyStd / 100) * w.jitter;
    risk += Math.max(0, (0.8 - f.successRate) / 0.8) * w.successRate;
    if (f.latencyTrend > 5) risk += 0.1 * w.trend;
    if (f.lossTrend > 0.1) risk += 0.1 * w.trend;
    if (f.successTrend < -0.1) risk += 0.1 * w.trend;
    risk += Math.max(0, (50 - f.recentQuality) / 50) * w.quality;
    risk *= (1 - f.success * 0.3);
    risk = Utils.clamp01(risk);
    const stabilityScore = Math.round((1 - risk) * 100);
    return { risk, expectedLatency: f.weightedLatency + f.latencyTrend * 5, expectedStability: 1 - risk, stabilityScore, confidence: Math.min(1, f.sampleSize / CONSTANTS.FEATURE_WINDOW_SIZE) };
  }

  getDynamicRiskWeights(f) {
    const base = { latency: 0.25, loss: 0.25, jitter: 0.15, successRate: 0.15, trend: 0.1, quality: 0.1 };
    if (f.successRate < 0.8 || f.latencyStd > 50) {
      base.successRate = Math.min(0.3, base.successRate + 0.1);
      base.jitter = Math.min(0.3, base.jitter + 0.05);
      base.latency = Math.max(0.1, base.latency - 0.1);
      base.loss = Math.max(0.1, base.loss - 0.05);
    }
    const sum = Object.values(base).reduce((s, v) => s + v, 0) || 1;
    return Object.keys(base).reduce((acc, k) => (acc[k] = base[k] / sum, acc), {});
  }

  calculateScoreAdjustment(p, success) { if (!success) return -10; if (p.risk < 0.3) return 5; if (p.risk < 0.5) return 2; if (p.risk > 0.7) return -3; return 0; }

  processConfiguration(config) {
    if (!config || typeof config !== "object") throw new ConfigurationError("processConfiguration: 配置对象无效");
    let safe;
    try { safe = JSON.parse(JSON.stringify(config)); if (!safe || typeof safe !== "object") throw new Error("深拷贝结果无效"); }
    catch (e) { throw new ConfigurationError(`配置对象无法深拷贝: ${e?.message || "unknown error"}`); }

    try { this.state.config = safe; this.stats?.reset?.(); this.successTracker?.reset?.(); } catch (e) { Logger.warn("重置统计信息失败:", e.message); }

    const proxyCount = Array.isArray(safe?.proxies) ? safe.proxies.length : 0;
    const providerCount = (typeof safe?.["proxy-providers"] === "object" && safe["proxy-providers"] !== null) ? Object.keys(safe["proxy-providers"]).length : 0;
    if (proxyCount === 0 && providerCount === 0) throw new ConfigurationError("未检测到任何代理节点或代理提供者");

    try {
      if (Config?.system && typeof Config.system === "object") Object.assign(safe, Config.system);
      if (Config?.dns && typeof Config.dns === "object") safe.dns = Config.dns;
    } catch (e) { Logger.warn("应用系统配置失败:", e.message); }

    if (!Config || !Config.enable) { Logger.info("配置处理已禁用，返回原始配置"); return safe; }

    try {
      const discovered = this.regionAutoManager.discoverRegionsFromProxies(safe.proxies || []);
      Config.regionOptions.regions = this.regionAutoManager.mergeNewRegions(Config.regionOptions?.regions || [], discovered);
    } catch (e) { Logger.warn("自动发现新区域失败（不影响原逻辑）:", e.message); }

    const { regionProxyGroups, otherProxyNames } = this.regionAutoManager.buildRegionGroups(safe, Config.regionOptions.regions || []);
    let regionGroupNames = [];
    try {
      regionGroupNames = regionProxyGroups.filter(g => g?.name).map(g => g.name);
      if (otherProxyNames.length) regionGroupNames.push("其他节点");
      regionGroupNames = Array.from(new Set(regionGroupNames));
    } catch (e) { Logger.warn("构建区域组名称列表失败:", e.message); }

    try {
      safe["proxy-groups"] = [{ ...Utils.getProxyGroupBase(), name: "默认节点", type: "select", proxies: [...regionGroupNames, "直连"], icon: ICON_VAL(ICONS.Proxy) }];
    } catch (e) { Logger.warn("初始化代理组失败:", e.message); safe["proxy-groups"] = []; }

    try {
      safe.proxies = Array.isArray(safe?.proxies) ? safe.proxies : [];
      if (!safe.proxies.some(p => p?.name === "直连")) safe.proxies.push({ name: "直连", type: "direct" });
    } catch (e) { Logger.warn("添加直连代理失败:", e.message); }

    const ruleProviders = new Map(); const rules = [];
    try {
      const baseRP = Utils.getRuleProviderBase();
      ruleProviders.set("applications", { ...baseRP, behavior: "classical", format: "text", url: URLS.rulesets.applications(), path: "./ruleset/DustinWin/applications.list" });
      if (Array.isArray(Config.preRules)) rules.push(...Config.preRules);
      try { this.adBlockManager.injectRuleProvider(ruleProviders); } catch (e) { Logger.warn("注入广告规则提供者失败:", e?.message || e); }
      Utils.createServiceGroups(safe, regionGroupNames, ruleProviders, rules);
    } catch (e) { Logger.warn("处理服务规则失败:", e.message); }

    try {
      if (Config.common?.defaultProxyGroups?.length) {
        Config.common.defaultProxyGroups.forEach(group => {
          if (group?.name) safe["proxy-groups"].push({
            ...Utils.getProxyGroupBase(),
            name: group.name, type: "select",
            proxies: [...(Array.isArray(group.proxies) ? group.proxies : []), ...regionGroupNames],
            url: group.url || (Config.common?.proxyGroup?.url || ""), icon: group.icon || ""
          });
        });
      }
    } catch (e) { Logger.warn("添加默认代理组失败:", e.message); }

    try { if (regionProxyGroups.length) safe["proxy-groups"] = (safe["proxy-groups"] || []).concat(regionProxyGroups); }
    catch (e) { Logger.warn("添加区域代理组失败:", e.message); }

    try { if (otherProxyNames.length) safe["proxy-groups"].push({ ...Utils.getProxyGroupBase(), name: "其他节点", type: "select", proxies: otherProxyNames, icon: ICON_VAL(ICONS.WorldMap) }); }
    catch (e) { Logger.warn("添加其他节点组失败:", e.message); }

    try { if (Config.common?.postRules?.length) rules.push(...Config.common.postRules); safe.rules = rules; }
    catch (e) { Logger.warn("添加后置规则失败:", e.message); safe.rules = rules; }

    try { if (ruleProviders.size) safe["rule-providers"] = Object.fromEntries(ruleProviders); }
    catch (e) { Logger.warn("添加规则提供者失败:", e.message); }

    return safe;
  }

  selfTest() {
    try {
      const demoConfig = { proxies: [
        { id: "n1", name: "香港HK x1", type: "http", server: "1.2.3.4:80" },
        { id: "n2", name: "US美国✕2", type: "http", server: "5.6.7.8:80" },
        { id: "n3", name: "ES西班牙 x1", type: "http", server: "9.9.9.9:80" },
        { id: "n4", name: "TR土耳其 x1", type: "http", server: "10.20.30.40:80" }
      ]};
      const out = this.processConfiguration(demoConfig);
      const groups = out["proxy-groups"].map(g => g.name);
      if (!groups.includes("HK香港")) throw new Error("未生成香港分组");
      if (!groups.includes("US美国")) throw new Error("未生成美国分组");
      if (!groups.includes("ES西班牙")) throw new Error("未自动识别ES西班牙分组");
      if (!groups.includes("TR土耳其")) throw new Error("未识别土耳其分组");
      Logger.info("自检通过：自动地区分组生成正常");
    } catch (e) { Logger.error("自检失败:", e.message); }
  }
}

/* ===================== 指标与吞吐 ===================== */
class MetricsManager { constructor(state) { this.state = state; } append(id, m) {
  if (!id) return; const arr = this.state.metrics.get(id) || []; arr.push(m);
  this.state.metrics.set(id, arr.length > CONSTANTS.FEATURE_WINDOW_SIZE ? arr.slice(-CONSTANTS.FEATURE_WINDOW_SIZE) : arr);
}}
class AvailabilityTracker {
  constructor(state, nodeManager) { this.state = state; this.nodeManager = nodeManager; this.trackers = nodeManager.nodeSuccess; }
  ensure(id) { if (!this.trackers.get(id)) this.trackers.set(id, new SuccessRateTracker()); }
  record(id, success, opts = {}) { this.ensure(id); const t = this.trackers.get(id); t.record(success, opts); this.state.updateNodeStatus(id, { availabilityRate: t.rate }); }
  rate(id) { return this.trackers.get(id)?.rate || 0; }
  hardFailStreak(id) { return this.trackers.get(id)?.hardFailStreak || 0; }
}
class ThroughputEstimator {
  async tcpConnectLatency(host, port, timeout) {
    if (!PLATFORM.isNode) throw new Error("Not Node"); const net = require("net");
    return new Promise((resolve, reject) => {
      const start = Utils.now(); const socket = new net.Socket(); let done = false;
      const cleanup = (err) => { if (done) return; done = true; try { socket.destroy(); } catch {} if (err) reject(err); else resolve(Utils.now() - start); };
      socket.setTimeout(timeout, () => cleanup(new Error("TCP connect timeout"))); socket.once("error", err => cleanup(err)); socket.connect(port, host, () => cleanup());
    });
  }
  async measureResponse(response) {
    let bytes = 0, jitter = 0;
    try {
      if (response?.body?.getReader) {
        const reader = response.body.getReader(), maxBytes = 64 * 1024; const readStart = Utils.now();
        while (true) { const chunk = await reader.read(); if (chunk?.done) break; const v = chunk?.value; if (v) { const len = v.byteLength || v.length || 0; bytes += len; if (bytes >= maxBytes) break; } }
        const readTime = Math.max(1, Utils.now() - readStart);
        const speedKbps = (bytes * 8) / readTime;
        jitter = Math.max(1, 200 - Math.min(200, Math.round(speedKbps / 10)));
        jitter = Math.min(jitter, CONSTANTS.JITTER_CLAMP_MS);
        return { bytes, jitter };
      }
      if (typeof response?.arrayBuffer === "function") { const buf = await response.arrayBuffer(); bytes = buf?.byteLength || 0; return { bytes, jitter: 0 }; }
      if (response?.headers?.get) { bytes = parseInt(response.headers.get("Content-Length") || "0", 10); return { bytes, jitter: 0 }; }
      return { bytes: 0, jitter: 0 };
    } catch { return { bytes: 0, jitter: 0 }; }
  }
  bpsFromBytesLatency({ bytes = 0, latency = 0 }) { const ms = Math.max(1, Number(latency) || 1); const bps = Math.max(0, Math.round((bytes * 8 / ms) * 1000)); return Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, bps); }
}

/* ===================== AI 数据存取（隐私与健壮） ===================== */
CentralManager.prototype.loadAIDBFromFile = function () {
  return new Promise((resolve) => {
    try {
      let raw = ""; let storage = null;
      try { if (typeof $persistentStore !== "undefined" && $persistentStore) storage = $persistentStore; else if (PLATFORM.isBrowser && window.localStorage) storage = window.localStorage; } catch (e) { Logger.debug("存储检测失败:", e.message); }
      if (storage) {
        try {
          raw = typeof storage.getItem === "function" ? (storage.getItem("ai_node_data") || "") : (typeof storage.read === "function" ? (storage.read("ai_node_data") || "") : "");
        } catch (e) { Logger.warn("读取存储数据失败:", e.message); raw = ""; }
      }
      if (raw && typeof raw === "string" && raw.trim()) {
        try {
          const data = JSON.parse(raw);
          if (data && typeof data === "object" && !Array.isArray(data)) {
            let loaded = 0; Object.entries(data).forEach(([id, stats]) => {
              if (id && typeof id === "string" && stats && typeof stats === "object") {
                try { this.state.metrics.set(id, Array.isArray(stats) ? stats : [stats]); loaded++; } catch (e) { Logger.debug(`加载节点数据失败 (${id}):`, e.message); }
              }
            });
            Logger.info(`成功加载AI节点数据，共${loaded}条记录`);
          } else { Logger.warn("AI数据格式无效，预期为对象"); }
        } catch (e) {
          Logger.error("AI数据解析失败:", e?.stack || e);
          try {
            const empty = "{}";
            if (typeof $persistentStore !== "undefined" && $persistentStore.write) $persistentStore.write(empty, "ai_node_data");
            else if (PLATFORM.isBrowser && window.localStorage?.setItem) window.localStorage.setItem("ai_node_data", empty);
          } catch (delErr) { Logger.warn("重置损坏数据失败:", delErr.message); }
        }
      }
    } catch (e) { Logger.error("AI数据加载失败:", e?.stack || e); } finally { resolve(); }
  });
};
CentralManager.prototype.saveAIDBToFile = function () {
  try {
    if (!this.state?.metrics) { Logger.warn("无法保存AI数据: state.metrics 未初始化"); return; }
    const data = Object.fromEntries(this.state.metrics.entries()); if (!data || !Object.keys(data).length) { Logger.debug("没有AI数据需要保存"); return; }
    const raw = JSON.stringify(data, null, 2); if (!raw?.length) { Logger.warn("序列化AI数据失败: 结果为空"); return; }
    let saved = false;
    try {
      if (typeof $persistentStore !== "undefined" && typeof $persistentStore?.write === "function") { $persistentStore.write(raw, "ai_node_data"); saved = true; }
      else if (PLATFORM.isBrowser && typeof window.localStorage?.setItem === "function") { window.localStorage.setItem("ai_node_data", raw); saved = true; }
      if (saved) Logger.debug(`AI数据保存成功，共${Object.keys(data).length}条记录`); else Logger.warn("无法保存AI数据: 未找到可用的存储接口");
    } catch (e) { Logger.error("AI数据保存到存储失败:", e?.message || e); }
  } catch (e) { Logger.error("AI数据保存失败:", e?.stack || e); }
};

/* ===================== 节点多指标测试（安全拦截） ===================== */
CentralManager.prototype.testNodeMultiMetrics = async function (node) {
  const cacheKey = `nodeMetrics:${node.id}`; const cached = this.lruCache.get(cacheKey); if (cached) return cached;
  const timeout = CONSTANTS.NODE_TEST_TIMEOUT || 5000;
  const probe = async () => {
    const probeUrl = node.proxyUrl || node.probeUrl || (node.server ? `http://${node.server}` : null);
    const safeUrl = probeUrl ? Utils.sanitizeUrl(probeUrl) : null;
    if (!safeUrl) throw new Error("无探测URL或URL不安全，使用模拟测试");

    let tcpLatencyMs = null;
    if (PLATFORM.isNode && node.server) {
      try {
        const [host, portStr] = node.server.split(":"); const port = parseInt(portStr || "80", 10) || 80;
        if (Utils.isIPv4(host) && (Utils.isPrivateIP(host) || Utils.isLoopbackOrLocal(host))) throw new Error("私网/本地地址阻断");
        tcpLatencyMs = await this.throughputEstimator.tcpConnectLatency(host, port, timeout);
      } catch { tcpLatencyMs = null; }
    }
    const start = Utils.now(); let response;
    try { response = await this._safeFetch(safeUrl, { method: "GET" }, timeout); }
    catch { return { latency: timeout, loss: 1, jitter: 100, bytes: 0, bps: 0, __hardFail: true }; }
    const latency = Utils.now() - start;
    const measure = await this.throughputEstimator.measureResponse(response); const bytes = measure.bytes || 0;
    const jitter = Utils.clamp(measure.jitter || 0, 0, CONSTANTS.JITTER_CLAMP_MS);
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
        const latency = Math.random() * 500 + 50, loss = Math.random() * 0.1, jitter = Math.random() * 50, bytes = Math.floor(Math.random() * 32 * 1024);
        const bps = this.throughputEstimator.bpsFromBytesLatency({ bytes, latency });
        const simulated = { latency, loss, jitter, bytes, bps, __simulated: true };
        try { this.lruCache.set(cacheKey, simulated, 60000); } catch {}
        resolve(simulated);
      }, Math.random() * 500);
    });
  }
};

/* ===================== 主流程入口与导出 ===================== */
function main(config) {
  const centralManager = CentralManager.getInstance();
  return centralManager.processConfiguration(config);
}

if (typeof module !== "undefined") { module.exports = { main, CentralManager, NodeManager, Config }; }