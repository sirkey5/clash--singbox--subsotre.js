"use strict";

/**
 * Central Orchestrator - 全自动智能事件驱动增强版 (极致优化重构版)
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

/** 统一常量管理（极致精简版） */
const CONSTANTS = Object.freeze({
  PREHEAT_NODE_COUNT: 10, NODE_TEST_TIMEOUT: 5e3, BASE_SWITCH_COOLDOWN: 1.8e6,
  MIN_SWITCH_COOLDOWN: 3e5, MAX_SWITCH_COOLDOWN: 7.2e6, MAX_HISTORY_RECORDS: 100,
  NODE_EVALUATION_THRESHOLD: 1.08e7, LRU_CACHE_MAX_SIZE: 1e3, LRU_CACHE_TTL: 3.6e6,
  CONCURRENCY_LIMIT: 5, MIN_SAMPLE_SIZE: 5, GEO_FALLBACK_TTL: 3.6e6,
  QUALITY_SCORE_THRESHOLD: 30, NODE_CLEANUP_THRESHOLD: 20, GEO_INFO_TIMEOUT: 3e3,
  FEATURE_WINDOW_SIZE: 50, ENABLE_SCORE_DEBUGGING: !1, QUALITY_WEIGHT: .5,
  METRIC_WEIGHT: .35, SUCCESS_WEIGHT: .15, CACHE_CLEANUP_THRESHOLD: .1,
  CACHE_CLEANUP_BATCH_SIZE: 50, MAX_RETRY_ATTEMPTS: 3, RETRY_DELAY_BASE: 200,
  MAX_RETRY_BACKOFF_MS: 5e3, DEFAULT_USER_AGENT: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  AVAILABILITY_MIN_RATE: .75, AVAILABILITY_EMERGENCY_FAILS: 2, THROUGHPUT_SOFT_CAP_BPS: 5e7,
  THROUGHPUT_SCORE_MAX: 15, LATENCY_CLAMP_MS: 3e3, JITTER_CLAMP_MS: 500,
  LOSS_CLAMP: 1, LARGE_PAYLOAD_THRESHOLD_BYTES: 524288, STREAM_HINT_REGEX: /youtube|netflix|stream|video|live|hls|dash/i,
  AI_HINT_REGEX: /openai|claude|gemini|ai|chatgpt|api\.openai|anthropic|googleapis/i,
  GAMING_PORTS: [3074,27015,27016,27017,27031,27036,5e3,5001], TLS_PORTS: [443,8443],
  HTTP_PORTS: [80,8080,8880], BIAS_AVAIL_BONUS_OK: 10, BIAS_AVAIL_PENALTY_BAD: -30,
  BIAS_LATENCY_MAX_BONUS: 15, BIAS_JITTER_MAX_PENALTY: 10,
  SAFE_PORTS: new Set([80,443,8080,8081,8088,8880,8443]), ADBLOCK_UPDATE_INTERVAL_MS: 4.32e7,
  ADBLOCK_RULE_TTL_MS: 8.64e7, EARLY_SAMPLE_SCORE: 2, POOL_WINDOW_SIZE: 100,
  GOOD_PERCENTILE: 90, BAD_PERCENTILE: 50, ADAPT_ALPHA: .5, MIN_POOL_ITEMS_FOR_ADAPT: 10,
  DATA_URL_MAX_BYTES: 2097152, DATA_URL_PREFIX: "data:text/plain;base64,",
  VIDEO_STREAM_BONUS: 1, ASYNC_POOL_MAX_CONCURRENCY: 50, ASYNC_POOL_DEFAULT_LIMIT: 3,
  DEFAULT_SCORING_WEIGHTS: {latency:.4,loss:.3,jitter:.2,speed:.1}, LATENCY_HIGH_THRESHOLD: 500,
  LATENCY_BASE_SCORE: 35, LATENCY_SCALE_FACTOR: 100, LATENCY_EXPONENT: 1.5,
  LATENCY_DIVISOR: 25, JITTER_BASE_SCORE: 25, LOSS_BASE_SCORE: 25, THROUGHPUT_SCALE_FACTOR: 2,
  ADBLOCK_BATCH_SIZE: 500, ADBLOCK_CHUNK_SIZE: 5e4, GH_PROBE_TTL: 6e5
});

const ScoringStrategies = {
  Default(context, helpers) {
    return helpers.adjust(context.prediction, context.metrics.success);
  },
  Video(context, helpers) {
    const base = helpers.adjust(context.prediction, context.metrics.success);
    const bytes = Number(context.metrics.bytes) || 0;
    return base + (bytes >= CONSTANTS.LARGE_PAYLOAD_THRESHOLD_BYTES ? CONSTANTS.VIDEO_STREAM_BONUS : 0);
  }
};

// 修复：添加敏感信息脱敏工具（优化版）
const DataMasker = {
  _urlRegex: /([?&](token|key|auth|password|secret|access_token|api_key|session_id|credential|bearer|x-api-key|x-token|authorization)=)[^&]+/gi,
  _ipv4Regex: /\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b/g,
  _sensitiveKeyRegex: /password|token|key|secret|auth|credential|access|bearer|authorization/i,
  
  maskUrl: (url) => {
    if (typeof url !== "string") return url;
    try { return url.replace(DataMasker._urlRegex, "$1***"); } catch { return url; }
  },
  
  maskIP: (ip) => {
    if (typeof ip !== "string") return ip;
    try {
      let m = ip.replace(DataMasker._ipv4Regex, "$1***");
      return m.replace(/([0-9a-fA-F]{1,4}:){4}[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}:[0-9a-fA-F]{0,4}/g, "****:****:****:****");
    } catch { return ip; }
  },
  
  maskObject: (obj, depth = 0, maxDepth = 3) => {
    if (depth > maxDepth) return "[DEPTH]";
    if (!obj || typeof obj !== "object") return obj;
    if (Array.isArray(obj)) return obj.map(i => DataMasker.maskObject(i, depth + 1, maxDepth));
    const r = {};
    for (const k in obj) {
      if (!Object.prototype.hasOwnProperty.call(obj, k)) continue;
      if (DataMasker._sensitiveKeyRegex.test(k)) {
        r[k] = "***";
      } else {
        const v = obj[k];
        r[k] = typeof v === "string" ? DataMasker.maskUrl(DataMasker.maskIP(v)) : DataMasker.maskObject(v, depth + 1, maxDepth);
      }
    }
    return r;
  }
};

// 修复：提取私有日志函数，减少代码重复（超精简版）
const Logger = {
  _log: (level, ctx, args) => {
    if (typeof console === "undefined" || (level === "DEBUG" && !CONSTANTS.ENABLE_SCORE_DEBUGGING)) return;
    const prefix = `[${level}]`, context = ctx || "-";
    const sanitized = args.map(a =>
      typeof a === "string"
        ? DataMasker.maskUrl(DataMasker.maskIP(a))
        : (a && typeof a === "object" ? DataMasker.maskObject(a) : a)
    );
    const method = console[level.toLowerCase()] || console.log;
    if (typeof method === "function") method(prefix, context, ...sanitized);
  },
  error: (c, ...a) => Logger._log("ERROR", c, a),
  info: (c, ...a) => Logger._log("INFO", c, a),
  warn: (c, ...a) => Logger._log("WARN", c, a),
  debug: (c, ...a) => Logger._log("DEBUG", c, a)
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

/* ============== 优化工具集（精简版） ============== */
const Utils = {
  now: () => Date.now(),
  clamp: (v, min, max) => Math.max(min, Math.min(max, v)),
  clamp01: (v) => Math.max(0, Math.min(1, v)),
  sleep: (ms = 0) => new Promise(r => setTimeout(r, Math.max(0, ms | 0))),
  
  deepClone: (obj) => {
    if (typeof structuredClone === "function") {
      try { return structuredClone(obj); } catch {}
    }
    const cache = typeof WeakMap !== "undefined" ? new WeakMap() : null;
    const impl = (item) => {
      if (item === null || typeof item !== "object") return item;
      if (item instanceof Date) return new Date(item.getTime());
      if (item instanceof RegExp) return new RegExp(item.source, item.flags);
      if (item instanceof Set) { const s = new Set(); for (const v of item) s.add(impl(v)); return s; }
      if (item instanceof Map) { const m = new Map(); for (const [k,v] of item) m.set(impl(k), impl(v)); return m; }
      if (Array.isArray(item)) return item.map(impl);
      if (typeof item === "object") {
        if (cache && cache.has(item)) return cache.get(item);
        const r = {}; 
        if (cache) cache.set(item, r);
        for (const k in item) {
          if (!/^(__proto__|constructor|prototype)$/.test(k) && Object.prototype.hasOwnProperty.call(item, k)) {
            r[k] = impl(item[k]);
          }
        }
        return r;
      }
      return item;
    };
    try { return impl(obj); } catch {
      try { return JSON.parse(JSON.stringify(obj)); } catch { return obj; }
    }
  },

  async asyncPool(tasks, limit = CONSTANTS.CONCURRENCY_LIMIT) {
    const list = Array.isArray(tasks) ? tasks.filter(f => typeof f === "function") : [];
    if (!list.length) return [];
    const maxC = Math.max(1, Math.min(CONSTANTS.ASYNC_POOL_MAX_CONCURRENCY, (limit | 0) || CONSTANTS.ASYNC_POOL_DEFAULT_LIMIT));
    const results = new Array(list.length);
    let idx = 0;

    const runTask = async (i) => {
      try { results[i] = await list[i](); } catch (e) {
        results[i] = { __error: e?.message || "失败", __index: i, __err: e };
      } finally {
        if (idx < list.length) {
          const ni = idx++;
          await runTask(ni);
        }
      }
    };

    const ps = [];
    for (; idx < Math.min(maxC, list.length); idx++) {
      ps.push(runTask(idx));
    }
    await Promise.all(ps);
    return results;
  },

  async retry(fn, attempts = CONSTANTS.MAX_RETRY_ATTEMPTS, delay = CONSTANTS.RETRY_DELAY_BASE) {
    const maxA = Math.max(1, Math.min(10, attempts | 0));
    const baseD = Math.max(0, Math.min(CONSTANTS.MAX_RETRY_BACKOFF_MS, delay | 0));
    let lastErr;
    for (let i = 0; i < maxA; i++) {
      try { return await fn(); } catch (e) {
        lastErr = e;
        if (i < maxA - 1) await Utils.sleep(Math.min(CONSTANTS.MAX_RETRY_BACKOFF_MS, baseD * Math.pow(2, i)));
      }
    }
    throw lastErr || new Error("retry: 所有重试都失败");
  },

  isValidDomain: (d) => typeof d === "string" && /^[a-zA-Z0-9.-]+$/.test(d) && !d.startsWith(".") && !d.endsWith(".") && !d.includes(".."),
  
  isIPv4: (ip) => {
    if (typeof ip !== "string" || !/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) return !1;
    const parts = ip.split(".");
    for (let i = 0; i < 4; i++) {
      const n = Number(parts[i]);
      if (!Number.isInteger(n) || n < 0 || n > 255) return !1;
    }
    return !0;
  },

  isLoopbackOrLocal: (ip) => typeof ip === "string" && (/^localhost|::1$|^127\./.test(ip) || ip === "0.0.0.0"),

  isPrivateIP: (ip) => {
    if (typeof ip !== "string" || !ip) return !1;
    if (ip.includes(":")) {
      const v = ip.toLowerCase();
      return v === "::1" || /^(fc|fd|fe80)/.test(v);
    }
    if (!Utils.isIPv4(ip)) return !1;
    const pts = ip.split(".").map(n => parseInt(n, 10));
    if (pts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return !1;
    const [a, b] = pts;
    return a === 10 || a === 127 || (a === 192 && b === 168) ||
           (a === 172 && b >= 16 && b <= 31) || (a === 169 && b === 254) ||
           (a === 100 && b >= 64 && b <= 127) || (a >= 224 && a <= 239);
  },

  isLocalDomain: (d) => typeof d === "string" && /\.(local|localhost|localdomain|test)$/.test(d),

  sanitizeUrl: (u) => {
    if (typeof u !== "string" || !u) return null;
    const t = u.trim();
    if (!t) return null;

    if (t.startsWith(CONSTANTS.DATA_URL_PREFIX)) {
      const b64 = t.slice(CONSTANTS.DATA_URL_PREFIX.length);
      const estB = (b64.length * 3 / 4) | 0;
      return estB <= CONSTANTS.DATA_URL_MAX_BYTES ? u : null;
    }

    if (!/^https?:\/\//i.test(t)) return null;

    try {
      const url = new URL(t);
      const scheme = url.protocol.slice(0, -1).toLowerCase();
      if (!["http", "https"].includes(scheme)) return null;
      url.username = ""; 
      url.password = "";

      const port = url.port ? parseInt(url.port, 10) : (scheme === "https" ? 443 : 80);
      if (!CONSTANTS.SAFE_PORTS.has(port) && (port <= 0 || port > 65535 || port < 1024)) return null;

      const host = url.hostname;
      if (Utils.isLocalDomain(host) || Utils.isLoopbackOrLocal(host) || (Utils.isIPv4(host) && Utils.isPrivateIP(host))) return null;

      return url.toString();
    } catch { return null; }
  },

  filterProxiesByRegion: (proxies, region) => {
    if (!Array.isArray(proxies) || !region?.regex) return [];
    const limit = Config?.regionOptions?.ratioLimit ?? 2;
    return proxies
      .filter(p => {
        const name = p?.name;
        if (typeof name !== "string" || name.length > 100) return !1;
        const m = name.match(/(?:[xX✕✖⨉]|倍率)(\d+\.?\d*)/i);
        const mult = m ? parseFloat(m[1]) : 1;
        return region.regex.test(name) && mult <= limit;
      })
      .map(p => p.name);
  },

  getProxyGroupBase: () => (Config.common?.proxyGroup || {}),
  getRuleProviderBase: () => (Config.common?.ruleProvider || {type:"http", format:"yaml", interval:86400}),
  safeInt: (h, def = 0) => { try { const n = parseInt(h ?? "0", 10); return Number.isFinite(n) ? n : def; } catch { return def; } },

  toDataUrl: (text) => {
    if (typeof text !== "string" || !text) return "";
    const maxSize = (CONSTANTS.DATA_URL_MAX_BYTES / 1.34) | 0;
    if (text.length > maxSize) return "";
    try {
      if (typeof Buffer !== "undefined") {
        const b64 = Buffer.from(text).toString("base64");
        return ((b64.length * 0.75) | 0) <= CONSTANTS.DATA_URL_MAX_BYTES
          ? `${CONSTANTS.DATA_URL_PREFIX}${b64}`
          : "";
      }
      if (typeof btoa === "function") {
        const b64 = btoa(unescape(encodeURIComponent(text)));
        return ((b64.length * 0.75) | 0) <= CONSTANTS.DATA_URL_MAX_BYTES
          ? `${CONSTANTS.DATA_URL_PREFIX}${b64}`
          : "";
      }
    } catch {}
    return "";
  },
  
  safeSet: (obj, key, val) => { if (obj && typeof obj === "object") obj[key] = val; }
};

/* ============== GitHub 镜像系统 ============== */
const GH_MIRRORS = ["", "https://mirror.ghproxy.com/", "https://ghproxy.net/"];
const GH_TEST_TARGETS = [
  "https://raw.githubusercontent.com/github/gitignore/main/Node.gitignore",
  "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/main/README.md",
  "https://raw.githubusercontent.com/cli/cli/trunk/README.md"
];

let GH_CURRENT_MIRROR = "";
let GH_PROXY_PREFIX = "";
let GH_LAST_PROBE_TIMESTAMP = 0;
let GH_IS_SELECTING = false;
const GH_WAITERS = [];

const GH_RAW_URL = (path) => `${GH_PROXY_PREFIX}https://raw.githubusercontent.com/${path}`;
const GH_RELEASE_URL = (path) => `${GH_PROXY_PREFIX}https://github.com/${path}`;
const pickTestTarget = () => GH_TEST_TARGETS[Math.floor(Math.random() * GH_TEST_TARGETS.length)];

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
  if (GH_CURRENT_MIRROR && (now - GH_LAST_PROBE_TIMESTAMP) < CONSTANTS.GH_PROBE_TTL) return GH_CURRENT_MIRROR;
  if (GH_IS_SELECTING) return new Promise((resolve) => GH_WAITERS.push(resolve));
  GH_IS_SELECTING = true;
  try {
    let resolved = false;
    let chosen = "";

    await Promise.all(
      GH_MIRRORS.map(m => (async () => {
        try {
          const ok = await __probeMirror(m, runtimeFetch, CONSTANTS.GEO_INFO_TIMEOUT);
          if (!resolved && ok) {
            resolved = true;
            chosen = m;
          }
        } catch {}
      })())
    );

    // 修复：当没有找到更好的镜像时，保持当前有效的镜像
    if (!resolved && chosen === "") {
      chosen = GH_CURRENT_MIRROR || "";
    }
    GH_CURRENT_MIRROR = chosen;
    GH_LAST_PROBE_TIMESTAMP = now;
    GH_PROXY_PREFIX = chosen;
    return chosen;
  } catch (e) {
    Logger.warn("GH.selectBestMirror", e?.message || e);
    return GH_CURRENT_MIRROR || "";
  } finally {
    GH_IS_SELECTING = false;
    while (GH_WAITERS.length) {
      const fn = GH_WAITERS.shift();
      try { fn(GH_CURRENT_MIRROR || ""); } catch {}
    }
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
  const CDN_SOURCES = [
    f => `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@main/${f}`,
    f => `https://raw.fastgit.org/MetaCubeX/meta-rules-dat/main/${f}`,
    f => `https://raw.iqiq.io/MetaCubeX/meta-rules-dat/main/${f}`
  ];
  
  const getCDNUrl = (file, fallbackIndex = 0) =>
    CDN_SOURCES[Math.min(fallbackIndex, CDN_SOURCES.length - 1)](file);

  const rulesets = {
    applications: () => getCDNUrl("applications.list"),
    ai: () => getCDNUrl("ai.list"),
    adblock_mihomo_mrs: () => getCDNUrl("adblock.mrs"),
    category_bank_jp_mrs: () => getCDNUrl("geo/geosite/category-bank-jp.mrs"),
    adblock_easylist: () => "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easylist/easylist.txt",
    adblock_easyprivacy: () => "https://cdn.jsdelivr.net/gh/easylist/easylist@master/easylist/easyprivacy.txt",
    adblock_ublock_filters: () => "https://cdn.jsdelivr.net/gh/uBlockOrigin/uAssets@master/filters/filters.txt"
  };
  const rel = f => getCDNUrl(f);
  const geox = {
    geoip: () => rel("geoip-lite.dat"),
    geosite: () => rel("geosite.dat"), 
    mmdb: () => rel("country-lite.mmdb"),
    asn: () => rel("GeoLite2-ASN.mmdb")
  };
  return { rulesets, geox, getCDNUrl };
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
    const o = {}; ks.forEach(k => { o[k] = true; }); return o; 
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
    enable: true, listen: "127.0.0.1:1053", ipv6: true, "prefer-h3": true, "use-hosts": true, "use-system-hosts": true,
    "respect-rules": true, "enhanced-mode": "fake-ip", "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": ["*", "+.lan", "+.local", "+.market.xiaomi.com"],
    nameserver: ["https://223.5.5.5/dns-query", "https://119.29.29.29/dns-query", "https://8.8.8.8/dns-query"],
    "proxy-server-nameserver": ["https://223.5.5.5/dns-query", "https://119.29.29.29/dns-query", "https://8.8.8.8/dns-query"],
    "nameserver-policy": { "geosite:private": "system", "geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn": ["119.29.29.29", "223.5.5.5"] }
  },
  services: [
    { id:"openai", rule:["DOMAIN-SUFFIX,openai.com,国外AI","DOMAIN-SUFFIX,anthropic.com,国外AI","RULE-SET,ai,国外AI"], name:"国外AI", url:"https://api.openai.com/v1/models", icon: ICON_VAL(ICONS.ChatGPT), ruleProvider:{ name:"ai", url: URLS.rulesets.ai(), format: "text", behavior: "classical" } },
    { id:"youtube", rule:["GEOSITE,youtube,YouTube"], name:"YouTube", url:"https://www.youtube.com/s/desktop/494dd881/img/favicon.ico", icon: ICON_VAL(ICONS.YouTube) },
    { id:"biliintl", rule:["GEOSITE,biliintl,哔哩哔哩东南亚"], name:"哔哩哔哩东南亚", url:"https://www.bilibili.tv/", icon: ICON_VAL(ICONS.Bilibili3), proxiesOrder:["默认节点","直连"] },
    { id:"bahamut", rule:["GEOSITE,bahamut,巴哈姆特"], name:"巴哈姆特", url:"https://ani.gamer.com.tw/ajax/getdeviceid.php", icon: ICON_VAL(ICONS.Bahamut), proxiesOrder:["默认节点","直连"] },
    { id:"disney", rule:["GEOSITE,disney,Disney+"], name:"Disney+", url:"https://www.disneyplus.com/robots.txt", icon: ICON_VAL(ICONS.DisneyPlus) },
    { id:"netflix", rule:["GEOSITE,netflix,NETFLIX"], name:"NETFLIX", url:"https://api.fast.com/netflix/speedtest/v2?https=true", icon: ICON_VAL(ICONS.Netflix) },
    { id:"tiktok", rule:["GEOSITE,tiktok,Tiktok"], name:"Tiktok", url:"https://www.tiktok.com/", icon: ICON_VAL(ICONS.TikTok) },
    { id:"spotify", rule:["GEOSITE,spotify,Spotify"], name:"Spotify", url:"https://api.spotify.com/v1/me", icon: ICON_VAL(ICONS.Spotify) },
    { id:"pixiv", rule:["GEOSITE,pixiv,Pixiv"], name:"Pixiv", url:"https://www.pixiv.net/favicon.ico", icon: ICON_VAL(ICONS.Pixiv) },
    { id:"hbo", rule:["GEOSITE,hbo,HBO"], name:"HBO", url:"https://www.hbo.com/favicon.ico", icon: ICON_VAL(ICONS.HBO) },
    { id:"tvb", rule:["GEOSITE,tvb,TVB"], name:"TVB", url:"https://www.tvb.com/logo_b.svg", icon: ICON_VAL(ICONS.TVB) },
    { id:"primevideo", rule:["GEOSITE,primevideo,Prime Video"], name:"Prime Video", url:"https://m.media-amazon.com/images/G/01/digital/video/web/logo-min-remaster.png", icon: ICON_VAL(ICONS.PrimeVideo) },
    { id:"hulu", rule:["GEOSITE,hulu,Hulu"], name:"Hulu", url:"https://www.hulu.com/robots.txt", icon: ICON_VAL(ICONS.Hulu) },
    { id:"telegram", rule:["GEOIP,telegram,Telegram"], name:"Telegram", url:"https://web.telegram.org/robots.txt", icon: ICON_VAL(ICONS.Telegram) },
    { id:"whatsapp", rule:["GEOSITE,whatsapp,WhatsApp"], name:"WhatsApp", url:"https://web.whatsapp.com/data/manifest.json", icon: ICON_VAL(ICONS.Telegram) },
    { id:"line", rule:["GEOSITE,line,Line"], name:"Line", url:"https://line.me/page-data/app-data.json", icon: ICON_VAL(ICONS.Line) },
    { id:"games", rule:["GEOSITE,category-games@cn,国内网站","GEOSITE,category-games,游戏专用"], name:"游戏专用", icon: ICON_VAL(ICONS.Game) },
    { id:"tracker", rule:["GEOSITE,tracker,跟踪分析"], name:"跟踪分析", icon: ICON_VAL(ICONS.Reject), proxies:["REJECT","直连","默认节点"] },
    { id:"ads", rule:["GEOSITE,category-ads-all,广告过滤","RULE-SET,adblock_combined,广告过滤"], name:"广告过滤", icon: ICON_VAL(ICONS.Advertising), proxies:["REJECT","直连","默认节点"], ruleProvider:{ name:"adblock_combined", url: URLS.rulesets.adblock_mihomo_mrs(), format:"mrs", behavior:"domain" } },
    { id:"apple", rule:["GEOSITE,apple-cn,苹果服务"], name:"苹果服务", url:"https://www.apple.com/robots.txt", icon: ICON_VAL(ICONS.Apple2) },
    { id:"google", rule:["GEOSITE,google,谷歌服务"], name:"谷歌服务", url:"https://www.google.com/robots.txt", icon: ICON_VAL(ICONS.GoogleSearch) },
    { id:"microsoft", rule:["GEOSITE,microsoft@cn,国内网站","GEOSITE,microsoft,微软服务"], name:"微软服务", url:"https://www.microsoft.com/robots.txt", icon: ICON_VAL(ICONS.Microsoft) },
    { id:"github", rule:["GEOSITE,github,Github"], name:"Github", url:"https://github.com/robots.txt", icon: ICON_VAL(ICONS.GitHub) },
    { id:"japan", rule:["RULE-SET,category-bank-jp,日本网站","GEOIP,jp,日本网站,no-resolve"], name:"日本网站", url:"https://r.r10s.jp/com/img/home/logo/touch.png", icon: ICON_VAL(ICONS.JP), ruleProvider:{ name:"category-bank-jp", url: URLS.rulesets.category_bank_jp_mrs(), format:"mrs", behavior:"domain" } }
  ],
  system: {
    "allow-lan": true,
    "bind-address": "*",
    mode: "rule",
    profile: { "store-selected": true, "store-fake-ip": true },
    "unified-delay": true,
    "tcp-concurrent": true,
    "keep-alive-interval": 1800,
    "find-process-mode": "strict",
    "geodata-mode": true,
    "geodata-loader": "memconservative",
    "geo-auto-update": true,
    "geo-update-interval": 24,
    sniffer: {
      enable: true,
      "force-dns-mapping": true,
      "parse-pure-ip": false,
      "override-destination": true,
      sniff: {
        TLS: { ports: [443, 8443] },
        HTTP: { ports: [80, "8080-8880"] },
        QUIC: { ports: [443, 8443] }
      },
      "skip-src-address": ["127.0.0.0/8", "192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"],
      "force-domain": [
        "+.google.com", "+.googleapis.com", "+.googleusercontent.com", "+.youtube.com",
        "+.facebook.com", "+.messenger.com", "+.fbcdn.net", "fbcdn-a.akamaihd.net"
      ],
      "skip-domain": ["Mijia Cloud", "+.oray.com"]
    },
    ntp: { enable: true, "write-to-system": false, server: "cn.ntp.org.cn" },
    "geox-url": { geoip: URLS.geox.geoip(), geosite: URLS.geox.geosite(), mmdb: URLS.geox.mmdb(), asn: URLS.geox.asn() }
  },
  common: {
    ruleProvider: { type: "http", format: "yaml", interval: 86400 },
    proxyGroup: { interval: 300, timeout: 3000, url: "https://cp.cloudflare.com/generate_204", lazy: true, "max-failed-times": 3, hidden: false },
    defaultProxyGroups: [
      { name:"下载软件", icon: ICON_VAL(ICONS.Download), proxies:["直连","REJECT","默认节点","国内网站"] },
      { name:"其他外网", icon: ICON_VAL(ICONS.StreamingNotCN), proxies:["默认节点","国内网站"] },
      { name:"国内网站", url:"http://www.gstatic.com/generate_204", icon: ICON_VAL(ICONS.StreamingCN), proxies:["直连","默认节点"] }
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
  static build(baseConfig, options = {}) {
    const config = Utils.deepClone(baseConfig);
    
    if (!this._validateConfig(config)) return config;

    this._mergeSystemConfig(config);

    const { regions, regionProxyGroups, otherProxyNames } = this._discoverAndBuildRegions(config);
    const regionGroupNames = this._buildRegionGroupNames(regionProxyGroups, otherProxyNames);

    this._ensureDirectProxy(config);

    config["proxy-groups"] = this._buildProxyGroups(config, regionGroupNames, regionProxyGroups, otherProxyNames);

    const { rules, ruleProviders } = this._buildRules(config, regionGroupNames);
    config.rules = rules;
    config["rule-providers"] = ruleProviders;

    return config;
  }

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

  static _discoverAndBuildRegions(config) {
    const regionAuto = new RegionAutoManager();
    let regions = Config.regionOptions?.regions || [];
    const proxies = config.proxies || [];
    
    try {
      const discovered = regionAuto.discoverRegionsFromProxies(proxies);
      regions = regionAuto.mergeNewRegions(regions, discovered);
    } catch (e) { 
      Logger.warn("ConfigBuilder.regionDiscover", e?.message || e); 
    }

    const { regionProxyGroups, otherProxyNames } = regionAuto.buildRegionGroups(config, regions);
    return { regions, regionProxyGroups, otherProxyNames };
  }

  static _mergeSystemConfig(config) {
    try {
      if (Config?.system && typeof Config.system === "object") Object.assign(config, Config.system);
      if (Config?.dns && typeof Config.dns === "object") config.dns = Config.dns;
    } catch (e) { Logger.warn("ConfigBuilder.mergeSystem", e?.message || e); }
  }

  static _buildRegionGroupNames(regionProxyGroups, otherProxyNames) {
    const regionGroupNames = new Set();
    try {
      regionProxyGroups.forEach(g => {
        if (g?.name) regionGroupNames.add(g.name);
      });
      if (otherProxyNames.length) regionGroupNames.add("其他节点");
    } catch (e) { 
      Logger.warn("ConfigBuilder.regionGroupNames", e?.message || e); 
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
    const proxyGroups = [{
      ...groupBase,
      name: "默认节点",
      type: "select",
      proxies: [...regionGroupNames, "直连"],
      icon: ICON_VAL(ICONS.Proxy)
    }];

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
        Logger.warn("ConfigBuilder.serviceGroup", svc?.id, e?.message || e);
      }
    }

    for (const group of Config.common?.defaultProxyGroups || []) {
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

    if (regionProxyGroups.length) proxyGroups.push(...regionProxyGroups);

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

    ruleProviders.applications = {
      ...baseRP,
      behavior: "classical",
      format: "text",
      url: URLS.rulesets.applications(),
      path: "./ruleset/DustinWin/applications.list"
    };

    if (Array.isArray(Config.preRules)) rules.push(...Config.preRules);

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

    const adsService = Config.services?.find(s => s.id === "ads");
    if (adsService?.ruleProvider) {
      const adRP = adsService.ruleProvider;
      ruleProviders.adblock_combined = {
        ...baseRP,
        behavior: adRP.behavior || "domain",
        format: adRP.format || "mrs",
        url: adRP.url,
        path: `./ruleset/adblock_combined.${adRP.format || "mrs"}`
      };
    }

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
    aliases.split(",").forEach(alias => {
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
    this._cache = new Map();
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
      
      if (this._cache.has(name)) {
        const cached = this._cache.get(name);
        if (cached !== null) found.set(cached.name, cached);
        continue;
      }

      let matched = null;
      for (const e of this.knownRegexMap) {
        if (e.regex.test(name)) {
          matched = e;
          found.set(e.name, e);
          break;
        }
      }

      if (!matched) {
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
              const cn = wl[k].replace(/[A-Z]{2}/, "").replace(/[^\u4e00-\u9fa5]/g, "");
              const region = { name: wl[k], regex: new RegExp(`${k}|${cn}`, "i"), icon: ICON_VAL(ICONS.WorldMap) };
              found.set(wl[k], region);
              matched = region;
              break;
            }
          }
        }
      }

      this._cache.set(name, matched);
    }
    return found;
  }

  mergeNewRegions(configRegions, discoveredMap) {
    const merged = Array.isArray(configRegions) ? [...configRegions] : [];
    for (const r of discoveredMap.values()) {
      if (r && !this._hasRegion(merged, r.name)) {
        merged.push({ name: r.name, regex: r.regex, icon: r.icon || ICON_VAL(ICONS.WorldMap) });
      }
    }
    return merged;
  }

  buildRegionGroups(config, regions) {
    const regionProxyGroups = [];
    let otherNames = (config.proxies || [])
      .filter(p => typeof p?.name === "string")
      .map(p => p.name);
    
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

    for (const text of texts) {
      await this.processTextStreamed(text, domainSet);
    }

    this.cache.set("adblock_combined_set", domainSet, CONSTANTS.ADBLOCK_RULE_TTL_MS);
  }

  async processTextStreamed(text, domainSet) {
    const BATCH_SIZE = CONSTANTS.ADBLOCK_BATCH_SIZE;
    const CHUNK_SIZE = CONSTANTS.ADBLOCK_CHUNK_SIZE;
    let pos = 0;
    let lineCount = 0;
    let lineBuffer = "";

    while (pos < text.length) {
      const endPos = Math.min(pos + CHUNK_SIZE, text.length);
      let currentPos = pos;
      
      while (currentPos < endPos) {
        const newlineIndex = text.indexOf("\n", currentPos);
        
        if (newlineIndex === -1 || newlineIndex >= endPos) {
          lineBuffer += text.slice(currentPos, endPos);
          break;
        }
        
        const line = (lineBuffer + text.slice(currentPos, newlineIndex)).trim();
        lineBuffer = "";
        lineCount++;
        currentPos = newlineIndex + 1;

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

        if (lineCount % BATCH_SIZE === 0) {
          await Utils.sleep(0);
        }
      }
      
      pos = endPos;
    }
    
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
    
    const primaryUrl = src.url;
    const fallbackUrls = [];
    
    if (primaryUrl.includes("cdn.jsdelivr.net")) {
      fallbackUrls.push(
        primaryUrl.replace("cdn.jsdelivr.net", "raw.fastgit.org"),
        primaryUrl.replace("cdn.jsdelivr.net/gh", "raw.iqiq.io")
      );
    } else if (primaryUrl.includes("raw.githubusercontent.com")) {
      fallbackUrls.push(
        primaryUrl.replace("raw.githubusercontent.com", "raw.fastgit.org")
      );
    }
    
    const urlsToTry = [primaryUrl, ...fallbackUrls];
    let lastError;
    
    for (const url of urlsToTry) {
      try {
        const resp = await this.central._safeFetch(url, { headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT } }, this.central._nodeTimeout());
        if (src.type === "text") {
          const text = await resp.text();
          this.cache.set(`src:${src.name}`, text, CONSTANTS.ADBLOCK_RULE_TTL_MS);
          return text;
        }
        const marker = "mrs";
        this.cache.set(`src:${src.name}`, marker, CONSTANTS.ADBLOCK_RULE_TTL_MS);
        return marker;
      } catch (e) {
        lastError = e;
        Logger.warn("AdBlockManager", `URL 获取失败 (${url.substring(0,50)}...): ${e?.message || e}`);
      }
    }
    
    Logger.error("AdBlockManager", `所有URL都失败，包括备用源: ${lastError?.message || lastError}`);
    throw lastError;
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
    if (domainSet) {
      // 当前 Clash/Mihomo 不支持 data: 协议规则，保留为后续扩展点
      return;
    }
  }
}

/* ============== 简化的事件系统和状态管理 ============== */
class AppState {
  constructor() {
    this.nodes = new Map();
    this.metrics = new Map();
    this.config = {};
    this.lastUpdated = Utils.now();
  }
  updateNodeStatus(nodeId, status) { 
    if (!nodeId || typeof nodeId !== "string") return; 
    const current = this.nodes.get(nodeId) || {};
    this.nodes.set(nodeId, { ...current, ...status }); 
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
    const value = entry.value;
    this.cache.delete(key);
    this.cache.set(key, { value, ttl: entry.ttl, timestamp: Utils.now() });
    return value;
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
  getRate() { return this.rate; }
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
    const l = Utils.clamp(Number(metrics?.latency) || 0, 0, CONSTANTS.LATENCY_CLAMP_MS);
    const j = Utils.clamp(Number(metrics?.jitter) || 0, 0, CONSTANTS.JITTER_CLAMP_MS);
    const lo = Utils.clamp(Number(metrics?.loss) || 0, 0, CONSTANTS.LOSS_CLAMP);
    const b = Utils.clamp(Number(metrics?.bps) || 0, 0, CONSTANTS.THROUGHPUT_SOFT_CAP_BPS);

    const lScore = l > CONSTANTS.LATENCY_HIGH_THRESHOLD 
      ? Math.max(0, CONSTANTS.LATENCY_BASE_SCORE - Math.pow((l - CONSTANTS.LATENCY_HIGH_THRESHOLD) / CONSTANTS.LATENCY_SCALE_FACTOR, CONSTANTS.LATENCY_EXPONENT))
      : Utils.clamp(CONSTANTS.LATENCY_BASE_SCORE - l / CONSTANTS.LATENCY_DIVISOR, 0, CONSTANTS.LATENCY_BASE_SCORE);
    
    const jScore = Utils.clamp(CONSTANTS.JITTER_BASE_SCORE - j, 0, CONSTANTS.JITTER_BASE_SCORE);
    const loScore = Utils.clamp(CONSTANTS.LOSS_BASE_SCORE * (1 - lo), 0, CONSTANTS.LOSS_BASE_SCORE);
    const bScore = Utils.clamp(Math.round(Math.log10(1 + b) * CONSTANTS.THROUGHPUT_SCALE_FACTOR), 0, CONSTANTS.THROUGHPUT_SCORE_MAX);

    const totalW = weights.latency + weights.loss + weights.jitter + weights.speed;
    
    return Utils.clamp(
      (lScore * weights.latency + loScore * weights.loss + jScore * weights.jitter + bScore * weights.speed) / totalW,
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

    score += (availability >= CONSTANTS.AVAILABILITY_MIN_RATE) ? CONSTANTS.BIAS_AVAIL_BONUS_OK : CONSTANTS.BIAS_AVAIL_PENALTY_BAD;

    if (preferHighThroughput) {
      score += 5;
    }
    if (preferLowLatency) {
      score += 3;
    }
    if (preferStability) {
      score += 4;
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
    
    this.state = new AppState();
    this.httpClient = new HttpClient();
    this.nodeScorer = NodeScorer;
    this.adBlockManager = new AdBlockManager(this);
    
    this.stats = new RollingStats();
    this.successTracker = new SuccessRateTracker();
    this.lruCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.LRU_CACHE_MAX_SIZE, ttl: CONSTANTS.LRU_CACHE_TTL });
    
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

  processConfiguration(config) {
    if (!config || typeof config !== "object") throw new ConfigurationError("processConfiguration: 配置对象无效");
    
    try {
      this.state.config = config;
      this.stats?.reset?.();
      this.successTracker?.reset?.();
    } catch (e) { Logger.warn("Central.processConfig", e?.message || e); }

    return ConfigBuilder.build(config);
  }

  async _safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
    return this.httpClient.safeFetch(url, options, timeout);
  }

  calculateQuality(metrics) {
    return this.nodeScorer.calculate(metrics);
  }

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
    } catch (e) { Logger.warn("Central.destroy", e?.message || e); }
    Logger.info("Central.destroy", "资源清理完成");
  }
}

/* ============== 优劣节点池（超优化版） ============== */
class NodePools {
  constructor() { 
    this.good = new Set(); 
    this.bad = new Set(); 
    this._scoreBuf = new Array(CONSTANTS.POOL_WINDOW_SIZE).fill(null);
    this._availBuf = new Array(CONSTANTS.POOL_WINDOW_SIZE).fill(null);
    this._idx = 0;
    this._cnt = 0;
  }

  pushSamples(score, avail) {
    if (Number.isFinite(score)) this._scoreBuf[this._idx] = Number(score);
    if (Number.isFinite(avail)) this._availBuf[this._idx] = Number(avail);
    this._idx = (this._idx + 1) % CONSTANTS.POOL_WINDOW_SIZE;
    if (this._cnt < CONSTANTS.POOL_WINDOW_SIZE) this._cnt++;
  }
  
  getAdaptiveThresholds() {
    if (this._cnt < CONSTANTS.MIN_POOL_ITEMS_FOR_ADAPT) {
      return { goodScore: CONSTANTS.QUALITY_SCORE_THRESHOLD, goodAvail: CONSTANTS.AVAILABILITY_MIN_RATE };
    }
    
    const alpha = CONSTANTS.ADAPT_ALPHA;
    const p90Score = this._calcPercentile(this._scoreBuf.slice(0, this._cnt), CONSTANTS.GOOD_PERCENTILE);
    const p50Avail = this._calcPercentile(this._availBuf.slice(0, this._cnt), CONSTANTS.BAD_PERCENTILE);
    const goodScore = alpha * CONSTANTS.QUALITY_SCORE_THRESHOLD + (1 - alpha) * p90Score;
    const goodAvail = alpha * CONSTANTS.AVAILABILITY_MIN_RATE + (1 - alpha) * p50Avail;
    return { goodScore: Utils.clamp(goodScore, 0, 100), goodAvail: Utils.clamp(goodAvail, 0, 1) };
  }

  _calcPercentile(values, p) {
    const arr = values.filter(v => v !== null);
    if (!arr.length) return 0;
    arr.sort((a, b) => a - b);
    const idx = (p / 100) * (arr.length - 1);
    const i = Math.floor(idx);
    const frac = idx - i;
    if (i >= arr.length - 1) return arr[arr.length - 1];
    return arr[i] + (arr[i + 1] - arr[i]) * frac;
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
    this._scoreBuf.fill(null);
    this._availBuf.fill(null);
    this._idx = 0;
    this._cnt = 0;
  }

  snapshot() { 
    return { good: Array.from(this.good), bad: Array.from(this.bad) }; 
  }

  namesFromIds(proxies, ids) {
    if (!Array.isArray(proxies) || !Array.isArray(ids) || !ids.length) return [];
    const map = new Map(proxies.filter(p => p?.id && p?.name).map(p => [p.id, p.name]));
    return ids.map(id => map.get(id)).filter(Boolean);
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
  
  isCommonJS() {
    if (this._cache.commonjs === undefined) {
      this._cache.commonjs = (typeof module !== "undefined" && module.exports);
    }
    return this._cache.commonjs;
  },
  
  isNode() {
    if (this._cache.node === undefined) {
      this._cache.node = (typeof global !== "undefined");
    }
    return this._cache.node;
  },
  
  isBrowser() {
    if (this._cache.browser === undefined) {
      this._cache.browser = (typeof window !== "undefined");
    }
    return this._cache.browser;
  },
  
  getEnvironment() {
    if (this.isNode()) return "Node";
    if (this.isBrowser()) return "Browser";
    return "Unknown";
  }
};

/* ============== 错误对象工厂模式 ============== */
const ErrorConfigFactory = {
  createErrorConfig: (msg, opts = {}) => ({
    name: `⛔ 脚本错误: ${msg.substring(0, 20)}...`,
    type: "direct",
    server: "127.0.0.1",
    port: 80,
    version: "optimized_fixed",
    ...opts,
    _error: !0,
    _errorMessage: msg,
    _errorTimestamp: Utils.now(),
    _scriptError: { timestamp: Utils.now(), message: msg, fallback: !0, version: "optimized_fixed" }
  })
};

/* ============== 修复后的 Main 函数（超精简版） ============== */
function main(config) {
  if (!config || typeof config !== "object") {
    Logger.error("Main", "配置无效");
    return config;
  }

  try {
    return ConfigBuilder.build(config);
  } catch (e) {
    const msg = e?.message || "未知错误";
    Logger.error("Main", `构建失败: ${msg}`);
    try {
      const fallbackCfg = { ...config };
      if (!Array.isArray(fallbackCfg.proxies)) fallbackCfg.proxies = [];
      fallbackCfg.proxies.unshift(ErrorConfigFactory.createErrorConfig(msg));
      return fallbackCfg;
    } catch (fallbackErr) {
      Logger.error("Main", "回退失败，返回原始配置");
      return config;
    }
  }
}

/* ============== 优化后的统一导出逻辑 ============== */
const EXPORTS = {
  main,
  CentralManager,
  ConfigBuilder,
  buildConfigForParser: ConfigBuilder.build.bind(ConfigBuilder),
  RegionAutoManager,
  LRUCache,
  NodeScorer,
  Utils,
  DataMasker,
  CONSTANTS,
  Config,
  GH_MIRRORS
};

if (EnvDetector.isCommonJS()) module.exports = EXPORTS;
if (EnvDetector.isNode()) {
  const safeExports = { ...EXPORTS };
  delete safeExports.Proxy;
  Object.assign(global, safeExports);
}
if (EnvDetector.isBrowser()) {
  window.__MihomoScript__ = EXPORTS;
}

Logger.info("Script", `优化版加载完成 - 环境: ${EnvDetector.getEnvironment()}`);
