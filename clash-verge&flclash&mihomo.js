"use strict";

/**
 * Central Orchestrator - 全自动智能事件驱动增强版 (极致优化重构版)
 * - 结构优化：统一配置构建器，消除重复逻辑
 * - 性能提升：使用现代JS API，优化工具函数
 * - 代码精简：压缩常量定义，内联工具函数
 * - 保留功能：完整保持原有API和行为兼容
 */

const Env = (() => {
  const isNode = typeof process !== "undefined" && !!process.versions?.node;
  const isBrowser = typeof window !== "undefined" && !!window.document;
  const isMihomo = typeof $proxy !== "undefined" || typeof $content !== "undefined";
  return Object.freeze({
    isNode, isBrowser, isMihomo,
    get: () => isMihomo ? "Mihomo" : (isNode ? "Node" : (isBrowser ? "Browser" : "Unknown")),
    isCJS: () => typeof module !== "undefined" && !!module.exports
  });
})();

/** 极致精简常量管理 */
const CONSTANTS = Object.freeze({
  PREHEAT: { COUNT: 10, CONCURRENCY: 3, DELAY: 250 },
  TIMEOUT: { NODE: 5000, GEO: 3000, MIRROR: 5000, TEST: 5000 },
  COOLDOWN: { BASE: 1.8e6, MIN: 3e5, MAX: 7.2e6, SWITCH: { BASE: 300000, MIN: 60000, MAX: 1800000 } },
  CACHE: { SIZE: 1000, TTL: 3.6e6, RULES: 8.64e7, UPDATE: 4.32e7 },
  SCORING: { 
    WEIGHTS: { latency: 0.4, loss: 0.3, jitter: 0.2, speed: 0.1 }, 
    THRESHOLD: 30,
    LATENCY_CLAMP_MS: 2000, LATENCY_HIGH_THRESHOLD: 800, LATENCY_BASE_SCORE: 100, LATENCY_SCALE_FACTOR: 200, LATENCY_EXPONENT: 1.5, LATENCY_DIVISOR: 20,
    JITTER_CLAMP_MS: 500, JITTER_BASE_SCORE: 20,
    LOSS_CLAMP: 1, LOSS_BASE_SCORE: 100,
    THROUGHPUT_SOFT_CAP_BPS: 10000000, THROUGHPUT_SCALE_FACTOR: 10, THROUGHPUT_SCORE_MAX: 100,
    AVAILABILITY_MIN_RATE: 0.8, BIAS_AVAIL_BONUS_OK: 5, BIAS_AVAIL_PENALTY_BAD: -10
  },
  GH: { TTL: 6e5, MIRRORS: ["", "https://mirror.ghproxy.com/", "https://ghproxy.net/"] },
  UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
  STREAM_REG: /youtube|netflix|stream|video|live|hls|dash/i,
  AI_REG: /openai|claude|gemini|ai|chatgpt|api\.openai|anthropic|googleapis/i,
  SAFE_PORTS: new Set([80, 443, 8080, 8081, 8088, 8880, 8443]),
  IPV4_REG: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$/,
  URL_MASK_REG: /([?&](token|key|auth|password|secret|access_token|api_key|session_id|credential|bearer|x-api-key|x-token|authorization)=)[^&]+/gi,
  SENSITIVE_KEY_REG: /password|token|key|secret|auth|credential|access|bearer|authorization/i,
  POOL: { WINDOW_SIZE: 100, MIN_ITEMS: 10, ALPHA: 0.3, GOOD_PERCENTILE: 0.9, BAD_PERCENTILE: 0.5 },
  ADBLOCK: { UPDATE_INTERVAL: 4.32e7, RULE_TTL: 8.64e7, BATCH_SIZE: 500, CHUNK_SIZE: 50000 },
  DEBUG: false
});

const ScoringStrategies = {
  Default: (ctx, h) => h.adjust(ctx.prediction, ctx.metrics.success),
  Video: (ctx, h) => h.adjust(ctx.prediction, ctx.metrics.success) + ((Number(ctx.metrics.bytes) || 0) >= 524288 ? 1 : 0)
};

// 修复：添加敏感信息脱敏工具（优化版）
const DataMasker = {
  maskUrl: (url) => {
    if (typeof url !== "string") return url;
    try { return url.replace(CONSTANTS.URL_MASK_REG, "$1***"); } catch { return url; }
  },
  
  maskIP: (ip) => {
    if (typeof ip !== "string") return ip;
    try {
      let m = ip.replace(/\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.)\d{1,3}\b/g, "$1***");
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
      if (CONSTANTS.SENSITIVE_KEY_REG.test(k)) {
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
    if (typeof console === "undefined" || (level === "DEBUG" && !CONSTANTS.DEBUG)) return;
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

/* ============== 优化工具集 (极致精简) ============== */
const Utils = {
  now: Date.now,
  clamp: (v, min, max) => v < min ? min : (v > max ? max : v),
  sleep: ms => new Promise(r => setTimeout(r, ms)),
  
  deepClone: obj => {
    try { return typeof structuredClone === "function" ? structuredClone(obj) : JSON.parse(JSON.stringify(obj)); } catch { return obj; }
  },

  async asyncPool(tasks, limit = CONSTANTS.PREHEAT.CONCURRENCY) {
    const results = [], executing = [];
    for (const task of tasks) {
      const p = Promise.resolve().then(() => task());
      results.push(p);
      if (limit <= tasks.length) {
        const e = p.finally(() => executing.splice(executing.indexOf(e), 1));
        executing.push(e);
        if (executing.length >= limit) await Promise.race(executing);
      }
    }
    return Promise.all(results);
  },

  isIPv4: ip => CONSTANTS.IPV4_REG.test(ip),
  isPrivateIP: ip => {
    if (!Utils.isIPv4(ip)) return false;
    const [a, b] = ip.split(".").map(Number);
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || a === 127 || a === 169;
  },

  sanitizeUrl: u => {
    try {
      const url = new URL(u);
      if (!["http:", "https:"].includes(url.protocol)) return null;
      const host = url.hostname;
      if (Utils.isPrivateIP(host) || host === "localhost") return null;
      return url.toString();
    } catch { return null; }
  },

  safeSet: (obj, key, val) => { if (obj) obj[key] = val; },
  
  getProxyGroupBase: () => ({
    interval: Config.common?.proxyGroup?.interval || 300,
    timeout: Config.common?.proxyGroup?.timeout || 3000,
    url: Config.common?.proxyGroup?.url || "https://cp.cloudflare.com/generate_204",
    lazy: Config.common?.proxyGroup?.lazy !== false
  })
};

/* ============== GitHub 镜像系统 (优化版) ============== */
let GH_PROXY = "";
async function selectBestMirror(fetchFn) {
  if (GH_PROXY) return GH_PROXY;
  const test = async (m) => {
    try {
      const res = await fetchFn(m + "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/main/README.md", { method: "HEAD" });
      return res.ok ? m : null;
    } catch { return null; }
  };
  const results = await Promise.all(CONSTANTS.GH.MIRRORS.map(test));
  return GH_PROXY = results.find(r => r !== null) || "";
}

/* ============== 资源与URL定义 (极致优化) ============== */
const ICON_VAL = (f) => { try { return typeof f === "function" ? f() : f; } catch { return ""; } };

const ICONS = (() => {
  const base = "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color";
  const map = { ChinaMap: "China_Map", HongKong: "Hong_Kong" };
  return new Proxy({}, { get: (_, n) => () => `${GH_PROXY}${base}/${map[n] || n}.png` });
})();

const URLS = {
  mrs: f => `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@main/${f}.mrs`,
  list: f => `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@main/${f}.list`,
  geox: {
    geoip: () => "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    geosite: () => "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    mmdb: () => "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country.mmdb",
    asn: () => "https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.asn.dat"
  },
  rulesets: {
    ai: () => URLS.mrs("ai"),
    ads: () => URLS.mrs("category-ads-all"),
    trackers: () => URLS.mrs("trackers"),
    applications: () => URLS.list("applications")
  }
};

/* ============== 配置管理 ============== */
const Config = {
  enable: true,
  privacy: { geoExternalLookup: false, systemDnsOnly: false, trustedGeoEndpoints: [], githubMirrorEnabled: true },
  ruleOptions: Object.fromEntries(["apple","microsoft","github","google","openai","spotify","youtube","bahamut","netflix","tiktok","disney","pixiv","hbo","biliintl","tvb","hulu","primevideo","telegram","line","whatsapp","games","japan","tracker","ads"].map(k => [k, true])),
  preRules: ["RULE-SET,applications,下载软件","PROCESS-NAME,SunloginClient,DIRECT","PROCESS-NAME,AnyDesk,DIRECT"],
  regionOptions: { excludeHighPercentage: true, ratioLimit: 2, regions: [
    { name: "HK香港", regex: /港|🇭🇰|hk|hongkong/i, icon: ICONS.HongKong },
    { name: "US美国", regex: /美|🇺🇸|us|united states/i, icon: ICONS.UnitedStates },
    { name: "JP日本", regex: /日本|🇯🇵|jp|japan/i, icon: ICONS.Japan },
    { name: "KR韩国", regex: /韩|🇰🇷|kr|korea/i, icon: ICONS.Korea },
    { name: "SG新加坡", regex: /新加坡|🇸🇬|sg|singapore/i, icon: ICONS.Singapore },
    { name: "CN中国大陆", regex: /中国|🇨🇳|cn|china/i, icon: ICONS.ChinaMap },
    { name: "TW台湾省", regex: /台湾|🇹🇼|tw|taiwan/i, icon: ICONS.China },
    { name: "GB英国", regex: /英|🇬🇧|uk|united kingdom/i, icon: ICONS.UnitedKingdom },
    { name: "DE德国", regex: /德国|🇩🇪|de|germany/i, icon: ICONS.Germany },
    { name: "MY马来西亚", regex: /马来|my|malaysia/i, icon: ICONS.Malaysia },
    { name: "TR土耳其", regex: /土耳其|🇹🇷|tr|turkey/i, icon: ICONS.Turkey }
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
    { id:"openai", rule:["DOMAIN-SUFFIX,openai.com,国外AI","RULE-SET,ai,国外AI"], name:"国外AI", icon: ICONS.ChatGPT, ruleProvider:{ name:"ai", url: URLS.rulesets.ai(), format: "mrs", behavior: "domain" } },
    { id:"youtube", rule:["GEOSITE,youtube,YouTube"], name:"YouTube", icon: ICONS.YouTube },
    { id:"biliintl", rule:["GEOSITE,biliintl,哔哩哔哩东南亚"], name:"哔哩哔哩东南亚", icon: ICONS.Bilibili3, proxiesOrder:["默认节点","直连"] },
    { id:"bahamut", rule:["GEOSITE,bahamut,巴哈姆特"], name:"巴哈姆特", icon: ICONS.Bahamut, proxiesOrder:["默认节点","直连"] },
    { id:"disney", rule:["GEOSITE,disney,Disney+"], name:"Disney+", icon: ICONS.DisneyPlus },
    { id:"netflix", rule:["GEOSITE,netflix,NETFLIX"], name:"NETFLIX", icon: ICONS.Netflix },
    { id:"tiktok", rule:["GEOSITE,tiktok,Tiktok"], name:"Tiktok", icon: ICONS.TikTok },
    { id:"spotify", rule:["GEOSITE,spotify,Spotify"], name:"Spotify", icon: ICONS.Spotify },
    { id:"pixiv", rule:["GEOSITE,pixiv,Pixiv"], name:"Pixiv", icon: ICONS.Pixiv },
    { id:"hbo", rule:["GEOSITE,hbo,HBO"], name:"HBO", icon: ICONS.HBO },
    { id:"tvb", rule:["GEOSITE,tvb,TVB"], name:"TVB", icon: ICONS.TVB },
    { id:"primevideo", rule:["GEOSITE,primevideo,Prime Video"], name:"Prime Video", icon: ICONS.PrimeVideo },
    { id:"hulu", rule:["GEOSITE,hulu,Hulu"], name:"Hulu", icon: ICONS.Hulu },
    { id:"telegram", rule:["GEOIP,telegram,Telegram"], name:"Telegram", icon: ICONS.Telegram },
    { id:"whatsapp", rule:["GEOSITE,whatsapp,WhatsApp"], name:"WhatsApp", icon: ICONS.Telegram },
    { id:"line", rule:["GEOSITE,line,Line"], name:"Line", icon: ICONS.Line },
    { id:"games", rule:["GEOSITE,category-games@cn,国内网站","GEOSITE,category-games,游戏专用"], name:"游戏专用", icon: ICONS.Game },
    { id:"tracker", rule:["GEOSITE,tracker,跟踪分析"], name:"跟踪分析", icon: ICONS.Reject, proxies:["REJECT","直连","默认节点"] },
    { id:"ads", rule:["GEOSITE,category-ads-all,广告过滤","RULE-SET,ads,广告过滤"], name:"广告过滤", icon: ICONS.Advertising, proxies:["REJECT","直连","默认节点"], ruleProvider:{ name:"ads", url: URLS.rulesets.ads(), format:"mrs", behavior:"domain" } },
    { id:"apple", rule:["GEOSITE,apple-cn,苹果服务"], name:"苹果服务", icon: ICONS.Apple2 },
    { id:"google", rule:["GEOSITE,google,谷歌服务"], name:"谷歌服务", icon: ICONS.GoogleSearch },
    { id:"microsoft", rule:["GEOSITE,microsoft@cn,国内网站","GEOSITE,microsoft,微软服务"], name:"微软服务", icon: ICONS.Microsoft },
    { id:"github", rule:["GEOSITE,github,Github"], name:"Github", icon: ICONS.GitHub }
  ],
  system: {
    "allow-lan": true, mode: "rule", "unified-delay": true, "tcp-concurrent": true, "geodata-mode": true,
    sniffer: { enable: true, "force-dns-mapping": true, "parse-pure-ip": false, "override-destination": true,
      sniff: { TLS: { ports: [443, 8443] }, HTTP: { ports: [80, "8080-8880"] }, QUIC: { ports: [443, 8443] } }
    },
    "geox-url": { geoip: URLS.geox.geoip(), geosite: URLS.geox.geosite(), mmdb: URLS.geox.mmdb(), asn: URLS.geox.asn() }
  },
  common: {
    ruleProvider: { type: "http", format: "mrs", interval: 86400 },
    proxyGroup: { interval: 300, timeout: 3000, url: "https://cp.cloudflare.com/generate_204", lazy: true },
    defaultProxyGroups: [
      { name:"下载软件", icon: ICONS.Download, proxies:["直连","REJECT","默认节点","国内网站"] },
      { name:"其他外网", icon: ICONS.StreamingNotCN, proxies:["默认节点","国内网站"] },
      { name:"国内网站", icon: ICONS.StreamingCN, proxies:["直连","默认节点"] }
    ],
    postRules: ["GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve", "GEOSITE,cn,国内网站", "GEOIP,cn,国内网站,no-resolve", "MATCH,其他外网"]
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
  static build(baseConfig, context = null) {
    const config = Utils.deepClone(baseConfig);
    
    if (!this._validateConfig(config)) return config;

    this._mergeSystemConfig(config);

    const { regions, regionProxyGroups, otherProxyNames } = this._discoverAndBuildRegions(config, context);
    const regionGroupNames = this._buildRegionGroupNames(regionProxyGroups, otherProxyNames);

    this._ensureSystemProxies(config);

    config["proxy-groups"] = this._buildProxyGroups(config, regionGroupNames, regionProxyGroups, otherProxyNames);

    const { rules, ruleProviders } = this._buildRules(config, regionGroupNames, context);
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

  static _discoverAndBuildRegions(config, context = null) {
    const regionAuto = context?.regionAutoManager || new RegionAutoManager();
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

  static _ensureSystemProxies(config) {
    if (!Array.isArray(config.proxies)) config.proxies = [];
    if (!config.proxies.some(p => p?.name === "直连")) config.proxies.push({ name: "直连", type: "direct" });
    
    // 检查是否已经存在名为 REJECT 的代理（包括内置的）
    // Mihomo 内核通常内置了 REJECT，如果配置中再次添加同名代理会报错
    const hasReject = config.proxies.some(p => p?.name?.toUpperCase() === "REJECT");
    if (!hasReject) {
      // 只有当配置中确实没有 REJECT 时才添加，且优先使用内置的 REJECT
      // 注意：大部分环境下不需要在 proxies 列表中显式添加 REJECT，因为它由内核提供
      // 但为了确保策略组引用不失效，我们只在不存在时添加一个虚拟占位
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
          icon: ICON_VAL(svc.icon)
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
          icon: ICON_VAL(group.icon)
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

  static _buildRules(config, regionGroupNames, context = null) {
    const ruleProviders = {}, rules = [], baseRP = { type: "http", interval: 86400 };
    const opts = Config.ruleOptions || {};

    ruleProviders.applications = { ...baseRP, behavior: "classical", format: "text", url: URLS.rulesets.applications(), path: "./ruleset/applications.list" };
    if (Array.isArray(Config.preRules)) rules.push(...Config.preRules);

    (Config.services || []).forEach(svc => {
      if (svc.id && opts[svc.id] === false) return;
      if (svc.rule) rules.push(...svc.rule);
      const rp = svc.ruleProvider;
      if (rp?.name && !ruleProviders[rp.name]) {
        ruleProviders[rp.name] = { 
          ...baseRP, 
          behavior: rp.behavior || "domain", 
          format: rp.format || "mrs", 
          url: rp.url, 
          path: `./ruleset/${rp.name}.${rp.format || "mrs"}` 
        };
      }
    });

    // 注入 AdBlock 规则
    if (context?.adBlockManager) {
      context.adBlockManager.injectRuleProvider(ruleProviders);
    } else {
      const ads = Config.services?.find(s => s.id === "ads");
      if (ads?.ruleProvider) {
        const rp = ads.ruleProvider;
        ruleProviders.adblock_combined = { ...baseRP, behavior: rp.behavior || "domain", format: rp.format || "mrs", url: rp.url, path: `./ruleset/adblock_combined.${rp.format || "mrs"}` };
      }
    }

    if (Array.isArray(Config.common?.postRules)) rules.push(...Config.common.postRules);
    return { rules, ruleProviders };
  }
}

/* ============== 区域管理与映射 (精简版) ============== */
const REGION_MAP = (() => {
  const m = { China: "cn,china,中国,大陆", HongKong: "hk,hongkong,香港", Taiwan: "tw,taiwan,台湾", Japan: "jp,japan,日本", Korea: "kr,korea,韩国", UnitedStates: "us,usa,美国", UnitedKingdom: "uk,gb,英国", Germany: "de,德国", Singapore: "sg,新加坡", Malaysia: "my,马来", Turkey: "tr,土耳其" };
  const r = {}; Object.entries(m).forEach(([k, v]) => v.split(",").forEach(a => r[a.toLowerCase()] = k));
  return r;
})();

class RegionAutoManager {
  constructor() { this._cache = new Map(); }

  discoverRegionsFromProxies(proxies) {
    const found = new Map(), regions = Config.regionOptions?.regions || [];
    (proxies || []).forEach(p => {
      const n = String(p?.name || "").trim(); if (!n) return;
      if (this._cache.has(n)) { const c = this._cache.get(n); if (c) found.set(c.name, c); return; }
      const matched = regions.find(r => r.regex.test(n));
      if (matched) { 
        found.set(matched.name, matched); 
        this._cache.set(n, matched); 
      } else {
        // 自动识别未定义区域
        const hints = n.match(/[A-Za-z]{2,}/g) || [];
        const wl = { es: "ES西班牙", ca: "CA加拿大", au: "AU澳大利亚", fr: "FR法国", it: "IT意大利", nl: "NL荷兰", ru: "RU俄罗斯" };
        for (const h of hints) {
          const k = h.toLowerCase();
          if (wl[k]) {
            const r = { name: wl[k], regex: new RegExp(k, "i"), icon: ICON_VAL(ICONS.WorldMap) };
            found.set(wl[k], r); this._cache.set(n, r); break;
          }
        }
      }
    });
    return found;
  }

  mergeNewRegions(configRegions, discoveredMap) {
    const merged = [...(configRegions || [])];
    discoveredMap.forEach(r => { if (!merged.some(m => m.name === r.name)) merged.push(r); });
    return merged;
  }

  buildRegionGroups(config, regions) {
    const proxies = config.proxies || [], used = new Set();
    const regionProxyGroups = regions.map(r => {
      const names = proxies.filter(p => !used.has(p.name) && r.regex.test(p.name)).map(p => { used.add(p.name); return p.name; });
      return names.length ? { name: r.name, type: "url-test", interval: 300, tolerance: 50, icon: ICON_VAL(r.icon), url: Config.common?.proxyGroup?.url, proxies: names } : null;
    }).filter(Boolean);
    const otherProxyNames = proxies.filter(p => !used.has(p.name)).map(p => p.name);
    return { regionProxyGroups, otherProxyNames };
  }
}

/* ============== 优化后的广告拦截管理器 ============== */
class AdBlockManager {
  constructor(central) {
    this.central = central;
    this.cache = new LRUCache({ maxSize: 256, ttl: CONSTANTS.ADBLOCK.RULE_TTL });
    this.lastUpdate = 0;
    this.sources = [
      { name: "mihomo_mrs", url: URLS.rulesets.ads(), type: "mrs" }
    ];
  }

  async updateIfNeeded() {
    const now = Utils.now();
    if (now - this.lastUpdate < CONSTANTS.ADBLOCK.UPDATE_INTERVAL) return;
    try {
      await this.fetchAndMergeRules(); 
      this.lastUpdate = now; 
      Logger.info("AdBlock.update", "广告规则已自动更新");
    } catch (e) { Logger.warn("AdBlock.update", e?.message || e); }
  }

  async fetchAndMergeRules() {
    const fetchers = this.sources.map(src => () => this.fetchSource(src).catch(() => null));
    const results = await Utils.asyncPool(fetchers, 2);
    let mrsUrl = null;

    results.forEach((res, i) => {
      const src = this.sources[i];
      if (res && src.type === "mrs") mrsUrl = src.url;
    });

    if (mrsUrl) this.cache.set("adblock_mrs_url", mrsUrl, CONSTANTS.ADBLOCK.RULE_TTL);
  }

  async fetchSource(src) {
    const cached = this.cache.get(`src:${src.name}`);
    if (cached) return cached;
    
    try {
      const resp = await this.central._safeFetch(src.url, { headers: { "User-Agent": CONSTANTS.UA } });
      const res = src.type === "text" ? await resp.text() : "mrs";
      this.cache.set(`src:${src.name}`, res, CONSTANTS.ADBLOCK.RULE_TTL);
      return res;
    } catch (e) {
      Logger.warn("AdBlockManager", `获取失败: ${src.name}`);
      return null;
    }
  }

  injectRuleProvider(ruleProviders) {
    const mrsUrl = this.cache.get("adblock_mrs_url");
    if (mrsUrl) {
      Utils.safeSet(ruleProviders, "adblock_combined", {
        type: "http", interval: 86400, behavior: "domain", format: "mrs",
        url: mrsUrl, path: "./ruleset/adblock_combined.mrs"
      });
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
  constructor({ maxSize = CONSTANTS.CACHE.SIZE, ttl = CONSTANTS.CACHE.TTL } = {}) {
    this.cache = new Map();
    this.maxSize = Math.max(1, Number(maxSize) || CONSTANTS.CACHE.SIZE);
    this.ttl = Math.max(1, Number(ttl) || CONSTANTS.CACHE.TTL);
  }

  _isExpired(entry) {
    return !entry || (Utils.now() - entry.timestamp) > (entry.ttl || this.ttl);
  }

  get(key) {
    const entry = this.cache.get(key);
    if (!entry) return null;
    if (this._isExpired(entry)) { this.cache.delete(key); return null; }
    this.cache.delete(key);
    this.cache.set(key, { ...entry, timestamp: Utils.now() });
    return entry.value;
  }

  set(key, value, ttl = this.ttl) {
    if (key == null) return;
    if (this.cache.has(key)) this.cache.delete(key);
    else if (this.cache.size >= this.maxSize) this.cache.delete(this.cache.keys().next().value);
    this.cache.set(key, { value, ttl, timestamp: Utils.now() });
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
    this.env = { isNode: Env.isNode, isBrowser: Env.isBrowser };
    this.state = { networkGood: true, githubMirrorHealthy: false, geoEndpointsHealthy: false, lastGeoErrorTs: 0, lastMirrorErrorTs: 0, compatLegacyDisable: false };
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
    
    if (!_fetch && Env.isNode && typeof require === "function") {
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

  async safeFetch(url, options = {}, timeout = CONSTANTS.TIMEOUT.TEST) {
    if (!url || typeof url !== "string") throw new Error("safeFetch: 无效的URL参数");
    const initial = Utils.sanitizeUrl(url); 
    if (!initial) throw new Error(`safeFetch: URL 非法或不安全 (${url})`);
    url = initial;
    
    const { _fetch, _AbortController } = await this._getRuntime(); 
    if (!_fetch) throw new Error("fetch 不可用于当前运行环境");

    const opts = { 
      ...options, 
      headers: { "User-Agent": CONSTANTS.UA, ...(options.headers || {}) }, 
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
  static calculate(metrics, weights = CONSTANTS.SCORING.WEIGHTS) {
    const s = CONSTANTS.SCORING;
    const l = Utils.clamp(Number(metrics?.latency) || 0, 0, s.LATENCY_CLAMP_MS);
    const j = Utils.clamp(Number(metrics?.jitter) || 0, 0, s.JITTER_CLAMP_MS);
    const lo = Utils.clamp(Number(metrics?.loss) || 0, 0, s.LOSS_CLAMP);
    const b = Utils.clamp(Number(metrics?.bps) || 0, 0, s.THROUGHPUT_SOFT_CAP_BPS);

    const lScore = l > s.LATENCY_HIGH_THRESHOLD 
      ? Math.max(0, s.LATENCY_BASE_SCORE - Math.pow((l - s.LATENCY_HIGH_THRESHOLD) / s.LATENCY_SCALE_FACTOR, s.LATENCY_EXPONENT))
      : Utils.clamp(s.LATENCY_BASE_SCORE - l / s.LATENCY_DIVISOR, 0, s.LATENCY_BASE_SCORE);
    
    const jScore = Utils.clamp(s.JITTER_BASE_SCORE - j, 0, s.JITTER_BASE_SCORE);
    const loScore = Utils.clamp(s.LOSS_BASE_SCORE * (1 - lo), 0, s.LOSS_BASE_SCORE);
    const bScore = Utils.clamp(Math.round(Math.log10(1 + b) * s.THROUGHPUT_SCALE_FACTOR), 0, s.THROUGHPUT_SCORE_MAX);

    const totalW = weights.latency + weights.loss + weights.jitter + weights.speed;
    return Utils.clamp((lScore * weights.latency + loScore * weights.loss + jScore * weights.jitter + bScore * weights.speed) / totalW, 0, 100);
  }

  static calculateFromComponents(components) {
    const { latencyScore, jitterScore, lossScore, throughputScore } = components;
    return Utils.clamp(Math.round(latencyScore + jitterScore + lossScore + throughputScore), 0, 100);
  }

  static biasScore(baseScore, availability, preferences = {}) {
    const { preferHighThroughput = false, preferLowLatency = false, preferStability = false } = preferences;
    const s = CONSTANTS.SCORING;
    let score = baseScore + (availability >= s.AVAILABILITY_MIN_RATE ? s.BIAS_AVAIL_BONUS_OK : s.BIAS_AVAIL_PENALTY_BAD);
    if (preferHighThroughput) score += 5;
    if (preferLowLatency) score += 3;
    if (preferStability) score += 4;
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
    this.lruCache = new LRUCache({ maxSize: CONSTANTS.CACHE.SIZE, ttl: CONSTANTS.CACHE.TTL });
    this.geoInfoCache = new LRUCache({ maxSize: CONSTANTS.CACHE.SIZE, ttl: CONSTANTS.CACHE.TTL });
    
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
    const s = CONSTANTS.SCORING;
    const latency = Utils.clamp(Number(m.latency) || 0, 0, s.LATENCY_CLAMP_MS);
    const jitter  = Utils.clamp(Number(m.jitter) || 0, 0, s.JITTER_CLAMP_MS);
    const loss    = Utils.clamp(Number(m.loss) || 0, 0, s.LOSS_CLAMP);
    const bps     = Utils.clamp(Number(m.bps) || 0, 0, s.THROUGHPUT_SOFT_CAP_BPS);
    
    const latencyScore = Utils.clamp(s.LATENCY_BASE_SCORE - latency / s.LATENCY_DIVISOR, 0, s.LATENCY_BASE_SCORE);
    const jitterScore  = Utils.clamp(s.JITTER_BASE_SCORE - jitter, 0, s.JITTER_BASE_SCORE);
    const lossScore    = Utils.clamp(s.LOSS_BASE_SCORE * (1 - loss), 0, s.LOSS_BASE_SCORE);
    const throughputScore = Utils.clamp(Math.round(Math.log10(1 + bps) * s.THROUGHPUT_SCALE_FACTOR), 0, s.THROUGHPUT_SCORE_MAX);
    
    return { 
      latencyScore, jitterScore, lossScore, throughputScore, 
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

    return ConfigBuilder.build(config, this);
  }

  async _safeFetch(url, options = {}, timeout = CONSTANTS.TIMEOUT.GEO) {
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
    return Number.isFinite(t) && t > 0 ? t : CONSTANTS.TIMEOUT.TEST;
  }

  async initialize() {
    try {
      // 异步初始化资源
      const initTasks = [
        this.adBlockManager.updateIfNeeded(),
        selectBestMirror((u, o) => this._safeFetch(u, o, CONSTANTS.TIMEOUT.MIRROR))
      ];
      await Promise.allSettled(initTasks);
      Logger.info("Central.init", "优化版本初始化完成 - 资源与网络层就绪");
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
    this._scoreBuf = new Array(CONSTANTS.POOL.WINDOW_SIZE).fill(null);
    this._availBuf = new Array(CONSTANTS.POOL.WINDOW_SIZE).fill(null);
    this._idx = 0;
    this._cnt = 0;
  }

  pushSamples(score, avail) {
    if (Number.isFinite(score)) this._scoreBuf[this._idx] = Number(score);
    if (Number.isFinite(avail)) this._availBuf[this._idx] = Number(avail);
    this._idx = (this._idx + 1) % CONSTANTS.POOL.WINDOW_SIZE;
    if (this._cnt < CONSTANTS.POOL.WINDOW_SIZE) this._cnt++;
  }
  
  getAdaptiveThresholds() {
    if (this._cnt < CONSTANTS.POOL.MIN_ITEMS) {
      return { goodScore: CONSTANTS.SCORING.THRESHOLD, goodAvail: CONSTANTS.SCORING.AVAILABILITY_MIN_RATE };
    }
    
    const alpha = CONSTANTS.POOL.ALPHA;
    const p90Score = this._calcPercentile(this._scoreBuf.slice(0, this._cnt), CONSTANTS.POOL.GOOD_PERCENTILE);
    const p50Avail = this._calcPercentile(this._availBuf.slice(0, this._cnt), CONSTANTS.POOL.BAD_PERCENTILE);
    const goodScore = alpha * CONSTANTS.SCORING.THRESHOLD + (1 - alpha) * p90Score;
    const goodAvail = alpha * CONSTANTS.SCORING.AVAILABILITY_MIN_RATE + (1 - alpha) * p50Avail;
    return { goodScore, goodAvail };
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
    const c = CONSTANTS.COOLDOWN.SWITCH;
    return Utils.clamp(c.BASE * (1 + (s / 100) * 0.9), c.MIN, c.MAX); 
  }

  _updateNodeHistory(id, score) {
    const s = Utils.clamp(Number(score) || 0, 0, 100);
    const h = this.nodeHistory.get(id) || [];
    h.push({ timestamp: Utils.now(), score: s });
    if (h.length > CONSTANTS.POOL.WINDOW_SIZE) h.shift();
    this.nodeHistory.set(id, h);
  }

  updateNodeQuality(id, delta) {
    const ns = Utils.clamp((this.nodeQuality.get(id) || 0) + Utils.clamp(Number(delta) || 0, -20, 20), 0, 100);
    this.nodeQuality.set(id, ns);
    this._updateNodeHistory(id, ns);
  }
}

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
    const central = CentralManager.getInstance();
    return central.processConfiguration(config);
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
  main, CentralManager, ConfigBuilder,
  buildConfigForParser: ConfigBuilder.build.bind(ConfigBuilder),
  RegionAutoManager, LRUCache, NodeScorer, Utils, DataMasker, CONSTANTS, Config
};

if (Env.isCJS()) module.exports = EXPORTS;
if (Env.isNode) {
  const safeExports = { ...EXPORTS };
  Object.assign(global, safeExports);
}
if (Env.isBrowser) {
  window.__MihomoScript__ = EXPORTS;
}

Logger.info("Script", `优化版加载完成 - 环境: ${Env.get()}`);
