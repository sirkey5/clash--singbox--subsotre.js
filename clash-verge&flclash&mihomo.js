"use strict";

/**
 * Central Orchestrator - 精简增强版（优化版）
 * - 安全强化：严格 data URL 白名单与大小限制、逐跳重定向审计、SSRF 与私网阻断
 * - 结构优化：统一常量与权重来源、日志上下文标签、区域同义映射提升匹配鲁棒性
 * - 性能提升：并发池调度微调、模拟数据稳定化、LRU 清理防抖、区域候选加速过滤
 * 保留 API：main, CentralManager, NodeManager, Config
 * 兼容范围：Node.js >= 14（推荐 16+）、现代浏览器（支持 fetch/AbortController）
 */

const PLATFORM = (() => {
  // 运行环境能力检测（Node/Browser）
  const isNode = typeof process !== "undefined" && !!process.versions?.node;
  const isBrowser = typeof window !== "undefined" && typeof window.addEventListener === "function";
  return Object.freeze({ isNode, isBrowser });
})();

/** 统一常量集中管理（消除魔法值，便于全局调参与审计） */
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

  EARLY_SAMPLE_SCORE: 2,

  POOL_WINDOW_SIZE: 100,
  GOOD_PERCENTILE: 90,
  BAD_PERCENTILE: 50,
  ADAPT_ALPHA: 0.5,
  MIN_POOL_ITEMS_FOR_ADAPT: 10,

  // 安全补充：data URL 白名单与大小限制（防滥用）
  DATA_URL_MAX_BYTES: 2 * 1024 * 1024, // 2MB 上限
  DATA_URL_PREFIX: "data:text/plain;base64,"
});

/** 统一日志，增加上下文标签与结构化信息输出（提升可观测性） */
const Logger = {
  error: (ctx, ...a) => console.error("[ERROR]", ctx || "-", ...a),
  info:  (ctx, ...a) => console.info("[INFO]", ctx || "-", ...a),
  warn:  (ctx, ...a) => console.warn("[WARN]", ctx || "-", ...a),
  debug: (ctx, ...a) => { if (CONSTANTS.ENABLE_SCORE_DEBUGGING) console.debug("[DEBUG]", ctx || "-", ...a); }
};

class ConfigurationError extends Error { constructor(m) { super(m); this.name = "ConfigurationError"; } }
class InvalidRequestError extends Error { constructor(m) { super(m); this.name = "InvalidRequestError"; } }

/* ============== 通用工具与封装（安全/性能/复用） ============== */
const Utils = {
  now: () => Date.now(),
  clamp: (v, min, max) => Math.max(min, Math.min(max, v)),
  clamp01: (v) => Math.max(0, Math.min(1, v)),
  isFunc: (f) => typeof f === "function",
  toUnique: (arr) => Array.from(new Set(arr || [])).filter(Boolean),
  safeSet(map, k, v) { try { map.set(k, v); } catch (e) { Logger.debug("Utils.safeSet", e?.message || e); } },
  sleep(ms = 0) { return new Promise(r => setTimeout(r, Math.max(0, ms | 0))); },

  /** 指数退避重试，失败时保留最后错误上下文 */
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

  /**
   * 并发池执行：
   * - 失败任务后移（轻量），优先完成成功任务；避免失败阻塞吞吐
   */
  async asyncPool(tasks, limit = CONSTANTS.CONCURRENCY_LIMIT) {
    const list = Array.isArray(tasks) ? tasks.filter(Utils.isFunc) : [];
    if (!list.length) return [];
    const n = Math.max(1, Math.min(50, Math.floor(limit) || 3));
    const res = new Array(list.length);
    let idx = 0;

    async function runner() {
      while (true) {
        const cur = idx++; if (cur >= list.length) return;
        try {
          const v = list[cur](); res[cur] = (v && typeof v.then === "function") ? await v : v;
        } catch (e) {
          // 失败任务后移：简单记录错误，并不重排数组（保持次序可预测）
          res[cur] = { __error: e?.message || "任务执行失败" };
        }
      }
    }
    await Promise.all(Array(Math.min(n, list.length)).fill(0).map(runner));
    return res;
  },

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
    if (ip === "localhost") return true;
    if (!Utils.isIPv4(ip)) return false;
    return ip === "127.0.0.1" || ip === "0.0.0.0";
  },
  isPrivateIP(ip) {
    if (!Utils.isIPv4(ip)) return false;
    try {
      const [a, b] = ip.split(".").map(n => parseInt(n, 10));
      return a === 10 || a === 127 || (a === 192 && b === 168) || (a === 172 && b >= 16 && b <= 31);
    } catch { return false; }
  },

  /**
   * URL 安全化：
   * - 支持 http/https
   * - 禁止访问私网/回环
   * - http 自动升级 https（端口同步）
   * - 限制 data URL（仅 text/plain/base64，大小≤2MB）
   */
  sanitizeUrl(u) {
    if (typeof u !== "string" || !u) return null;

    // 安全放行 data URL：严格类型与大小限制
    if (u.startsWith(CONSTANTS.DATA_URL_PREFIX)) {
      const b64 = u.slice(CONSTANTS.DATA_URL_PREFIX.length);
      // 简单大小估算：Base64 每 4 字节代表 3 原字节
      const estBytes = Math.floor(b64.length * 0.75);
      if (estBytes <= CONSTANTS.DATA_URL_MAX_BYTES) return u;
      return null;
    }

    try {
      const url = new URL(u);
      const scheme = url.protocol.replace(":", "").toLowerCase();
      if (!["http", "https"].includes(scheme)) return null;
      url.username = ""; url.password = "";

      const port = url.port ? parseInt(url.port, 10) : (scheme === "https" ? 443 : 80);
      if (!CONSTANTS.SAFE_PORTS.has(port)) return null;

      const host = url.hostname;
      if (Utils.isLoopbackOrLocal(host)) return null;
      if (Utils.isIPv4(host) && Utils.isPrivateIP(host)) return null;

      if (scheme === "http" && !Utils.isPrivateIP(host) && !Utils.isLoopbackOrLocal(host)) {
        url.protocol = "https:"; if (!url.port || url.port === "80") url.port = "443";
      }
      return url.toString();
    } catch { return null; }
  },

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

  getProxyGroupBase() { return (Config.common?.proxyGroup || {}); },
  getRuleProviderBase() { return (Config.common?.ruleProvider || { type: "http", format: "yaml", interval: 86400 }); },

  safeInt(hdrValue, def = 0) {
    try { const n = parseInt(hdrValue ?? "0", 10); return Number.isFinite(n) ? n : def; } catch { return def; }
  },

  /** 深拷贝（兼容老环境） */
  deepClone(obj) {
    if (obj === null || typeof obj !== "object") return obj;
    if (obj instanceof RegExp) return new RegExp(obj);
    if (obj instanceof Date) return new Date(obj);
    if (Array.isArray(obj)) return obj.map(Utils.deepClone);
    const cloned = {};
    for (const key in obj) if (Object.prototype.hasOwnProperty.call(obj, key)) cloned[key] = Utils.deepClone(obj[key]);
    return cloned;
  },

  /** 文本转 data URL（用于内嵌规则） */
  toDataUrl(text) {
    try {
      // Node 环境处理
      // eslint-disable-next-line no-undef
      const b64 = Buffer.from(text).toString("base64");
      const estBytes = Math.floor(b64.length * 0.75);
      if (estBytes > CONSTANTS.DATA_URL_MAX_BYTES) throw new Error("data-url 超出大小限制");
      return `${CONSTANTS.DATA_URL_PREFIX}${b64}`;
    } catch {
      // 浏览器回退
      const base64 = typeof btoa === "function" ? btoa(unescape(encodeURIComponent(text))) : "";
      const estBytes = Math.floor(base64.length * 0.75);
      if (estBytes > CONSTANTS.DATA_URL_MAX_BYTES) throw new Error("data-url 超出大小限制");
      return `${CONSTANTS.DATA_URL_PREFIX}${base64}`;
    }
  }
};

/* ============== GitHub 镜像（默认禁用、结果缓存） ============== */
const GH_MIRRORS = ["", "https://mirror.ghproxy.com/", "https://github.moeyy.xyz/", "https://ghproxy.com/"];
const GH_TEST_TARGETS = ["https://raw.githubusercontent.com/github/gitignore/main/Node.gitignore","https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/main/README.md","https://raw.githubusercontent.com/cli/cli/trunk/README.md"];

let GH_PROXY_PREFIX = "";
let __ghSelected = "";
let __ghLastProbeTs = 0;
const __GH_PROBE_TTL = 10 * 60 * 1000;
let __ghSelecting = false;
const __waiters = [];

const GH_RAW_URL = (path) => `${GH_PROXY_PREFIX}https://raw.githubusercontent.com/${path}`;
const GH_RELEASE_URL = (path) => `${GH_PROXY_PREFIX}https://github.com/${path}`;
const pickTestTarget = () => GH_TEST_TARGETS[Math.floor(Math.random() * GH_TEST_TARGETS.length)];

/** 单镜像探测（逐跳重定向受控、超时受控） */
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

/** 并行选择最佳镜像（失败兜底，保证唤醒所有等待者） */
async function selectBestMirror(runtimeFetch) {
  const now = Utils.now();
  if (__ghSelected && (now - __ghLastProbeTs) < __GH_PROBE_TTL) return __ghSelected;
  if (__ghSelecting) return new Promise((resolve) => __waiters.push(resolve));
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
    Logger.warn("GH.selectBestMirror", e?.message || e);
    return __ghSelected || "";
  } finally {
    __ghSelecting = false;
    while (__waiters.length) { const fn = __waiters.shift(); try { fn(__ghSelected || ""); } catch {} }
  }
}

/* ============== 资源与规则 URL（保持原有来源） ============== */
const ICONS = (() => { const b="Koolson/Qure/master/IconSet/Color", mk=n=>GH_RAW_URL(`${b}/${n}.png`), m={Proxy:"Proxy",WorldMap:"World_Map",HongKong:"Hong_Kong",UnitedStates:"United_States",Japan:"Japan",Korea:"Korea",Singapore:"Singapore",ChinaMap:"China_Map",China:"China",UnitedKingdom:"United_Kingdom",Germany:"Germany",Malaysia:"Malaysia",Turkey:"Turkey",ChatGPT:"ChatGPT",YouTube:"YouTube",Bilibili3:"bilibili_3",Bahamut:"Bahamut",DisneyPlus:"Disney+",Netflix:"Netflix",TikTok:"TikTok",Spotify:"Spotify",Pixiv:"Pixiv",HBO:"HBO",TVB:"TVB",PrimeVideo:"Prime_Video",Hulu:"Hulu",Telegram:"Telegram",Line:"Line",Game:"Game",Reject:"Reject",Advertising:"Advertising",Apple2:"Apple_2",GoogleSearch:"Google_Search",Microsoft:"Microsoft",GitHub:"GitHub",JP:"JP",Download:"Download",StreamingCN:"StreamingCN",StreamingNotCN:"Streaming!CN"}; const o={}; for(const k in m) o[k]=()=>mk(m[k]); return o; })();
const ICON_VAL = (fn) => { try { return Utils.isFunc(fn) ? fn() : fn; } catch { return ""; } };

const URLS = (() => { const rulesets={applications:()=>GH_RAW_URL("DustinWin/ruleset_geodata/clash-ruleset/applications.list"),ai:()=>GH_RAW_URL("dahaha-365/YaNet/dist/rulesets/mihomo/ai.list"),adblock_mihomo_mrs:()=>GH_RAW_URL("217heidai/adblockfilters/main/rules/adblockmihomo.mrs"),category_bank_jp_mrs:()=>GH_RAW_URL("MetaCubeX/meta-rules-dat/meta/geo/geosite/category-bank-jp.mrs"),adblock_easylist:()=>"https://easylist.to/easylist/easylist.txt",adblock_easyprivacy:()=>"https://easylist.to/easylist/easyprivacy.txt",adblock_ublock_filters:()=>"https://raw.githubusercontent.com/uBlockOrigin/uAssets/master/filters/filters.txt"}; const rel=f=>GH_RELEASE_URL(`MetaCubeX/meta-rules-dat/releases/download/latest/${f}`); const geox={geoip:()=>rel("geoip-lite.dat"),geosite:()=>rel("geosite.dat"),mmdb:()=>rel("country-lite.mmdb"),asn:()=>rel("GeoLite2-ASN.mmdb")}; return {rulesets,geox}; })();

/* ============== 基础配置（隐私默认保守） ============== */
const Config = {
  enable: true,
  privacy: {
    geoExternalLookup: false,
    systemDnsOnly: false,
    trustedGeoEndpoints: [],
    githubMirrorEnabled: false
  },
  ruleOptions: (() => { const ks=["apple","microsoft","github","google","openai","spotify","youtube","bahamut","netflix","tiktok","disney","pixiv","hbo","biliintl","tvb","hulu","primevideo","telegram","line","whatsapp","games","japan","tracker","ads"]; const o={}; ks.forEach(k=>o[k]=true); return o; })(),
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
  ] },
  dns: {
    enable: true, listen: ":1053", ipv6: true, "prefer-h3": true, "use-hosts": true, "use-system-hosts": true,
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
  on(ev, fn) { if (!ev || !Utils.isFunc(fn)) return; const arr = this.eventListeners.get(ev) || []; arr.push(fn); this.eventListeners.set(ev, arr); }
  off(ev, fn) { const arr = this.eventListeners.get(ev); if (!arr) return; const i = arr.indexOf(fn); if (i !== -1) arr.splice(i, 1); if (!arr.length) this.eventListeners.delete(ev); }
  emit(ev, ...args) { const arr = this.eventListeners.get(ev); if (!arr?.length) return; for (const fn of arr.slice()) { try { fn(...args); } catch (e) { Logger.error("Event.emit", e.stack || e); } } }
  removeAllListeners(ev) { if (ev) this.eventListeners.delete(ev); else this.eventListeners.clear(); }
}

/* ============== 状态与缓存 ============== */
class AppState {
  constructor() { this.nodes = new Map(); this.metrics = new Map(); this.config = {}; this.lastUpdated = Utils.now(); }
  updateNodeStatus(nodeId, status) { if (!nodeId || typeof nodeId !== "string") return; this.nodes.set(nodeId, { ...(this.nodes.get(nodeId) || {}), ...status }); this.lastUpdated = Utils.now(); }
}

/** LRU 缓存（防抖清理、TTL 驱逐） */
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
    // 防抖清理：至少 500ms 间隔、比例阈值触发
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

/* ============== 统计与成功率 ============== */
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

/* ============== 区域自动分组（同义映射增强） ============== */
const REGION_SYNONYMS = {
  China: ["China", "CN", "Mainland"],
  "Hong Kong": ["Hong Kong", "HK"],
  Taiwan: ["Taiwan", "TW"],
  Japan: ["Japan", "JP"],
  Korea: ["Korea", "KR"],
  "United States": ["United States", "US", "USA", "America"],
  "United Kingdom": ["United Kingdom", "UK", "Britain", "Great Britain"],
  Germany: ["Germany", "DE"],
  France: ["France", "FR"],
  Canada: ["Canada", "CA"],
  Australia: ["Australia", "AU"]
};

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
    for (const p of proxies) {
      const name = this._normalizeName(p?.name); if (!name) continue;
      for (const e of this.knownRegexMap) if (e.regex.test(name)) found.set(e.name, { name: e.name, regex: e.regex, icon: e.icon });
      const hints = name.match(/[A-Za-z]{2,}|[\u4e00-\u9fa5]{2,}/g);
      if (hints?.length) {
        const wl = { es: "ES西班牙", ca: "CA加拿大", au: "AU澳大利亚", fr: "FR法国", it: "IT意大利", nl: "NL荷兰", ru: "RU俄罗斯", in: "IN印度", br: "BR巴西", ar: "AR阿根廷" };
        for (const h of hints) {
          const k = h.toLowerCase();
          if (wl[k]) {
            const cn = wl[k].replace(/[A-Z]{2}/, '').replace(/[^\u4e00-\u9fa5]/g, '');
            const regex = new RegExp(`${k}|${cn}`, 'i');
            found.set(wl[k], { name: wl[k], regex, icon: ICON_VAL(ICONS.WorldMap) });
          }
        }
      }
    }
    return found;
  }

  mergeNewRegions(configRegions, discoveredMap) {
    const merged = Array.isArray(configRegions) ? [...configRegions] : [];
    for (const r of discoveredMap.values()) if (!this._hasRegion(merged, r.name)) merged.push({ name: r.name, regex: r.regex, icon: r.icon || ICON_VAL(ICONS.WorldMap) });
    return merged;
  }

  buildRegionGroups(config, regions) {
    const regionProxyGroups = [];
    let otherNames = (config.proxies || []).filter(p => typeof p?.name === "string").map(p => p.name);
    for (const region of regions) {
      const names = Utils.filterProxiesByRegion(config.proxies || [], region);
      if (names.length) {
        regionProxyGroups.push({ ...Utils.getProxyGroupBase(), name: region.name || "Unknown", type: "url-test", tolerance: 50, icon: region.icon || ICON_VAL(ICONS.WorldMap), proxies: names });
        otherNames = otherNames.filter(n => !names.includes(n));
      }
    }
    return { regionProxyGroups, otherProxyNames: Utils.toUnique(otherNames) };
  }
}

/* ============== 广告拦截管理器 ============== */
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
      await this.fetchAndMergeRules(); this.lastUpdate = now; Logger.info("AdBlock.update", "广告规则已自动更新与合并");
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

    const domainSet = new Set();
    texts.forEach(t => {
      t.split("\n").forEach(line => {
        line = line.trim();
        // 过滤注释/例外/段头
        if (!line || line.startsWith("!") || line.startsWith("#") || line.startsWith("[") || line.startsWith("@@")) return;
        // 提取域名（支持多格式）
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
    const cached = this.cache.get(`src:${src.name}`); if (cached) return cached;
    const resp = await this.central._safeFetch(src.url, { headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT } }, this.central._nodeTimeout());
    const text = (src.type === "text") ? await resp.text() : "mrs";
    this.cache.set(`src:${src.name}`, text, CONSTANTS.ADBLOCK_RULE_TTL_MS);
    return text;
  }

  injectRuleProvider(ruleProviders) {
    const mrsUrl = this.cache.get("adblock_mrs_url");
    const list = this.cache.get("adblock_combined_list") || [];
    if (mrsUrl) {
      Utils.safeSet(ruleProviders, "adblock_combined", {
        ...Utils.getRuleProviderBase(),
        behavior: "domain", format: "mrs", url: mrsUrl, path: "./ruleset/adblock_combined.mrs", interval: 43200
      });
      return;
    }
    // 使用安全 data URL 注入（受大小限制）
    const dataUrl = Utils.toDataUrl(list.join("\n"));
    Utils.safeSet(ruleProviders, "adblock_combined", {
      type: "http", behavior: "domain", format: "text", url: dataUrl, path: "./ruleset/adblock_combined.list", interval: 43200
    });
  }
}

/* ============== 优劣节点池（自适应阈值） ============== */
class NodePools {
  constructor() { this.good = new Set(); this.bad = new Set(); }
  recentScores = []; recentAvail = [];
  _lastSnapshot = { good: [], bad: [] };

  pushSamples(score, avail) {
    if (Number.isFinite(score)) { this.recentScores.push(Number(score)); if (this.recentScores.length > CONSTANTS.POOL_WINDOW_SIZE) this.recentScores.shift(); }
    if (Number.isFinite(avail)) { this.recentAvail.push(Number(avail)); if (this.recentAvail.length > CONSTANTS.POOL_WINDOW_SIZE) this.recentAvail.shift(); }
  }
  getAdaptiveThresholds() {
    const enough = (this.recentScores.length >= CONSTANTS.MIN_POOL_ITEMS_FOR_ADAPT) && (this.recentAvail.length >= CONSTANTS.MIN_POOL_ITEMS_FOR_ADAPT);
    const alpha = CONSTANTS.ADAPT_ALPHA;
    if (!enough) return { goodScore: CONSTANTS.QUALITY_SCORE_THRESHOLD, goodAvail: CONSTANTS.AVAILABILITY_MIN_RATE };
    const p90Score = Utils.calculatePercentile(this.recentScores, CONSTANTS.GOOD_PERCENTILE);
    const p50Avail = Utils.calculatePercentile(this.recentAvail, CONSTANTS.BAD_PERCENTILE);
    const goodScore = alpha * CONSTANTS.QUALITY_SCORE_THRESHOLD + (1 - alpha) * p90Score;
    const goodAvail = alpha * CONSTANTS.AVAILABILITY_MIN_RATE + (1 - alpha) * p50Avail;
    return { goodScore: Utils.clamp(goodScore, 0, 100), goodAvail: Utils.clamp(goodAvail, 0, 1) };
  }
  classify(id, score, avail) {
    if (!id) return;
    this.pushSamples(Number(score), Number(avail));
    const thr = this.getAdaptiveThresholds();
    const isGood = (Number(score) >= thr.goodScore) && (Number(avail) >= thr.goodAvail);
    if (isGood) { this.good.add(id); this.bad.delete(id); } else { this.bad.add(id); this.good.delete(id); }
  }
  clear() { this.good.clear(); this.bad.clear(); this.recentScores = []; this.recentAvail = []; }
  snapshot() { this._lastSnapshot = { good: Array.from(this.good), bad: Array.from(this.bad) }; return this._lastSnapshot; }
  namesFromIds(proxies, ids) {
    if (!Array.isArray(proxies) || !Array.isArray(ids) || !ids.length) return [];
    const map = new Map(proxies.filter(p => p?.id && p?.name).map(p => [p.id, p.name]));
    const out = []; for (const id of ids) { const name = map.get(id); if (name) out.push(name); }
    return out;
  }
}

/* ============== 中央管理器（主控制器） ============== */
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
    this.adBlockManager = new AdBlockManager(this); this.nodePools = new NodePools();
    this._regionPreferredCache = new Map();
    this._dispatchCacheEnabled = true;
    this.runtimeSwitches = {
      smartConfigEnabled: !!(Config && Config.enable !== false),
      geoExternalLookup: null,
      systemDnsOnly: null,
      githubMirror: null,
      preheatEnabled: Config?.tuning?.preheatEnabled !== false,
      dispatchCacheEnabled: true,
      lastAdjustTs: 0
    };
    this._switchTimerId = null;
    this._boundSystemListeners = null; this._listenersRegistered = false; CentralManager.instance = this;
    Promise.resolve().then(() => this.initialize().catch(err => Logger.error("Central.init", err?.stack || err)));
  }

  /** 指标分解与度量分（统一权重来源） */
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
    if (__runtimeCache.fetch && __runtimeCache.AbortController !== undefined) return { _fetch: __runtimeCache.fetch, _AbortController: __runtimeCache.AbortController };
    let _fetch = (typeof fetch === "function") ? fetch : null;
    let _AbortController = (typeof AbortController !== "undefined") ? AbortController : null;
    if (!_fetch && PLATFORM.isNode) {
      try { const nf = require("node-fetch"); _fetch = nf.default || nf; } catch {}
      if (!_AbortController) { try { const AC = require("abort-controller"); _AbortController = AC.default || AC; } catch { if (typeof AbortController !== "undefined") _AbortController = AbortController; } }
    }
    __runtimeCache.fetch = _fetch; __runtimeCache.AbortController = _AbortController;
    return { _fetch, _AbortController };
  }

  _autoAdjustSwitches(trigger) {
    try {
      const now = Utils.now();
      const rs = this.runtimeSwitches || (this.runtimeSwitches = {
        smartConfigEnabled: !!(Config && Config.enable !== false),
        geoExternalLookup: null,
        systemDnsOnly: null,
        githubMirror: null,
        preheatEnabled: Config?.tuning?.preheatEnabled !== false,
        dispatchCacheEnabled: true,
        lastAdjustTs: 0
      });
      if (rs.lastAdjustTs && (now - rs.lastAdjustTs) < CONSTANTS.MIN_SWITCH_COOLDOWN) return;
      rs.lastAdjustTs = now;

      const successRate = Number(this.successTracker?.rate || 0);
      const avgLatency = Number(this.stats?.average || 0);
      const highLatency = avgLatency > CONSTANTS.LATENCY_CLAMP_MS * 1.5;
      const badSuccess = successRate > 0 && successRate < CONSTANTS.AVAILABILITY_MIN_RATE;
      const hasTrustedGeo = Array.isArray(Config?.privacy?.trustedGeoEndpoints) && Config.privacy.trustedGeoEndpoints.length > 0;

      if (hasTrustedGeo && !badSuccess && !highLatency) rs.geoExternalLookup = true;
      else rs.geoExternalLookup = false;

      if (Config?.privacy?.systemDnsOnly === true && badSuccess && highLatency) rs.systemDnsOnly = false;
      else rs.systemDnsOnly = Config?.privacy?.systemDnsOnly === true;

      if (Config?.privacy?.githubMirrorEnabled) rs.githubMirror = !highLatency;
      else rs.githubMirror = false;

      if (trigger === "networkOnline" || trigger === "init") rs.preheatEnabled = Config?.tuning?.preheatEnabled !== false;
      rs.dispatchCacheEnabled = !(badSuccess && highLatency);
      rs.smartConfigEnabled = !!(Config && Config.enable !== false);
      this.runtimeSwitches = rs;
    } catch (e) { Logger.debug("Central.autoSwitch", e?.message || e); }
  }

  isSmartConfigEnabled() {
    const v = this.runtimeSwitches?.smartConfigEnabled;
    if (typeof v === "boolean") return v;
    return !!(Config && Config.enable !== false);
  }
  isDispatchCacheEnabled() {
    const v = this.runtimeSwitches?.dispatchCacheEnabled;
    if (typeof v === "boolean") return v;
    return this._dispatchCacheEnabled !== false;
  }
  isPreheatEnabled() {
    const v = this.runtimeSwitches?.preheatEnabled;
    if (typeof v === "boolean") return v;
    return Config?.tuning?.preheatEnabled !== false;
  }
  isGithubMirrorEnabled() {
    const v = this.runtimeSwitches?.githubMirror;
    if (typeof v === "boolean") return v;
    return !!(Config?.privacy?.githubMirrorEnabled);
  }
  isSystemDnsOnly() {
    const v = this.runtimeSwitches?.systemDnsOnly;
    if (typeof v === "boolean") return v;
    return !!(Config?.privacy?.systemDnsOnly);
  }
  isGeoExternalLookupEnabled() {
    const v = this.runtimeSwitches?.geoExternalLookup;
    if (typeof v === "boolean") return v;
    return !!(Config?.privacy && Config.privacy.geoExternalLookup === true);
  }

  _nodeTimeout() { const t = Config?.tuning?.nodeTestTimeoutMs; return Number.isFinite(t) && t > 0 ? t : CONSTANTS.NODE_TEST_TIMEOUT; }
  _nodeAttempts() { const a = Config?.tuning?.nodeTestMaxAttempts; return Number.isFinite(a) && a > 0 ? a : CONSTANTS.MAX_RETRY_ATTEMPTS; }
  _nodeRetryBase() { const b = Config?.tuning?.nodeTestRetryDelayBaseMs; return Number.isFinite(b) && b > 0 ? b : CONSTANTS.RETRY_DELAY_BASE; }

  /**
   * 安全网络请求：
   * - URL 预清洗
   * - GitHub 镜像可选
   * - 逐跳重定向审计
   * - 超时受控、中断安全
   */
  async _safeFetch(url, options = {}, timeout = CONSTANTS.GEO_INFO_TIMEOUT) {
    if (!url || typeof url !== "string") throw new Error("_safeFetch: 无效的URL参数");
    const initial = Utils.sanitizeUrl(url); if (!initial) throw new Error(`_safeFetch: URL 非法或不安全 (${url})`);
    url = initial;
    const { _fetch, _AbortController } = await this._getFetchRuntime(); if (!_fetch) throw new Error("fetch 不可用于当前运行环境");

    if (this.isGithubMirrorEnabled() && (url.startsWith("https://raw.githubusercontent.com/") || url.startsWith("https://github.com/"))) {
      try { const best = await selectBestMirror(_fetch); GH_PROXY_PREFIX = best || ""; url = `${GH_PROXY_PREFIX}${url}`; }
      catch (e) { Logger.warn("GH._safeFetch", e?.message || e); }
    }

    const opts = { ...options, headers: { "User-Agent": CONSTANTS.DEFAULT_USER_AGENT, ...(options.headers || {}) }, redirect: "manual" };

    const execFetch = async (targetUrl, count = 0) => {
      if (count > 3) throw new Error("重定向次数过多");
      const sanitized = Utils.sanitizeUrl(targetUrl); if (!sanitized) throw new Error(`重定向至非安全 URL: ${targetUrl}`);

      let controller, id;
      if (_AbortController && timeout > 0) { controller = new _AbortController(); id = setTimeout(() => { try { controller.abort(); } catch {} }, timeout); opts.signal = controller.signal; }

      try {
        const resp = await _fetch(sanitized, opts); if (id) clearTimeout(id);
        if (resp.status >= 300 && resp.status < 400) {
          const location = resp.headers.get("location");
          if (location) {
            const nextUrl = new URL(location, sanitized).toString();
            const ok = Utils.sanitizeUrl(nextUrl); if (!ok) throw new Error(`重定向目标不安全: ${nextUrl}`);
            return execFetch(nextUrl, count + 1);
          }
        }
        return resp;
      } catch (err) {
        if (id) clearTimeout(id);
        if (["AbortError", "TimeoutError"].includes(err?.name)) throw new Error(`请求超时 (${timeout}ms): ${sanitized}`);
        throw err;
      }
    };
    return execFetch(url);
  }

  async initialize() {
    try { const { _fetch } = await this._getFetchRuntime(); if (_fetch && this.isGithubMirrorEnabled()) await selectBestMirror(_fetch); }
    catch (e) { Logger.warn("Central.init", e?.message || e); }
    await this.loadAIDBFromFile().catch(err => Logger.warn("Central.loadAI", err?.message || err));
    this._registerEvents();
    this.on("requestDetected", (ip) => this.handleRequestWithGeoRouting(ip).catch(err => Logger.warn("Central.geoRouting", err?.message || err)));
    if (this.isPreheatEnabled()) this.preheatNodes().catch(err => Logger.warn("Central.preheat", err?.message || err));
    try { await this.adBlockManager.updateIfNeeded(); } catch (e) { Logger.warn("Central.adBlockInit", e?.message || e); }

    try {
      if (typeof setInterval === "function") {
        const interval = CONSTANTS.MIN_SWITCH_COOLDOWN;
        this._switchTimerId = setInterval(() => {
          try { this._autoAdjustSwitches("timer"); } catch (e) { Logger.warn("Central.autoSwitch.timer", e?.message || e); }
        }, interval);
      }
    } catch (e) { Logger.warn("Central.autoSwitch.timerReg", e?.message || e); }

    try {
      if (PLATFORM.isNode && process.on) {
        const cleanup = () => this.destroy().catch(err => Logger.error("Central.destroy", err?.message || err));
        process.on("SIGINT", cleanup); process.on("SIGTERM", cleanup);
      } else if (PLATFORM.isBrowser) {
        window.addEventListener("beforeunload", () => this.destroy().catch(err => Logger.error("Central.destroy", err?.message || err)));
      }
    } catch (e) { Logger.warn("Central.cleanupReg", e?.message || e); }

    this._autoAdjustSwitches("init");
    Logger.info("Central.init", "初始化完成");
  }
  async destroy() {
    Logger.info("Central.destroy", "开始清理资源...");
    try { this._unregisterEvents(); } catch (e) { Logger.warn("Central.destroy", e?.message || e); }
    try { await this.saveAIDBToFile(); } catch (e) { Logger.warn("Central.saveAI", e?.message || e); }
    try {
      if (this._switchTimerId && typeof clearInterval === "function") {
        clearInterval(this._switchTimerId);
        this._switchTimerId = null;
      }
    } catch (e) { Logger.warn("Central.destroy", e?.message || e); }
    try { this.lruCache?.clear(); this.geoInfoCache?.clear(); this.nodePools?.clear?.(); } catch (e) { Logger.warn("Central.clearCache", e?.message || e); }
    Logger.info("Central.destroy", "资源清理完成");
  }
  _registerEvents() {
    if (this._listenersRegistered) return;
    this._boundSystemListeners = {
      configChanged: async () => this.onConfigChanged(),
      networkOnline: async () => this.onNetworkOnline(),
      performanceThresholdBreached: async (nodeId) => this.onPerformanceThresholdBreached(nodeId),
      evaluationCompleted: () => this.onEvaluationCompleted()
    };
    try { if (typeof Config !== "undefined" && Config.on) Config.on("configChanged", this._boundSystemListeners.configChanged); } catch {}
    try { if (PLATFORM.isBrowser) window.addEventListener("online", this._boundSystemListeners.networkOnline); } catch {}
    try { if (this.nodeManager?.on) this.nodeManager.on("performanceThresholdBreached", this._boundSystemListeners.performanceThresholdBreached); } catch {}
    this.on("evaluationCompleted", this._boundSystemListeners.evaluationCompleted);
    this._listenersRegistered = true;
  }
  _unregisterEvents() {
    if (!this._listenersRegistered || !this._boundSystemListeners) return;
    try { if (typeof Config !== "undefined" && Config.off) Config.off("configChanged", this._boundSystemListeners.configChanged); } catch {}
    try { if (PLATFORM.isBrowser && window.removeEventListener) window.removeEventListener("online", this._boundSystemListeners.networkOnline); } catch {}
    try { if (this.nodeManager?.off) this.nodeManager.off("performanceThresholdBreached", this._boundSystemListeners.performanceThresholdBreached); } catch {}
    try { this.off("evaluationCompleted", this._boundSystemListeners.evaluationCompleted); } catch {}
    this._boundSystemListeners = null; this._listenersRegistered = false;
  }

  onNodeUpdate(id, status) { this.nodeManager.updateNodeQuality(id, status.score || 0); }
  async onConfigChanged() { Logger.info("Central.onConfigChanged", "配置变更，触发节点评估..."); await this.evaluateAllNodes(); }
  async onNetworkOnline() { Logger.info("Central.onNetworkOnline", "网络恢复，触发节点评估..."); await this.evaluateAllNodes(); this._autoAdjustSwitches("networkOnline"); }
  async onPerformanceThresholdBreached(nodeId) {
    Logger.info("Central.onThreshold", `节点 ${nodeId} 性能阈值突破，触发单节点评估...`);
    const node = this.state.config.proxies?.find(n => n?.id === nodeId);
    if (node) await this.evaluateNodeQuality(node); else Logger.warn("Central.onThreshold", `节点 ${nodeId} 不存在，无法评估`);
  }
  onEvaluationCompleted() { Logger.info("Central.onEvalDone", "节点评估完成，触发数据保存和节点清理..."); this.saveAIDBToFile(); this.autoEliminateNodes(); }

  async preheatNodes() {
    const proxies = this.state.config.proxies || []; if (!proxies.length) return;
    const testNodes = proxies.slice(0, CONSTANTS.PREHEAT_NODE_COUNT);
    const limit = Math.max(1, Number(Config?.tuning?.preheatConcurrency) || CONSTANTS.CONCURRENCY_LIMIT);
    const batchDelay = Math.max(0, Number(Config?.tuning?.preheatBatchDelayMs) || 250);

    const tasks = testNodes.map((node, idx) => async () => {
      if (idx && idx % limit === 0) await Utils.sleep(batchDelay);
      return Utils.retry(() => this.testNodeMultiMetrics(node), this._nodeAttempts(), this._nodeRetryBase());
    });

    const results = await Utils.asyncPool(tasks, limit);
    results.forEach((res, i) => {
      const node = testNodes[i];
      if (res?.__error) { Logger.error("Central.preheat", `节点预热失败: ${node.id}`, res.__error); return; }
      const bps = this.throughputEstimator.bpsFromBytesLatency(res); const enriched = { ...res, bps };
      this.state.updateNodeStatus(node.id, { initialMetrics: enriched, lastTested: Utils.now() });
      this.metricsManager.append(node.id, enriched);
      const score = this.calculateQuality(enriched);
      this.nodeManager.updateNodeQuality(node.id, score);
      this.availabilityTracker.ensure(node.id);
      const avail = this.availabilityTracker.rate(node.id);
      this.nodePools.classify(node.id, score, avail);
    });
    this.nodePools.snapshot();
  }
  calculateQuality(metrics) { return CentralManager.scoreComponents(metrics || {}).metricScore; }

  async evaluateAllNodes() {
    const proxies = this.state.config.proxies || []; if (!proxies.length) return;
    const tasks = proxies.map((node, idx) => async () => {
      if (idx && idx % CONSTANTS.CONCURRENCY_LIMIT === 0) await Utils.sleep(100);
      return this.evaluateNodeQuality(node);
    });
    const results = await Utils.asyncPool(tasks, CONSTANTS.CONCURRENCY_LIMIT);
    results.forEach((r, idx) => { if (r?.__error) { const node = proxies[idx]; Logger.warn("Central.evaluateAll", `节点评估失败: ${node?.id}`, r.__error); } });
    this.emit("evaluationCompleted");
  }

  async evaluateNodeQuality(node) {
    if (!node?.id || typeof node.id !== "string") { Logger.warn("Central.evaluateNode", "无效的节点对象"); return; }
    let metrics;
    try { metrics = await Utils.retry(() => this.testNodeMultiMetrics(node), this._nodeAttempts(), this._nodeRetryBase()); }
    catch {
      Logger.warn("Central.evaluateNode", `节点探测多次失败，使用回退模拟: ${node.id}`);
      try { metrics = await this.testNodeMultiMetrics(node); }
      catch { Logger.error("Central.evaluateNode", `节点回退测试也失败: ${node.id}`); metrics = { latency: this._nodeTimeout(), loss: 1, jitter: 100, bytes: 0, bps: 0, __simulated: true }; }
    }
    if (typeof metrics.bps !== "number") metrics.bps = this.throughputEstimator.bpsFromBytesLatency(metrics);

    this.availabilityTracker.ensure(node.id);
    const isSim = metrics?.__simulated === true;
    const latency = Math.max(0, Number(metrics?.latency) || 0);
    const hardFail = !!metrics.__hardFail;
    const success = !!(metrics && !hardFail && latency > 0 && latency < (this._nodeTimeout() * 2) && !isSim);
    this.availabilityTracker.record(node.id, success, { hardFail });

    let score = 0; try { score = Utils.clamp(this.calculateQuality(metrics), 0, 100); } catch (e) { Logger.error("Central.evaluateNode", `计算节点质量分失败 (${node.id}):`, e.message); }

    let geoInfo = null;
    try {
      const ip = (node.server && typeof node.server === "string") ? node.server.split(":")[0] : null;
      if (Utils.isIPv4(ip) && !Utils.isPrivateIP(ip) && !Utils.isLoopbackOrLocal(ip)) {
        geoInfo = this.isGeoExternalLookupEnabled() ? await this.getGeoInfo(ip) : this._getFallbackGeoInfo();
      }
    } catch (e) { Logger.debug("Central.evaluateNode", `获取节点地理信息失败 (${node.id}):`, e.message); }

    try {
      this.nodeManager.updateNodeQuality(node.id, score);
      this.metricsManager.append(node.id, metrics);
      const avail = this.availabilityTracker.rate(node.id);
      this.state.updateNodeStatus(node.id, { metrics, score, geoInfo, lastEvaluated: Utils.now(), availabilityRate: avail });
      this.nodePools.classify(node.id, score, avail);
    } catch (e) { Logger.error("Central.evaluateNode", `更新节点状态失败 (${node.id}):`, e.message); }

    try {
      const isCurrent = this.nodeManager.currentNode === node.id;
      if (isCurrent && this._shouldEmergencySwitch(node.id, score)) {
        const proxies = this.state?.config?.proxies;
        if (Array.isArray(proxies) && proxies.length) {
          if (this.availabilityTracker.hardFailStreak(node.id) >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS) this.nodeManager.switchCooldown.delete(node.id);
          await this.nodeManager.switchToBestNode(proxies);
        }
      }
    } catch (e) { Logger.warn("Central.evaluateNode", `节点切换失败 (${node.id}):`, e.message); }
  }

  _shouldEmergencySwitch(nodeId, score) {
    const st = this.state.nodes.get(nodeId) || {};
    const availRate = Number(st.availabilityRate) || 0;
    const failStreak = this.availabilityTracker.hardFailStreak(nodeId);
    return failStreak >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS
      || availRate < CONSTANTS.AVAILABILITY_MIN_RATE
      || score < CONSTANTS.QUALITY_SCORE_THRESHOLD;
  }

  async handleRequestWithGeoRouting(targetIp) {
    const nodes = this.state.config.proxies || []; if (!targetIp || !nodes.length) { Logger.warn("Central.geoRouting", "缺少目标IP或代理节点"); return; }
    const targetGeo = this.isGeoExternalLookupEnabled() ? await this.getGeoInfo(targetIp) : this._getFallbackGeoInfo();
    if (!targetGeo) { Logger.warn("Central.geoRouting", "无法获取目标IP地理信息，使用默认路由"); await this.nodeManager.switchToBestNode(nodes); return; }
    await this.nodeManager.switchToBestNode(nodes, targetGeo);
  }

  autoEliminateNodes() {
    const proxies = this.state.config.proxies || []; const threshold = Utils.now() - CONSTANTS.NODE_EVALUATION_THRESHOLD;
    for (const node of proxies) {
      const st = this.state.nodes.get(node.id); const samples = (this.state.metrics.get(node.id) || []).length;
      if (samples < CONSTANTS.MIN_SAMPLE_SIZE) continue;
      if ((!st || st.lastEvaluated < threshold) || (st?.score < CONSTANTS.NODE_CLEANUP_THRESHOLD)) {
        this.state.nodes.delete(node.id); this.state.metrics.delete(node.id); this.nodeManager.nodeQuality.delete(node.id);
        this.nodePools.good.delete(node.id); this.nodePools.bad.delete(node.id);
        Logger.info("Central.cleanup", `已清理异常节点: ${node.id}`);
      }
    }
    this.nodePools.snapshot();
  }

  _biasScore(c, prefers) {
    const { preferHighThroughput, preferLowLatency, preferStability } = prefers;
    return c.score
      + ((c.availability >= CONSTANTS.AVAILABILITY_MIN_RATE) ? CONSTANTS.BIAS_AVAIL_BONUS_OK : CONSTANTS.BIAS_AVAIL_PENALTY_BAD)
      + (preferHighThroughput ? Math.min(10, Math.round(Math.log10(1 + c.bps) * 2)) : 0)
      + (preferLowLatency ? Utils.clamp(CONSTANTS.BIAS_LATENCY_MAX_BONUS - (c.latency / 30), 0, CONSTANTS.BIAS_LATENCY_MAX_BONUS) : 0)
      - (preferStability ? Math.min(CONSTANTS.BIAS_JITTER_MAX_PENALTY, Math.round(c.jitter / 50)) : 0);
  }

  _normalizeUrlContext(reqCtx) {
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
    return { urlStr, hostname, port, protocol };
  }
  _computePrefers({ urlStr, hostname, port, protocol, headers, contentLength }) {
    const isVideo = !!(headers?.["Content-Type"]?.includes("video") || CONSTANTS.STREAM_HINT_REGEX.test(urlStr));
    const isAI = CONSTANTS.AI_HINT_REGEX.test(urlStr || hostname || "");
    const isLarge = (Number(contentLength) || 0) >= CONSTANTS.LARGE_PAYLOAD_THRESHOLD_BYTES;
    const isGaming = CONSTANTS.GAMING_PORTS.includes(Number(port));
    const isTLS = (protocol === "https" || CONSTANTS.TLS_PORTS.includes(Number(port)));
    const isHTTP = (protocol === "http" || CONSTANTS.HTTP_PORTS.includes(Number(port)));
    return {
      preferHighThroughput: isVideo || isLarge,
      preferLowLatency: isGaming || isAI || isTLS,
      preferStability: isAI || isVideo,
      flags: { isVideo, isAI, isLarge, isGaming, isTLS, isHTTP }
    };
  }

  /** 区域候选集过滤（加入同义映射提升命中） */
  _regionCandidates(nodes, targetGeo, candidates) {
    if (!targetGeo?.country || !Array.isArray(Config.regionOptions?.regions)) return candidates;
    const synonyms = Object.entries(REGION_SYNONYMS).find(([k, arr]) => arr.includes(targetGeo.country));
    const targetName = synonyms ? synonyms[0] : targetGeo.country;
    // 使用区域候选缓存提升过滤性能
    const regionPreferred = this._getRegionPreferredSet(targetName, nodes);
    if (regionPreferred?.length) {
      const set = new Set(regionPreferred);
      const regionCandidates = candidates.filter(c => set.has(c.node.name));
      if (regionCandidates.length) return regionCandidates;
    }
    return candidates;
  }

  /** 获取区域候选集合（按目标区域名缓存） */
  _getRegionPreferredSet(targetName, nodes) {
    try {
      const key = String(targetName || "").toLowerCase();
      const hit = this._regionPreferredCache.get(key);
      if (hit) return hit;
      const region = Config.regionOptions.regions.find(r => r && ((r.name?.includes(targetName)) || (r.regex?.test(targetName))));
      const arr = Utils.filterProxiesByRegion(nodes, region);
      this._regionPreferredCache.set(key, arr);
      return arr;
    } catch { return []; }
  }

  async onRequestOutbound(reqCtx = {}) {
    if (!this.state?.config) throw new ConfigurationError("系统配置未初始化");
    const nodes = this.state.config.proxies || []; if (!nodes.length) return { mode: "direct" };

    const { urlStr, hostname, port, protocol } = this._normalizeUrlContext(reqCtx);
    const clientIP = reqCtx.clientIP || reqCtx.headers?.["X-Forwarded-For"] || reqCtx.headers?.["Remote-Address"];
    const clientGeo = clientIP ? (this.isGeoExternalLookupEnabled() ? await this.getGeoInfo(clientIP) : this._getFallbackGeoInfo(hostname)) : null;

    let targetGeo = null;
    try {
      if (hostname && Utils.isValidDomain(hostname)) {
        if (this.isSystemDnsOnly()) { targetGeo = this._getFallbackGeoInfo(hostname); }
        else {
          const targetIP = await this.resolveDomainToIP(hostname);
          if (targetIP) targetGeo = this.isGeoExternalLookupEnabled() ? await this.getGeoInfo(targetIP) : this._getFallbackGeoInfo(hostname);
        }
      }
    } catch {}

    const { preferHighThroughput, preferLowLatency, preferStability, flags } = this._computePrefers({
      urlStr, hostname, port, protocol, headers: reqCtx.headers, contentLength: reqCtx.contentLength
    });

    // 路由选择缓存命中则直接返回，避免重复排序计算
    try {
      if (this.isDispatchCacheEnabled()) {
        const cacheKey = `${typeof reqCtx.user === "string" ? reqCtx.user : "default"}:${clientGeo?.country || "unknown"}:${hostname || "unknown"}`;
        const cachedId = this.lruCache.get(cacheKey);
        if (cachedId && !this.nodeManager.isInCooldown(cachedId)) {
          const cachedNode = nodes.find(n => n?.id === cachedId);
          if (cachedNode) return { mode: "proxy", node: cachedNode, targetGeo, clientGeo, reason: { cached: true, preferHighThroughput, preferLowLatency, preferStability, ...flags } };
        }
      }
    } catch {}

    const enriched = nodes.map(n => {
      const st = this.state.nodes.get(n.id) || {}; const m = st.metrics || {};
      return { node: n, score: st.score || 0, availability: st.availabilityRate || 0, latency: Number(m.latency) || Infinity, bps: Number(m.bps) || 0, jitter: Number(m.jitter) || 0 };
    }).filter(c => c.node?.id);

    let candidates = enriched;
    const poolSnap = this.nodePools.snapshot();
    if (poolSnap.good.length) {
      const goodSet = new Set(poolSnap.good);
      const filtered = candidates.filter(c => goodSet.has(c.node.id));
      if (filtered.length) candidates = filtered;
    }
    candidates = this._regionCandidates(nodes, targetGeo, candidates);

    const prefers = { preferHighThroughput, preferLowLatency, preferStability };
    const ordered = (candidates.length ? candidates : enriched).sort((a, b) => this._biasScore(b, prefers) - this._biasScore(a, prefers)).map(c => c.node);
    const bestNode = await this.nodeManager.getBestNode(ordered.length ? ordered : nodes, targetGeo);
    const selected = bestNode || nodes[0];

    const cacheKey = `${typeof reqCtx.user === "string" ? reqCtx.user : "default"}:${clientGeo?.country || "unknown"}:${hostname || "unknown"}`;
    try { if (selected?.id) this.lruCache.set(cacheKey, selected.id); } catch {}

    if (!selected) return { mode: "direct" };
    return { mode: "proxy", node: selected, targetGeo, clientGeo, reason: { preferHighThroughput, preferLowLatency, preferStability, ...flags } };
  }

  async onResponseInbound(resCtx = {}) {
    const node = resCtx.node; if (!node?.id) return;
    const result = { success: !!resCtx.success, latency: Number(resCtx.latency) || 0, bytes: Number(resCtx.bytes) || 0 };
    const req = { url: resCtx.url, method: resCtx.method, headers: resCtx.headers };
    this.recordRequestMetrics(node, result, req);

    const st = this.state.nodes.get(node.id) || {};
    if (this._shouldEmergencySwitch(node.id, Number(st.score) || 0) || result.latency > CONSTANTS.LATENCY_CLAMP_MS) {
      const proxies = this.state?.config?.proxies || [];
      if (proxies.length) {
        if (this.availabilityTracker.hardFailStreak(node.id) >= CONSTANTS.AVAILABILITY_EMERGENCY_FAILS) this.nodeManager.switchCooldown.delete(node.id);
        await this.nodeManager.switchToBestNode(proxies);
      }
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
    } catch (error) { Logger.error("Central.proxyHandle", error.stack || error); return this.proxyToDirect(...args); }
  }

  async smartDispatchNode(user, nodes, context) {
    if (!Array.isArray(nodes) || !nodes.length) throw new InvalidRequestError("smartDispatchNode: 节点列表不能为空");
    if (!context || typeof context !== "object") throw new InvalidRequestError("smartDispatchNode: 无效的上下文信息");

    const userStr = typeof user === "string" ? user : "default";
    const country = context.clientGeo?.country || "unknown";
    const hostname = context.req?.url ? (typeof context.req.url === "string" ? new URL(context.req.url).hostname : (context.req.url.hostname || "unknown")) : "unknown";
    const cacheKey = `${userStr}:${country}:${hostname}`;

    let cached = null; try { cached = this.lruCache?.get(cacheKey); } catch (e) { Logger.debug("Central.smartDispatch", e.message); }
    if (cached) {
      try { const node = nodes.find(n => n?.id === cached); if (node) return node; } catch (e) { Logger.debug("Central.smartDispatch", e.message); }
      try { this.lruCache?.delete(cacheKey); } catch (e) { Logger.debug("Central.smartDispatch", e.message); }
    }

    const url = context.req?.url ? (typeof context.req.url === "string" ? context.req.url : context.req.url.toString()) : "";
    const prefers = this._computePrefers({
      urlStr: url, hostname, port: context.req?.port, protocol: context.req?.protocol, headers: context.req?.headers, contentLength: 0
    });

    if (prefers.flags.isVideo) {
      try {
        const candidateIds = Array.from(this.state.nodes.entries()).filter(([_, node]) => typeof node?.score === "number" && node.score > CONSTANTS.QUALITY_SCORE_THRESHOLD).map(([id]) => id);
        const candidates = candidateIds.map(id => { try { return this.state.config?.proxies?.find(p => p?.id === id); } catch { return null; } }).filter(Boolean);
        const limit = CONSTANTS.CONCURRENCY_LIMIT || 3;
        if (candidates.length) {
          const tests = candidates.slice(0, limit * 2).map(n => () => Utils.retry(() => this.testNodeMultiMetrics(n), this._nodeAttempts(), this._nodeRetryBase()));
          await Utils.asyncPool(tests, limit);
          const best = await this.nodeManager.getBestNode(candidates);
          if (best) { try { this.lruCache?.set(cacheKey, best.id); } catch (e) { Logger.debug("Central.smartDispatch", e.message); } return best; }
        }
      } catch (error) { Logger.warn("Central.smartDispatch", "视频流节点选择失败，使用默认策略:", error.message); }
    }

    if (context.targetGeo?.country && Array.isArray(Config.regionOptions?.regions)) {
      try {
        const synonyms = Object.entries(REGION_SYNONYMS).find(([k, arr]) => arr.includes(context.targetGeo.country));
        const targetName = synonyms ? synonyms[0] : context.targetGeo.country;
        const targetRegion = Config.regionOptions.regions.find(r => r && ((r.name?.includes(targetName)) || (r.regex?.test(targetName))));
        if (targetRegion) {
          const regionNodes = Utils.filterProxiesByRegion(nodes, targetRegion);
          if (regionNodes?.length) {
            const candidates = nodes.filter(n => n?.name && regionNodes.includes(n.name));
            if (candidates.length) {
              const bn = await this.nodeManager.getBestNode(candidates);
              if (bn) { try { this.lruCache?.set(cacheKey, bn.id); } catch (e) { Logger.debug("Central.smartDispatch", e.message); } return bn; }
            }
          }
        }
      } catch (error) { Logger.warn("Central.smartDispatch", "区域节点选择失败，使用默认策略:", error.message); }
    }

    const bestNode = await this.nodeManager.getBestNode(nodes);
    if (!bestNode) { Logger.warn("Central.smartDispatch", "无法选择最佳节点，返回第一个可用节点"); return nodes[0] || null; }
    try { this.lruCache?.set(cacheKey, bestNode.id); } catch (e) { Logger.debug("Central.smartDispatch", e.message); }
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
      const data = await this._fetchGeoSeries(ip);
      if (data) { this.geoInfoCache.set(ip, data); return data; }
      const d = this._getFallbackGeoInfo(domain); this.geoInfoCache.set(ip, d, CONSTANTS.GEO_FALLBACK_TTL); return d;
    } catch (error) { Logger.error("Central.geo", `获取地理信息失败: ${error.message}`, error.stack); return this._getFallbackGeoInfo(domain); }
  }
  async getIpGeolocation(ip) { return this.getGeoInfo(ip); }

  async _fetchGeoSeries(ip) {
    const endpoints = (Array.isArray(Config?.privacy?.trustedGeoEndpoints) && Config.privacy.trustedGeoEndpoints.length)
      ? Config.privacy.trustedGeoEndpoints
      : [];
    for (const tmpl of endpoints) {
      const url = tmpl.replace("{ip}", ip);
      try {
        const resp = await this._safeFetch(url, { headers: { "User-Agent": "Mozilla/5.0" } }, CONSTANTS.GEO_INFO_TIMEOUT);
        if (!resp.ok) continue;
        const json = await resp.json().catch(() => null);
        if (!json) continue;
        const country = json.country_name || json.country || "Unknown";
        const region = json.region || json.city || "Unknown";
        if (country) return { country, region };
      } catch {}
    }
    return null;
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
    if (!Utils.isValidDomain(domain)) { Logger.error("Central.dns", `无效的域名参数或格式: ${domain}`); return null; }
    if (this.isSystemDnsOnly()) return null;
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
    } catch (error) { if (error.name !== "AbortError") Logger.error("Central.dns", `域名解析失败: ${error.message}`); return null; }
  }

  async proxyRequestWithNode(node, ...args) {
    if (!node || typeof node !== "object") throw new InvalidRequestError("代理请求失败: 无效的节点信息");
    if (!node.id || !(node.server || node.proxyUrl)) throw new InvalidRequestError(`代理请求失败: 节点缺少必要属性 (id: ${node?.id}, server: ${node?.server}, proxyUrl: ${node?.proxyUrl})`);

    const probeUrl = node.proxyUrl || (node.server ? `http://${node.server}` : "");
    const safeUrl = Utils.sanitizeUrl(probeUrl);
    if (!safeUrl) {
      Logger.warn("Central.proxy", `代理请求阻断（不安全URL或私网）[${node.id}]: ${probeUrl}`);
      this.availabilityTracker.record(node.id, false, { hardFail: true });
      return { success: false, error: "不安全URL或私网地址", latency: this._nodeTimeout() };
    }

    try {
      const start = Utils.now(); const fetchOptions = (args && args.length && typeof args[0] === "object") ? args[0] : {};
      const response = await this._safeFetch(safeUrl, fetchOptions, this._nodeTimeout());
      const latency = Utils.now() - start; const bytes = Utils.safeInt(response.headers?.get?.("Content-Length"), 0);
      return { success: true, latency, bytes, status: response.status, headers: response.headers };
    } catch (error) {
      Logger.error("Central.proxy", `代理请求失败 [${node.id}]: ${error?.message || error}`); this.availabilityTracker.record(node.id, false, { hardFail: true });
      return { success: false, error: error?.message || String(error), latency: this._nodeTimeout() };
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

    const st = this.state.nodes.get(node.id) || {};
    const avail = Number(st.availabilityRate) || 0;
    const score = Number(st.score) || 0;
    this.nodePools.classify(node.id, score, avail);
    try { this._autoAdjustSwitches("metrics"); } catch (e) { Logger.debug("Central.autoSwitch.metrics", e?.message || e); }
  }

  aiScoreNode(node, metrics) {
    const history = this.nodeManager.nodeHistory.get(node.id) || [];
    const recents = this.state.metrics.get(node.id) || [];
    if (recents.length < CONSTANTS.MIN_SAMPLE_SIZE) return metrics.success ? CONSTANTS.EARLY_SAMPLE_SCORE : -CONSTANTS.EARLY_SAMPLE_SCORE;
    const f = this.extractNodeFeatures(node, metrics, recents, history);
    const p = this.predictNodeFuturePerformance(f);
    const adj = this.calculateScoreAdjustment(p, metrics.success);
    if (CONSTANTS.ENABLE_SCORE_DEBUGGING && Math.abs(adj) > 3) Logger.debug("Central.aiScore", { risk: p.risk, latency: f.currentLatency, loss: f.currentLoss, adjustment: adj });
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

  calculateScoreAdjustment(p, success) { if (!success) return -10; if (p.risk < 0.3) return 5; if (p.risk < 0.5) return 2; if (p.risk > 0.7) return -3; return 0; }

  /* ======= 配置处理：统一构建器（完整保留原逻辑） ======= */
  processConfiguration(config) {
    if (!config || typeof config !== "object") throw new ConfigurationError("processConfiguration: 配置对象无效");
    let safe;
    try {
      if (typeof structuredClone === "function") safe = structuredClone(config);
      else safe = Utils.deepClone(config);
      if (!safe || typeof safe !== "object") throw new Error("拷贝结果无效");
    } catch (e) { throw new ConfigurationError(`配置对象无法拷贝: ${e?.message || "unknown error"}`); }

    try { this.state.config = safe; this.stats?.reset?.(); this.successTracker?.reset?.(); this._regionPreferredCache?.clear?.(); } catch (e) { Logger.warn("Central.processConfig", e.message); }

    const proxyCount = Array.isArray(safe?.proxies) ? safe.proxies.length : 0;
    const providerCount = (typeof safe?.["proxy-providers"] === "object" && safe["proxy-providers"] !== null) ? Object.keys(safe["proxy-providers"]).length : 0;
    if (proxyCount === 0 && providerCount === 0) throw new ConfigurationError("未检测到任何代理节点或代理提供者");

    try {
      if (Config?.system && typeof Config.system === "object") Object.assign(safe, Config.system);
      if (Config?.dns && typeof Config.dns === "object") safe.dns = Config.dns;
    } catch (e) { Logger.warn("Central.applySystem", e.message); }

    if (!this.isSmartConfigEnabled()) { Logger.info("Central.processConfig", "配置处理已禁用，返回原始配置"); return safe; }

    // 自动发现区域
    try {
      const discovered = this.regionAutoManager.discoverRegionsFromProxies(safe.proxies || []);
      Config.regionOptions.regions = this.regionAutoManager.mergeNewRegions(Config.regionOptions?.regions || [], discovered);
    } catch (e) { Logger.warn("Central.regionDiscover", e.message); }

    // 组构建器
    const groupBase = Utils.getProxyGroupBase();
    const pushGroup = (name, type, proxies, icon, extra = {}) => {
      const pg = safe["proxy-groups"] || [];
      pg.push({ ...groupBase, name, type, proxies, icon: icon || "", ...extra });
      safe["proxy-groups"] = pg;
    };

    // 区域分组
    const { regionProxyGroups, otherProxyNames } = this.regionAutoManager.buildRegionGroups(safe, Config.regionOptions.regions || []);
    let regionGroupNames = [];
    try {
      regionGroupNames = regionProxyGroups.filter(g => g?.name).map(g => g.name);
      if (otherProxyNames.length) regionGroupNames.push("其他节点");
      regionGroupNames = Utils.toUnique(regionGroupNames);
    } catch (e) { Logger.warn("Central.regionGroupNames", e.message); }

    // 默认组 & 直连保底
    try {
      safe["proxy-groups"] = [{ ...groupBase, name: "默认节点", type: "select", proxies: [...regionGroupNames, "直连"], icon: ICON_VAL(ICONS.Proxy) }];
      safe.proxies = Array.isArray(safe?.proxies) ? safe.proxies : [];
      if (!safe.proxies.some(p => p?.name === "直连")) safe.proxies.push({ name: "直连", type: "direct" });
    } catch (e) { Logger.warn("Central.defaultGroup", e.message); safe["proxy-groups"] = safe["proxy-groups"] || []; }

    // 规则提供者与服务组
    const ruleProviders = new Map(); const rules = [];
    try {
      const baseRP = Utils.getRuleProviderBase();
      ruleProviders.set("applications", { ...baseRP, behavior: "classical", format: "text", url: URLS.rulesets.applications(), path: "./ruleset/DustinWin/applications.list" });
      if (Array.isArray(Config.preRules)) rules.push(...Config.preRules);
      try { this.adBlockManager.injectRuleProvider(ruleProviders); } catch (e) { Logger.warn("Central.injectAdBlock", e?.message || e); }

      // 服务组统一创建
      const services = Array.isArray(Config?.services) ? Config.services : [];
      const defaultOrder = ["默认节点", "国内网站", "直连", "REJECT"];
      for (const svc of services) {
        try {
          const groupName = svc.name || svc.id;
          const base = Array.isArray(svc.proxiesOrder) ? svc.proxiesOrder : (Array.isArray(svc.proxies) ? svc.proxies : defaultOrder);
          const finalOrder = Utils.toUnique([...(base || []), ...regionGroupNames]);
          pushGroup(groupName, "select", finalOrder, svc.icon || "");
          (Array.isArray(svc.rule) ? svc.rule : []).forEach(r => rules.push(r));
          if (svc.ruleProvider?.name && svc.ruleProvider.url) {
            Utils.safeSet(ruleProviders, svc.ruleProvider.name, {
              ...Utils.getRuleProviderBase(),
              behavior: svc.ruleProvider.behavior || "domain",
              format: svc.ruleProvider.format || "yaml",
              url: svc.ruleProvider.url,
              path: `./ruleset/${svc.ruleProvider.name}.${(svc.ruleProvider.format || "yaml")}`
            });
          }
        } catch (e) { Logger.warn("Central.serviceGroup", svc?.id, e?.message || e); }
      }
    } catch (e) { Logger.warn("Central.rules", e.message); }

    // 默认代理组
    try {
      if (Config.common?.defaultProxyGroups?.length) {
        for (const group of Config.common.defaultProxyGroups) {
          if (group?.name) pushGroup(group.name, "select", [...(Array.isArray(group.proxies) ? group.proxies : []), ...regionGroupNames], group.icon, { url: group.url || (Config.common?.proxyGroup?.url || "") });
        }
      }
    } catch (e) { Logger.warn("Central.defaultProxyGroups", e.message); }

    // 追加区域组与其他节点
    try { if (regionProxyGroups.length) safe["proxy-groups"] = (safe["proxy-groups"] || []).concat(regionProxyGroups); } catch (e) { Logger.warn("Central.appendRegionGroups", e.message); }
    try { if (otherProxyNames.length) pushGroup("其他节点", "select", otherProxyNames, ICON_VAL(ICONS.WorldMap)); } catch (e) { Logger.warn("Central.appendOther", e.message); }

    // 优劣分组
    try {
      const snap = this.nodePools.snapshot();
      const goodNames = this.nodePools.namesFromIds(safe.proxies, snap.good);
      const badNames = this.nodePools.namesFromIds(safe.proxies, snap.bad);
      pushGroup("优质节点", "select", Utils.toUnique([...goodNames, ...regionGroupNames, "直连"]), ICON_VAL(ICONS.WorldMap));
      pushGroup("劣质节点", "select", Utils.toUnique([...badNames, "直连"]), ICON_VAL(ICONS.WorldMap));
    } catch (e) { Logger.warn("Central.qualityGroups", e.message); }

    // 规则与提供者输出
    try { if (Config.common?.postRules?.length) rules.push(...Config.common.postRules); safe.rules = rules; }
    catch (e) { Logger.warn("Central.postRules", e.message); safe.rules = rules; }
    try { if (ruleProviders.size) safe["rule-providers"] = Object.fromEntries(ruleProviders); }
    catch (e) { Logger.warn("Central.ruleProviders", e.message); }

    return safe;
  }

}

/* ============== 指标与吞吐 ============== */
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
    if (!PLATFORM.isNode) throw new Error("当前运行环境非Node，无法执行TCP连通性测试");
    const net = require("net");
    return new Promise((resolve, reject) => {
      const start = Utils.now(); const socket = new net.Socket(); let done = false;
      const cleanup = (err) => { if (done) return; done = true; try { socket.destroy(); } catch {} if (err) reject(err); else resolve(Utils.now() - start); };
      socket.setTimeout(timeout, () => cleanup(new Error("TCP connect timeout"))); socket.once("error", err => cleanup(err)); socket.connect(port, host, () => cleanup());
    });
  }
  async measureResponse(response) {
    let bytes = 0, jitter = 0;
    try {
      // 浏览器流式读取路径（快速估计吞吐与抖动）
      if (response?.body?.getReader) {
        const reader = response.body.getReader(), maxBytes = 64 * 1024; const readStart = Utils.now();
        while (true) { const chunk = await reader.read(); if (chunk?.done) break; const v = chunk?.value; if (v) { const len = v.byteLength || v.length || 0; bytes += len; if (bytes >= maxBytes) break; } }
        const readTime = Math.max(1, Utils.now() - readStart);
        const speedKbps = (bytes * 8) / readTime;
        jitter = Math.max(1, 200 - Math.min(200, Math.round(speedKbps / 10)));
        jitter = Math.min(jitter, CONSTANTS.JITTER_CLAMP_MS);
        return { bytes, jitter };
      }
      // 其他路径：使用 Content-Length 或 ArrayBuffer 估计
      if (typeof response?.arrayBuffer === "function") { const buf = await response.arrayBuffer(); bytes = buf?.byteLength || 0; return { bytes, jitter: 0 }; }
      if (response?.headers?.get) { bytes = Utils.safeInt(response.headers.get("Content-Length"), 0); return { bytes, jitter: 0 }; }
      return { bytes: 0, jitter: 0 };
    } catch { return { bytes: 0, jitter: 0 }; }
  }
  bpsFromBytesLatency({ bytes = 0, latency = 0 }) { const ms = Math.max(1, Number(latency) || 1); const bps = Math.max(0, Math.round((bytes * 8 / ms) * 1000)); return Math.min(CONSTANTS.THROUGHPUT_SOFT_CAP_BPS, bps); }
}

/* ============== KV 存储封装（含形状校验） ============== */
function getKVStore() {
  try {
    if (typeof $persistentStore !== "undefined" && $persistentStore) return {
      read: (k) => { try { return $persistentStore.read(k); } catch { return ""; } },
      write: (v, k) => { try { return $persistentStore.write(v, k); } catch { return false; } }
    };
    if (PLATFORM.isBrowser && window.localStorage) return {
      read: (k) => { try { return window.localStorage.getItem(k) || ""; } catch { return ""; } },
      write: (v, k) => { try { window.localStorage.setItem(k, v); return true; } catch { return false; } }
    };
  } catch {}
  return null;
}
CentralManager.prototype.loadAIDBFromFile = function () {
  return new Promise((resolve) => {
    try {
      const store = getKVStore(); const raw = store?.read?.("ai_node_data") || "";
      if (raw && typeof raw === "string" && raw.trim()) {
        try {
          const data = JSON.parse(raw);
          if (data && typeof data === "object" && !Array.isArray(data)) {
            let loaded = 0; Object.entries(data).forEach(([id, stats]) => {
              // 形状校验：id 为 string，stats 为对象或数组
              if (typeof id === "string" && stats && (typeof stats === "object")) {
                try {
                  const arr = Array.isArray(stats) ? stats : [stats];
                  this.state.metrics.set(id, arr); loaded++;
                } catch (e) { Logger.debug("Central.loadAI.shape", `加载节点数据失败 (${id}):`, e.message); }
              }
            });
            Logger.info("Central.loadAI", `成功加载AI节点数据，共${loaded}条记录`);
          } else { Logger.warn("Central.loadAI", "AI数据格式无效，预期为对象"); }
        } catch (e) {
          Logger.error("Central.loadAI", "AI数据解析失败:", e?.stack || e);
          try { store?.write?.("{}", "ai_node_data"); } catch (delErr) { Logger.warn("Central.loadAI", "重置损坏数据失败:", delErr.message); }
        }
      }
    } catch (e) { Logger.error("Central.loadAI", "AI数据加载失败:", e?.stack || e); } finally { resolve(); }
  });
};
CentralManager.prototype.saveAIDBToFile = function () {
  try {
    if (!this.state?.metrics) { Logger.warn("Central.saveAI", "无法保存AI数据: state.metrics 未初始化"); return; }
    const data = Object.fromEntries(this.state.metrics.entries()); if (!data || !Object.keys(data).length) { Logger.debug("Central.saveAI", "没有AI数据需要保存"); return; }
    const raw = JSON.stringify(data, null, 2); if (!raw?.length) { Logger.warn("Central.saveAI", "序列化AI数据失败: 结果为空"); return; }
    const store = getKVStore(); const ok = store?.write?.(raw, "ai_node_data");
    if (ok) Logger.debug("Central.saveAI", `AI数据保存成功，共${Object.keys(data).length}条记录`); else Logger.warn("Central.saveAI", "无法保存AI数据: 未找到可用的存储接口");
  } catch (e) { Logger.error("Central.saveAI", "AI数据保存失败:", e?.stack || e); }
};

/* ============== 节点多指标测试（模拟稳定化） ============== */
CentralManager.prototype.testNodeMultiMetrics = async function (node) {
  const cacheKey = `nodeMetrics:${node.id}`; const cached = this.lruCache.get(cacheKey); if (cached) return cached;
  const timeout = this._nodeTimeout();
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
    const result = await Utils.retry(() => probe(), this._nodeAttempts(), this._nodeRetryBase());
    try { this.lruCache.set(cacheKey, result, 60000); } catch {}
    return result;
  } catch (e) {
    // 模拟稳定化：限定抖动范围，减少池波动
    const JITTER_MS = 50, LAT_BASE = 250, LAT_SPAN = 150;
    const LOSS_MAX = 0.08, BYTES_MAX = 28 * 1024;

    return new Promise(resolve => {
      setTimeout(() => {
        const latency = LAT_BASE + Math.random() * LAT_SPAN;
        const loss = Math.random() * LOSS_MAX;
        const jitter = Math.random() * JITTER_MS;
        const bytes = Math.floor(Math.random() * BYTES_MAX);
        const bps = this.throughputEstimator.bpsFromBytesLatency({ bytes, latency });
        const simulated = { latency, loss, jitter, bytes, bps, __simulated: true };
        try { this.lruCache.set(cacheKey, simulated, 60000); } catch {}
        resolve(simulated);
      }, Math.random() * 250);
    });
  }
};

/* ============== 节点管理器（打分与切换） ============== */
class NodeManager extends EventEmitter {
  static getInstance() { if (!NodeManager.instance) NodeManager.instance = new NodeManager(); return NodeManager.instance; }
  constructor() { super(); this.currentNode = null; this.nodeQuality = new Map(); this.switchCooldown = new Map(); this.nodeHistory = new Map(); this.nodeSuccess = new Map(); }
  isInCooldown(id) { const end = this.switchCooldown.get(id); return !!(end && Utils.now() < end); }
  _cooldownTime(id) { const s = Utils.clamp(this.nodeQuality.get(id) || 0, 0, 100); return Utils.clamp(CONSTANTS.BASE_SWITCH_COOLDOWN * (1 + (s / 100) * 0.9), CONSTANTS.MIN_SWITCH_COOLDOWN, CONSTANTS.MAX_SWITCH_COOLDOWN); }
  _recordSwitchEvent(oldId, newId, targetGeo) { Logger.debug("Node.switch", { timestamp: Utils.now(), oldNodeId: oldId, newNodeId: newId, targetGeo: targetGeo ? { country: targetGeo.country, region: targetGeo.regionName || targetGeo.region } : null, reason: oldId ? "质量过低" : "初始选择" }); }
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
    if (!Array.isArray(nodes) || !nodes.length) { Logger.warn("Node.getBest", "节点列表为空或无效"); return null; }
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
    Logger.info("Node.switch", `节点已切换: ${oldId || "无"} -> ${best.id} (质量分: ${this.nodeQuality.get(best.id)}, 区域: ${region})`);
    return best;
  }
  async switchToNode(id, targetGeo) {
    if (!id || typeof id !== "string") { Logger.warn("Node.switchToNode", "无效的节点ID"); return null; }
    if (this.currentNode === id) return { id };
    const central = CentralManager.getInstance?.(); const node = central?.state?.config?.proxies?.find(n => n?.id === id);
    if (!node) { Logger.warn("Node.switchToNode", `尝试切换到不存在的节点: ${id}`); return null; }
    const oldId = this.currentNode; this.currentNode = id;
    this.switchCooldown.set(id, Utils.now() + this._cooldownTime(id));
    this._recordSwitchEvent(oldId, id, targetGeo);
    const st = central.state.nodes?.get(id); const region = st?.geoInfo?.region || st?.geoInfo?.regionName || "未知区域";
    Logger.info("Node.switchToNode", `节点已切换: ${oldId || "无"} -> ${id} (区域: ${region})`);
    return node;
  }
}

/* ============== 主流程入口与导出 ============== */
function main(config) {
  const centralManager = CentralManager.getInstance();
  return centralManager.processConfiguration(config);
}

if (typeof module !== "undefined") { module.exports = { main, CentralManager, NodeManager, Config }; }
