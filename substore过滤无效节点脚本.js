// SubStore 节点过滤脚本 - 智能高效重构版（含地理标识命名）
// 版本: 6.4 (2025)
// 维度: 归一 | 高效 | 快速 | 稳定 | 精准 | 智能 | 自动 | 科学 | 精简 | 多平台兼容 | 模块化 | 先进 | 强大 | 安全 | 隐私保护 | 零干预 | 高内聚低耦合 | 平滑性
"use strict";

// ===================== 配置与常量 =====================
const CONFIG = Object.freeze({
  FREE_KEYWORDS: ["公益", "白嫖", "免费", "白用", "公用"],
  MAX_MULTIPLIER: 15,
  CONCURRENCY: Math.max(5, Math.min(30, typeof navigator?.hardwareConcurrency === "number" ? navigator.hardwareConcurrency * 2 : 8)),
  TIMEOUT: 3000,
  RETRY_TIMES: 3,
  CHUNK_SIZE: 200,
  CACHE_TTL: 3600000,
  MAX_CHECKS: 2000,
  PROGRESS_INTERVAL: 5000,
  BATCH_PROGRESS_INTERVAL: 5000,
  PROGRESS_REPORT_THRESHOLD: 100,
  TIMEOUT_STATS_WINDOW: 10,
  MIN_PORT: 10,
  MAX_PORT: 65000,
  MIN_PASSWORD_LENGTH: 4,
  MAX_PASSWORD_LENGTH: 1024,
  MAX_USERNAME_LENGTH: 256,
  MAX_DOMAIN_LENGTH: 253,
  WIREGUARD_KEY_LENGTH: 44,
  UUID_LENGTH: 36,
  SUPPORTED_TYPES: new Set(["ss","ssr","vmess","trojan","http","https","socks5","socks5-tls","vless","hysteria","hysteria2","tuic","wireguard","snell"]),
  INVALID_KEYWORDS: ["过期","失效","expired","invalid","test","测试","到期","剩余","流量用尽","官网","购买","更新","不支持","disabled","维护","已用完","错误"],
  PORT_BLACKLIST: new Set([25,135,137,138,139,445,1433,3306,3389,69,143,161,162,465,587,993,995,5432,6379,22,23,1935,554,1935,37777,47808]),
  SUPPORTED_CIPHERS: new Set(["aes-128-gcm","aes-192-gcm","aes-256-gcm","chacha20-poly1305","chacha20-ietf-poly1305","xchacha20-poly1305","xchacha20-ietf-poly1305"]),
  SUPPORTED_ALPN: ["h3","h2","http/1.1"],
  TEST_URLS: ["https://www.google.com/generate_204", "https://www.gstatic.com/generate_204", "https://connectivitycheck.gstatic.com/generate_204", "https://cp.cloudflare.com/generate_204"],
  USER_AGENT: "SubStore/1.0"
});

const REGEX = Object.freeze({
  PRIVATE_IP: /^(127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|169\.254\.\d+\.\d+|224\.\d+\.\d+\.\d+|localhost)/,
  MULTIPLIER: /(?:[xX✕✖⨉倍率]|rate)[:\s]*([0-9]+\.?[0-9]*|0*\.[0-9]+)/i,
  INVALID_SERVER_START: /^(0\.|255\.|127\.)/,
  IPV6_CHECK: /^[0-9a-fA-F:]+$/,
  DOMAIN_NAME: /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/,
  IPV4: /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  UUID: /^[a-fA-F0-9-]{36}$/,
  WG_KEY: /^[A-Za-z0-9+/]+={0,2}$/
});

// ===================== 工具库（日志/缓存/校验/通用） =====================
const utils = (() => {
  let isDebug = false, startTime = Date.now();
  const metrics = { checks: 0, hits: 0, misses: 0 }, PERF_MARKS = new Map();

  class LRUCache {
    constructor(maxSize = 5000) { this.maxSize = maxSize; this.cache = new Map(); }
    get(key) {
      const e = this.cache.get(key);
      if (!e || (e.expireAt > 0 && Date.now() >= e.expireAt)) {
        if (e) this.cache.delete(key);
        metrics.misses++;
        return null;
      }
      metrics.hits++;
      this.cache.delete(key);
      this.cache.set(key, e);
      return e.value;
    }
    set(key, value, ttlMs = CONFIG.CACHE_TTL) {
      const expireAt = ttlMs > 0 ? Date.now() + ttlMs : 0;
      if (this.cache.has(key)) this.cache.delete(key);
      else if (this.cache.size >= this.maxSize) this.cache.delete(this.cache.keys().next().value);
      this.cache.set(key, { value, expireAt });
    }
    clear() { this.cache.clear(); }
  }

  const cache = new LRUCache(2000);
  const redact = s => typeof s === "string" ? s.replace(/([Pp]assword|token|secret)\s*[:=]\s*[^,\s]+/g, "$1=<redacted>") : s;
  const makeAbort = timeout => {
    const c = typeof AbortController === "function" ? new AbortController() : null;
    const id = c ? setTimeout(() => { try { c.abort(); } catch {} }, timeout) : null;
    return { signal: c?.signal, clear: () => id && clearTimeout(id) };
  };
  const fetchJSON = async (fetchImpl, url, headers, timeout) => {
    const { signal, clear } = makeAbort(timeout);
    try {
      const res = await fetchImpl(url, { headers, signal });
      clear();
      return res && res.ok ? res.json() : null;
    } catch (e) {
      clear();
      // 特别处理502和握手异常
      if (e && (e.name === "AbortError" || e.name === "TimeoutError" || e.message.includes("502") || e.message.includes("handshake") || e.message.includes("ECONNRESET") || e.message.includes("socket hang up"))) {
        utils.log(`网络请求异常: ${e?.message || String(e)}`, "debug");
      }
      throw e;
    }
  };

  return {
    setDebug: f => { isDebug = !!f; },
    log(msg, type = "info", details = null) {
      if (!isDebug && type !== "error") return;
      const t = new Date().toISOString(), d = details ? `\n${JSON.stringify(details, null, 2)}` : "";
      (typeof console[type] === "function" ? console[type] : console.log)(`[${type.toUpperCase()}][${t}] ${redact(String(msg))}${d}`);
    },
    mark: n => { PERF_MARKS.set(n, Date.now()); },
    measure: n => {
      const s = PERF_MARKS.get(n); if (!s) return 0;
      const d = Date.now() - s; utils.log(`Performance '${n}': ${d}ms`, "debug"); PERF_MARKS.delete(n); return d;
    },
    getMetrics() {
      const rate = metrics.checks ? (metrics.hits / metrics.checks * 100).toFixed(2) : "0.00";
      return { uptime: Math.floor((Date.now() - startTime) / 1000), cacheHitRate: `${rate}%`, checks: metrics.checks, hits: metrics.hits, misses: metrics.misses };
    },
    getCacheKey: (...args) => {
      const arr = [];
      for (const a of args) {
        if (typeof a === "object") arr.push(JSON.stringify(a));
        else if (typeof a === "string" && a.length < 100) arr.push(a);
        else arr.push(String(a));
      }
      return arr.join(":");
    },
    getCachedResult(...args) { metrics.checks++; return cache.get(utils.getCacheKey(...args)); },
    setCacheResult(...args) { const v = args.pop(); cache.set(utils.getCacheKey(...args), v, CONFIG.CACHE_TTL); },
    isValidPort: p => { const n = Number(p); return Number.isInteger(n) && n > 0 && n <= 65535 && !CONFIG.PORT_BLACKLIST.has(n); },
    normalizeServer: s => s ? String(s).trim().toLowerCase().replace(/\.$/, "") : "",
    isValidDomain: d => d && typeof d === "string" && d.length <= CONFIG.MAX_DOMAIN_LENGTH && REGEX.DOMAIN_NAME.test(d),
    isIPV6(ip) { return ip && typeof ip === "string" && ip.includes(":") && (ip.match(/::/g) || []).length <= 1 && REGEX.IPV6_CHECK.test(ip); },
    isValidIPv4(ip) {
      if (!ip || typeof ip !== "string" || ip.length > 15 || !REGEX.IPV4.test(ip)) return false;
      const parts = ip.split(".");
      if (parts.length !== 4) return false;
      for (const p of parts) {
        if (p.length === 0 || p.length > 3) return false;
        const n = parseInt(p, 10);
        if (isNaN(n) || n < 0 || n > 255 || (p.length > 1 && p[0] === "0")) return false;
      }
      return true;
    },
    async retry(fn, times = CONFIG.RETRY_TIMES, initial = 100, maxDelay = 5000) {
      if (typeof fn !== "function") throw new Error("重试函数必须是函数");
      let last;
      const attempts = Math.max(1, times | 0);
      for (let i = 0; i < attempts; i++) {
        try { return await fn(); } catch (e) {
          last = e;
          utils.log(`重试操作失败(${i + 1}/${attempts}): ${e?.message || String(e)}`, "warn");
          if (i < attempts - 1) await new Promise(r => setTimeout(r, Math.min(initial * (2 ** i), maxDelay)));
        }
      }
      throw last || new Error("重试失败");
    },
    validateServer(server) {
      if (!server || typeof server !== "string") return false;
      const s = utils.normalizeServer(server);
      if (!s || REGEX.PRIVATE_IP.test(s) || REGEX.INVALID_SERVER_START.test(s)) return false;
      return utils.isValidDomain(s) || utils.isValidIPv4(s) || utils.isIPV6(s);
    },
    safeJSONParse(str, def = {}) { try { return typeof str === "string" ? JSON.parse(str) : def; } catch (e) { utils.log(`JSON解析失败: ${e?.message || String(e)}`, "error"); return def; } },
    async safeAsync(fn, def = null) { try { return typeof fn === "function" ? await fn() : def; } catch (e) { utils.log(`异步操作失败: ${e?.message || String(e)}`, "error"); return def; } },
    sanitizeInput: (input, max = 1000) => typeof input === "string" ? String(input).slice(0, max).replace(/[\x00-\x1F\x7F]/g, "") : "",
    makeAbort, fetchJSON
  };
})();

// ===================== 并发池（分布式可扩展） =====================
function createAsyncPool(limit) {
  let active = 0, queue = [], paused = false, completed = 0, failed = 0, taskId = 0, start = Date.now();
  const next = () => {
    if (paused || !queue.length || active >= limit) return;
    active++; const { fn, resolve, reject, taskId: tid } = queue.shift(), t0 = Date.now();
    utils.log(`开始任务 #${tid} (活跃: ${active}, 队列: ${queue.length})`, "debug");
    Promise.resolve().then(fn).then(
      r => { completed++; utils.log(`完成任务 #${tid} (${Date.now() - t0}ms)`, "debug"); resolve(r); },
      e => { failed++; utils.log(`任务 #${tid} 失败: ${e?.message || String(e)}`, "error"); reject(e); }
    ).finally(() => { active--; next(); });
  };
  return {
    submit(fn, priority = 0) {
      return new Promise((resolve, reject) => {
        queue.push({ fn, resolve, reject, priority, taskId: ++taskId });
        queue.sort((a,b) => (a.priority||0)-(b.priority||0));
        next();
      });
    },
    pause() { paused = true; return this; },
    resume() { paused = false; for (let i = 0; i < limit; i++) next(); return this; },
    clear() { const n = queue.length; queue.forEach(({ reject }) => reject(new Error("任务已取消"))); queue = []; utils.log(`已清空队列，${n}个任务被取消`, "warn"); return this; },
    status() { return { active, queued: queue.length, completed, failed, total: active + queue.length + completed + failed, uptime: Math.floor((Date.now() - start) / 1000) }; }
  };
}

// ===================== 地理标识命名 =====================
class GeoTagger {
  constructor(options = {}) {
    this.options = this._normalizeOptions(options);
    this._pool = createAsyncPool(this.options.geoConcurrency);
    this._loadEnv();
    this.tldMap = { ...this.options.geo?.tldMap, cn: "中国", hk: "中国香港", mo: "中国澳门", tw: "中国台湾", jp: "日本", sg: "新加坡", us: "美国", kr: "韩国", de: "德国", uk: "英国", gb: "英国", fr: "法国", nl: "荷兰", ru: "俄罗斯", in: "印度", au: "澳大利亚", ca: "加拿大", es: "西班牙", it: "意大利", se: "瑞典", no: "挪威", fi: "芬兰", pl: "波兰", cz: "捷克", br: "巴西", ar: "阿根廷", mx: "墨西哥", id: "印度尼西亚", th: "泰国", my: "马来西亚", ph: "菲律宾", vn: "越南" };
  }
  _normalizeOptions(opt) {
    const o = { enableGeo: true, geoConcurrency: CONFIG.CONCURRENCY, geo: { enableRemote: false, provider: "ip-api", timeout: CONFIG.TIMEOUT }, ...opt };
    o.geoConcurrency = Math.max(1, Math.min(50, o.geoConcurrency | 0));
    o.geo.timeout = Math.max(500, Math.min(10000, o.geo.timeout | 0));
    return o;
  }
  _loadEnv() {
    this.isNode = typeof process?.versions?.node === "string";
    if (this.isNode) {
      try { this.dns = require("dns").promises; } catch { }
      if (typeof fetch === "function") this.fetchImpl = fetch;
      else { try { this.fetchImpl = require("node-fetch"); } catch { } }
    } else { this.fetchImpl = typeof fetch === "function" ? fetch : null; }
  }
  _guessCountryByDomain(domain) {
    if (!domain || !utils.isValidDomain(domain)) return null;
    return this.tldMap[domain.split(".").pop().toLowerCase()] || null;
  }
  async _resolveIP(host) {
    if (utils.isValidIPv4(host) || utils.isIPV6(host)) return host;
    const cached = utils.getCachedResult("dns", host);
    if (cached !== null) return cached;
    let ip = null;
    try {
      if (this.isNode && this.dns) {
        const a = await utils.retry(() => this.dns.lookup(host, { all: true }), CONFIG.RETRY_TIMES);
        ip = Array.isArray(a) && a.length ? a[0].address : null;
      } else if (this.fetchImpl) {
        const sanitizedHost = host.replace(/[^a-zA-Z0-9.-]/g, "");
        if (sanitizedHost !== host) throw new Error("Invalid characters in hostname");
        const url = `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(sanitizedHost)}&type=A`;
        const json = await utils.fetchJSON(this.fetchImpl, url, { "accept": "application/dns-json", "User-Agent": CONFIG.USER_AGENT }, this.options.geo.timeout);
        ip = json?.Answer?.find(a => a?.type === 1 && a?.data)?.data || null;
      }
    } catch (e) { utils.log(`DNS解析失败: ${host} - ${e?.message || String(e)}`, "debug"); }
    utils.setCacheResult("dns", host, ip);
    return ip;
  }
  async _remoteGeo(ip) {
    if (!this.options.geo.enableRemote || !this.fetchImpl || !ip) return null;
    const key = utils.getCacheKey("geo", ip, this.options.geo.provider), cached = utils.getCachedResult(key);
    if (cached !== null) return cached;
    let r = null;
    try {
      const sanitizedIP = ip.replace(/[^0-9a-fA-F:.]/g, "");
      if (sanitizedIP !== ip) throw new Error("Invalid characters in IP address");
      const url = `https://ip-api.com/json/${encodeURIComponent(sanitizedIP)}?fields=status,country,countryCode,regionName,city`;
      const data = await utils.fetchJSON(this.fetchImpl, url, { "User-Agent": CONFIG.USER_AGENT }, this.options.geo.timeout);
      if (data?.status === "success") r = { country: data.country || null, city: data.city || data.regionName || null };
    } catch (e) { utils.log(`远程地理解析失败: ${ip} - ${e?.message || String(e)}`, "debug"); }
    utils.setCacheResult(key, r);
    return r;
  }
  _composeLabel(country, city) { return country ? (city ? `[${country}-${city}]` : `[${country}]`) : `[未知]`; }
  async tagOne(proxy) {
    try {
      const server = utils.normalizeServer(proxy.server);
      if (!server) return proxy;
      const byDomain = this._guessCountryByDomain(server), ip = await this._resolveIP(server);
      const geo = byDomain ? null : await this._remoteGeo(ip);
      const label = this._composeLabel(byDomain || geo?.country || null, geo?.city || null);
      const originalName = String(proxy.name || "").trim();
      // 仅当原始名称不包含地理标签时才添加新标签，避免重复标签
      const hasGeoTag = /^\[.{1,10}(-.{1,10})?\]/.test(originalName);
      const newName = hasGeoTag ? originalName : `${label} ${originalName || `${server}:${proxy.port}`}`;
      return { ...proxy, name: newName.trim(), ip: ip || proxy.ip || undefined };
    } catch (e) { utils.log(`地理标识失败: ${proxy?.server}:${proxy?.port} - ${e?.message || String(e)}`, "debug"); return proxy; }
  }
  async tagAll(proxies = []) {
    if (!this.options.enableGeo || !Array.isArray(proxies) || !proxies.length) return proxies;
    const tasks = proxies.map(p => this._pool.submit(() => this.tagOne(p)));
    const settled = await Promise.allSettled(tasks);
    return settled.map((r, i) => r.status === "fulfilled" ? r.value : proxies[i]);
  }
}

// ===================== 节点校验器（核心） =====================
class ProxyValidator {
  constructor(options = {}) {
    this.options = this._normalizeOptions(options);
    utils.setDebug(this.options.debug);
    this._init();
    this._pool = createAsyncPool(this.options.concurrency);
    this.stats = { startTime: Date.now(), validationTime: 0, connectivityTime: 0, dedupTime: 0, validCount: 0, invalidCount: 0, timeoutCount: 0, errorCount: 0 };
    this._loadNodeDependencies();
  }
  _normalizeOptions(opt) {
    const o = { debug: false, freeKeywords: CONFIG.FREE_KEYWORDS, maxMultiplier: CONFIG.MAX_MULTIPLIER, concurrency: CONFIG.CONCURRENCY, timeout: CONFIG.TIMEOUT, supportedTypes: CONFIG.SUPPORTED_TYPES, invalidKeywords: CONFIG.INVALID_KEYWORDS, portBlacklist: CONFIG.PORT_BLACKLIST, retryTimes: CONFIG.RETRY_TIMES, chunkSize: CONFIG.CHUNK_SIZE, maxChecks: CONFIG.MAX_CHECKS, progressInterval: CONFIG.PROGRESS_INTERVAL, adaptiveTimeout: true, fastFail: true, testUrls: CONFIG.TEST_URLS, enableGeo: true, geoConcurrency: CONFIG.CONCURRENCY, geo: { enableRemote: false, provider: "ip-api", timeout: CONFIG.TIMEOUT }, allowPrivateIPs: false, ...opt };
    o.concurrency = Math.max(1, Math.min(50, o.concurrency | 0));
    o.timeout = Math.max(500, Math.min(30000, o.timeout | 0));
    o.retryTimes = Math.max(1, Math.min(10, o.retryTimes | 0));
    o.chunkSize = Math.max(50, Math.min(1000, o.chunkSize | 0));
    o.maxChecks = Math.max(100, Math.min(100000, o.maxChecks | 0));
    o.progressInterval = Math.max(500, Math.min(30000, o.progressInterval | 0));
    o.geo.timeout = Math.max(500, Math.min(10000, o.geo.timeout | 0));
    return o;
  }
  _loadNodeDependencies() {
    const isNode = typeof process?.versions?.node === "string";
    if (!isNode) return;
    if (typeof fetch === "function") this.fetchImpl = fetch;
    const tryRequire = n => { try { const m = require(n); return m && (typeof m === "function" ? m : (m.default || m)); } catch { return null; } };
    if (!this.fetchImpl) this.fetchImpl = tryRequire("node-fetch") || null;
    const socksAgent = tryRequire("socks-proxy-agent");
    if (socksAgent) this.SocksProxyAgent = socksAgent.SocksProxyAgent || socksAgent.default?.SocksProxyAgent || socksAgent;
    const httpProxyAgent = tryRequire("http-proxy-agent");
    if (httpProxyAgent) { this.HttpProxyAgent = httpProxyAgent.HttpProxyAgent || httpProxyAgent.default?.HttpProxyAgent || httpProxyAgent; this.HttpsProxyAgent = httpProxyAgent.HttpsProxyAgent || httpProxyAgent.default?.HttpsProxyAgent || httpProxyAgent; }
  }
  _init() {
    this.keywordSet = new Set([...this.options.invalidKeywords, ...this.options.freeKeywords].filter(Boolean).map(k => k.toLowerCase()));
    this.connectivityChecks = 0;
    this.checkedServers = new Set();
    this.timeoutStats = { success: [], failure: [], avgSuccessTime: this.options.timeout / 2, avgFailureTime: this.options.timeout };
    this.progress = { total: 0, current: 0, lastReportTime: 0 };
  }
  _reportProgress(force = false) {
    const now = Date.now();
    if (!force && (now - this.progress.lastReportTime) <= this.options.progressInterval) return;
    const pct = this.progress.total ? Math.round(this.progress.current / this.progress.total * 100) : 0;
    utils.log(`进度: ${this.progress.current}/${this.progress.total} (${pct}%)`, "info");
    if (this.progress.current > 0) {
      const elapsed = (now - this.stats.startTime) / 1000, rate = elapsed > 0 ? (this.progress.current / elapsed) : 0, eta = rate > 0 ? ((this.progress.total - this.progress.current) / rate) : 0;
      utils.log(`速率: ${rate.toFixed(2)}节点/秒, 预计剩余时间: ${eta.toFixed(0)}秒`, "info");
    }
    this.progress.lastReportTime = now;
  }
  isValidBasic(proxy) {
    try {
      if (!proxy || typeof proxy !== "object" || Array.isArray(proxy)) return false;
      const server = utils.normalizeServer(proxy.server), port = Number(proxy.port), type = String(proxy.type || "").toLowerCase();
      if (!server || !port || !type || Number.isNaN(port)) return false;
      if (!utils.validateServer(server) || !utils.isValidPort(port) || !this.options.supportedTypes.has(type)) return false;
      // 增加对特殊IP范围的检查
      if (REGEX.PRIVATE_IP.test(server) && !this.options.allowPrivateIPs) return false;
      if (!this._validateByType(proxy)) return false;
      const name = (proxy.name || "").toString().toLowerCase();
      for (const k of this.keywordSet) if (name.includes(k)) return false;
      const m = name.match(REGEX.MULTIPLIER);
      if (m) { const v = parseFloat(m[1]); if (!Number.isNaN(v) && v > this.options.maxMultiplier) return false; }
      if (proxy.free === true) return false;
      const invalid = (port === 80 && !["http", "https", "trojan"].includes(type)) || (port === 443 && !["https", "trojan", "vmess", "vless"].includes(type)) || (port < CONFIG.MIN_PORT || port > CONFIG.MAX_PORT) || (type === "vmess" && Number(proxy.aid) > 0) || (type === "ss" && (proxy.cipher === "rc4" || proxy.method === "rc4")) || (proxy.tls && !proxy.sni && !utils.isValidDomain(server));
      return !invalid;
    } catch (e) { utils.log(`验证过程出错: ${e?.message || String(e)}`, "error"); this.stats.errorCount++; return false; }
  }
  _validateByType(p) {
    try {
      const t = String(p.type || "").toLowerCase();
      // 增强 vmess/vless 验证
      if (["vmess", "vless"].includes(t)) {
        if (!this._validateUUID(p.uuid)) return false;
        if (t === "vmess" && Number(p.aid) > 0) return false;
        // 检查 vless 特定字段
        if (t === "vless" && p.flow && typeof p.flow !== "string") return false;
        return true;
      }
      if (["trojan", "snell"].includes(t)) return this._validatePassword(p.password);
      if (["ss", "ssr"].includes(t)) {
        if (!this._validatePassword(p.password)) return false;
        if (!this._validateCipher(p.cipher)) return false;
        // 额外验证 ssr 特定字段
        if (t === "ssr" && p.protocol && typeof p.protocol !== "string") return false;
        if (t === "ssr" && p.obfs && typeof p.obfs !== "string") return false;
        return true;
      }
      if (["hysteria", "hysteria2", "tuic"].includes(t)) {
        if (!(p.password || p.token)) return false;
        if (p.alpn && !this._validateALPN(p.alpn)) return false;
        // 检查特定协议的额外字段
        if (t === "hysteria" && p.up && isNaN(Number(p.up))) return false;
        if (t === "hysteria2" && p.obfs && typeof p.obfs !== "string") return false;
        return true;
      }
      if (t === "wireguard") return this._validateWireGuardKey(p.privateKey) && this._validatePublicKey(p.publicKey);
      if (["http", "https", "socks5", "socks5-tls"].includes(t)) return !(p.username || p.password) || this._validateCredentials(p.username, p.password);
      return false;
    } catch (e) { utils.log(`类型验证出错: ${e?.message || String(e)}`, "error"); return false; }
  }
  _validateUUID(uuid) { return uuid && typeof uuid === "string" && uuid.length === CONFIG.UUID_LENGTH && REGEX.UUID.test(uuid); }
  _validatePassword(password) { return password && typeof password === "string" && password.length >= CONFIG.MIN_PASSWORD_LENGTH && password.length <= CONFIG.MAX_PASSWORD_LENGTH; }
  _validateCipher(cipher) { return cipher && typeof cipher === "string" && cipher.toLowerCase() !== "none" && CONFIG.SUPPORTED_CIPHERS.has(cipher.toLowerCase()); }
  _validateALPN(alpn) { return alpn && typeof alpn === "string" && CONFIG.SUPPORTED_ALPN.includes(alpn); }
  _validateWireGuardKey(key) { return key && typeof key === "string" && key.length === CONFIG.WIREGUARD_KEY_LENGTH && REGEX.WG_KEY.test(key); }
  _validatePublicKey(key) { return key && typeof key === "string" && key.length === CONFIG.WIREGUARD_KEY_LENGTH && REGEX.WG_KEY.test(key); }
  _validateCredentials(u, p) { return (!u || (typeof u === "string" && u.length > 0 && u.length <= CONFIG.MAX_USERNAME_LENGTH)) && (!p || (typeof p === "string" && p.length > 0 && p.length <= CONFIG.MAX_PASSWORD_LENGTH)); }
  async isNodeConnectable(host, port) {
    const key = `${host}:${port}`;
    if (this.connectivityChecks >= this.options.maxChecks || this.checkedServers.has(key) || !this.fetchImpl) return true;
    const cached = utils.getCachedResult("nodeCheck", host, port);
    if (cached !== null) { this.checkedServers.add(key); return cached; }
    this.connectivityChecks++;
    const start = Date.now();
    try {
      let timeout = this.options.timeout;
      if (this.options.adaptiveTimeout && this.timeoutStats.success.length >= 5) {
        const adaptive = Math.max(this.timeoutStats.avgSuccessTime * 2, Math.min(this.options.timeout, this.timeoutStats.avgFailureTime));
        timeout = Math.max(1000, Math.min(adaptive, this.options.timeout * 2));
      }
      const ok = await utils.retry(() => this._testHTTP(timeout), this.options.retryTimes);
      const dt = Date.now() - start, pushAvg = (arr, v, cap) => { arr.push(v); if (arr.length > cap) arr.shift(); return arr.reduce((a,b)=>a+b,0)/arr.length; };
      if (ok) this.timeoutStats.avgSuccessTime = pushAvg(this.timeoutStats.success, dt, CONFIG.TIMEOUT_STATS_WINDOW);
      else this.timeoutStats.avgFailureTime = pushAvg(this.timeoutStats.failure, dt, CONFIG.TIMEOUT_STATS_WINDOW);
      utils.setCacheResult("nodeCheck", host, port, ok);
      this.checkedServers.add(key);
      return ok;
    } catch (e) {
      utils.log(`连接测试异常: ${e?.message || String(e)}`, "error");
      this.stats.errorCount++;
      utils.setCacheResult("nodeCheck", host, port, false);
      this.checkedServers.add(key);
      return false;
    } finally { this.stats.connectivityTime += (Date.now() - start); }
  }
  async _testHTTP(timeoutMs = this.options.timeout) {
    const f = this.fetchImpl || (typeof fetch === "function" ? fetch : null);
    if (!f) return true;
    const urls = Array.isArray(this.options.testUrls) ? this.options.testUrls : CONFIG.TEST_URLS;
    const tasks = urls.map(url => (async () => {
      const { signal, clear } = utils.makeAbort(timeoutMs);
      try {
        const res = await f(url, { method: "GET", headers: { "User-Agent": CONFIG.USER_AGENT }, signal });
        clear();
        return res && res.status === 204;
      } catch (e) {
        clear();
        if (e && (e.name === "AbortError" || e.name === "TimeoutError")) { this.stats.timeoutCount++; utils.log(`测试URL超时: ${url}`, "debug"); }
        else utils.log(`测试URL失败: ${url} - ${e?.message || String(e)}`, "debug");
        return false;
      }
    })());
    const r = await Promise.allSettled(tasks);
    return r.some(x => x.status === "fulfilled" && x.value === true);
  }
  getNodeKey(p) {
    try {
      if (!p || typeof p !== "object") return "invalid";
      const s = utils.normalizeServer(p.server), t = String(p.type || "").toLowerCase(), port = Number(p.port);
      if (!s || !t || Number.isNaN(port)) return "invalid";
      const k = [t, s, String(port)];
      if (["vmess", "vless"].includes(t)) {
        if (p.uuid) k.push(String(p.uuid));
        if (p.aid) k.push(String(p.aid));
        if (p.encryption) k.push(String(p.encryption));
        if (p.tls) k.push("tls");
        if (p.network) k.push(String(p.network));
      } else if (["ss", "ssr"].includes(t)) {
        if (p.cipher) k.push(String(p.cipher));
        if (p.password) k.push(String(p.password));
        if (p.protocol) k.push(String(p.protocol));
        if (p.obfs) k.push(String(p.obfs));
        if (p.obfsParam) k.push(String(p.obfsParam));
        if (p.protocolParam) k.push(String(p.protocolParam));
      } else if (["trojan", "snell"].includes(t)) {
        if (p.password) k.push(String(p.password));
        if (p.sni) k.push(String(p.sni));
        if (p.alpn) k.push(String(p.alpn));
      } else if (["hysteria", "hysteria2", "tuic"].includes(t)) {
        if (p.password) k.push(String(p.password));
        if (p.token) k.push(String(p.token));
        if (p.alpn) k.push(String(p.alpn));
        if (p.sni) k.push(String(p.sni));
        if (p.obfs) k.push(String(p.obfs));
      } else if (t === "wireguard") {
        if (p.privateKey) k.push(String(p.privateKey));
        if (p.publicKey) k.push(String(p.publicKey));
        if (p.endpoint) k.push(String(p.endpoint));
      } else if (["http", "https", "socks5", "socks5-tls"].includes(t)) {
        if (p.username) k.push(String(p.username));
        if (p.password) k.push(String(p.password));
        if (p.tls) k.push("tls");
      }
      return k.filter(Boolean).join(":");
    } catch (e) { utils.log(`生成节点键出错: ${e?.message || String(e)}`, "error"); return p ? `${p.type || "unknown"}:${p.server || "unknown"}:${p.port || "unknown"}` : "invalid"; }
  }
  async validateAll(proxies) {
    if (!Array.isArray(proxies)) { utils.log("输入必须是数组", "error"); return []; }
    if (proxies.length === 0) { utils.log("节点列表为空", "info"); return []; }
    utils.mark("total");
    utils.log(`开始验证，共${proxies.length}个节点`, "info");
    this.progress.total = proxies.length;
    this.progress.current = 0;

    try {
      utils.mark("basic");
      const valid = [];
      for (const p of proxies) {
        this.progress.current++;
        if (this.progress.current % CONFIG.PROGRESS_REPORT_THRESHOLD === 0) this._reportProgress();
        if (this.isValidBasic(p)) { this.stats.validCount++; valid.push(p); }
        else { this.stats.invalidCount++; }
      }
      const basicTime = utils.measure("basic");
      utils.log(`基础验证完成: ${proxies.length} -> ${valid.length} 个节点 (${basicTime}ms)`, "info");

      utils.mark("prededup");
      const preDeduped = await this._dedup(valid);
      const preDedupTime = utils.measure("prededup");
      utils.log(`预去重完成: ${valid.length} -> ${preDeduped.length} 个节点 (${preDedupTime}ms)`, "info");

      utils.mark("connect");
      this.progress.total = preDeduped.length;
      this.progress.current = 0;
      this._reportProgress(true);
      const tested = await this._batchCheck(preDeduped);
      const connectTime = utils.measure("connect");
      utils.log(`连接测试完成: ${preDeduped.length} -> ${tested.length} 个节点 (${connectTime}ms)`, "info");

      utils.mark("finaldedup");
      const unique = await this._dedup(tested);
      const finalDedupTime = utils.measure("finaldedup");
      utils.log(`最终去重完成: ${tested.length} -> ${unique.length} 个节点 (${finalDedupTime}ms)`, "info");

      utils.mark("geotag");
      const geoTagger = new GeoTagger({ enableGeo: this.options.enableGeo, geoConcurrency: this.options.geoConcurrency, geo: this.options.geo });
      const tagged = await geoTagger.tagAll(unique);
      const geoTime = utils.measure("geotag");
      utils.log(`地理标识完成: ${tagged.length} 个节点 (${geoTime}ms)`, "info");

      const totalTime = utils.measure("total");
      utils.log(`验证流程完成: 共处理 ${proxies.length} 个节点，最终保留 ${tagged.length} 个有效节点 (总耗时: ${totalTime}ms)`, "info");
      utils.log(`性能统计: 基础验证=${basicTime}ms, 连接测试=${connectTime}ms, 去重=${preDedupTime + finalDedupTime}ms, 地理标识=${geoTime}ms`, "info");
      return tagged;
    } catch (e) { utils.log(`验证过程出错: ${e?.message || String(e)}`, "error"); return []; }
  }
  async validateProxyConnect(proxy) {
    if (!proxy || typeof proxy !== "object") return false;
    if (!this.fetchImpl) return true;
    const testUrl = CONFIG.TEST_URLS[0], timeout = this.options.timeout, key = utils.getCacheKey("proxyCheck", proxy.server, proxy.port, proxy.type), cached = utils.getCachedResult(key);
    if (cached !== null) return cached;
    let ok = false;
    try {
      switch (proxy.type) {
        case "socks5":
        case "socks5-tls": {
          if (!this.SocksProxyAgent || !this.fetchImpl) break;
          const agent = new this.SocksProxyAgent({ hostname: String(proxy.server), port: Number(proxy.port), userId: proxy.username, password: proxy.password });
          const { signal, clear } = utils.makeAbort(timeout);
          const res = await this.fetchImpl(testUrl, { agent, signal });
          clear();
          ok = !!(res && res.status === 204);
          break;
        }
        case "http":
        case "https": {
          if (!this.HttpProxyAgent || !this.HttpsProxyAgent || !this.fetchImpl) break;
          const proxyUrl = `${proxy.type}://${proxy.server}:${proxy.port}`, Agent = proxy.type === "http" ? this.HttpProxyAgent : this.HttpsProxyAgent, agent = new Agent(proxyUrl), { signal, clear } = utils.makeAbort(timeout);
          const res = await this.fetchImpl(testUrl, { agent, signal });
          clear();
          ok = !!(res && res.status === 204);
          break;
        }
        default:
          ok = await this._testHTTP(timeout);
      }
    } catch (e) { utils.log(`代理协议检测失败: ${proxy.type} ${proxy.server}:${proxy.port} - ${e?.message || String(e)}`, "error"); ok = false; }
    utils.setCacheResult(key, ok);
    return ok;
  }
  async _batchCheck(proxies) {
    if (!Array.isArray(proxies) || !proxies.length) return [];
    utils.mark("batchCheck");
    const stats = { total: proxies.length, checked: 0, valid: 0, failed: 0, skipped: 0, errors: 0 };
    try {
      const groups = new Map();
      for (const p of proxies) {
        if (!p || typeof p !== "object") continue;
        const s = utils.normalizeServer(p.server), port = Number(p.port);
        if (!s || Number.isNaN(port)) continue;
        const k = `${s}:${port}`;
        if (!groups.has(k)) groups.set(k, []);
        groups.get(k).push(p);
      }
      utils.log(`开始批量检查: ${groups.size} 个唯一服务器组，共 ${proxies.length} 个节点`, "info");

      const results = [], entries = Array.from(groups.entries());
      if (!entries.length) return [];
      let lastReport = Date.now(), start = Date.now();

      const tasks = entries.map(([key, group]) => this._pool.submit(async () => {
        const [host, portStr] = key.split(":"), numPort = Number(portStr);
        try {
          if (Number.isNaN(numPort) || this.options.portBlacklist.has(numPort)) { stats.skipped += group.length; return; }
          const testProxy = group[0];
          if (!testProxy || typeof testProxy !== "object") { stats.failed += group.length; return; }
          let isValid = false;
          try { isValid = await utils.retry(() => this.validateProxyConnect(testProxy), this.options.retryTimes); }
          catch (e) { utils.log(`节点组最终失败: ${key} - ${e?.message || String(e)}`, "debug"); }
          if (isValid) { results.push(...group); stats.valid += group.length; }
          else { stats.failed += group.length; }
        } catch (e) { stats.errors += group.length; utils.log(`检查出错: ${key} - ${e?.message || String(e)}`, "error"); }
        finally {
          stats.checked += group.length;
          const now = Date.now();
          if (now - lastReport >= CONFIG.BATCH_PROGRESS_INTERVAL) { this._reportBatchProgress(stats, start); lastReport = now; }
        }
      }));

      await Promise.allSettled(tasks);
      this._reportBatchProgress(stats, start, true);
      const batchTime = utils.measure("batchCheck");
      utils.log(`批量检查完成: ${results.length}/${proxies.length} 个节点有效 (${batchTime}ms)`, "info");
      return results;
    } catch (e) { utils.log(`批量检查过程出错: ${e?.message || String(e)}`, "error"); return []; }
  }
  _reportBatchProgress(stats, startTime, final = false) {
    const elapsed = (Date.now() - startTime) / 1000, pct = stats.total ? ((stats.checked / stats.total) * 100).toFixed(1) : "0.0", rate = elapsed > 0 ? (stats.checked / elapsed).toFixed(1) : "0.0", remaining = Math.max(0, stats.total - stats.checked), eta = Number(rate) > 0 ? ((remaining / Number(rate))).toFixed(0) : "未知", msg = [`进度: ${pct}% (${stats.checked}/${stats.total})`, `速率: ${rate} 节点/秒`, `有效: ${stats.valid}`, `失败: ${stats.failed}`, `跳过: ${stats.skipped}`, `错误: ${stats.errors}`, `已用时间: ${elapsed.toFixed(0)}秒`, `预计剩余: ${eta}秒`].join(", ");
    utils.log(msg, final ? "info" : "debug");
  }
  _dedup(proxies) {
    if (!Array.isArray(proxies) || !proxies.length) return proxies;
    utils.mark("dedup");
    const seen = new Map(), unique = [], stats = { total: proxies.length, duplicates: 0, updates: 0 };
    try {
      for (const p of proxies) {
        if (!p || typeof p !== "object") continue;
        const k = this.getNodeKey(p);
        if (!k || k === "invalid") continue;
        const ex = seen.get(k);
        if (!ex) { seen.set(k, { proxy: p, index: unique.length }); unique.push(p); continue; }
        stats.duplicates++;
        if (this._isBetter(p, ex.proxy)) { unique[ex.index] = p; seen.set(k, { proxy: p, index: ex.index }); stats.updates++; }
      }
      const t = utils.measure("dedup");
      utils.log(`去重完成: 处理 ${stats.total} 个节点，发现 ${stats.duplicates} 个重复，更新 ${stats.updates} 个节点 (${t}ms)`, "info");
      return unique;
    } catch (e) { utils.log(`去重过程出错: ${e?.message || String(e)}`, "error"); return proxies; }
  }
  _getQualityScore(p) {
    if (!p || typeof p !== "object") return 0;
    try {
      let s = 0;
      if (p.tls) s += 10;
      const net = String(p.network || "").toLowerCase();
      if (net === "ws") s += 5;
      if (net === "grpc") s += 6;
      if (net === "h2") s += 7;
      s += Math.min(Object.keys(p).length, 20);
      const name = String(p.name || "").toLowerCase();
      if (name.includes("premium")) s += 15;
      if (name.includes("vip")) s += 12;
      if (name.includes("高级")) s += 12;
      if (name.includes("高速")) s += 10;
      if (name.includes("标准")) s += 8;
      if (name.includes("game")) s += 8;
      if (name.includes("netflix")) s += 6;
      switch (String(p.type || "").toLowerCase()) {
        case "vless":
        case "trojan": s += 10; break;
        case "vmess": s += 8; break;
        case "ss": s += 6; break;
        case "ssr": s += 4; break;
      }
      if (p.alpn) s += 5;
      if (p.sni) s += 5;
      if (p.udp) s += 3;
      return s;
    } catch (e) { utils.log(`计算质量分数出错: ${e?.message || String(e)}`, "error"); return 0; }
  }
  _isBetter(a, b) {
    try {
      if (!a || !b) return false;
      const sa = this._getQualityScore(a), sb = this._getQualityScore(b);
      if (sa !== sb) return sa > sb;
      if (a.path && b.path && typeof a.path === "string" && typeof b.path === "string" && a.path.length !== b.path.length) return a.path.length < b.path.length;
      const ha = !!(a.name && typeof a.name === "string"), hb = !!(b.name && typeof b.name === "string");
      if (ha && hb && a.name.length !== b.name.length) return a.name.length < b.name.length;
      return false;
    } catch (e) { utils.log(`节点比较出错: ${e?.message || String(e)}`, "error"); return false; }
  }
}

// ===================== 过滤引擎（集成地理标识） =====================
class FilterEngine {
  constructor(options = {}) { this.validator = new ProxyValidator(options); }
  async filter(proxies = []) { return await this.validator.validateAll(proxies); }
}

// ===================== 外部调用入口 =====================
async function filter(proxies = [], options = {}) {
  try {
    if (!Array.isArray(proxies)) { utils.log("输入必须是数组", "error"); return []; }
    const engine = new FilterEngine(options);
    return await engine.filter(proxies);
  } catch (e) { utils.log(`过滤过程出错: ${e?.message || String(e)}`, "error"); return []; }
}

if (typeof module !== "undefined" && module.exports) module.exports = filter;
else if (typeof window !== "undefined") window.filter = filter;
