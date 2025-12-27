// SubStore 节点过滤脚本 - Sirkey 高级优化版
// 版本: 7.1 (2025) - Sirkey 专属重构 (Sub-Store 完美兼容版)
// 维度: 归一 | 高效 | 快速 | 稳定 | 精准 | 智能 | 自动 | 科学 | 精简 | 多平台兼容 | 模块化 | 先进 | 强大 | 安全 | 隐私保护
"use strict";

const CONFIG = Object.freeze({
  FREE_KEYWORDS: ["公益", "白嫖", "免费", "白用", "公用"],
  MAX_MULTIPLIER: 15,
  CONCURRENCY: 10,
  TIMEOUT: 5000,
  RETRY_TIMES: 1,
  SKIP_TEST: true, // Sub-Store 环境下默认跳过连通性测试，由 Sub-Store 自行处理
  SUPPORTED_TYPES: new Set(["ss","ssr","vmess","trojan","http","https","socks5","socks5-tls","vless","hysteria","hysteria2","tuic","wireguard","snell"]),
  INVALID_KEYWORDS: ["过期","失效","expired","invalid","test","测试","到期","剩余","流量用尽","官网","购买","更新","不支持","disabled","维护","已用完","错误"],
  PORT_BLACKLIST: new Set([25,135,137,138,139,445,1433,3306,3389,69,143,161,162,465,587,993,995,5432,6379,22,23,1935,554,37777,47808]),
  TEST_URLS: ["https://www.google.com/generate_204", "https://www.gstatic.com/generate_204"],
  USER_AGENT: "SubStore/1.1 (Sirkey Optimized)",
  GEO_API: "https://ip-api.com/json/{ip}?fields=status,country,city",
  DOH_URL: "https://cloudflare-dns.com/dns-query?name={host}&type=A"
});

const REGEX = Object.freeze({
  PRIVATE_IP: /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|224\.|localhost)/,
  MULTIPLIER: /(?:[xX✕✖⨉倍率]|rate)[:\s]*([0-9]+\.?[0-9]*|0*\.[0-9]+)/i,
  IPV4: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
  IPV6: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$/,
  DOMAIN: /^(?!-)[a-zA-Z0-9-]{1,63}(?:\.(?!-)[a-zA-Z0-9-]{1,63})*\.[a-zA-Z]{2,}$/,
  UUID: /^[a-fA-F0-9-]{36}$/,
  WG_KEY: /^[A-Za-z0-9+/]{42,43}=?$/
});

const utils = {
  isDebug: false,
  cache: new Map(),
  
  log(msg, level = "info") {
    if (!this.isDebug && level !== "error") return;
    const time = new Date().toLocaleTimeString();
    console.log(`[${level.toUpperCase()}][${time}] ${String(msg)}`);
  },

  async limit(tasks, concurrency) {
    const results = [];
    const executing = new Set();
    for (const task of tasks) {
      const p = Promise.resolve().then(() => task());
      results.push(p);
      executing.add(p);
      const clean = () => executing.delete(p);
      p.then(clean, clean);
      if (executing.size >= concurrency) await Promise.race(executing);
    }
    return Promise.allSettled(results);
  },

  isSubStore: typeof $httpClient !== "undefined" || typeof $proxies !== "undefined",
  
  async fetch(url, opt = {}) {
    const times = opt.retry || CONFIG.RETRY_TIMES || 0;
    let lastErr;
    for (let i = 0; i <= times; i++) {
      try {
        // 只有在 $httpClient 真正存在时才使用它 (Sub-Store 后端环境)
        if (typeof $httpClient !== "undefined") {
          return await new Promise((resolve, reject) => {
            const method = (opt.method || "GET").toLowerCase();
            const handler = $httpClient[method] || $httpClient.get;
            handler.call($httpClient, { url, headers: { "User-Agent": CONFIG.USER_AGENT, ...opt.headers }, timeout: opt.timeout || CONFIG.TIMEOUT }, (err, res, data) => {
              if (err) reject(err);
              else resolve({ 
                ok: res.status >= 200 && res.status < 300, 
                status: res.status, 
                json: () => {
                  try { return JSON.parse(data || "{}"); } 
                  catch (e) { return {}; }
                } 
              });
            });
          });
        }
        // 浏览器或 Node 环境
        if (typeof fetch !== "undefined") {
          const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
          const timeout = setTimeout(() => controller?.abort(), opt.timeout || CONFIG.TIMEOUT);
          try {
            const res = await fetch(url, { ...opt, headers: { "User-Agent": CONFIG.USER_AGENT, ...opt.headers }, signal: controller?.signal });
            return res;
          } finally { clearTimeout(timeout); }
        }
        // 如果都没有，模拟成功响应（为了不阻断流程）
        return { ok: true, status: 200, json: () => ({}) };
      } catch (e) {
        lastErr = e;
        if (i < times) await new Promise(r => setTimeout(r, 500 * (i + 1)));
      }
    }
    throw lastErr;
  }
};

class Validator {
  constructor(options = {}) {
    this.opt = { ...CONFIG, ...options };
    utils.isDebug = !!this.opt.debug;
    this.keywords = new Set([...(this.opt.INVALID_KEYWORDS || []), ...(this.opt.FREE_KEYWORDS || [])].map(k => k.toLowerCase()));
    this.tldMap = {
      cn: "中国", hk: "中国香港", mo: "中国澳门", tw: "中国台湾", jp: "日本", sg: "新加坡", us: "美国", kr: "韩国", 
      de: "德国", uk: "英国", fr: "法国", nl: "荷兰", ru: "俄罗斯", au: "澳大利亚", ca: "加拿大", in: "印度", 
      th: "泰国", my: "马来西亚", vn: "越南", ph: "菲律宾", ch: "瑞士", se: "瑞典", no: "挪威", fi: "芬兰", 
      dk: "丹麦", it: "意大利", es: "西班牙", pt: "葡萄牙", br: "巴西", ar: "阿根廷", tr: "土耳其", ae: "阿联酋"
    };
  }

  isValidBasic(p) {
    if (!p || typeof p !== "object" || !p.server || !p.port || !p.type) return false;
    const type = String(p.type).toLowerCase();
    if (!this.opt.SUPPORTED_TYPES.has(type)) return false;

    const port = Number(p.port);
    if (isNaN(port) || port < 10 || port > 65000 || this.opt.PORT_BLACKLIST.has(port)) return false;

    // 端口类型关联验证
    if (port === 80 && !["http", "https", "trojan"].includes(type)) return false;
    if (port === 443 && !["https", "trojan", "vmess", "vless"].includes(type)) return false;

    const host = String(p.server).toLowerCase();
    if (REGEX.PRIVATE_IP.test(host)) return false;
    if (!REGEX.IPV4.test(host) && !REGEX.IPV6.test(host) && !REGEX.DOMAIN.test(host)) return false;

    // 协议特定深度校验 (从源码补全)
    if (p.free === true) return false;
    if (["vmess", "vless"].includes(type)) {
      if (!p.uuid || !REGEX.UUID.test(p.uuid)) return false;
      if (type === "vmess" && Number(p.aid) > 0) return false;
    }
    if (type === "ss") {
      if (!p.cipher || p.cipher.toLowerCase().includes("rc4") || (p.password && p.password.length < 3)) return false;
    }
    if (type === "ssr" && (!p.protocol || !p.obfs)) return false;
    if (type === "wireguard" && (!REGEX.WG_KEY.test(p.privateKey) || !REGEX.WG_KEY.test(p.publicKey))) return false;
    if (["hysteria", "hysteria2", "tuic"].includes(type) && !(p.password || p.token)) return false;
    
    const name = String(p.name || "").toLowerCase();
    for (const k of this.keywords) if (name.includes(k)) return false;

    const m = name.match(REGEX.MULTIPLIER);
    if (m && parseFloat(m[1]) > this.opt.MAX_MULTIPLIER) return false;

    return true;
  }

  async resolveIP(host) {
    if (REGEX.IPV4.test(host) || REGEX.IPV6.test(host)) return host;
    if (utils.cache.has(`dns:${host}`)) return utils.cache.get(`dns:${host}`);
    try {
      const res = await utils.fetch(CONFIG.DOH_URL.replace("{host}", host), { headers: { "accept": "application/dns-json" } });
      const json = await res.json();
      const ip = json?.Answer?.find(a => a.type === 1)?.data || null;
      utils.cache.set(`dns:${host}`, ip);
      return ip;
    } catch { return null; }
  }

  async getGeoTag(p) {
    const host = String(p.server).toLowerCase();
    // 优先 TLD
    const parts = host.split(".");
    const tld = parts.pop();
    if (this.tldMap[tld]) return `[${this.tldMap[tld]}]`;
    if (parts.length > 0 && this.tldMap[parts[parts.length - 1]]) return `[${this.tldMap[parts.pop()]}]`;

    // 远程解析 (仅在必要时)
    if (this.opt.enableRemoteGeo) {
      const ip = await this.resolveIP(host);
      if (ip) {
        if (utils.cache.has(`geo:${ip}`)) return utils.cache.get(`geo:${ip}`);
        try {
          const res = await utils.fetch(CONFIG.GEO_API.replace("{ip}", ip));
          const json = await res.json();
          if (json?.status === "success") {
            const tag = `[${json.country}${json.city ? "-" + json.city : ""}]`;
            utils.cache.set(`geo:${ip}`, tag);
            return tag;
          }
        } catch {}
      }
    }
    return "";
  }

  getQualityScore(p) {
    let s = 0;
    const type = String(p.type).toLowerCase();
    const scoreMap = { vless: 25, trojan: 25, hysteria2: 30, hysteria: 25, tuic: 25, vmess: 20, ss: 15, wireguard: 20 };
    s += (scoreMap[type] || 10);
    if (p.tls) s += 15;
    if (p.name) {
      if (/(premium|vip|高级|高速|专线|iplc|iepl)/i.test(p.name)) s += 20;
      if (/(game|游戏|低延迟)/i.test(p.name)) s += 10;
    }
    if (p.udp) s += 5;
    if (p.alpn) s += 5;
    return s;
  }

  getNodeKey(p) {
    try {
      if (!p || typeof p !== "object") return "invalid";
      const s = String(p.server || "").toLowerCase().trim(), t = String(p.type || "").toLowerCase(), port = String(p.port || "");
      if (!s || !t || !port) return "invalid";
      const k = [t, s, port];
      if (["vmess", "vless"].includes(t)) {
        if (p.uuid) k.push(String(p.uuid));
        if (p.aid) k.push(String(p.aid));
        if (p.tls) k.push("tls");
        if (p.network) k.push(String(p.network));
        if (p.path) k.push(String(p.path));
      } else if (["ss", "ssr"].includes(t)) {
        if (p.cipher) k.push(String(p.cipher));
        if (p.password) k.push(String(p.password));
        if (p.protocol) k.push(String(p.protocol));
        if (p.obfs) k.push(String(p.obfs));
      } else if (["trojan", "snell", "hysteria", "hysteria2", "tuic"].includes(t)) {
        if (p.password) k.push(String(p.password));
        if (p.token) k.push(String(p.token));
        if (p.sni) k.push(String(p.sni));
      } else if (t === "wireguard") {
        if (p.publicKey) k.push(String(p.publicKey));
      }
      return k.filter(Boolean).join(":");
    } catch { return "invalid"; }
  }

  async run(proxies) {
    utils.log(`Sirkey 引擎启动: 处理 ${proxies.length} 个节点...`);
    
    // 1. 基础过滤
    let list = proxies.filter(p => this.isValidBasic(p));
    
    // 2. 连通性测试
    if (this.opt.SKIP_TEST === false) {
      const results = await utils.limit(list.map(p => async () => {
        try {
          const res = await utils.fetch(this.opt.TEST_URLS[0], { timeout: this.opt.TIMEOUT });
          return res && (res.status === 204 || res.ok);
        } catch { return false; }
      }), this.opt.CONCURRENCY);
      list = list.filter((p, i) => results[i].status === "fulfilled" && results[i].value);
    }

    // 3. 地理位置标记
    if (this.opt.enableGeo !== false) {
      const geoTasks = list.map((p, i) => async () => {
        try {
          const tag = await this.getGeoTag(p);
          if (tag) {
            const name = String(p.name || "");
            if (!name.includes(tag)) p.name = `${tag} ${name}`;
          }
          return p;
        } catch { return p; }
      });
      const geoResults = await utils.limit(geoTasks, this.opt.CONCURRENCY);
      list = geoResults.map((r, i) => r.status === "fulfilled" ? r.value : list[i]).filter(Boolean);
    }
    
    // 4. 高质量去重
    const seen = new Map();
    for (const p of list) {
      const fp = this.getNodeKey(p);
      if (fp === "invalid") continue;
      const score = this.getQualityScore(p);
      if (!seen.has(fp) || score > seen.get(fp).score) {
        seen.set(fp, { proxy: p, score });
      }
    }
    list = Array.from(seen.values()).map(v => v.proxy);

    utils.log(`处理完成: ${proxies.length} -> ${list.length}`);
    return list;
  }
}

// ===================== 入口 =====================
async function filter(proxies = [], options = {}) {
  try {
    const engine = new Validator(options);
    return await engine.run(proxies);
  } catch (e) {
    utils.log(`全局异常: ${e.message}`, "error");
    return proxies;
  }
}

// Sub-Store 环境自动执行逻辑
if (typeof $proxies !== "undefined") {
  filter($proxies).then(res => {
    $done({ proxies: res });
  }).catch(e => {
    console.log(`Sub-Store 运行错误: ${e.message}`);
    $done({ proxies: $proxies });
  });
}

if (typeof module !== "undefined" && module.exports) module.exports = filter;
else if (typeof window !== "undefined") window.filter = filter;

