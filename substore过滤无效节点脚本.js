// SubStore 节点过滤脚本 - 融合优化版
// 版本: 11.1 (2025) - 严格过滤模式
// 特性: 真实配置验证 + 智能地理识别 + 集群共识 + 隐私保护 + 性能指标提取 + DNS解析
// 
// 新增功能 (v11.0):
// ✅ P0: 弱加密算法过滤 + 强加密白名单验证
// ✅ P0: 协议特定字段完整验证（UUID、WireGuard密钥等）
// ✅ P0: 垃圾域名黑名单过滤（免费域名、动态DNS等）
// ✅ P1: WebSocket/gRPC 传输层配置验证
// ✅ P1: 抢占式 DNS 解析（多提供商竞速）
// ✅ P1: 英文国家名自动转中文（完整映射表）
// ✅ P2: 性能指标智能提取（延迟、速度、带宽、倍率）
// ✅ P2: 性能指标在质量评分中的应用
// ✅ P2: 配置逻辑异常检测
// ✅ P2: ALPN 验证（可选）
//
// 更新 (v11.1):
// 🔥 严格性能过滤：移除延迟豁免条款，所有节点一视同仁
// 🔥 质量评分阈值：低于30分的节点直接丢弃
"use strict";

const CONFIG = Object.freeze({
  // 关键词过滤
  FREE_KEYWORDS: ["公益", "白嫖", "免费", "白用", "公用", "订阅转发", "分享"],
  INVALID_KEYWORDS: ["过期","失效","expired","invalid","test","测试","到期","剩余","流量用尽","官网","购买","更新","不支持","disabled","维护","已用完","错误","限流","非法"],
  
  // 性能配置
  MAX_MULTIPLIER: 10,
  CONCURRENCY: 15,
  TIMEOUT: 3000,
  RETRY_TIMES: 1,
  SKIP_TEST: true,
  
  // 协议支持
  SUPPORTED_TYPES: new Set(["ss","ssr","vmess","trojan","vless","hysteria","hysteria2","tuic","wireguard","snell"]),
  
  // 端口黑名单
  PORT_BLACKLIST: new Set([25,135,137,138,139,445,1433,3306,3389,69,143,161,162,465,587,993,995,5432,6379,22,23,1935,554,37777,47808]),
  
  // 质量阈值
  MAX_LATENCY: 1000,
  MAX_JITTER: 50,
  MIN_SPEED: 0.5,
  MIN_QUALITY_SCORE: 30,
  
  // 网络配置
  TEST_URLS: [
    "https://www.google.com/generate_204",
    "https://cp.cloudflare.com/generate_204"
  ],
  USER_AGENT: "SubStore/1.1 (Optimized)",
  
  // 地理位置API
  GEO_APIS: [
    "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp&lang=zh-CN",
    "https://api.ip.sb/geoip/{ip}",
    "https://ipapi.co/{ip}/json/",
    "https://ipwho.is/{ip}",
    "https://freeipapi.com/api/json/{ip}"
  ],
  DOH_URL: "https://cloudflare-dns.com/dns-query?name={host}&type=A",
  enableRemoteGeo: true,
  
  // 安全配置
  REQUIRE_ALPN: false,
  
  // CDN识别
  CDN_RANGES: [
    { start: '104.16.0.0', end: '104.31.255.255', name: 'Cloudflare' },
    { start: '172.64.0.0', end: '172.71.255.255', name: 'Cloudflare' },
    { start: '162.159.0.0', end: '162.159.255.255', name: 'Cloudflare' }
  ],
  
  // ==================== 新增功能配置 ====================
  
  // 1. 强制加密验证配置 (Requirements 1.1, 1.2, 1.3)
  ENCRYPTION_VALIDATION: {
    enabled: true,  // 是否启用加密验证
    strictMode: false,  // 严格模式：拒绝所有不符合规范的节点
    // SS/SSR 允许的加密算法（强加密）
    allowedCiphers: {
      ss: ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm'],
      ssr: ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305']
    },
    // 禁止的弱加密算法
    forbiddenCiphers: ['rc4', 'rc4-md5', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr'],
    // 需要强制 TLS 的协议
    requireTLS: ['trojan', 'vless']
  },
  
  // 2. 传输层配置验证 (Requirements 2.1, 2.2, 2.3, 2.4)
  TRANSPORT_VALIDATION: {
    enabled: true,  // 是否启用传输层验证
    strictMode: false,  // 严格模式：拒绝配置不完整的节点
    warnOnly: false  // 仅警告模式：记录问题但不过滤节点
  },
  
  // 3. 性能指标智能提取配置 (Requirements 3.1, 3.2, 3.3, 3.4, 3.5)
  PERFORMANCE_METRICS: {
    enabled: true,  // 是否启用性能指标提取
    extractMultiplier: true,  // 提取倍率信息
    extractBandwidth: true,  // 提取带宽信息
    extractLatency: true,  // 提取延迟信息
    extractQuality: true,  // 提取质量标签
    useInScoring: true,  // 在质量评分中使用性能指标
    displayInName: false,  // 是否在重命名时保留性能指标
    // 性能指标评分权重
    scoringWeights: {
      multiplierWeight: 2,  // 倍率权重（每倍率单位的分数）
      multiplierMaxScore: 20,  // 倍率最高得分
      bandwidthGbpsWeight: 10,  // Gbps 带宽权重
      bandwidthMbpsWeight: 0.1,  // Mbps 带宽权重
      bandwidthMaxScore: 30,  // 带宽最高得分
      lowLatencyThreshold: 50,  // 低延迟阈值（ms）
      lowLatencyScore: 15,  // 低延迟得分
      mediumLatencyThreshold: 100,  // 中等延迟阈值（ms）
      mediumLatencyScore: 10,  // 中等延迟得分
      highLatencyThreshold: 200,  // 高延迟阈值（ms）
      highLatencyScore: 5  // 高延迟得分
    }
  },
  
  // 4. DNS 抢占式解析配置 (Requirements 4.1, 4.2, 4.3, 4.4)
  DNS_RESOLVE: {
    enabled: true,  // 是否启用 DNS 解析
    // DNS over HTTPS 提供商列表（按优先级排序）
    dohProviders: [
      'https://cloudflare-dns.com/dns-query?name={host}&type=A',
      'https://dns.google/resolve?name={host}&type=A',
      'https://dns.quad9.net:5053/dns-query?name={host}&type=A'
    ],
    timeout: 2000,  // DNS 查询超时时间（毫秒）
    cacheEnabled: true,  // 是否启用 DNS 缓存
    cacheTTL: 3600000  // DNS 缓存过期时间（1小时，毫秒）
  },
  
  // 5. 垃圾域名过滤配置 (Requirements 5.1, 5.2, 5.3, 5.4)
  JUNK_DOMAINS_FILTER: {
    enabled: true,  // 是否启用垃圾域名过滤
    strictMode: false,  // 严格模式：包含更多域名
    allowCDN: true,  // 是否允许 CDN 域名
    customDomains: []  // 用户自定义垃圾域名列表
  },
  
  // 垃圾域名列表
  JUNK_DOMAINS: new Set([
    // 免费域名服务（Freenom 等）
    'freenom.world', 'tk', 'ml', 'ga', 'cf', 'gq',
    // 已知的低质量/测试域名
    'example.com', 'example.org', 'example.net',
    'test.com', 'test.org', 'test.net',
    'localhost', 'local', 'localdomain',
    // 动态 DNS 服务
    'ddns.net', 'dyndns.org', 'no-ip.com', 'no-ip.org',
    'duckdns.org', 'dynu.com', 'dynu.net',
    'freedns.afraid.org', 'changeip.com',
    // 临时域名服务
    'tempurl.com', 'temp-dns.com', 'temporary.link',
    // CDN 边缘节点（可选，根据 allowCDN 配置）
    // 'cloudfront.net', 'azureedge.net',
    // 已知的垃圾节点提供商
    'v2ray.com', 'v2fly.org',  // 官方域名，不应用于节点
    'trojan-gfw.github.io',
    // 其他已知问题域名
    'sslip.io', 'nip.io', 'xip.io'
  ])
});

const REGEX = Object.freeze({
  PRIVATE_IP: /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|224\.|localhost|0\.0\.0\.0)/,
  MULTIPLIER: /(?:[xX✕✖⨉倍率]|rate)[:\s]*([0-9]+\.?[0-9]*|0*\.[0-9]+)/i,
  MULTIPLIER_ALT: /([0-9]+\.?[0-9]*|0*\.[0-9]+)\s*(?:[xX✕✖⨉倍率])/i,
  IPV4: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
  IPV6: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})/,
  DOMAIN: /^(?!-)[a-zA-Z0-9-]{1,63}(?:\.(?!-)[a-zA-Z0-9-]{1,63})+$/,
  UUID: /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/,
  WG_KEY: /^[A-Za-z0-9+/]{42,43}=?$/,
  MARKETING: /([\u2700-\u27BF]|[\uE000-\uF8FF]|\uD83C[\uDC00-\uDFFF]|\uD83D[\uDC00-\uDFFF]|[\u2011-\u26FF]|\uD83E[\uDD10-\uDDFF]){3,}/,
  CONTACT: /(?:t\.me|群|联系|客服|网站|购买|订阅|获取|发布)/i
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
    for (let i = 0; i <= times; i++) {
      try {
        if (utils.cache.has(`fetch:${url}`)) {
          return utils.cache.get(`fetch:${url}`);
        }

        let result;
        if (typeof $httpClient !== "undefined") {
          result = await new Promise((resolve, reject) => {
            const options = {
              url,
              headers: { "User-Agent": CONFIG.USER_AGENT, ...opt.headers },
              timeout: opt.timeout || CONFIG.TIMEOUT
            };
            const method = (opt.method || "GET").toLowerCase();
            const handler = $httpClient[method] || $httpClient.get;
            
            handler.call($httpClient, options, (error, response, data) => {
              if (error) {
                reject(new Error(typeof error === 'string' ? error : JSON.stringify(error)));
              } else {
                const status = response ? (response.status || response.statusCode) : 200;
                resolve({
                  ok: status >= 200 && status < 300,
                  status: status,
                  json: () => {
                    try { return JSON.parse(data || "{}"); } 
                    catch (e) { return {}; }
                  },
                  body: data
                });
              }
            });
          });
        } else if (typeof fetch !== "undefined") {
          const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
          const timeout = setTimeout(() => controller?.abort(), opt.timeout || CONFIG.TIMEOUT);
          try {
            const res = await fetch(url, { 
              method: opt.method || "GET",
              headers: { "User-Agent": CONFIG.USER_AGENT, ...opt.headers },
              signal: controller?.signal 
            });
            const data = await res.text();
            result = {
              ok: res.ok,
              status: res.status,
              json: () => {
                try { return JSON.parse(data || "{}"); }
                catch (e) { return {}; }
              },
              body: data
            };
          } finally { clearTimeout(timeout); }
        }

        if (result && result.ok) {
          utils.cache.set(`fetch:${url}`, result);
          if (utils.cache.size > 200) {
            const firstKey = utils.cache.keys().next().value;
            utils.cache.delete(firstKey);
          }
        }
        if (result) return result;
        throw new Error("无可用网络请求组件");
      } catch (e) {
        if (i === times) throw e;
        await new Promise(r => setTimeout(r, 1000));
      }
    }
  },

  async race(promises, timeout = CONFIG.TIMEOUT) {
    return new Promise((resolve, reject) => {
      let settledCount = 0;
      const errors = [];
      const len = promises.length;
      const timeoutId = setTimeout(() => reject(new Error("所有请求超时或失败")), timeout);

      if (len === 0) {
        clearTimeout(timeoutId);
        reject(new Error("无任务"));
        return;
      }

      promises.forEach((p, i) => {
        Promise.resolve(p).then(
          val => {
            if (val) {
              clearTimeout(timeoutId);
              resolve(val);
            } else {
              handleFailure(new Error("返回空结果"));
            }
          },
          err => handleFailure(err)
        );
      });

      function handleFailure(err) {
        settledCount++;
        errors.push(err);
        if (settledCount === len) {
          clearTimeout(timeoutId);
          reject(new Error("所有请求均已失败: " + errors.map(e => e.message).join(", ")));
        }
      }
    });
  },

  searchTrie(trie, text) {
    const upper = text.toUpperCase();
    for (let i = 0; i < upper.length; i++) {
      let node = trie;
      for (let j = i; j < upper.length; j++) {
        const char = upper[j];
        if (!node[char]) break;
        node = node[char];
        if (node.v) return node.v;
      }
    }
    return null;
  },

  calculateEntropy(str) {
    if (!str) return 0;
    const len = str.length;
    const freq = {};
    for (let i = 0; i < len; i++) {
      const char = str[i];
      freq[char] = (freq[char] || 0) + 1;
    }
    let entropy = 0;
    for (const char in freq) {
      const p = freq[char] / len;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  },

  getMainDomain(host) {
    if (!host || REGEX.IPV4.test(host) || REGEX.IPV6.test(host)) return host;
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const last2 = parts.slice(-2).join('.');
    if (['com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn'].includes(last2)) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  },

  getSubnet(ip) {
    if (!ip || !REGEX.IPV4.test(ip)) return ip;
    return ip.split('.').slice(0, 3).join('.') + '.0';
  },

  ipToLong(ip) {
    const parts = ip.split('.');
    return (parseInt(parts[0]) << 24) + (parseInt(parts[1]) << 16) + 
           (parseInt(parts[2]) << 8) + parseInt(parts[3]);
  },

  isInRange(ip, start, end) {
    const ipLong = utils.ipToLong(ip);
    const startLong = utils.ipToLong(start);
    const endLong = utils.ipToLong(end);
    return ipLong >= startLong && ipLong <= endLong;
  }
};

class Validator {
  constructor(options = {}) {
    this.opt = { ...CONFIG, ...options };
    utils.isDebug = !!this.opt.debug;
    this.keywords = new Set([...(this.opt.INVALID_KEYWORDS || []), ...(this.opt.FREE_KEYWORDS || [])].map(k => k.toLowerCase()));
    
    this.tldMap = {
      cn: "中国", hk: "中国香港", mo: "中国澳門", tw: "中国台湾", jp: "日本", sg: "新加坡", us: "美国", kr: "韩国", de: "德国", uk: "英国", fr: "法国", nl: "荷兰", ru: "俄罗斯", au: "澳大利亚", ca: "加拿大", in: "印度", 
      th: "泰国", my: "马来西亚", vn: "越南", ph: "菲律宾", ch: "瑞士", se: "瑞典", no: "挪威", fi: "芬兰", 
      dk: "丹麦", it: "意大利", es: "西班牙", pt: "葡萄牙", br: "巴西", ar: "阿根廷", tr: "土耳其", ae: "阿联酋",
      am: "亚美尼亚", at: "奥地利", cl: "智利", pl: "波兰", be: "比利时", ie: "爱尔兰", ro: "罗马尼亚", 
      ua: "乌克兰", kz: "哈萨克斯坦", id: "印尼", za: "南非", mx: "墨西哥", co: "哥伦比亚", pe: "秘鲁", nz: "新西兰",
      sgp: "新加坡", usa: "美国", gbr: "英国", fra: "法国", deu: "德国", jpn: "日本", kor: "韩国", hkg: "中国香港",
      ir: "伊朗", bg: "保加利亚", md: "摩尔多瓦", hu: "匈牙利", cz: "捷克", sk: "斯洛伐克",
      il: "以色列", cy: "塞浦路斯", gr: "希腊", ee: "爱沙尼亚", lv: "拉脱维亚", lt: "立陶宛", lu: "卢森堡",
      is: "冰岛", si: "斯洛文尼亚", hr: "克罗地亚", rs: "塞尔维亚", me: "黑山", mk: "北马其顿", al: "阿尔巴尼亚"
    };
    
    this.geoKeywords = [
      { k: "香港", v: "中国香港" }, { k: "HK", v: "中国香港" }, { k: "HongKong", v: "中国香港" },
      { k: "台湾", v: "中国台湾" }, { k: "TW", v: "中国台湾" }, { k: "TaiWan", v: "中国台湾" },
      { k: "澳门", v: "中国澳门" }, { k: "MO", v: "中国澳门" }, { k: "Macao", v: "中国澳门" },
      { k: "日本", v: "日本" }, { k: "JP", v: "日本" }, { k: "Japan", v: "日本" }, { k: "Tokyo", v: "日本" }, { k: "Osaka", v: "日本" },
      { k: "新加坡", v: "新加坡" }, { k: "SG", v: "新加坡" }, { k: "Singapore", v: "新加坡" },
      { k: "美国", v: "美国" }, { k: "US", v: "美国" }, { k: "USA", v: "美国" }, { k: "America", v: "美国" }, { k: "NewYork", v: "美国" },
      { k: "韩国", v: "韩国" }, { k: "KR", v: "韩国" }, { k: "Korea", v: "韩国" }, { k: "Seoul", v: "韩国" },
      { k: "德国", v: "德国" }, { k: "DE", v: "德国" }, { k: "Germany", v: "德国" }, { k: "Frankfurt", v: "德国" },
      { k: "英国", v: "英国" }, { k: "UK", v: "英国" }, { k: "GB", v: "英国" }, { k: "London", v: "英国" },
      { k: "阿联酋", v: "阿联酋" }, { k: "AE", v: "阿联酋" }, { k: "Dubai", v: "阿联酋" },
      { k: "西班牙", v: "西班牙" }, { k: "ES", v: "西班牙" }, { k: "Spain", v: "西班牙" },
      { k: "俄罗斯", v: "俄罗斯" }, { k: "RU", v: "俄罗斯" }, { k: "Russia", v: "俄罗斯" }, { k: "Moscow", v: "俄罗斯" },
      { k: "法国", v: "法国" }, { k: "FR", v: "法国" }, { k: "France", v: "法国" }, { k: "Paris", v: "法国" },
      { k: "荷兰", v: "荷兰" }, { k: "NL", v: "荷兰" }, { k: "Netherlands", v: "荷兰" }, { k: "Amsterdam", v: "荷兰" },
      { k: "加拿大", v: "加拿大" }, { k: "CA", v: "加拿大" }, { k: "Canada", v: "加拿大" },
      { k: "澳大利亚", v: "澳大利亚" }, { k: "AU", v: "澳大利亚" }, { k: "Australia", v: "澳大利亚" }, { k: "Sydney", v: "澳大利亚" },
      { k: "泰国", v: "泰国" }, { k: "TH", v: "泰国" }, { k: "Thailand", v: "泰国" }, { k: "Bangkok", v: "泰国" },
      { k: "越南", v: "越南" }, { k: "VN", v: "越南" }, { k: "VietNam", v: "越南" },
      { k: "印度", v: "印度" }, { k: "IN", v: "印度" }, { k: "India", v: "印度" },
      { k: "土耳其", v: "土耳其" }, { k: "TR", v: "土耳其" }, { k: "Turkey", v: "土耳其" },
      { k: "以色列", v: "以色列" }, { k: "IL", v: "以色列" }, { k: "Israel", v: "以色列" },
      { k: "马来西亚", v: "马来西亚" }, { k: "MY", v: "马来西亚" }, { k: "Malaysia", v: "马来西亚" }
    ];

    this.iataMap = {
      HKG: "中国香港", TPE: "中国台湾", KHH: "中国台湾", MFM: "中国澳門",
      NRT: "日本", HND: "日本", KIX: "日本", NGO: "日本", FUK: "日本", CTS: "日本", OKA: "日本",
      ICN: "韩国", GMP: "韩国", PUS: "韩国", CJU: "韩国",
      SIN: "新加坡",
      SFO: "美国", LAX: "美国", JFK: "美国", EWR: "美国", SEA: "美国", ORD: "美国", DFW: "美国", MIA: "美国", SJC: "美国", ATL: "美国", LAS: "美国",
      LHR: "英国", LGW: "英国", MAN: "英国", STN: "英国", EDI: "英国",
      FRA: "德国", MUC: "德国", BER: "德国", HAM: "德国", DUS: "德国",
      CDG: "法国", ORY: "法国", LYS: "法国", MRS: "法国",
      AMS: "荷兰", RTM: "荷兰",
      DXB: "阿联酋", AUH: "阿联酋",
      BKK: "泰国", DMK: "泰国", HKT: "泰国", CNX: "泰国",
      SGN: "越南", HAN: "越南", DAD: "越南",
      SYD: "澳大利亚", MEL: "澳大利亚", BNE: "澳大利亚", PER: "澳大利亚", ADL: "澳大利亚",
      YYZ: "加拿大", YVR: "加拿大", YUL: "加拿大", YYC: "加拿大",
      IST: "土耳其", SAW: "土耳其", AYT: "土耳其",
      SVO: "俄罗斯", DME: "俄罗斯", LED: "俄罗斯", OVB: "俄罗斯",
      BOM: "印度", DEL: "印度", BLR: "印度", MAA: "印度",
      ZRH: "瑞士", GVA: "瑞士", BSL: "瑞士",
      CPH: "丹麦", BLL: "丹麦",
      ARN: "瑞典", GOT: "瑞典",
      OSL: "挪威", BGO: "挪威",
      HEL: "芬兰",
      MAD: "西班牙", BCN: "西班牙", PMI: "西班牙",
      MXP: "意大利", FCO: "意大利", VCE: "意大利",
      LIS: "葡萄牙", OPO: "葡萄牙",
      GRU: "巴西", GIG: "巴西",
      EZE: "阿根廷",
      KUL: "马来西亚", BKI: "马来西亚",
      MNL: "菲律宾", CEB: "菲律宾",
      TLV: "以色列"
    };

    const rawIndex = [
      ...Object.entries(this.iataMap).map(([k, v]) => ({ k: k.toUpperCase(), v })),
      ...this.geoKeywords.map(i => ({ k: i.k.toUpperCase(), v: i.v }))
    ].sort((a, b) => b.k.length - a.k.length);

    this._geoTrie = {};
    for (const item of rawIndex) {
      let node = this._geoTrie;
      for (const char of item.k) {
        if (!node[char]) node[char] = {};
        node = node[char];
      }
      node.v = item.v;
    }
    this._geoIndex = rawIndex;

    this.isoMap = {
      HK: "中国香港", TW: "中国台湾", MO: "中国澳门", JP: "日本", KR: "韩国", SG: "新加坡", 
      US: "美国", GB: "英国", DE: "德国", FR: "法国", NL: "荷兰", AE: "阿联酋", ES: "西班牙", 
      RU: "俄罗斯", CA: "加拿大", AU: "澳大利亚", TH: "泰国", VN: "越南", IN: "印度", TR: "土耳其",
      CN: "中国", MY: "马来西亚", PH: "菲律宾", CH: "瑞士", SE: "瑞典", NO: "挪威", FI: "芬兰", 
      DK: "丹麦", IT: "意大利", PT: "葡萄牙", BR: "巴西", AR: "阿根廷", IL: "以色列",
      AM: "亚美尼亚", AT: "奥地利", CL: "智利", PL: "波兰", BE: "比利时", IE: "爱尔兰", RO: "罗马尼亚",
      UA: "乌克兰", KZ: "哈萨克斯坦", ID: "印尼", ZA: "南非", MX: "墨西哥", CO: "哥伦比亚", PE: "秘鲁", NZ: "新西兰",
      BG: "保加利亚", HU: "匈牙利", CZ: "捷克", SK: "斯洛伐克", CY: "塞浦路斯", GR: "希腊", EE: "爱沙尼亚", 
      LV: "拉脱维亚", LT: "立陶宛", LU: "卢森堡", IS: "冰岛", SI: "斯洛文尼亚", HR: "克罗地亚", RS: "塞尔维亚"
    };
    
    this.nameToIso = Object.entries(this.isoMap).reduce((acc, [code, name]) => {
      acc[name] = code;
      return acc;
    }, {});
  }

  getFlagEmoji(geo) {
    const name = (typeof geo === 'object' ? geo.tag : geo) || "";
    const code = this.nameToIso[name];
    if (!code) return "";
    return code.toUpperCase().replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397));
  }

  parseFlagEmoji(text) {
    if (!text) return null;
    const regex = /[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/g;
    const matches = text.match(regex);
    if (!matches) return null;
    const emoji = matches[0];
    const code = Array.from(emoji).map(char => String.fromCharCode(char.codePointAt(0) - 127397)).join("");
    return code.toUpperCase();
  }
  
  // P2: 性能指标智能提取方法
  extractPerformanceMetrics(p) {
    const name = String(p.name || "");
    const info = p.info || {};
    const metrics = {
      multiplier: 0,
      bandwidth: 0,
      latency: 0,
      speed: 0,
      quality: ""
    };
    
    if (!this.opt.PERFORMANCE_METRICS.enabled) return metrics;
    
    // 1. 提取倍率信息
    if (this.opt.PERFORMANCE_METRICS.extractMultiplier) {
      const m = name.match(REGEX.MULTIPLIER) || name.match(REGEX.MULTIPLIER_ALT);
      if (m) metrics.multiplier = parseFloat(m[1]) || 0;
    }
    
    // 2. 提取带宽信息
    if (this.opt.PERFORMANCE_METRICS.extractBandwidth) {
      const bwMatch = name.match(/(\d+(?:\.\d+)?)\s*(?:Gbps|Mbps)/i);
      if (bwMatch) {
        const val = parseFloat(bwMatch[1]);
        metrics.bandwidth = name.toLowerCase().includes("gbps") ? val * 1000 : val;
      }
    }
    
    // 3. 提取延迟信息
    if (this.opt.PERFORMANCE_METRICS.extractLatency) {
      metrics.latency = Number(p.latency || info.latency || info.delay || 0);
      if (metrics.latency <= 0) {
        const msMatch = name.match(/(\d+(?:\.\d+)?)\s*m?\s*ms/i);
        if (msMatch) metrics.latency = parseFloat(msMatch[1]);
      }
    }
    
    // 4. 提取速度信息
    metrics.speed = Number(p.speed || info.speed || 0);
    if (metrics.speed <= 0) {
      const speedMatch = name.match(/(\d+(?:\.\d+)?)\s*(?:MB\/s|Mbps)/i);
      if (speedMatch) {
        const val = parseFloat(speedMatch[1]);
        metrics.speed = name.toLowerCase().includes("mbps") ? val / 8 : val;
      }
    }
    
    // 5. 提取质量标签
    if (this.opt.PERFORMANCE_METRICS.extractQuality) {
      if (/(premium|vip|高级)/i.test(name)) metrics.quality = "premium";
      else if (/(高速|专线|iplc|iepl)/i.test(name)) metrics.quality = "high-speed";
      else if (/(game|游戏|低延迟)/i.test(name)) metrics.quality = "low-latency";
      else if (/(netflix|disney|流媒体)/i.test(name)) metrics.quality = "streaming";
    }
    
    return metrics;
  }

  // ==================== 核心验证方法（融合版） ====================
  
  isValidBasic(p) {
    const name = p.name || "未知节点";
    const type = String(p.type).toLowerCase();

    // 1. 验证必要字段
    const requiredFields = ["type", "name", "server", "port"];
    for (const field of requiredFields) {
      if (!p[field]) {
        utils.log(`[字段缺失] ${field}: ${name}`, "debug");
        return false;
      }
    }

    // 2. 协议类型验证
    if (!this.opt.SUPPORTED_TYPES.has(type)) {
      utils.log(`[不支持协议] ${type}: ${name}`, "debug");
      return false;
    }

    // 3. 协议特定字段验证（增强版）
    switch(type) {
      case 'vmess':
      case 'vless':
        // UUID 格式验证
        if (!p.uuid || !REGEX.UUID.test(p.uuid)) {
          utils.log(`[UUID无效] ${name}`, "debug");
          return false;
        }
        break;
      
      case 'ss':
      case 'ssr':
        // 必要字段验证
        if (!p.cipher || !p.password) {
          utils.log(`[SS/SSR配置不完整] 缺少cipher或password: ${name}`, "debug");
          return false;
        }
        
        // P0: 弱加密算法过滤
        if (this.opt.ENCRYPTION_VALIDATION.enabled) {
          const cipher = String(p.cipher).toLowerCase();
          if (this.opt.ENCRYPTION_VALIDATION.forbiddenCiphers.includes(cipher)) {
            utils.log(`[弱加密算法] ${cipher}: ${name}`, "debug");
            return false;
          }
          
          // P0: 强加密白名单验证（严格模式）
          if (this.opt.ENCRYPTION_VALIDATION.strictMode) {
            const allowedList = this.opt.ENCRYPTION_VALIDATION.allowedCiphers[type] || [];
            if (!allowedList.includes(cipher)) {
              utils.log(`[非白名单加密] ${cipher}: ${name}`, "debug");
              return false;
            }
          }
        }
        break;
      
      case 'trojan':
        if (!p.password) {
          utils.log(`[Trojan缺少密码] ${name}`, "debug");
          return false;
        }
        break;
      
      case 'hysteria':
      case 'hysteria2':
      case 'tuic':
        // 认证信息验证
        if (!p.password && !p.token) {
          utils.log(`[${type}缺少认证信息] ${name}`, "debug");
          return false;
        }
        break;
      
      case 'wireguard':
        // P0: WireGuard 密钥验证
        if (!p.publicKey || !p.privateKey) {
          utils.log(`[WireGuard密钥缺失] ${name}`, "debug");
          return false;
        }
        // 密钥格式验证
        if (!REGEX.WG_KEY.test(p.publicKey) || !REGEX.WG_KEY.test(p.privateKey)) {
          utils.log(`[WireGuard密钥格式无效] ${name}`, "debug");
          return false;
        }
        break;
    }

    // 4. 服务器地址验证
    const host = String(p.server).toLowerCase();
    if (REGEX.PRIVATE_IP.test(host)) {
      utils.log(`[无效地址] 私有IP: ${name}`, "debug");
      return false;
    }

    const isIP = REGEX.IPV4.test(host) || REGEX.IPV6.test(host);
    const isDomain = REGEX.DOMAIN.test(host);
    if (!isIP && !isDomain) {
      utils.log(`[地址格式无效] ${name}`, "debug");
      return false;
    }
    
    // P0: 垃圾域名黑名单过滤
    if (this.opt.JUNK_DOMAINS_FILTER.enabled && !isIP) {
      const mainDomain = utils.getMainDomain(host);
      const tld = host.split('.').pop();
      
      // 检查完整域名和 TLD
      if (this.opt.JUNK_DOMAINS.has(mainDomain) || this.opt.JUNK_DOMAINS.has(tld)) {
        utils.log(`[垃圾域名] ${mainDomain}: ${name}`, "debug");
        return false;
      }
      
      // 检查用户自定义黑名单
      for (const junkDomain of this.opt.JUNK_DOMAINS_FILTER.customDomains) {
        if (host.includes(junkDomain)) {
          utils.log(`[自定义垃圾域名] ${junkDomain}: ${name}`, "debug");
          return false;
        }
      }
    }

    // 5. 端口验证
    const port = Number(p.port);
    if (isNaN(port) || port < 1 || port > 65535 || this.opt.PORT_BLACKLIST.has(port)) {
      utils.log(`[无效端口] ${port}: ${name}`, "debug");
      return false;
    }

    // 6. TLS配置验证（针对需要TLS的协议）
    if (this.opt.ENCRYPTION_VALIDATION.enabled) {
      const tlsRequired = this.opt.ENCRYPTION_VALIDATION.requireTLS;
      if (tlsRequired.includes(type)) {
        if (!p.tls && !p.sni && !p.servername) {
          utils.log(`[TLS配置缺失] ${type}协议必须启用TLS: ${name}`, "debug");
          return false;
        }
        
        // P2: ALPN 验证（可选）
        if (this.opt.REQUIRE_ALPN && p.tls && !p.alpn) {
          utils.log(`[ALPN缺失] ${type}节点建议设置ALPN: ${name}`, "debug");
          if (this.opt.ENCRYPTION_VALIDATION.strictMode) {
            return false; // 严格模式下拒绝
          }
        }
      }
    }
    
    // P1: 传输层配置验证
    if (this.opt.TRANSPORT_VALIDATION.enabled) {
      // WebSocket 配置检查
      if (p.network === 'ws' || p['ws-opts']) {
        const wsOpts = p['ws-opts'] || {};
        if (!wsOpts.path) {
          utils.log(`[WebSocket配置不完整] 缺少path: ${name}`, "debug");
          if (this.opt.TRANSPORT_VALIDATION.strictMode) return false;
        }
        if (!wsOpts.headers || (!wsOpts.headers.Host && !wsOpts.headers.host)) {
          utils.log(`[WebSocket配置不完整] 缺少Host头: ${name}`, "debug");
          if (this.opt.TRANSPORT_VALIDATION.strictMode) return false;
        }
      }
      
      // gRPC 配置检查
      if (p.network === 'grpc' || p['grpc-opts']) {
        const grpcOpts = p['grpc-opts'] || {};
        if (!grpcOpts['grpc-service-name']) {
          utils.log(`[gRPC配置不完整] 缺少service-name: ${name}`, "debug");
          if (this.opt.TRANSPORT_VALIDATION.strictMode) return false;
        }
      }
    }

    // 7. 信息熵检测（防止乱码节点）
    if (name.length > 16 && utils.calculateEntropy(name) > 4.5 && !/[\u4e00-\u9fa5]/.test(name)) {
      utils.log(`[信息熵异常] ${name}`, "debug");
      return false;
    }

    // 8. 关键词黑名单
    for (const k of this.keywords) {
      if (name.toLowerCase().includes(k)) {
        utils.log(`[关键词黑名单] ${k}: ${name}`, "debug");
        return false;
      }
    }

    // 9. 倍率过滤
    const m = name.match(REGEX.MULTIPLIER) || name.match(REGEX.MULTIPLIER_ALT);
    if (m && parseFloat(m[1]) > this.opt.MAX_MULTIPLIER) {
      utils.log(`[倍率超标] ${m[1]}x: ${name}`, "debug");
      return false;
    }

    // 10. 营销特征识别
    if (REGEX.MARKETING.test(name) || REGEX.CONTACT.test(name)) {
      utils.log(`[营销节点] ${name}`, "debug");
      return false;
    }
    
    // P2: 性能指标智能提取与过滤（严格模式）
    if (this.opt.PERFORMANCE_METRICS.enabled) {
      const perfMetrics = this.extractPerformanceMetrics(p);
      
      // 严格延迟过滤：移除豁免条款，所有节点一视同仁
      if (perfMetrics.latency > 0 && perfMetrics.latency > this.opt.MAX_LATENCY) {
        utils.log(`[延迟过高] ${perfMetrics.latency}ms: ${name}`, "debug");
        return false;
      }
      
      // 严格速度过滤
      if (perfMetrics.speed > 0 && perfMetrics.speed < this.opt.MIN_SPEED) {
        utils.log(`[速度过低] ${perfMetrics.speed}MB/s: ${name}`, "debug");
        return false;
      }
      
      // P2: 配置逻辑异常检测
      if (/(?:10Gbps|专线|IPLC|IEPL)/i.test(name)) {
        if (type === "ss" && p.port === 80) {
          utils.log(`[逻辑异常] 高速标签但使用SS+80端口: ${name}`, "debug");
          return false;
        }
      }
      
      // 保存提取的性能指标供后续使用
      p._perfMetrics = perfMetrics;
    }
    
    // 质量评分最低阈值过滤（在基础验证阶段就计算并过滤）
    const qualityScore = this.getQualityScore(p);
    if (qualityScore < this.opt.MIN_QUALITY_SCORE) {
      utils.log(`[质量评分过低] ${qualityScore}分 (最低${this.opt.MIN_QUALITY_SCORE}分): ${name}`, "debug");
      return false;
    }
    p._qualityScore = qualityScore; // 保存评分供后续使用

    // 11. CDN检测（标记但不过滤）
    if (isIP && REGEX.IPV4.test(host)) {
      for (const range of CONFIG.CDN_RANGES) {
        if (utils.isInRange(host, range.start, range.end)) {
          p._isCDN = true;
          p._cdnProvider = range.name;
          break;
        }
      }
    }

    // 12. 常见端口标记
    const commonPorts = [443, 80, 8080, 8443, 2053, 2083, 2087, 2096];
    if (commonPorts.includes(port)) {
      p._commonPort = true;
    }

    utils.log(`[✅ 通过] ${name} (${type})`, "debug");
    return true;
  }

  getQualityScore(p) {
    let s = 0;
    const type = String(p.type).toLowerCase();
    const name = String(p.name || "");

    // 1. 协议评分
    const protocolScores = {
      hysteria2: 40, hysteria: 35, tuic: 35,
      vless: 30, trojan: 30, vmess: 25,
      ss: 20, wireguard: 20, ssr: 10
    };
    s += protocolScores[type] || 10;

    // 2. TLS配置
    if (p.tls) s += 15;
    if (p.sni || p.servername) s += 5;
    if (p.alpn) s += 10;

    // 3. 传输层
    if (p.network === 'grpc') s += 10;
    if (p.network === 'h2') s += 10;
    if (p.network === 'ws' && p['ws-opts']?.path) s += 5;
    if (p.udp) s += 10;

    // 4. 端口评分
    if (p._commonPort) s += 5;
    if (p.port === 443) s += 10;

    // 5. CDN中转（降低评分）
    if (p._isCDN) s -= 10;

    // 6. 配置完整性
    if (p['client-fingerprint']) s += 5;
    if (p['skip-cert-verify'] === false) s += 5;

    // 7. 名称特征加分
    if (/(premium|vip|高级|高速|专线|iplc|iepl|bgp|cn2)/i.test(name)) s += 25;
    if (/(game|游戏|低延迟)/i.test(name)) s += 15;
    if (/(netflix|disney|youtube|流媒体|解锁)/i.test(name)) s += 10;
    
    // P2: 8. 性能指标评分（使用提取的指标）
    if (this.opt.PERFORMANCE_METRICS.enabled && this.opt.PERFORMANCE_METRICS.useInScoring) {
      const metrics = p._perfMetrics || this.extractPerformanceMetrics(p);
      const weights = this.opt.PERFORMANCE_METRICS.scoringWeights;
      
      // 倍率评分
      if (metrics.multiplier > 0) {
        const multiplierScore = Math.min(
          metrics.multiplier * weights.multiplierWeight,
          weights.multiplierMaxScore
        );
        s += multiplierScore;
      }
      
      // 带宽评分
      if (metrics.bandwidth > 0) {
        let bandwidthScore = 0;
        if (metrics.bandwidth >= 1000) { // Gbps
          bandwidthScore = (metrics.bandwidth / 1000) * weights.bandwidthGbpsWeight;
        } else { // Mbps
          bandwidthScore = metrics.bandwidth * weights.bandwidthMbpsWeight;
        }
        s += Math.min(bandwidthScore, weights.bandwidthMaxScore);
      }
      
      // 延迟评分
      if (metrics.latency > 0) {
        if (metrics.latency < weights.lowLatencyThreshold) {
          s += weights.lowLatencyScore;
        } else if (metrics.latency < weights.mediumLatencyThreshold) {
          s += weights.mediumLatencyScore;
        } else if (metrics.latency < weights.highLatencyThreshold) {
          s += weights.highLatencyScore;
        }
      }
      
      // 质量标签评分
      const qualityScores = {
        "premium": 20,
        "high-speed": 15,
        "low-latency": 15,
        "streaming": 10
      };
      if (metrics.quality && qualityScores[metrics.quality]) {
        s += qualityScores[metrics.quality];
      }
    }

    return Math.max(0, s);
  }

  async getGeoTag(p) {
    const name = String(p.name || "");
    const server = String(p.server || "").toLowerCase();
    
    let fingerHost = server;
    if (p.sni) fingerHost = String(p.sni).toLowerCase();
    else if (p["ws-opts"]?.headers?.Host) fingerHost = String(p["ws-opts"].headers.Host).toLowerCase();
    else if (p["ws-opts"]?.headers?.host) fingerHost = String(p["ws-opts"].headers.host).toLowerCase();
    else if (p.servername) fingerHost = String(p.servername).toLowerCase();

    const cacheKey = `geo_v3:${name}:${fingerHost}`;
    if (utils.cache.has(cacheKey)) return utils.cache.get(cacheKey);
    if (utils.cache.has(`remote_geo:${fingerHost}`)) {
      const cached = utils.cache.get(`remote_geo:${fingerHost}`);
      return { tag: cached, confidence: 95, source: "cache" };
    }

    let result = { tag: "未知地点", confidence: 0 };

    // 1. Emoji优先级
    const emojiCode = this.parseFlagEmoji(name);
    if (emojiCode && this.isoMap[emojiCode]) {
      result = { tag: this.isoMap[emojiCode], confidence: 100 };
      utils.cache.set(cacheKey, result);
      return result;
    }

    // 2. Trie树名称匹配
    const trieMatch = utils.searchTrie(this._geoTrie, name);
    if (trieMatch) {
      result = { tag: trieMatch, confidence: 80 };
      utils.cache.set(cacheKey, result);
      return result;
    }

    // 3. TLD域名匹配
    const tld = fingerHost.split('.').pop();
    if (this.tldMap[tld]) {
      result = { tag: this.tldMap[tld], confidence: 70 };
      utils.cache.set(cacheKey, result);
      return result;
    }

    // 4. Host关键词匹配
    const hostGeo = utils.searchTrie(this._geoTrie, fingerHost);
    if (hostGeo) {
      result = { tag: hostGeo, confidence: 60 };
      utils.cache.set(cacheKey, result);
      return result;
    }

    // 5. 远程IP库查询
    if (this.opt.enableRemoteGeo) {
      const ipToQuery = (REGEX.IPV4.test(fingerHost) || REGEX.IPV6.test(fingerHost)) ? fingerHost : 
                       (REGEX.IPV4.test(server) || REGEX.IPV6.test(server) ? server : null);
      
      if (ipToQuery) {
        try {
          const remoteGeo = await this.fetchRemoteGeo(ipToQuery);
          if (remoteGeo) {
            result = { tag: remoteGeo.country || remoteGeo, confidence: 95, source: "remote", isp: remoteGeo.isp };
            utils.cache.set(cacheKey, result);
            utils.cache.set(`remote_geo:${fingerHost}`, remoteGeo.country || remoteGeo);
            if (server !== fingerHost) utils.cache.set(`remote_geo:${server}`, remoteGeo.country || remoteGeo);
            return result;
          }
        } catch (e) {
          utils.log(`远程Geo查询失败 (${ipToQuery}): ${e.message}`, "debug");
        }
      }
    }

    utils.cache.set(cacheKey, result);
    return result;
  }

  async fetchRemoteGeo(ip) {
    if (utils.cache.has(`remote_geo:${ip}`)) return utils.cache.get(`remote_geo:${ip}`);

    // P1: 英文国家名到中文的映射表（完整版）
    const englishToChinese = {
      // 常见国家/地区
      "Hong Kong": "中国香港", "Taiwan": "中国台湾", "Macao": "中国澳门", "Macau": "中国澳门", "China": "中国",
      "Japan": "日本", "South Korea": "韩国", "Korea": "韩国", "Singapore": "新加坡",
      "United States": "美国", "USA": "美国", "America": "美国", "US": "美国",
      "United Kingdom": "英国", "UK": "英国", "Britain": "英国", "Great Britain": "英国",
      "Germany": "德国", "France": "法国", "Netherlands": "荷兰", "Holland": "荷兰",
      "United Arab Emirates": "阿联酋", "UAE": "阿联酋",
      "Spain": "西班牙", "Russia": "俄罗斯", "Russian Federation": "俄罗斯", "Canada": "加拿大",
      "Australia": "澳大利亚", "Thailand": "泰国", "Vietnam": "越南",
      "India": "印度", "Turkey": "土耳其", "Israel": "以色列",
      "Malaysia": "马来西亚", "Philippines": "菲律宾",
      "Switzerland": "瑞士", "Sweden": "瑞典", "Norway": "挪威",
      "Finland": "芬兰", "Denmark": "丹麦", "Italy": "意大利",
      "Portugal": "葡萄牙", "Brazil": "巴西", "Argentina": "阿根廷",
      "Armenia": "亚美尼亚", "Austria": "奥地利", "Chile": "智利",
      "Poland": "波兰", "Belgium": "比利时", "Ireland": "爱尔兰",
      "Romania": "罗马尼亚", "Ukraine": "乌克兰", "Kazakhstan": "哈萨克斯坦",
      "Indonesia": "印尼", "South Africa": "南非", "Mexico": "墨西哥",
      "Colombia": "哥伦比亚", "Peru": "秘鲁", "New Zealand": "新西兰",
      "Iran": "伊朗", "Bulgaria": "保加利亚", "Moldova": "摩尔多瓦",
      "Hungary": "匈牙利", "Czech Republic": "捷克", "Czechia": "捷克",
      "Slovakia": "斯洛伐克", "Cyprus": "塞浦路斯", "Greece": "希腊",
      "Estonia": "爱沙尼亚", "Latvia": "拉脱维亚", "Lithuania": "立陶宛",
      "Luxembourg": "卢森堡", "Iceland": "冰岛", "Slovenia": "斯洛文尼亚",
      "Croatia": "克罗地亚", "Serbia": "塞尔维亚", "Montenegro": "黑山",
      "North Macedonia": "北马其顿", "Albania": "阿尔巴尼亚"
    };

    const tasks = this.opt.GEO_APIS.map(api => async () => {
      try {
        const url = api.replace("{ip}", ip);
        const res = await utils.fetch(url, { timeout: 3500 });
        if (res && res.json) {
          const data = await res.json();
          let country = data.country || data.country_name || data.countryName;
          const countryCode = data.countryCode || data.country_code;
          const success = data.status === "success" || data.success === true || !data.status || data.status === 200;
          
          if (country && success) {
            // 1. 如果是两位国家代码，使用 isoMap 转换
            if (country.length === 2) {
              country = this.isoMap[country.toUpperCase()] || country;
            }
            // 2. 如果是英文国家名，转换为中文
            else if (englishToChinese[country]) {
              country = englishToChinese[country];
            }
            // 3. 如果已经是中文，直接使用
            // 4. 如果都不匹配，保持原样（可能是其他语言或未知国家）
            
            return {
              country: country,
              countryCode: countryCode || "XX",
              city: data.city || "",
              isp: data.isp || data.org || ""
            };
          }
        }
      } catch (e) {
        return null;
      }
    });

    try {
      const geoData = await utils.race(tasks.map(t => t()), 5000);
      if (geoData) {
        utils.log(`远程Geo成功 (${ip}): ${geoData.country}`, "debug");
        utils.cache.set(`remote_geo:${ip}`, geoData);
        return geoData;
      }
    } catch (e) {
      utils.log(`远程Geo失败 (${ip}): ${e.message}`, "debug");
    }
    return null;
  }
  
  // P1: 抢占式 DNS 解析方法
  async resolveIP(host) {
    if (!this.opt.DNS_RESOLVE.enabled) return null;
    if (REGEX.IPV4.test(host) || REGEX.IPV6.test(host)) return host;
    
    const cacheKey = `dns:${host}`;
    if (this.opt.DNS_RESOLVE.cacheEnabled && utils.cache.has(cacheKey)) {
      return utils.cache.get(cacheKey);
    }
    
    // 抢占式 DNS：同时请求多个提供商，谁快用谁
    const providers = this.opt.DNS_RESOLVE.dohProviders.map(url => url.replace("{host}", host));
    
    try {
      const ip = await utils.race(providers.map(async url => {
        try {
          const res = await utils.fetch(url, { 
            headers: { "accept": "application/dns-json" }, 
            timeout: this.opt.DNS_RESOLVE.timeout 
          });
          const json = await res.json();
          
          // 适配不同 DoH 提供商的响应格式
          if (json.Answer && Array.isArray(json.Answer)) {
            // Cloudflare/Google DNS 格式
            const aRecord = json.Answer.find(a => a.type === 1);
            return aRecord?.data || null;
          } else if (json.data && Array.isArray(json.data)) {
            // 其他格式
            return json.data[0] || null;
          }
          return null;
        } catch (e) {
          return null;
        }
      }), this.opt.DNS_RESOLVE.timeout + 1000);
      
      if (ip) {
        if (this.opt.DNS_RESOLVE.cacheEnabled) {
          utils.cache.set(cacheKey, ip);
        }
        utils.log(`DNS解析成功 (${host}): ${ip}`, "debug");
        return ip;
      }
    } catch (e) {
      utils.log(`DNS解析失败 (${host}): ${e.message}`, "debug");
    }
    return null;
  }

  applyConsensus(nodes) {
    const hostGroups = {};
    const subnetGroups = {};

    nodes.forEach(n => {
      let host = String(n.server || "").toLowerCase();
      if (n.sni) host = String(n.sni).toLowerCase();
      else if (n["ws-opts"]?.headers?.Host) host = String(n["ws-opts"].headers.Host).toLowerCase();
      else if (n.servername) host = String(n.servername).toLowerCase();

      const mainDomain = utils.getMainDomain(host);
      const subnet = utils.getSubnet(n._ip || n.server);
      
      if (!hostGroups[mainDomain]) hostGroups[mainDomain] = [];
      if (!subnetGroups[subnet]) subnetGroups[subnet] = [];
      
      hostGroups[mainDomain].push(n);
      subnetGroups[subnet].push(n);
    });

    const processGroups = (groups) => {
      for (const key in groups) {
        const group = groups[key];
        if (group.length < 2) continue;

        const votes = {};
        group.forEach(n => {
          if (n._geo && n._geo.confidence >= 60) {
            votes[n._geo.tag] = (votes[n._geo.tag] || 0) + 1;
          }
        });

        let winner = null;
        let maxVotes = 0;
        for (const tag in votes) {
          if (votes[tag] > maxVotes) {
            maxVotes = votes[tag];
            winner = tag;
          }
        }

        if (winner && (maxVotes / group.length) >= 0.5) {
          group.forEach(n => {
            if (!n._geo || n._geo.confidence < 60) {
              n._geo = { tag: winner, confidence: 40, source: "consensus" };
              utils.log(`集群共识: ${n.name} -> ${winner}`, "debug");
            }
          });
        }
      }
    };

    processGroups(hostGroups);
    processGroups(subnetGroups);
  }

  getNodeFingerprint(p) {
    try {
      if (!p || typeof p !== "object") return "invalid";
      const s = String(p.server || "").toLowerCase().trim();
      const t = String(p.type || "").toLowerCase();
      const port = String(p.port || "");
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
    } catch {
      return "invalid";
    }
  }
}

/**
 * 主过滤函数 - 融合优化版
 * 结合真实配置验证 + 智能地理识别 + 集群共识
 */
async function filter(proxies, options = {}) {
  const v = new Validator(options);
  const start = Date.now();
  const total = proxies.length;
  
  console.log(`[SubStore 融合版] 开始处理 ${total} 个节点...`);
  
  // ==================== 阶段 1: 并发基础验证 ====================
  utils.log("阶段 1: 基础配置验证...", "info");
  const validationTasks = proxies.map(p => async () => {
    if (v.isValidBasic(p)) {
      return p;
    }
    return null;
  });
  
  const validationResults = await utils.limit(validationTasks, CONFIG.CONCURRENCY);
  const validNodes = validationResults
    .filter(r => r.status === 'fulfilled' && r.value !== null)
    .map(r => r.value);
  
  console.log(`[SubStore 融合版] 验证完成: ${validNodes.length}/${total} 个节点通过基础验证`);
  
  if (validNodes.length === 0) {
    console.log(`[SubStore 融合版] 警告: 没有节点通过验证`);
    return [];
  }
  
  // ==================== 阶段 2: 智能地理位置识别 ====================
  utils.log("阶段 2: 地理位置识别（Trie树 + 远程API + DNS解析）...", "info");
  
  // P1: DNS 解析阶段（可选）
  if (v.opt.DNS_RESOLVE.enabled) {
    utils.log("执行 DNS 解析（域名 -> IP）...", "info");
    const dnsTasks = validNodes
      .filter(p => !REGEX.IPV4.test(p.server) && !REGEX.IPV6.test(p.server))
      .map(p => async () => {
        try {
          const ip = await v.resolveIP(p.server);
          if (ip) {
            p._resolvedIP = ip;
            utils.log(`DNS: ${p.server} -> ${ip}`, "debug");
          }
        } catch (e) {
          utils.log(`DNS解析失败: ${p.server}`, "debug");
        }
        return p;
      });
    
    if (dnsTasks.length > 0) {
      await utils.limit(dnsTasks, CONFIG.CONCURRENCY);
      const resolvedCount = validNodes.filter(p => p._resolvedIP).length;
      console.log(`[SubStore 融合版] DNS解析完成: ${resolvedCount}/${dnsTasks.length} 个域名`);
    }
  }
  
  // 预收集需要远程查询的唯一主机
  const uniqueHosts = new Set();
  validNodes.forEach(p => {
    let fingerHost = String(p.server || "").toLowerCase();
    if (p.sni) fingerHost = String(p.sni).toLowerCase();
    else if (p["ws-opts"]?.headers?.Host) fingerHost = String(p["ws-opts"].headers.Host).toLowerCase();
    else if (p["ws-opts"]?.headers?.host) fingerHost = String(p["ws-opts"].headers.host).toLowerCase();
    else if (p.servername) fingerHost = String(p.servername).toLowerCase();
    
    const cacheKey = `geo_v3:${p.name}:${fingerHost}`;
    if (!utils.cache.has(cacheKey) && !utils.cache.has(`remote_geo:${fingerHost}`)) {
      uniqueHosts.add(fingerHost);
    }
  });
  
  if (uniqueHosts.size > 0) {
    utils.log(`检测到 ${uniqueHosts.size} 个唯一主机需要地理位置查询`, "info");
  }
  
  // 并发获取地理位置
  const geoTasks = validNodes.map(p => async () => {
    try {
      p._geo = await v.getGeoTag(p);
      
      // 记录IP用于后续共识（优先使用解析的IP）
      if (p._resolvedIP) {
        p._ip = p._resolvedIP;
      } else if (REGEX.IPV4.test(p.server) || REGEX.IPV6.test(p.server)) {
        p._ip = p.server;
      }
      
      return p;
    } catch (e) {
      p._geo = { tag: "未知地点", confidence: 0 };
      return p;
    }
  });
  
  const geoResults = await utils.limit(geoTasks, CONFIG.CONCURRENCY);
  const nodesWithGeo = geoResults
    .filter(r => r.status === 'fulfilled')
    .map(r => r.value);
  
  console.log(`[SubStore 融合版] 地理位置识别完成: ${nodesWithGeo.length} 个节点`);
  
  // ==================== 阶段 3: 集群共识推断 ====================
  utils.log("阶段 3: 集群共识推断（解决未知地点）...", "info");
  v.applyConsensus(nodesWithGeo);
  
  // 统计共识效果
  const unknownBefore = nodesWithGeo.filter(n => !n._geo || n._geo.tag === "未知地点").length;
  const unknownAfter = nodesWithGeo.filter(n => {
    const tag = n._geo?.tag || "未知地点";
    return tag === "未知地点";
  }).length;
  
  if (unknownBefore > unknownAfter) {
    console.log(`[SubStore 融合版] 共识推断: 解决了 ${unknownBefore - unknownAfter} 个未知地点节点`);
  }
  
  // ==================== 阶段 4: 质量评分与去重 ====================
  utils.log("阶段 4: 质量评分与去重...", "info");
  const seen = new Map();
  
  for (const p of nodesWithGeo) {
    const fingerprint = v.getNodeFingerprint(p);
    if (fingerprint === "invalid") continue;
    
    // 使用已保存的评分（在 isValidBasic 中已计算）
    const score = p._qualityScore || v.getQualityScore(p);
    
    // 注意：低于阈值的节点已在 isValidBasic 中被过滤
    // 这里只需要处理去重逻辑
    
    // 保留评分最高的节点
    if (!seen.has(fingerprint) || score > seen.get(fingerprint).score) {
      seen.set(fingerprint, { proxy: p, score });
    }
  }
  
  const uniqueNodes = Array.from(seen.values()).map(item => item.proxy);
  console.log(`[SubStore 融合版] 去重完成: ${nodesWithGeo.length} -> ${uniqueNodes.length} 个唯一节点`);
  
  // ==================== 阶段 5: 统一重命名（隐私保护）====================
  utils.log("阶段 5: 统一重命名（国旗 + 国家 + 序号）...", "info");
  const countryCounts = new Map();
  
  const results = uniqueNodes.map(p => {
    const geo = p._geo || { tag: "未知地点", confidence: 0 };
    const countryTag = geo.tag || "未知地点";
    
    // 按国家计数
    const count = (countryCounts.get(countryTag) || 0) + 1;
    countryCounts.set(countryTag, count);
    
    // 生成新名称：国旗 + 国家 + 序号
    const flag = v.getFlagEmoji(countryTag);
    const indexStr = count < 10 ? `0${count}` : `${count}`;
    
    // 添加ISP信息（如果有且来自远程API）
    let ispInfo = "";
    if (geo.isp && geo.source === "remote") {
      const isp = String(geo.isp).substring(0, 15);
      ispInfo = ` [${isp}]`;
    }
    
    // 隐私保护：完全重写节点名，移除原始名称中的敏感信息
    p.name = `${flag}${countryTag} ${indexStr}${ispInfo}`.trim();
    
    // 清理所有临时字段
    delete p._geo;
    delete p._ip;
    delete p._isCDN;
    delete p._cdnProvider;
    delete p._commonPort;
    delete p._perfMetrics;
    delete p._resolvedIP;
    delete p._qualityScore; // 清理评分字段
    
    return p;
  });
  
  // ==================== 完成统计 ====================
  const duration = ((Date.now() - start) / 1000).toFixed(2);
  const stats = Array.from(countryCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([country, count]) => `${country}: ${count}`)
    .join(", ");
  
  console.log(`[SubStore 融合版] 处理完成! 耗时 ${duration}s`);
  console.log(`[SubStore 融合版] 最终保留: ${results.length} 个节点`);
  console.log(`[SubStore 融合版] 主要分布: ${stats}`);
  
  return results;
}

// ==================== Sub-Store 环境兼容 ====================

// 模块导出（Node.js 环境）
if (typeof module !== "undefined" && module.exports) {
  module.exports = { Validator, filter, CONFIG, REGEX, utils };
}

// 浏览器环境导出
if (typeof window !== "undefined") {
  window.SubStoreFilter = { Validator, filter, CONFIG, REGEX, utils };
}

// Sub-Store 环境自动执行
if (typeof $proxies !== "undefined") {
  filter($proxies).then(res => {
    $done({ proxies: res });
  }).catch(e => {
    console.log(`[SubStore 融合版] 运行错误: ${e.message}`);
    console.log(`[SubStore 融合版] 错误堆栈: ${e.stack}`);
    // 发生错误时返回原始节点列表
    $done({ proxies: $proxies });
  });
}
