/**
 * Mihomo 深度优化脚本 v4.6-2026.01.13-fixed (智能后台预检版)
 * 
 * [核心特性]
 * 1. 异步兼容：main 函数同步返回，完美适配所有 GUI 与移动端内核。
 * 2. 静默探测：在支持异步的环境下（如 Clash Verge）自动执行后台非阻塞测速。
 * 3. 闭环优化：结合历史统计与 AI 评分进行节点筛选，后台探测结果实时反馈至全局。
 * 4. 智能感知：自动识别运行环境，动态调整预检策略与分流逻辑。
 * 5. AI 优选：工程化 AI 决策内核，75分优质标准，65分兜底机制，75% AI + 25% 随机混合策略。
 * 6. 地理分组：自动识别节点地理位置，智能创建区域分组，港澳台统一管理。
 * 7. 功能分组：10大业务场景分组（AI、流媒体、游戏、社交等），智能路由分流。
 */

"use strict";

const Sirkey = (() => {
  // 运行环境全局对象兼容
  const root = (typeof globalThis !== "undefined") ? globalThis : 
               (typeof global !== "undefined") ? global : 
               (typeof window !== "undefined") ? window : 
               (typeof self !== "undefined") ? self : {};

  // 基础环境补丁
  if (typeof root.console === "undefined") {
    root.console = { log: () => {}, info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
  }

  /* ========== 1. 环境与常量 (Env & Constants) ========== */
  const Env = (() => {
    const isMihomo = typeof log === "function";
    const canAsync = typeof setTimeout === "function";
    const isVerge = typeof globalThis.process !== "undefined" || (typeof window !== "undefined" && typeof window.process !== "undefined");
    const platform = isVerge ? "Clash Verge" : (isMihomo ? "Mihomo" : "Unknown");
    
    return Object.freeze({
      isMihomo, platform, canAsync, isVerge,
      get: () => platform,
      version: "v4.6-2026.01.13-fixed",
      useES2022: true
    });
  })();

  const CONSTANTS = Object.freeze({
    RE: {
      GH_RAW: /raw\.githubusercontent\.com\/([^\/]+)\/([^\/]+)\/([^\/]+)\/(.+)/,
      GH_RELEASE: /github\.com\/([^\/]+)\/([^\/]+)\/releases\/download\/([^\/]+)\/(.+)/,
      URL_MASK: /([?&](token|key|auth|password|secret|access_token|api_key|session_id|credential|bearer|x-api-key|x-token|authorization)=)[^&]+/gi,
      SENSITIVE_KEY: /password|token|key|secret|auth|credential|access|bearer|authorization|cookie|session/i,
      DANGEROUS_PATTERNS: /eval|Function|require|process\.env|global\.|window\.|document\.|XMLHttpRequest|fetch|import\(|__dirname|__filename|child_process|fs\.|net\.|http\.|https\./i
    },
    TIME: { DAY: 86400000, HALF_DAY: 43200000, WEEK: 604800000, HOUR: 3600000 },
    GH: { MIRRORS: ["", "https://mirror.ghproxy.com/", "https://ghproxy.net/", "https://github.moeyy.xyz/", "https://gh.api.99988866.xyz/", "https://cdn.jsdelivr.net/gh/"] },
    UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    STREAM_REG: /youtube|netflix|stream|video|live|hls|dash|disney|hbo|hulu|tiktok|bilibili|amazon|prime|apple.*tv/i,
    AI_REG: /openai|claude|gemini|ai|chatgpt|api\.openai|anthropic|googleapis|perplex|mistral|cohere/i,
    SAFE_PORTS: new Set([80,443,8080,8081,8088,8880,8443,2052,2053,2082,2083,2086,2087,2095,2096]),
    IPV4_REG: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$/,
    DEBUG: false
  });

  /* ========== 2. 日志与脱敏 (Logger & Masker) ========== */
  const DataMasker = {
    maskUrl: (url) => typeof url === "string" ? url.replace(CONSTANTS.RE.URL_MASK, "$1***") : url,
    maskIPStr(str) {
      return typeof str === "string"
        ? str.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, ip => Utils.isPrivateIP(ip) ? ip : ip.replace(/\d{1,3}$/, "***"))
        : str;
    },
    mask(str) {
      if (typeof str !== "string") return str;
      let res = str.replace(CONSTANTS.RE.URL_MASK, "$1***");
      res = res.replace(/([?&; ])(password|token|key|secret|auth|credential|access|bearer|authorization|cookie|session)([:= ])[^;& ]+/gi, "$1$2$3***");
      return DataMasker.maskIPStr(res);
    },
    maskObject(obj, depth = 0) {
      if (depth > 4 || !obj || typeof obj !== "object") return obj;
      if (Array.isArray(obj)) return obj.map(v => DataMasker.maskObject(v, depth + 1));
      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        if (CONSTANTS.RE.SENSITIVE_KEY.test(k)) out[k] = "***";
        else if (typeof v === "string") out[k] = DataMasker.mask(v);
        else if (v && typeof v === "object") out[k] = DataMasker.maskObject(v, depth + 1);
        else out[k] = v;
      }
      return out;
    }
  };

  const Logger = new (class {
    _levelMap = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
    _currentLevel = CONSTANTS.DEBUG ? 0 : 1;
    /**
     * 多级降级日志输出：适配 Mihomo 与标准 Console
     */
    log(level, ctx, ...args) {
      if (this._levelMap[level] < this._currentLevel) return;
      const prefix = `[${level}] [${ctx || "Global"}]`;
      const sanitized = args.map(a => {
        if (a === null) return "null";
        if (a === undefined) return "undefined";
        if (typeof a === "object") {
          try { 
            return (typeof JSON !== "undefined") ? JSON.stringify(DataMasker.maskObject(a)) : "[Object]";
          } catch { return "[Object]"; }
        }
        return DataMasker.maskIPStr(String(a));
      });
      const msg = `${prefix} ${sanitized.join(" ")}`;
      if (typeof log === "function") {
        log(msg);
      } else if (typeof console !== "undefined" && typeof console.log === "function") {
        console.log(msg);
      }
    }
    error(c, ...a){this.log("ERROR",c,...a);} info(c,...a){this.log("INFO",c,...a);}
    warn(c,...a){this.log("WARN",c,...a);}  debug(c,...a){this.log("DEBUG",c,...a);}
  })();

  /* ========== 3. 通用工具 (Utils) ========== */
  const Utils = {
    now: Date.now,
    clamp: (v,min,max)=>v<min?min:(v>max?max:v),
    sleep: ms => new Promise(r=>setTimeout(r,ms)),
    deepClone(obj, keyName=null, seen = new WeakMap(), depth = 0) {
      // 添加最大深度限制，防止栈溢出
      const MAX_DEPTH = 10;
      
      if (depth > MAX_DEPTH) {
        Logger.warn("Utils.deepClone", `达到最大深度限制 ${MAX_DEPTH}，停止递归`);
        // 修复：返回 null 而不是原对象，避免引用污染
        return null;
      }
      
      if (!obj || typeof obj !== "object") return obj;
      if (seen.has(obj)) return seen.get(obj);
      
      if (Array.isArray(obj)) {
        const result = [];
        seen.set(obj, result);
        for (const item of obj) {
          const cloned = Utils.deepClone(item, null, seen, depth + 1);
          if (cloned !== null) result.push(cloned);
        }
        return result;
      }
      
      const result = Object.create(Object.getPrototypeOf(obj));
      seen.set(obj, result);
      
      for (const k in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, k)) {
          const needDeep = ["proxy-groups", "rules", "proxy-providers"].includes(k);
          result[k] = needDeep ? Utils.deepClone(obj[k], k, seen, depth + 1) : obj[k];
        }
      }
      return result;
    },
    isIPv4: ip => CONSTANTS.IPV4_REG.test(ip),
    isPrivateIP(ip) {
      if (!Utils.isIPv4(ip)) return false;
      const parts = ip.split(".").map(Number);
      if (parts.some(isNaN)) return false;
      const [a,b] = parts;
      return a===10 || (a===172&&b>=16&&b<=31) || (a===192&&b===168) || a===127 || a===169;
    },
    sanitizeUrl(u) {
      try{
        const url=new URL(u);
        return ["http:","https:"].includes(url.protocol)&&!Utils.isPrivateIP(url.hostname)?url.toString():null;
      }catch{return null;}
    },
    safeSet(obj,k,v){ if(obj && k) obj[k]=v; },
    escapeRegex(s){return s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");},
    regexToMihomo(re){return re instanceof RegExp ? (re.ignoreCase?"(?i)":"")+re.source : String(re);},
    getProxyGroupBase(){
      return {
        interval: Config.common?.proxyGroup?.interval ?? 300,
        timeout: Config.common?.proxyGroup?.timeout ?? 3000,
        url: Config.common?.proxyGroup?.url ?? "https://cp.cloudflare.com/generate_204",
        lazy: Config.common?.proxyGroup?.lazy !== false
      };
    },
    unique: arr => Array.from(new Set(arr)),
    uniqueBy(arr, fn){
      const seen=new Set(); return arr.filter(x=>{const v=fn(x); if(seen.has(v)) return false; seen.add(v); return true;});
    },
    mergeDefaults(target, source) {
      if (!source || typeof source !== "object") return target;
      if (!target || typeof target !== "object") return Utils.deepClone(source);
      const isPlain = (o) => Object.prototype.toString.call(o) === "[object Object]";
      for (const [k, v] of Object.entries(source)) {
        const tv = target[k];
        if (tv === undefined) target[k] = Utils.deepClone(v);
        else if (isPlain(tv) && isPlain(v)) Utils.mergeDefaults(tv, v);
      }
      return target;
    },
    percentile(sortedArr, percent) {
      if (!sortedArr?.length) return null;
      const p = Utils.clamp(percent, 0, 1);
      const idx = Math.min(sortedArr.length - 1, Math.max(0, Math.floor(sortedArr.length * p)));
      return sortedArr[idx];
    }
  };

  /* ========== 4. 存储与异常 (Storage & Exceptions) ========== */
  const PersistentStorage = new (class {
    constructor(){
      this._memoryCache = new Map();
    }
    read(key){ return this._memoryCache.get(key) || null; }
    write(key,val){ this._memoryCache.set(key, val); }
    delete(key){ return this._memoryCache.delete(key); }
  })();

  /* ========== 5. 镜像与资源 (Mirrors & Resources) ========== */
  class SirkeyError extends Error { constructor(m,c="INTERNAL_ERROR"){super(m);this.name="SirkeyError";this.code=c;this.timestamp=Date.now();} }
  class ConfigurationError extends SirkeyError { constructor(m){super(m,"CONFIG_ERROR");} }
  class InvalidRequestError extends SirkeyError { constructor(m){super(m,"INVALID_REQUEST");} }

  // 多镜像配置：优先使用 jsDelivr，失败时自动降级
  const MIRROR_CONFIG = {
    primary: "https://cdn.jsdelivr.net/gh/",     // 主镜像：jsDelivr（最稳定）
    fallbacks: [                                  // 备用镜像列表
      "https://ghproxy.net/",
      "https://mirror.ghproxy.com/",
      "https://github.moeyy.xyz/",
      "https://gh.api.99988866.xyz/",
      ""  // 最后直连 GitHub
    ],
    current: "https://cdn.jsdelivr.net/gh/"      // 当前使用的镜像
  };

  let GH_PROXY = MIRROR_CONFIG.current;

  async function selectBestMirror(){ return GH_PROXY; }
  const MIRROR_STATUS = new Map();

  const ICON_VAL = (f)=>{try{return typeof f==="function"?f():(f??"");}catch{return"";}};

  /**
   * ICONS 动态代理 - 修复闭包陷阱
   * 不再缓存 URL 函数，每次都动态生成以反映最新的 GH_PROXY
   */
  const ICONS = (() => {
    const base = "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color";
    const map = {
      ChinaMap:"China_Map",HongKong:"Hong_Kong",UnitedStates:"United_States",
      UnitedKingdom:"United_Kingdom",WorldMap:"Global",StreamingNotCN:"Streaming",
      StreamingCN:"StreamingCN",ChatGPT:"ChatGPT",Claude:"Claude",Gemini:"Gemini",
      YouTube:"YouTube",Netflix:"Netflix",DisneyPlus:"Disney",PrimeVideo:"Prime_Video",
      HBO:"HBO",Hulu:"Hulu",TikTok:"TikTok",Bilibili:"Bilibili",Bahamut:"Bahamut",
      TVB:"TVB",Pixiv:"Pixiv",Spotify:"Spotify",Telegram:"Telegram",Discord:"Discord",
      WhatsApp:"WhatsApp",Line:"Line",Slack:"Slack",Speedtest:"Speedtest",Steam:"Steam",
      Epic:"Epic",Game:"Game",Apple:"Apple",Microsoft:"Microsoft",Google:"Google",
      GoogleSearch:"Google_Search",Download:"Download",Proxy:"Proxy",Firewall:"Firewall",Update:"Update",
      Reject:"Privacy",Book:"Scholar",Taiwan:"Taiwan",Japan:"Japan",Singapore:"Singapore",Korea:"Korea",
      Germany:"Germany",France:"France",Malaysia:"Malaysia",Turkey:"Turkey",Russia:"Russia",Canada:"Canada",
      Australia:"Australia",Apple2:"Apple",GitHub:"GitHub",Advertising:"Privacy",Premium:"Global"
    };
    
    // 修复：不再缓存，每次动态生成 URL 以反映最新的 GH_PROXY
    return new Proxy({},{
      get(_,n){
        // 每次访问都返回新的函数，该函数会读取当前的 GH_PROXY
        return () => `${GH_PROXY}${base}/${map[n]??n}.png`;
      }
    });
  })();

  const URLS = {
    /**
     * 智能镜像 URL 转换
     * 支持 jsDelivr CDN 和其他 GitHub 镜像
     */
    _getMirrorUrl(original){
      if(!GH_PROXY) return original;
      
      // 清理已有的镜像前缀
      let clean = original;
      for(const m of CONSTANTS.GH.MIRRORS){
        if(m && clean.startsWith(m)){
          clean=clean.slice(m.length);
          break;
        }
      }
      
      // jsDelivr CDN 特殊处理（需要特定格式）
      if(GH_PROXY.includes("jsdelivr.net")){
        // 处理 raw.githubusercontent.com 格式
        const rawMatch = clean.match(CONSTANTS.RE.GH_RAW);
        if(rawMatch){
          const [,user,repo,branch,path]=rawMatch;
          return `https://cdn.jsdelivr.net/gh/${user}/${repo}@${branch}/${path}`;
        }
        
        // 处理 github.com releases 格式
        const releaseMatch = clean.match(CONSTANTS.RE.GH_RELEASE);
        if(releaseMatch){
          const [,user,repo,tag,file]=releaseMatch;
          return `https://cdn.jsdelivr.net/gh/${user}/${repo}@${tag}/${file}`;
        }
      }
      
      // 其他镜像：直接拼接
      const base = GH_PROXY.endsWith("/")?GH_PROXY:GH_PROXY+"/";
      const path = clean.startsWith("/")?clean.slice(1):clean;
      return base+path;
    },
    geox:{
      geoip:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"),
      geosite:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"),
      mmdb:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"),
      asn:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/asn.mmdb")
    },
    // 解决方案5：简化镜像URL生成，统一使用 _getMirrorUrl
    mrs(name){
      const baseUrl = `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/${name}.mrs`;
      return this._getMirrorUrl(baseUrl);
    },
    list(name){
      const baseUrl = `https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/${name}.txt`;
      return this._getMirrorUrl(baseUrl);
    },
    rulesets:{
      // ========== 1. MetaCubeX (MRS格式 - 性能最优，Mihomo官方推荐) ==========
      ai:()=>URLS.mrs("category-ai-!cn"),
      ads:()=>URLS.mrs("category-ads-all"),
      trackers:()=>URLS.mrs("tracker"),
      applications:()=>URLS.list("applications"),
      claude:()=>URLS.mrs("anthropic"),
      gemini:()=>URLS.mrs("google"),
      youtube:()=>URLS.mrs("youtube"),
      netflix:()=>URLS.mrs("netflix"),
      disney:()=>URLS.mrs("disney"),
      spotify:()=>URLS.mrs("spotify"),
      streaming:()=>URLS.mrs("category-streaming"),
      finance:()=>URLS.mrs("category-finance"),
      telegram:()=>URLS.mrs("telegram"),
      discord:()=>URLS.mrs("discord"),
      speedtest:()=>URLS.mrs("speedtest"),
      steam:()=>URLS.mrs("steam"),
      games:()=>URLS.mrs("category-games"),
      github:()=>URLS.mrs("github"),
      google:()=>URLS.mrs("google"),
      microsoft:()=>URLS.mrs("microsoft"),
      apple:()=>URLS.mrs("apple"),
      scholar:()=>URLS.mrs("category-scholar-!cn"),
      proxy:()=>URLS.mrs("proxy"),
      gfw:()=>URLS.mrs("gfw"),
      
      // ========== 2. Loyalsoldier (中国大陆优化，17k+ stars) ==========
      loyalsoldier:{
        reject:()=>URLS.list("reject"),
        icloud:()=>URLS.list("icloud"),
        apple:()=>URLS.list("apple"),
        google:()=>URLS.list("google"),
        proxy:()=>URLS.list("proxy"),
        direct:()=>URLS.list("direct"),
        private:()=>URLS.list("private"),
        gfw:()=>URLS.list("gfw"),
        greatfire:()=>URLS.list("greatfire"),
        tld_not_cn:()=>URLS.list("tld-not-cn"),
        telegram:()=>URLS.list("telegram"),
        cn:()=>URLS.list("direct")
      },
      
      // ========== 3. Blackmatrix7 (最全面规则集，35k+ stars) ==========
      blackmatrix7:{
        openai:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/OpenAI/OpenAI.yaml"),
        claude:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Claude/Claude.yaml"),
        gemini:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Gemini/Gemini.yaml"),
        youtube:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/YouTube/YouTube.yaml"),
        netflix:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Netflix/Netflix.yaml"),
        disney:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Disney/Disney.yaml"),
        spotify:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Spotify/Spotify.yaml"),
        tiktok:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/TikTok/TikTok.yaml"),
        telegram:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Telegram/Telegram.yaml"),
        github:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/GitHub/GitHub.yaml"),
        google:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Google/Google.yaml"),
        microsoft:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Microsoft/Microsoft.yaml"),
        apple:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Apple/Apple.yaml"),
        advertising:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Advertising/Advertising.yaml"),
        privacy:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Privacy/Privacy.yaml"),
        hijacking:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Hijacking/Hijacking.yaml")
      },
      
      // ========== 4. ACL4SSR (稳定分流，保守策略) ==========
      acl4ssr:{
        ban:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"),
        china:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list"),
        lan:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list")
      },
      
      // ========== 5. Anti-AD (广告拦截增强，中文广告最强) ==========
      anti_ad:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml")
    }
  };

  /* ========== 6. 全局配置 (Global Configuration) ========== */
  const Config = {
    autoIntervention: true, adaptive: true, enable: true,
    privacy: {
      geoExternalLookup: true, systemDnsOnly: false, trustedGeoEndpoints: [], githubMirrorEnabled: true
    },
    aiOptions: {
      enable: true,
      scoring: { latencyWeight:0.35, bandwidthWeight:0.15, stabilityWeight:0.25, jitterWeight:0.15, uptimeWeight:0.1 },
      scenes: {
        gaming:{ latencyWeight:0.6,jitterWeight:0.3,stabilityWeight:0.1,bandwidthWeight:0 },
        streaming:{ bandwidthWeight:0.6,stabilityWeight:0.3,latencyWeight:0.1,jitterWeight:0 },
        browsing:{ latencyWeight:0.4,stabilityWeight:0.3,bandwidthWeight:0.2,jitterWeight:0.1 },
        download:{ bandwidthWeight:0.8,stabilityWeight:0.2,latencyWeight:0,jitterWeight:0 }
      },
      evaluation:{ ewmaAlpha:0.3, driftThreshold:0.5, recoveryAlpha:0.1, baseTolerance:50, sampleSize:10 },
      protection:{ cooldown:300, maxSwitches24h:20, failIsolationH:12, threatDetection:true },
      cache:{ levels:3, strategy:"LRU+TTL", verifyInterval:3600, persistence:true },
      trendAnalysis:true
    },
    ruleOptions:{
      autoDiscover:true,
      defaults:Object.fromEntries(
        ["apple","microsoft","github","google","openai","spotify","youtube","bahamut","netflix","tiktok","disney","pixiv","hbo","biliintl","tvb","hulu","primevideo","telegram","line","whatsapp","games","japan","tracker","ads","acl4ssr","anti_ad","loyalsoldier","blackmatrix7"]
          .map(k=>[k,true])
      )
    },
    preRules:[
      "PROCESS-NAME,SunloginClient,DIRECT",
      "PROCESS-NAME,AnyDesk,DIRECT"
    ],
    regionOptions:{
      geoIpGrouping:true, autoDiscover:true, excludeHighPercentage:true, ratioLimit:2,
      maxRegions:10,  // 地理组上限：最多10个
      regions:[
        { name:"港澳台", regex:/港|澳|台|🇭🇰|🇲🇴|🇹🇼|hk|mo|tw|hongkong|macao|macau|taiwan|hkg|tpe/i, code:"HK_MO_TW", icon:ICONS.HongKong },
        { name:"日本", regex:/日|🇯🇵|jp|japan|nrt|hnd|kix/i, code:"JP", icon:ICONS.Japan },
        { name:"新加坡", regex:/新|🇸🇬|sg|singapore|sin/i, code:"SG", icon:ICONS.Singapore },
        { name:"美国", regex:/美|🇺🇸|us|united states|america|lax|sfo|jfk/i, code:"US", icon:ICONS.UnitedStates },
        { name:"韩国", regex:/韩|🇰🇷|kr|korea|sel|icn/i, code:"KR", icon:ICONS.Korea },
        { name:"英国", regex:/英|🇬🇧|uk|united kingdom|great britain|lhr/i, code:"GB", icon:ICONS.UnitedKingdom },
        { name:"德国", regex:/德|🇩🇪|de|germany|fra/i, code:"DE", icon:ICONS.Germany },
        { name:"法国", regex:/法|🇫🇷|fr|france|cdg/i, code:"FR", icon:ICONS.France },
        { name:"加拿大", regex:/加|🇨🇦|ca|canada|yvr|yyz/i, code:"CA", icon:ICONS.Canada },
        { name:"荷兰", regex:/荷|🇳🇱|nl|netherlands|holland|ams/i, code:"NL", icon:ICONS.WorldMap }
      ]
    },
    dns: {
      enable:true, listen:"127.0.0.1:1053", ipv6:true, "prefer-h3":true, "use-hosts":true, "use-system-hosts":true,
      "respect-rules":true, "enhanced-mode":"fake-ip", "fake-ip-range":"198.18.0.1/16", "cache-algorithm":"arc",
      "fake-ip-filter":["*","+.lan","+.local","+.market.xiaomi.com","+.msftconnecttest.com","+.msftncsi.com","msftconnecttest.com","msftncsi.com","+.xboxlive.com","+.battlenet.com.cn","+.wotgame.cn","+.wggames.cn","+.wowsgame.cn","+.wargaming.net","geosite:cn","geosite:private"],
      "default-nameserver":["223.5.5.5","119.29.29.29","1.1.1.1","8.8.8.8"],
      nameserver:["https://223.5.5.5/dns-query","https://119.29.29.29/dns-query","https://8.8.8.8/dns-query"],
      fallback:["https://1.1.1.1/dns-query","https://9.9.9.9/dns-query"],
      "fallback-filter":{geoip:true,"geoip-code":"CN",ipcidr:["240.0.0.0/4"],domain:["+.google.com","+.facebook.com","+.youtube.com","+.githubusercontent.com"]},
      "proxy-server-nameserver":["https://223.5.5.5/dns-query","https://119.29.29.29/dns-query","https://8.8.8.8/dns-query"],
      get "nameserver-policy"() {
        // 使用简化的 buildDNSPolicy 函数
        return typeof buildDNSPolicy !== "undefined" ? buildDNSPolicy() : {
          "geosite:private":["system"],
          "geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn":["119.29.29.29","223.5.5.5"],
          "rule-set:acl4ssr_china,ls_cn":["119.29.29.29","223.5.5.5"]
        };
      }
    },
    services: [
      { id:"applications", rule:["RULE-SET,applications,下载软件"], name:"应用程序", icon:ICONS.Download, ruleProvider:{ name:"applications", url:()=>URLS.rulesets.applications(), behavior:"classical" } },
      { id:"openai",  rule:["RULE-SET,ai,国外AI","RULE-SET,ai,国外AI"], name:"国外AI", icon:ICONS.ChatGPT, ruleProvider:{ name:"ai", url:()=>URLS.rulesets.ai(), behavior:"domain" } },
      { id:"claude",  rule:["RULE-SET,claude,Claude"], name:"Claude", icon:ICONS.Claude, ruleProvider:{ name:"claude", url:()=>URLS.rulesets.claude(), behavior:"domain" } },
      { id:"gemini",  rule:["RULE-SET,gemini,Gemini"], name:"Gemini", icon:ICONS.Gemini, ruleProvider:{ name:"gemini", url:()=>URLS.rulesets.gemini(), behavior:"domain" } },
      { id:"youtube", rule:["RULE-SET,youtube,YouTube"], name:"YouTube", icon:ICONS.YouTube, ruleProvider:{ name:"youtube", url:()=>URLS.rulesets.youtube(), behavior:"domain" } },
      { id:"netflix", rule:["RULE-SET,netflix,NETFLIX"], name:"NETFLIX", icon:ICONS.Netflix, ruleProvider:{ name:"netflix", url:()=>URLS.rulesets.netflix(), behavior:"domain" } },
      { id:"disney",  rule:["RULE-SET,disney,Disney+"], name:"Disney+", icon:ICONS.DisneyPlus, ruleProvider:{ name:"disney", url:()=>URLS.rulesets.disney(), behavior:"domain" } },
      { id:"primevideo", rule:["GEOSITE,primevideo,Prime Video"], name:"Prime Video", icon:ICONS.PrimeVideo },
      { id:"hbo",     rule:["GEOSITE,hbo,HBO"], name:"HBO", icon:ICONS.HBO },
      { id:"hulu",    rule:["GEOSITE,hulu,Hulu"], name:"Hulu", icon:ICONS.Hulu },
      { id:"tiktok",  rule:["GEOSITE,tiktok,Tiktok"], name:"Tiktok", icon:ICONS.TikTok },
      { id:"biliintl",rule:["GEOSITE,biliintl,哔哩哔哩东南亚"], name:"哔哩哔哩东南亚", icon:ICONS.Bilibili, proxiesOrder:["手动选择","DIRECT"] },
      { id:"bahamut", rule:["GEOSITE,bahamut,巴哈姆特"], name:"巴哈姆特", icon:ICONS.Bahamut, proxiesOrder:["手动选择","DIRECT"] },
      { id:"tvb",     rule:["GEOSITE,tvb,TVB"], name:"TVB", icon:ICONS.TVB },
      { id:"pixiv",   rule:["GEOSITE,pixiv,Pixiv"], name:"Pixiv", icon:ICONS.Pixiv },
      { id:"spotify", rule:["RULE-SET,spotify,Spotify"], name:"Spotify", icon:ICONS.Spotify, ruleProvider:{ name:"spotify", url:()=>URLS.rulesets.spotify(), behavior:"domain" } },
      { id:"streaming", rule:["RULE-SET,streaming,全球主流媒体"], name:"全球主流媒体", icon:ICONS.StreamingNotCN, ruleProvider:{ name:"streaming", url:()=>URLS.rulesets.streaming(), behavior:"domain" } },
      { id:"finance", rule:["RULE-SET,finance,金融组"], name:"金融服务", icon:ICONS.Premium, ruleProvider:{ name:"finance", url:()=>URLS.rulesets.finance(), behavior:"domain" } },
      { id:"telegram", rule:["GEOIP,telegram,Telegram","RULE-SET,telegram,Telegram"], name:"Telegram", icon:ICONS.Telegram, ruleProvider:{ name:"telegram", url:()=>URLS.rulesets.telegram(), behavior:"domain" } },
      { id:"discord",  rule:["RULE-SET,discord,Discord"], name:"Discord", icon:ICONS.Discord, ruleProvider:{ name:"discord", url:()=>URLS.rulesets.discord(), behavior:"domain" } },
      { id:"whatsapp", rule:["GEOSITE,whatsapp,WhatsApp"], name:"WhatsApp", icon:ICONS.WhatsApp },
      { id:"line",     rule:["GEOSITE,line,Line"], name:"Line", icon:ICONS.Line },
      { id:"slack",    rule:["GEOSITE,slack,Slack"], name:"Slack", icon:ICONS.Slack },
      { id:"speedtest",rule:["RULE-SET,speedtest,Speedtest"], name:"Speedtest", icon:ICONS.Speedtest, ruleProvider:{ name:"speedtest", url:()=>URLS.rulesets.speedtest(), behavior:"domain" } },
      { id:"steam",    rule:["RULE-SET,steam,Steam"], name:"Steam", icon:ICONS.Steam, ruleProvider:{ name:"steam", url:()=>URLS.rulesets.steam(), behavior:"domain" } },
      { id:"epic",     rule:["GEOSITE,epicgames,Epic Games"], name:"Epic Games", icon:ICONS.Epic },
      { id:"games",    rule:["RULE-SET,games,游戏专用"], name:"游戏专用", icon:ICONS.Game, ruleProvider:{ name:"games", url:()=>URLS.rulesets.games(), behavior:"domain" } },
      { id:"github",   rule:["RULE-SET,github,Github"], name:"Github", icon:ICONS.GitHub, ruleProvider:{ name:"github", url:()=>URLS.rulesets.github(), behavior:"domain" } },
      { id:"google",   rule:["RULE-SET,google,谷歌服务"], name:"谷歌服务", icon:ICONS.GoogleSearch, ruleProvider:{ name:"google", url:()=>URLS.rulesets.google(), behavior:"domain" } },
      { id:"microsoft",rule:["RULE-SET,microsoft,微软服务"], name:"微软服务", icon:ICONS.Microsoft, ruleProvider:{ name:"microsoft", url:()=>URLS.rulesets.microsoft(), behavior:"domain" } },
      { id:"apple",    rule:["RULE-SET,apple,苹果服务"], name:"苹果服务", icon:ICONS.Apple2, ruleProvider:{ name:"apple", url:()=>URLS.rulesets.apple(), behavior:"domain" } },
      { id:"scholar",  rule:["RULE-SET,scholar,学术网站"], name:"学术网站", icon:ICONS.Book, ruleProvider:{ name:"scholar", url:()=>URLS.rulesets.scholar(), behavior:"domain" } },
      { id:"proxy",    rule:["RULE-SET,proxy,全球加速"], name:"全球加速", icon:ICONS.Proxy, ruleProvider:{ name:"proxy", url:()=>URLS.rulesets.proxy(), behavior:"domain" } },
      { id:"gfw",      rule:["RULE-SET,gfw,GFW列表"], name:"GFW列表", icon:ICONS.Firewall, ruleProvider:{ name:"gfw", url:()=>URLS.rulesets.gfw(), behavior:"domain" } },
      { id:"tracker",  rule:["GEOSITE,tracker,REJECT"], name:"跟踪分析", icon:ICONS.Reject, proxies:["REJECT","DIRECT","手动选择"] },
      { id:"ads",      rule:["RULE-SET,ads,REJECT"], name:"广告过滤", icon:ICONS.Advertising, proxies:["REJECT","DIRECT","手动选择"], ruleProvider:{ name:"ads", url:()=>URLS.rulesets.ads(), behavior:"domain" } }
    ],
    functionalGroups: [
      { id:"ai_group", name:"AI组", icon:ICONS.ChatGPT, services:["openai","claude","gemini"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"streaming_group", name:"流媒体组", icon:ICONS.StreamingNotCN, services:["youtube","netflix","disney","hbo","hulu","primevideo","tiktok","biliintl","bahamut","tvb","pixiv","streaming"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"finance_group", name:"金融组", icon:ICONS.Premium, services:["finance"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"gaming_group", name:"游戏组", icon:ICONS.Game, services:["steam","epic","games"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"download_group", name:"下载组", icon:ICONS.Download, services:["speedtest"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"download_software_group", name:"下载软件", icon:ICONS.Download, services:["applications"], proxiesOrder:["DIRECT","手动选择","自动选择","AI优选"] },
      { id:"social_group", name:"社交组", icon:ICONS.Telegram, services:["telegram","discord","whatsapp","line","slack"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"search_group", name:"搜索组", icon:ICONS.GoogleSearch, services:["google"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"dev_group", name:"开发组", icon:ICONS.GitHub, services:["github","scholar"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"email_group", name:"邮件组", icon:ICONS.Microsoft, services:["microsoft","apple"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"music_group", name:"音乐组", icon:ICONS.Spotify, services:["spotify"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] },
      { id:"browsing_group", name:"浏览组", icon:ICONS.Proxy, services:["proxy","gfw"], proxiesOrder:["手动选择","自动选择","AI优选","DIRECT"] }
    ],
    system:{
      "allow-lan":true, mode:"rule", "unified-delay":true, "tcp-concurrent":true, "geodata-mode":true,
      "find-process-mode":"always", "global-client-fingerprint":"chrome",
      "external-controller":"0.0.0.0:9090", secret:"", "external-ui":"ui",
      profile:{ "store-selected":true, "store-fake-ip":true },
      sniffer:{
        enable:true, "force-dns-mapping":true, "parse-pure-ip":true, "override-destination":true,
        sniff:{ TLS:{ports:[443,8443]}, HTTP:{ports:[80,"8080-8880"],"override-destination":true}, QUIC:{ports:[443,8443]} },
        "force-domain":["+.v2ex.com","+.apple.com"], "skip-domain":["Mijia Cloud","+.push.apple.com","geosite:private"]
      },
      "geox-url":{geoip:()=>URLS.geox.geoip(),geosite:()=>URLS.geox.geosite(),mmdb:()=>URLS.geox.mmdb(),asn:()=>URLS.geox.asn()}
    },
    common:{ ruleProvider:{ type:"http", interval:86400 }, proxyGroup:{ interval:300, timeout:3000, url:"https://cp.cloudflare.com/generate_204", lazy:true }, defaultProxyGroups:[{ name:"国内网站", icon:ICONS.StreamingCN, proxies:["DIRECT","手动选择"] }], postRules:["GEOSITE,private,DIRECT","GEOIP,private,DIRECT,no-resolve","RULE-SET,ls_cn,国内网站","RULE-SET,acl4ssr_china,国内网站","GEOSITE,cn,国内网站","GEOIP,cn,国内网站,no-resolve","MATCH,其他节点"] },
    performance: { heavyProxyThreshold: 800, ioBudgetPerTick: 16 }
  };

  /* ========== 7. 基础组件 (Core Components) ========== */
  
  /* LRU 三层缓存 */
  class LRUCache {
    constructor({maxSize=300,ttl=3600000,persist=null}={}) {
      this._l1=new Map();
      this._l2=new Map();
      this._maxSize=maxSize;
      this._ttl=ttl;
      this._h=0; this._m=0;
      this._persist = (persist !== null) ? !!persist : !!(Config.aiOptions?.cache?.persistence);
      this._pendingWrites = new Map();
      this._maxPendingWrites = 1000; // 添加队列大小限制，防止无限增长
    }

    _entry(v,ttl){return {value:v,timestamp:Date.now(),ttl:ttl||this._ttl};}

    get(key){
      const now=Date.now();
      let e=this._l1.get(key);
      const check=(map,k)=>{
        const ent=map.get(k);
        if(!ent) return null;
        if(now-ent.timestamp>(ent.ttl||this._ttl)){map.delete(k);return null;}
        return ent;
      };
      e=check(this._l1,key);
      if(e){this._h++;return e.value;}
      e=check(this._l2,key);
      if(e){this._h++;this._promote(key,e);return e.value;}
      this._m++;
      return null;
    }

    set(key,val,ttl,persist=true){
      const e=this._entry(val,ttl);
      this._l1.set(key,e);
      this._evict();
      if(persist && this._persist){
        try{
          // 检查队列大小，防止内存泄漏
          if (this._pendingWrites.size >= this._maxPendingWrites) {
            Logger.warn("LRU.Set", `待写入队列已满 (${this._maxPendingWrites})，强制刷新`);
            this.flushPersistence(50, false);
          }
          this._pendingWrites.set(key, JSON.stringify(e));
        }catch(err){
          Logger.error("LRU.Set", `序列化失败: ${err.message}`);
        }
      }
    }

    _promote(key,entry){
      this._l2.delete(key); this._l1.set(key,entry); this._evict();
    }

    _evict(){
      if(this._l1.size>this._maxSize){
        const oldest=this._l1.keys().next().value;
        const ent=this._l1.get(oldest);
        this._l2.set(oldest,ent); this._l1.delete(oldest);
        if(this._l2.size>this._maxSize) this._l2.delete(this._l2.keys().next().value);
      }
    }

    validate(){
      const now=Date.now(); let cleaned=0;
      const clean=map=>{
        for(const [k,v] of map.entries()){
          if(now-v.timestamp>(v.ttl||this._ttl)){map.delete(k);cleaned++;}
        }
      };
      clean(this._l1); clean(this._l2);
      if(cleaned) Logger.debug("LRU.Validate",`清理 ${cleaned} 条缓存`);
    }

    getStats(){
      const t=this._h+this._m;
      return {hits:this._h,misses:this._m,ratio:t?this._h/t:0,l1Size:this._l1.size,l2Size:this._l2.size,_maxSize:this._maxSize};
    }

    clear(){
      this._l1.clear();
      this._l2.clear();
      this._pendingWrites.clear();
    }

    flushPersistence(ioBudget=16, force=false){
      if(!this._persist || !this._pendingWrites.size) return;
      const iter = this._pendingWrites.entries();
      let count = 0;
      const limit = force ? Infinity : ioBudget;  // force 模式下刷新所有
      
      for(const [key, serialized] of iter){
        try{
          PersistentStorage.write(key, serialized);
        }catch(e){
          Logger.error("LRU.Flush", `写入失败: ${key}`, e.message);
        }
        this._pendingWrites.delete(key);
        count++;
        if(count >= limit) break;
      }
      if(count) Logger.debug("LRU.Flush",`刷盘 ${count} 条, 剩余: ${this._pendingWrites.size}`);
    }

    /**
     * 强制刷新所有待写入数据
     * 用于脚本退出或需要确保数据持久化的场景
     */
    flushAll() {
      return this.flushPersistence(Infinity, true);
    }
  }

  class HttpClient {
    constructor(){
      this._avail=null;
      this._mirrorFailCount = new Map();
    }
    _check(){
      if(this._avail!==null) return this._avail;
      this._avail = (typeof fetch==="function");
      return this._avail;
    }
    
    /**
     * 镜像切换逻辑：当前镜像失败3次后自动切换到下一个
     * 简化版：使用简单的失败计数，避免复杂的锁机制
     */
    _handleMirrorFailure(url){
      if(!url || !GH_PROXY) return;
      
      // 只处理 GitHub 相关的 URL
      if(!url.includes("github") && !url.includes("jsdelivr")) return;
      
      const currentCount = this._mirrorFailCount.get(GH_PROXY) || 0;
      this._mirrorFailCount.set(GH_PROXY, currentCount + 1);
      
      // 失败3次后切换镜像
      if(currentCount + 1 >= 3){
        let currentIndex = MIRROR_CONFIG.fallbacks.indexOf(GH_PROXY);
        if(currentIndex === -1) {
          Logger.warn("HttpClient", `当前镜像不在列表中，重置到第一个`);
          currentIndex = -1;
        }
        
        const nextIndex = (currentIndex + 1) % MIRROR_CONFIG.fallbacks.length;
        const nextMirror = MIRROR_CONFIG.fallbacks[nextIndex];
        
        Logger.warn("HttpClient", `镜像失败${currentCount + 1}次，切换到: ${nextMirror || 'GitHub直连'}`);
        
        GH_PROXY = nextMirror;
        MIRROR_CONFIG.current = nextMirror;
        this._mirrorFailCount.clear();
      }
    }
    
    async safeFetch(url,opt={},timeout=5000){
      if(!this._check()) throw new SirkeyError("No HTTP client","HTTP_CLIENT_MISSING");
      const start=Date.now();
      try{
        if(typeof fetch==="function"){
          const ctrl = typeof AbortController!=="undefined"?new AbortController():null;
          const timer = ctrl?setTimeout(()=>ctrl.abort(),timeout):null;
          try{
            const method = opt.method || "GET";
            const resp=await fetch(url,{...opt,method,signal:ctrl?.signal});
            Logger.debug("HttpClient",`${method} ${url} ok in ${Date.now()-start}ms`);
            // 记录成功 (如果 context 可用)
            if(opt.proxy && opt.statsManager) opt.statsManager.recordSuccess(opt.proxy);
            return resp;
          }finally{if(timer)clearTimeout(timer);}
        }
      }catch(e){
        Logger.error("HttpClient",`失败 ${url}: ${e.message}`); 
        // 记录失败 (如果 context 可用)
        if(opt.proxy && opt.statsManager) opt.statsManager.recordFailure(opt.proxy);
        
        // 处理镜像切换
        this._handleMirrorFailure(url);
        
        throw e;
      }
      throw new SirkeyError("Env HTTP exec error","HTTP_CLIENT_EXEC_ERROR");
    }

    /**
     * 高并发预检探测 (HEAD 请求)
     */
    async probeNodes(proxies, statsManager, timeout = 800, maxConcurrency = 30) {
      if (!proxies || !proxies.length) return [];
      const results = new Map();
      const checkUrl = "http://cp.cloudflare.com/generate_204";
      
      // 分批执行，防止内存溢出或被系统判定为恶意行为
      for (let i = 0; i < proxies.length; i += maxConcurrency) {
        const batch = proxies.slice(i, i + maxConcurrency);
        await Promise.allSettled(batch.map(async (p) => {
          try {
            await this.safeFetch(checkUrl, { 
              method: "HEAD", 
              proxy: p, 
              statsManager: statsManager 
            }, timeout);
            results.set(p.name || p, true);
          } catch (e) {
            results.set(p.name || p, false);
          }
        }));
      }
      return results;
    }
  }

  /**
   * 后台静默预检引擎
   * 采用“异步探测，同步交付”策略，在不影响主流程返回的前提下，利用下一次执行更新状态
   */
  class BackgroundProbe {
    constructor(httpClient, statsManager) {
      this._http = httpClient;
      this._stats = statsManager;
    }

    trigger(proxies) {
      if (!Env.canAsync) {
        Logger.debug("BackgroundProbe", "当前环境不支持异步，跳过后台预检");
        return;
      }
      
      const now = Date.now();
      const interval = CONSTANTS.TIME.HOUR; // 每小时预检一次
      
      if (GLOBAL_STATS.checkInProgress) return;
      if (now - (GLOBAL_STATS.lastCheckTime || 0) < interval) return;
      
      Logger.info("BackgroundProbe", "触发后台静默预检 (异步非阻塞)...");
      GLOBAL_STATS.checkInProgress = true;
      
      // 使用 setTimeout 确保不阻塞主流程返回
      setTimeout(() => {
        const runProbe = async () => {
          try {
            // 挑选部分核心节点进行预检，避免资源消耗过大
            const targetNodes = proxies.filter(p => {
              const name = String(p?.name || "");
              return /HK|MO|TW|SG|JP|US|香港|澳门|台湾|新加坡|日本|美国|港|澳|台/i.test(name);
            }).slice(0, 60);

            if (targetNodes.length > 0) {
              await this._http.probeNodes(targetNodes, this._stats, 1000, 15);
              GLOBAL_STATS.lastCheckTime = Date.now();
              Logger.info("BackgroundProbe", `静默预检完成，已更新 ${targetNodes.length} 个核心节点的统计数据`);
            }
          } catch (e) {
            Logger.error("BackgroundProbe", "预检执行异常", e.message);
          } finally {
            GLOBAL_STATS.checkInProgress = false;
          }
        };
        runProbe();
      }, 3000); // 延迟 3 秒启动，避开启动峰值
    }
  }

  /* ========== 7. 智能评分与筛选系统 (AI Engine) ========== */
  class AIEngine {
    constructor(statsManager) {
      this._stats = statsManager;
      this._currentScene = "browsing";
      this._weights = {
        KEYWORDS: {
          "IPLC": 60, "IEPL": 55, "BGP": 35, "Premium": 45, "Vip": 40, "Special": 30,
          "Game": 40, "Gaming": 40, "Optimization": 25, "Fast": 20, "Direct": 15,
          "HKT": 15, "HKBN": 15, "PCCW": 15, "Oracle": 10, "Azure": 10, "GCP": 10, "AWS": 10,
          "Limit": -15, "Free": -60, "Test": -50, "Expired": -100, "Low": -25, "Slow": -30, "Backup": -20,
          "Maintenance": -80, "Down": -90, "Fix": -40
        },
        REGIONS: { "HK_MO_TW": 20, "港": 20, "澳": 20, "台": 20, "SG": 20, "JP": 15, "US": 10, "KR": 10, "UK": 5, "DE": 5 }
      };
      this._vetoReg = /Maintenance|Down|Fix|Expired|Error|Timeout|故障|维护|离线/i;
      this._regionReg = /HK|MO|TW|SG|JP|US|KR|UK|DE|香港|澳门|台湾|新加坡|日本|美国|韩国|英国|德国|港|澳|台/i;
      this._latencyReg = /(\d+)ms/i;
      this._kwRegs = new Map(Object.keys(this._weights.KEYWORDS).map(kw => [kw, new RegExp(kw, "i")]));
      
      this._SCORE_THRESHOLDS = {
        EXCELLENT: 75,
        GOOD: 65,
        MIN: 0
      };
    }

    setScene(scene) {
      if (["browsing", "gaming", "streaming", "download"].includes(scene)) {
        this._currentScene = scene;
      }
    }

    /**
     * 节点综合评分逻辑 (基础 25, 满分 100+)
     * 维度：协议(25%)、性能(20%)、稳定性(15%)、语义(15%)、动态(-20~+10)
     */
    score(proxy) {
      if (!proxy) return 0;
      let staticScore = 25;
      const name = typeof proxy === 'string' ? proxy : String(proxy.name || "");
      const type = String(proxy.type || "").toLowerCase();
      const port = parseInt(proxy.port || 0);

      if (this._vetoReg.test(name)) {
        Logger.debug("AIEngine.Veto", `否决节点: ${name}`);
        return 0;
      }

      const protocolWeights = { 
        "hysteria2": 25, "tuic": 25, "vless": 22, 
        "trojan": 18, "ss": 15, "snell": 12, 
        "vmess": 8, "ssr": 5 
      };
      staticScore += (protocolWeights[type] || 0);

      if (proxy.rate != null) {
        const rate = parseFloat(proxy.rate);
        if (rate <= 0.1) staticScore += 15;
        else if (rate <= 0.5) staticScore += 10;
        else if (rate <= 1.0) staticScore += 5;
        else if (rate > 1.0) staticScore -= 20;
      } else if (name.includes("0.1x")) staticScore += 15;
      else if (name.includes("1.0x")) staticScore += 5;

      if (CONSTANTS.SAFE_PORTS.has(port)) staticScore += 4;
      if (proxy.udp) staticScore += 2;
      if (proxy.tls) staticScore += 2;
      
      const stats = this._stats ? this._stats.getStats(proxy) : null;
      if (stats && stats.successCount > 10) staticScore += 2; 

      let semanticScore = 0;
      for (const [kw, reg] of this._kwRegs) {
        if (reg.test(name)) {
          const w = this._weights.KEYWORDS[kw];
          if (w <= -80) return 0;
          semanticScore += w;
        }
      }
      
      const regMatch = name.match(this._regionReg);
      if (regMatch) {
        const r = regMatch[0].toUpperCase();
        const regionMap = {
          "香港": "HK_MO_TW", "HK": "HK_MO_TW", "港": "HK_MO_TW",
          "澳门": "HK_MO_TW", "MO": "HK_MO_TW", "澳": "HK_MO_TW",
          "台湾": "HK_MO_TW", "TW": "HK_MO_TW", "台": "HK_MO_TW",
          "新加坡": "SG", "SG": "SG",
          "日本": "JP", "JP": "JP",
          "美国": "US", "US": "US",
          "韩国": "KR", "KR": "KR",
          "英国": "UK", "UK": "UK",
          "德国": "DE", "DE": "DE"
        };
        const rCode = regionMap[r] || r;
        semanticScore += (this._weights.REGIONS[rCode] || 0);
      }
      
      const latencyMatch = name.match(this._latencyReg);
      if (latencyMatch) {
        const ms = parseInt(latencyMatch[1]);
        if (ms > 800) staticScore -= 45;
        else if (ms > 400) staticScore -= 25;
        else if (ms < 150) staticScore += 10;
      }

      staticScore += Math.min(30, semanticScore);
      const baseScore = Utils.clamp(staticScore, 0, 80);

      const dynamicOffset = this._stats ? this._stats.getDynamicOffset(proxy) : 0;

      return Math.max(0, baseScore + dynamicOffset);
    }

    /**
     * 全量节点评判打分系统
     * 策略：75分优质标准 → 65分兜底标准 → 随机抽取
     * 输出：75%AI推送 + 25%随机抽取
     */
    getBestNodes(proxies) {
      if (!proxies || !proxies.length) return [];
      
      try {
        const total = proxies.length;
        let targetCount = Math.min(500, Math.max(5, Math.floor(total * 0.15)));
        if (total <= 5) targetCount = total;
        
        Logger.info("AIEngine", `优选筛选: 总数 ${total}, 目标 ${targetCount}`);

        const candidates = proxies.map(p => {
          const score = this.score(p);
          const name = typeof p === 'string' ? p : String(p.name || "");
          const isCore = /HK|MO|TW|SG|JP|US|香港|澳门|台湾|新加坡|日本|美国|港|澳|台/i.test(name);
          const stats = this._stats ? this._stats.getStats(p) : { failCount: 0 };
          
          return {
            id: name,
            score: score,
            proxy: p,
            server: p.server || "",
            isCore: isCore,
            failCount: stats.failCount
          };
        }).filter(item => {
          if (item.failCount > 0) return false;
          return item.score >= this._SCORE_THRESHOLDS.MIN;
        }).sort((a, b) => b.score - a.score);

        const excellentNodes = candidates.filter(item => item.score >= this._SCORE_THRESHOLDS.EXCELLENT);
        const goodNodes = candidates.filter(item => item.score >= this._SCORE_THRESHOLDS.GOOD && item.score < this._SCORE_THRESHOLDS.EXCELLENT);
        const fallbackNodes = candidates.filter(item => item.score >= this._SCORE_THRESHOLDS.MIN && item.score < this._SCORE_THRESHOLDS.GOOD);

        let selectedNodes = [];

        if (excellentNodes.length >= targetCount) {
          Logger.info("AIEngine", `优质节点充足: ${excellentNodes.length}个`);
          selectedNodes = excellentNodes.slice(0, targetCount);
        } else if (goodNodes.length > 0) {
          Logger.info("AIEngine", `降级到65分标准: 优质${excellentNodes.length}个, 良好${goodNodes.length}个`);
          selectedNodes = [...excellentNodes, ...goodNodes].slice(0, targetCount);
        } else if (fallbackNodes.length > 0) {
          Logger.warn("AIEngine", `降级到兜底标准: 使用${fallbackNodes.length}个可用节点`);
          selectedNodes = fallbackNodes.slice(0, Math.min(targetCount, fallbackNodes.length));
        } else {
          Logger.warn("AIEngine", "无可用节点，执行随机兜底");
          const randomNodes = candidates.sort(() => Math.random() - 0.5).slice(0, Math.min(targetCount, candidates.length));
          selectedNodes = randomNodes;
        }

        const aiPushCount = Math.ceil(selectedNodes.length * 0.75);
        const randomCount = selectedNodes.length - aiPushCount;

        const aiPushNodes = selectedNodes.slice(0, aiPushCount);
        let randomNodes = [];

        if (randomCount > 0) {
          const remainingNodes = candidates.filter(item => !aiPushNodes.some(s => s.id === item.id));
          randomNodes = remainingNodes.sort(() => Math.random() - 0.5).slice(0, randomCount);
        }

        const finalNodes = [...aiPushNodes, ...randomNodes];

        const diversityFiltered = this._applyDiversityFilter(finalNodes, targetCount);

        Logger.info("AIEngine", `优选完成: AI推送${aiPushNodes.length}个, 随机${randomNodes.length}个, 最终${diversityFiltered.length}个`);
        return diversityFiltered.map(s => s.id);
      } catch (e) {
        Logger.error("AIEngine", `筛选异常: ${e.message}`);
        return proxies.slice(0, 10).map(p => p.name || p);
      }
    }

    /**
     * 多样性过滤：确保节点来自不同服务器、ASN和集群
     * 简化版：只在外层添加异常处理
     */
    _applyDiversityFilter(nodes, targetCount) {
      // 基本输入验证
      if (!Array.isArray(nodes) || nodes.length === 0) {
        return [];
      }
      
      if (typeof targetCount !== 'number' || targetCount <= 0) {
        targetCount = Math.max(5, Math.floor(nodes.length * 0.15));
      }
      
      try {
        const selected = [];
        const seenServers = new Map();
        const seenASNs = new Map(); 
        const seenClusters = new Map(); 

        const getCluster = (name) => String(name || "").replace(/\d+|[_-]\d+|[A-Za-z]\d+$/g, "").trim();

        // 第一轮：严格多样性过滤
        for (const item of nodes) {
          if (selected.length >= targetCount) break;
          if (!item || !item.id) continue; // 简单跳过无效节点
          
          const asn = item.server && typeof item.server === 'string' 
            ? item.server.split('.').slice(-2).join('.') 
            : "0.0";
          const asnCount = seenASNs.get(asn) || 0;
          const cluster = getCluster(item.id);
          const clusterCount = seenClusters.get(cluster) || 0;
          const serverCount = item.server ? (seenServers.get(item.server) || 0) : 0;

          // 严格约束
          if (serverCount < 2 && asnCount < 3 && clusterCount < 3) {
            selected.push(item);
            if (item.server) seenServers.set(item.server, serverCount + 1);
            seenASNs.set(asn, asnCount + 1);
            seenClusters.set(cluster, clusterCount + 1);
          }
        }

        // 兜底逻辑：如果结果不足，放宽约束
        const minResult = Math.min(5, targetCount);
        if (selected.length < minResult) {
          for (const item of nodes) {
            if (selected.length >= targetCount) break;
            if (item && item.id && !selected.some(s => s.id === item.id)) {
              selected.push(item);
            }
          }
        }

        return selected;
      } catch (e) {
        Logger.error("AIEngine", `多样性过滤异常: ${e.message}`);
        return nodes.slice(0, Math.min(targetCount, nodes.length));
      }
    }

    detectNetworkState() { }
    performSelfCheck() { return 0; }
    reset() {}
  }

  /* ========== 全局持久化存储 (跨配置刷新保留) ========== */
  if (typeof root.__MIHOMO_STATS__ === "undefined") {
    root.__MIHOMO_STATS__ = {
      nodes: new Map(), // key: nodeHash, value: { failCount: 0, successCount: 0, lastSeen: Date.now(), scoreOffset: 0 }
      asns: new Map(),  // key: asn, value: count
      lastRun: Date.now(),
      lastCheckTime: 0,
      checkInProgress: false
    };
  }
  const GLOBAL_STATS = root.__MIHOMO_STATS__;

  /* ========== 8. 节点状态管理器 (Status Manager) ========== */
  class NodeStatsManager {
    constructor(cache) {
      this._cache = cache || new LRUCache();
      this._stats = GLOBAL_STATS.nodes;
    }

    _getHash(proxy) {
      if (!proxy) return "";
      const name = proxy.name || (typeof proxy === 'string' ? proxy : "");
      const server = proxy.server || "";
      const port = proxy.port || "";
      return `${name}|${server}|${port}`;
    }

    /**
     * 获取节点统计信息，不存在则初始化
     */
    getStats(proxy) {
      const hash = this._getHash(proxy);
      if (!this._stats.has(hash)) {
        this._stats.set(hash, { failCount: 0, successCount: 0, lastSeen: Date.now(), scoreOffset: 0 });
      }
      return this._stats.get(hash);
    }

    /**
     * 计算动态评分偏移 (-60 到 +10)
     * 规则：稳定在线奖励，失败记录严厉惩罚
     */
    getDynamicOffset(proxy) {
      const stats = this.getStats(proxy);
      const now = Date.now();
      let offset = 0;

      // 1. 忠诚度奖励
      if (now - stats.lastSeen < CONSTANTS.TIME.DAY) offset += 2; 
      if (stats.successCount > 5) offset += 3; 

      // 2. 失败惩罚：单次失败即大幅扣分，确保故障节点快速移出优选组
      if (stats.failCount > 0) {
        offset -= Math.min(60, stats.failCount * 40);
      }

      stats.lastSeen = now;
      stats.scoreOffset = Utils.clamp(offset, -60, 10);
      return stats.scoreOffset;
    }

    recordSuccess(proxy) {
      const stats = this.getStats(proxy);
      stats.successCount++;
      stats.failCount = Math.max(0, stats.failCount - 1);
    }

    recordFailure(proxy) {
      const stats = this.getStats(proxy);
      stats.failCount++;
      stats.successCount = 0;
    }

    /**
     * 清理过期统计数据 (默认保留 3 天)
     */
    cleanup(maxAge = CONSTANTS.TIME.DAY * 3) {
      const now = Date.now();
      let count = 0;
      for (const [hash, stats] of this._stats.entries()) {
        if (now - stats.lastSeen > maxAge) {
          this._stats.delete(hash);
          count++;
        }
      }
      if (count > 0) Logger.info("NodeStats", `清理 ${count} 条过期数据`);
    }

    update(id, data, scene) {}
    recordSwitch(id){}
    reset(){ this._stats.clear(); }
  }

  /* ========== 9. 功能组管理器 (Functional Group Manager) ========== */
  class FunctionalGroupManager {
    constructor(aiEngine, statsManager) {
      this._ai = aiEngine;
      this._stats = statsManager;
      
      // 功能组节点筛选标准（解决方案2：引用 Config.aiOptions.scenes 而不是重复定义）
      this._criteria = {
        'ai_group': { 
          minScore: 70, 
          maxFailCount: 0, 
          preferRegions: ['HK_MO_TW', 'SG', 'JP', 'US'],
          sceneWeights: Config.aiOptions.scenes.browsing  // 引用而非重复
        },
        'streaming_group': { 
          minScore: 65, 
          maxFailCount: 0, 
          preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'],
          sceneWeights: Config.aiOptions.scenes.streaming  // 引用而非重复
        },
        'gaming_group': { 
          minScore: 75, 
          maxFailCount: 0, 
          maxLatency: 100, 
          preferRegions: ['HK_MO_TW', 'JP', 'TW', 'SG'],
          sceneWeights: Config.aiOptions.scenes.gaming  // 引用而非重复
        },
        'download_group': { 
          minScore: 60, 
          maxFailCount: 1, 
          preferRegions: ['HK_MO_TW', 'SG', 'US', 'JP'],
          sceneWeights: Config.aiOptions.scenes.download  // 引用而非重复
        },
        'download_software_group': { 
          minScore: 55, 
          maxFailCount: 2, 
          preferRegions: ['HK_MO_TW', 'SG', 'JP', 'US'],
          sceneWeights: Config.aiOptions.scenes.download  // 引用而非重复
        },
        'social_group': { 
          minScore: 65, 
          maxFailCount: 0, 
          preferRegions: ['HK_MO_TW', 'SG', 'JP', 'US'],
          sceneWeights: Config.aiOptions.scenes.browsing  // 引用而非重复
        },
        'search_group': { 
          minScore: 65, 
          maxFailCount: 0, 
          preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'],
          sceneWeights: Config.aiOptions.scenes.browsing  // 引用而非重复
        },
        'dev_group': { 
          minScore: 70, 
          maxFailCount: 0, 
          preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'],
          sceneWeights: Config.aiOptions.scenes.browsing  // 引用而非重复
        },
        'email_group': { 
          minScore: 65, 
          maxFailCount: 0, 
          preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'],
          sceneWeights: Config.aiOptions.scenes.browsing  // 引用而非重复
        },
        'music_group': { 
          minScore: 65, 
          maxFailCount: 0, 
          preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'],
          sceneWeights: Config.aiOptions.scenes.streaming  // 引用而非重复
        },
        'browsing_group': { 
          minScore: 60, 
          maxFailCount: 1, 
          preferRegions: ['HK_MO_TW', 'SG', 'JP', 'US'],
          sceneWeights: { latencyWeight: 0.4, stabilityWeight: 0.3, bandwidthWeight: 0.2, jitterWeight: 0.1 }
        }
      };
    }

    /**
     * 为功能组筛选合适的节点（解决方案3：使用 ProxyFilter 统一过滤逻辑）
     */
    selectNodesForGroup(groupId, allProxies) {
      const standard = this._criteria[groupId];
      if (!standard) {
        Logger.warn("FunctionalGroup", `未找到 ${groupId} 的筛选标准,使用所有节点`);
        return allProxies.map(p => typeof p === 'string' ? p : p.name);
      }

      try {
        // 根据标准筛选节点
        const suitable = allProxies.filter(p => {
          const score = this._ai.score(p);
          const stats = this._stats.getStats(p);
          const name = typeof p === 'string' ? p : String(p.name || "");

          // 评分要求
          if (score < standard.minScore) return false;
          
          // 失败次数要求
          if (stats.failCount > standard.maxFailCount) return false;

          // 延迟要求(如果有)
          if (standard.maxLatency) {
            const latencyMatch = name.match(/(\d+)ms/i);
            if (latencyMatch) {
              const latency = parseInt(latencyMatch[1]);
              if (latency > standard.maxLatency) return false;
            }
          }

          // 地理位置偏好(可选)
          if (standard.preferRegions && standard.preferRegions.length > 0) {
            const matchRegion = standard.preferRegions.some(region => {
              if (region === 'HK_MO_TW') {
                return /港|澳|台|🇭🇰|🇲🇴|🇹🇼|hk|mo|tw|hongkong|macao|macau|taiwan/i.test(name);
              }
              return new RegExp(region, 'i').test(name);
            });
            // 如果不匹配偏好地区,降低优先级但不完全排除
            if (!matchRegion && score < standard.minScore + 10) return false;
          }

          return true;
        });

        // 如果筛选结果太少,放宽标准
        if (suitable.length < 3 && allProxies.length >= 3) {
          Logger.warn("FunctionalGroup", `${groupId} 筛选结果过少(${suitable.length}),放宽标准`);
          const relaxed = allProxies.filter(p => {
            const score = this._ai.score(p);
            const stats = this._stats.getStats(p);
            return score >= (standard.minScore - 10) && stats.failCount <= (standard.maxFailCount + 1);
          });
          return relaxed.slice(0, Math.max(10, Math.ceil(allProxies.length * 0.3))).map(p => typeof p === 'string' ? p : p.name);
        }

        // 限制数量,避免过多
        const maxNodes = Math.min(50, Math.max(10, Math.ceil(allProxies.length * 0.4)));
        const selected = suitable.slice(0, maxNodes);

        Logger.info("FunctionalGroup", `${groupId} 筛选完成: ${selected.length}/${allProxies.length} 个节点`);
        return selected.map(p => typeof p === 'string' ? p : p.name);
      } catch (e) {
        Logger.error("FunctionalGroup", `${groupId} 筛选异常: ${e.message}`);
        return allProxies.slice(0, 20).map(p => typeof p === 'string' ? p : p.name);
      }
    }
  }

  /* ========== 10. 自动化管理组件 (Region & AdBlock) ========== */
  
  /**
   * 广告拦截规则注入（简化为函数）
   */
  function injectAdBlockRules(ruleProviders) {
    const adBlockUrl = URLS.rulesets.ads();
    if (adBlockUrl) {
      Utils.safeSet(ruleProviders, "adblock_combined", {
        type: "http",
        interval: 86400,
        behavior: "domain",
        format: "mrs",
        url: adBlockUrl,
        path: "./ruleset/adblock_combined.mrs"
      });
    }
  }

  class RegionAutoManager {
    constructor(cache){
      this._cache=cache||new LRUCache();
      this._stats=new NodeStatsManager(this._cache);
      this._ai=new AIEngine(this._stats);
    }
    get stats(){return this._stats;}
    get ai(){return this._ai;}

    /**
     * 识别代理节点所属区域
     * 优先使用节点名称正则匹配，失败时可通过 GeoIP 兜底（需要外部实现）
     */
    discoverRegionsFromProxies(proxies){
      const regions=Config.regionOptions?.regions || [];
      const found=new Map();
      const list=Array.isArray(proxies)?proxies:[];
      list.forEach(p=>{
        const n=String(p?.name||"").trim(); if(!n) return;
        
        // 1. 优先使用节点名称正则匹配
        let matched=regions.find(r=>r.regex.test(n));
        
        // 2. GeoIP 兜底机制（可选实现）
        // 如果节点名称匹配失败，可以尝试通过 IP 地址查询地理位置
        // 注意：需要集成 GeoIP 数据库或 API，当前环境可能不支持
        // 实现示例：
        // if (!matched && p.server && this._geoIPResolver) {
        //   try {
        //     const countryCode = this._geoIPResolver.resolveIP(p.server);
        //     matched = regions.find(r => r.code === countryCode);
        //     if (matched) Logger.debug("GeoIP", `${p.name} -> ${matched.name} (via IP: ${p.server})`);
        //   } catch (e) {
        //     Logger.debug("GeoIP", `解析失败: ${p.server}`, e.message);
        //   }
        // }
        
        if(matched){found.set(matched.name,matched);p._geoMatch=matched.name;}
      });
      return found;
    }
    mergeNewRegions(base,discovered){
      const merged=[...(base||[])];
      discovered.forEach(r=>{ if(!merged.some(m=>m.name===r.name)) merged.push(r); });
      return merged;
    }

    /**
     * 核心逻辑：构建区域分组、优选组及策略组
     */
    buildRegionGroups(config,regions,proxies){
      const hasProviders = !!(config["proxy-providers"]&&Object.keys(config["proxy-providers"]).length);
      const list = Array.isArray(proxies)?proxies:[];
      const usedFilters=[]; const regionGroups=[];
      
      const activeRegions = hasProviders ? (Config.regionOptions?.regions || []) : regions;
      const maxRegions = Config.regionOptions?.maxRegions || 10;

      // 1. 生成区域分组（select 类型）- 限制最多 maxRegions 个
      let regionCount = 0;
      for(const r of activeRegions){
        if(regionCount >= maxRegions) {
          Logger.warn("RegionGroups", `已达到地理组上限 ${maxRegions}，跳过剩余区域`);
          break;
        }
        
        const regionProxies=list.filter(p=>{const n=String(p.name||""); if(["DIRECT","REJECT"].includes(n.toUpperCase())) return false; return p._geoMatch===r.name || r.regex.test(n);});
        if(!hasProviders && !regionProxies.length) continue;

        let pattern = Utils.regexToMihomo(r.regex);

        // AI 增强：如果开启了 AI 评分，将区域内的优选节点置顶
        if(Config.aiOptions?.enable && regionProxies.length){
          const count = Math.max(3, Math.ceil(regionProxies.length * 0.2));
          const best=this._ai.getBestNodes(regionProxies); 
          if(best.length){
            const exactPattern = best.slice(0, count).map(id=>`^${Utils.escapeRegex(id)}$`).join("|");
            pattern = `(${pattern})|(${exactPattern})`;
          }
        }
        usedFilters.push(pattern);
        // 地理组只包含该地理区域的节点，不添加全局组（避免逻辑污染）
        const base=Utils.getProxyGroupBase();
        regionGroups.push({
          ...base,
          name:r.name,
          type:"select",
          "include-all":true,
          filter:pattern,
          icon:ICON_VAL(r.icon)
        });
        regionCount++;
      }

      const excludeFilter = usedFilters.length ? usedFilters.map(f=>`(${f})`).join("|") : "";
      
      // 2. AI优选组 (AI 精选)
      const base=Utils.getProxyGroupBase();
      let bestIds = [];
      if(Config.aiOptions?.enable && list.length){
        bestIds = this._ai.getBestNodes(list);
      }

      const bestNodesGroup = {
        ...base,
        name: "AI优选",
        type: "select",
        proxies: bestIds.length ? bestIds : ["DIRECT"],
        "include-all": false,
        tolerance: 50,
        icon: ICON_VAL(ICONS.Premium)
      };

      // 3. 手动选择组 - 用户完全控制的选择组
      // 包含：DIRECT（默认）+ 策略组（自动选择、AI优选）+ 所有节点
      // 关键：第一项是 DIRECT，避免被"夺权"；同时提供策略组选项，提高灵活性
      const allNodeNames = list.map(p => p.name || p);
      const manualSelectionGroup = {
        ...base,
        name: "手动选择",
        type: "select",
        proxies: [
          "DIRECT",       // 第1项：默认选中，不会被夺权
          "自动选择",     // 第2项：用户可选，使用 url-test 自动测速
          "AI优选",       // 第3项：用户可选，使用 AI 智能筛选
          ...allNodeNames // 第4项起：所有具体节点
        ],
        "include-all": false,  // 使用显式节点列表
        icon: ICON_VAL(ICONS.Premium)
      };

      const autoSelectionGroup = {
        ...base,
        name: "自动选择",
        type: "url-test",  // 只有自动选择是 url-test
        "include-all": true,
        tolerance: 50,
        icon: ICON_VAL(ICONS.Proxy)
      };

      // 其他节点组：包含未匹配的节点 + 提供代理选择（用于 MATCH 兜底）
      // 关键：第一项是"手动选择"，确保 MATCH 规则默认不会被"夺权"
      const otherGroup={
        ...base,
        name:"其他节点",
        type:"select",
        proxies:["手动选择", "自动选择", "AI优选", "DIRECT"],  // 第一项改为"手动选择"
        "include-all":true,
        "exclude-filter":excludeFilter,
        icon:ICON_VAL(ICONS.WorldMap)
      };

      const regionProxyGroups = [bestNodesGroup, manualSelectionGroup, autoSelectionGroup];
      regionProxyGroups.push(...regionGroups, otherGroup);
      
      return {regionProxyGroups,otherProxyNames:[]};
    }
  }

  /* ========== 11. 中央管理器 (Central Manager) ========== */
  /**
   * 修复循环依赖：使用延迟初始化和依赖注入
   * 所有子管理器通过 getter 延迟创建，避免构造函数中的循环引用
   */
  class CentralManager {
    static _instance;
    static getInstance(){
      if(!CentralManager._instance) CentralManager._instance=new CentralManager();
      return CentralManager._instance;
    }
    constructor(){
      if(CentralManager._instance) return CentralManager._instance;
      
      // 基础组件：无依赖，直接初始化
      this._cache=new LRUCache();
      this._http=new HttpClient();
      
      // 延迟初始化的管理器：通过 getter 按需创建，避免循环依赖
      this._adBlock=null;
      this._regionMgr=null;
      this._functionalMgr=null;
      this._probe=null;
      this._initialized = false;
      
      CentralManager._instance=this;
    }
    
    // 基础组件访问器
    get lruCache(){return this._cache;}
    get httpClient(){return this._http;}
    
    // 延迟初始化的管理器访问器
    get regionAutoManager(){
      if(!this._regionMgr) {
        // 只传递 cache，避免传递整个 CentralManager
        this._regionMgr=new RegionAutoManager(this._cache);
      }
      return this._regionMgr;
    }
    
    get functionalGroupManager(){
      if(!this._functionalMgr) {
        // 依赖注入：从 regionAutoManager 获取 ai 和 stats
        const ai = this.regionAutoManager.ai;
        const stats = this.regionAutoManager.stats;
        this._functionalMgr = new FunctionalGroupManager(ai, stats);
      }
      return this._functionalMgr;
    }
    
    get backgroundProbe(){
      if(!this._probe) {
        // 依赖注入：传递 http 和 stats，避免传递整个 manager
        this._probe=new BackgroundProbe(this._http, this.regionAutoManager.stats);
      }
      return this._probe;
    }

    initialize(){
      if (this._initialized) return;
      this._initialized = true;
      try {
        // 延迟初始化：只在需要时创建 regionAutoManager
        this.regionAutoManager.stats.cleanup();
      } catch (e) {
        Logger.warn("Central.init", `初始化警告: ${e.message}`);
      }
      Logger.info("Central.init", `初始化完成 (环境: ${Env.get()})`);
    }

    processConfiguration(config,ctx=null){
      // 简化：场景检测功能失效，直接使用默认场景
      const scene = "browsing";
      this.regionAutoManager.ai.setScene(scene);
      const newConfig = ConfigBuilder.build(config,this);
      
      // 核心增强：触发后台静默预检
      if (config.proxies && Array.isArray(config.proxies)) {
        this.backgroundProbe.trigger(config.proxies);
      }
      
      return newConfig;
    }
  }

  const ErrorConfigFactory = {
    createErrorConfig(msg,opts={}){
      const t=Date.now();
      return {name:`⛔ 脚本错误: ${String(msg).slice(0,20)}...`,type:"direct",...opts,_error:true,_errorMessage:msg,_errorTimestamp:t,_scriptError:{timestamp:t,message:msg,fallback:true,version:"ultimate_optimized_v4.0"}};
    }
  };

  /* ========== 11. 配置生成引擎 (Config Builder) ========== */
  
  /**
   * 规则排序管理器 - 按优先级对规则进行排序（简化版）
   */
  class RuleOrderManager {
    /**
     * 按优先级对规则进行排序
     */
    static prioritizeRules(rules) {
      if (!Array.isArray(rules) || !rules.length) return rules || [];
      
      // 优先级映射（内联）
      const getPriority = (rule) => {
        if (typeof rule !== 'string') return 999;
        const ruleUpper = rule.toUpperCase();
        
        // 优先级 1: LAN 和私有网络
        if (ruleUpper.startsWith('GEOSITE,PRIVATE') || ruleUpper.startsWith('GEOIP,PRIVATE')) return 1;
        // 优先级 2: REJECT 规则
        if (ruleUpper.includes('REJECT')) return 2;
        // 优先级 3: 应用程序和进程
        if (ruleUpper.startsWith('PROCESS-NAME') || ruleUpper.startsWith('RULE-SET,APPLICATIONS')) return 3;
        // 优先级 4: 特定服务
        if (ruleUpper.startsWith('RULE-SET,') || ruleUpper.startsWith('GEOSITE,')) return 4;
        // 优先级 5: 国内路由
        if (ruleUpper.includes('CHINA') || ruleUpper.includes(',CN')) return 5;
        // 优先级 6: 国外代理
        if (ruleUpper.includes('PROXY') || ruleUpper.includes('GFW')) return 6;
        // 优先级 7: MATCH 兜底
        if (ruleUpper.startsWith('MATCH')) return 7;
        
        return 4; // 默认优先级
      };
      
      return [...rules].sort((a, b) => getPriority(a) - getPriority(b));
    }
  }

  /**
   * 安全验证器 - 验证和清理所有外部输入
   */
  class SecurityValidator {
    /**
     * 验证函数是否安全可执行（简化版：单一黑名单）
     */
    static validateFunction(funcStr) {
      if (typeof funcStr !== 'string') return false;
      
      // 黑名单：检查危险模式
      if (CONSTANTS.RE.DANGEROUS_PATTERNS.test(funcStr)) {
        Logger.warn("Security", `检测到危险函数模式: ${funcStr.substring(0, 50)}...`);
        return false;
      }
      
      // 简单检查：必须包含安全的函数调用
      const hasSafePattern = /URLS|ICONS|ICON_VAL|DNSPolicyManager/.test(funcStr);
      if (!hasSafePattern) {
        Logger.warn("Security", `函数不包含安全模式: ${funcStr.substring(0, 50)}...`);
        return false;
      }
      
      return true;
    }

    /**
     * 验证规则提供者配置
     */
    static validateRuleProvider(provider) {
      if (!provider || typeof provider !== 'object') return false;
      if (!provider.url || !provider.path) {
        Logger.warn("Security", `规则提供者缺少必需字段: url=${provider.url}, path=${provider.path}`);
        return false;
      }
      return true;
    }

    /**
     * 增强 URL 验证，防止 SSRF（保留有价值的部分）
     */
    static sanitizeUrl(url) {
      if (typeof url !== 'string') return null;
      
      try {
        const urlObj = new URL(url);
        
        // 只允许 HTTP 和 HTTPS 协议
        if (!['http:', 'https:'].includes(urlObj.protocol)) {
          Logger.warn("Security", `不安全的协议: ${urlObj.protocol}`);
          return null;
        }
        
        // 检查私有 IP 地址
        if (Utils.isPrivateIP(urlObj.hostname)) {
          Logger.warn("Security", `私有 IP 地址: ${urlObj.hostname}`);
          return null;
        }
        
        // 检查 localhost 和特殊地址
        const hostname = urlObj.hostname.toLowerCase();
        const dangerousHosts = [
          'localhost', '127.0.0.1', '0.0.0.0', '::1',
          '169.254.169.254', // AWS/Azure metadata
          'metadata.google.internal' // GCP metadata
        ];
        
        if (dangerousHosts.includes(hostname)) {
          Logger.warn("Security", `危险的主机名: ${hostname}`);
          return null;
        }
        
        // 检查内网域名
        if (hostname.endsWith('.local') || hostname.endsWith('.internal')) {
          Logger.warn("Security", `内网域名: ${hostname}`);
          return null;
        }
        
        return urlObj.toString();
      } catch (e) {
        Logger.warn("Security", `无效的 URL: ${url}`);
        return null;
      }
    }
  }

  /**
   * DNS 策略构建（简化为函数）
   */
  function buildDNSPolicy() {
    return {
      "geosite:private": ["system"],
      "geosite:cn": ["119.29.29.29", "223.5.5.5"],
      "geosite:category-games@cn": ["119.29.29.29", "223.5.5.5"],
      "geosite:steam@cn": ["119.29.29.29", "223.5.5.5"],
      "geosite:microsoft@cn": ["119.29.29.29", "223.5.5.5"],
      "geosite:apple@cn": ["119.29.29.29", "223.5.5.5"],
      "rule-set:acl4ssr_china": ["119.29.29.29", "223.5.5.5"],
      "rule-set:ls_cn": ["119.29.29.29", "223.5.5.5"],
      "rule-set:finance": ["8.8.8.8", "1.1.1.1"]
    };
  }

  class ConfigBuilder {
    /**
     * 构建最终配置
     * 包含：场景自适应、配置补全、区域发现、分流组构建及规则生成
     */
    static build(baseConfig,context=null){
      const cfg = {...baseConfig};
      if(baseConfig.proxies) cfg.proxies=Utils.deepClone(baseConfig.proxies,"proxies");
      if(baseConfig["proxy-groups"]) cfg["proxy-groups"] = Utils.deepClone(baseConfig["proxy-groups"],"proxy-groups");
      if(baseConfig.rules) cfg.rules=[...baseConfig.rules];

      if(Config.adaptive && context) this._applyAdaptive(cfg,context);
      if(!this._validate(cfg)){
        if(Config.autoIntervention) this._selfHeal(cfg);
        else return cfg;
      }

      this._mergeSystem(cfg);
      const {regions,regionProxyGroups,otherProxyNames} = this._discoverRegions(cfg,context);
      const regionGroupNames = this._regionGroupNames(regionProxyGroups);
      this._ensureSystemProxies(cfg);
      cfg["proxy-groups"] = this._buildProxyGroups(cfg,regionGroupNames,regionProxyGroups,otherProxyNames,context);
      const {rules,ruleProviders} = this._buildRules(cfg,regionGroupNames,context);
      cfg.rules=rules; cfg["rule-providers"]=ruleProviders;
      if(Config.autoIntervention) this._finalAudit(cfg);
      return cfg;
    }

    /**
     * 场景自适应权重调整（简化版）
     */
    static _applyAdaptive(cfg,context){
      // 简化：场景检测功能失效，直接使用默认场景
      const scene = "browsing";
      const opts=Config.aiOptions;
      if(opts?.enable && opts.scenes?.[scene]){
        Logger.info("Config.Adaptive",`场景: ${scene}, 调整权重`);
        opts.scoring = {...opts.scoring,...opts.scenes[scene]};
      }
    }

    /**
     * 配置自愈：补全基础结构
     */
    static _selfHeal(cfg){
      Logger.info("Config.SelfHeal","补全基础配置");
      cfg.proxies = Array.isArray(cfg.proxies) ? cfg.proxies : [];
      cfg["proxy-groups"] = Array.isArray(cfg["proxy-groups"]) ? cfg["proxy-groups"] : [];
      cfg.rules = Array.isArray(cfg.rules) ? cfg.rules : [];
      if(cfg.proxies.length===0 && !cfg["proxy-providers"]){
        Logger.warn("Config.SelfHeal","注入紧急 DIRECT");
        cfg.proxies.push({name:"DIRECT",type:"direct"});
      }
    }

    /**
     * 最终合规性审计
     */
    static _finalAudit(cfg){
      cfg["allow-lan"] ??= true; cfg["mode"] ??= "rule"; cfg["log-level"] ??= "info";
      if(cfg["proxy-providers"] && typeof cfg["proxy-providers"]==="object"){
        for(const [n,p] of Object.entries(cfg["proxy-providers"])){
          if(!p.url || !p.path){
            Logger.warn("Config.Audit",`移除无效 Provider: ${n}`);
            delete cfg["proxy-providers"][n];
          }
        }
      }
      // 使用 SecurityValidator 验证规则提供者
      if(cfg["rule-providers"] && typeof cfg["rule-providers"]==="object"){
        for(const [n,p] of Object.entries(cfg["rule-providers"])){
          if(!SecurityValidator.validateRuleProvider(p)){
            Logger.warn("Config.Audit",`移除无效规则提供者: ${n}`);
            delete cfg["rule-providers"][n];
          }
        }
      }
      if(Array.isArray(cfg.rules)) cfg.rules=cfg.rules.filter(r=>typeof r==="string" && r.split(",").length>=2);
    }
    static _validate(cfg){
      const p=cfg.proxies||[];
      const pCount=Array.isArray(p)?p.length:0;
      const prov=cfg["proxy-providers"];
      const provCount = prov && typeof prov==="object"?Object.keys(prov).length:0;
      if(!pCount && !provCount){Logger.warn("ConfigBuilder","未发现代理/提供商"); return false;}
      return true;
    }

    static _discoverRegions(cfg,context){
      const regionAuto = context?.regionAutoManager || new RegionAutoManager(context?.lruCache);
      let regions = Config.regionOptions?.regions || [];
      const proxies = cfg.proxies || [];
      if(Config.regionOptions?.autoDiscover || Config.autoIntervention){
        try{const discovered = regionAuto.discoverRegionsFromProxies(proxies); regions = regionAuto.mergeNewRegions(regions,discovered);}catch(e){Logger.warn("Config.RegionDiscover",e.message||e);}
      }
      const {regionProxyGroups,otherProxyNames} = regionAuto.buildRegionGroups(cfg,regions,proxies);
      return {regions,regionProxyGroups,otherProxyNames};
    }

    static _mergeSystem(cfg){
      try{
        if(Config.system && typeof Config.system==="object"){
          const sys = Utils.deepClone(Config.system);
          const hydrate = (obj)=>{
            for(const k in obj){
              if(typeof obj[k]==="function"){
                const fStr=obj[k].toString();
                // 使用 SecurityValidator 进行安全验证
                if(!SecurityValidator.validateFunction(fStr)){
                  Logger.warn("Config.Security",`拒绝执行不安全的函数: ${k}`);
                  delete obj[k];
                  continue;
                }
                try{
                  const v=obj[k]();
                  if(v==null || ["string","number","boolean"].includes(typeof v) || (typeof v==="object" && !Array.isArray(v))){
                    obj[k]=v;
                  }else{
                    Logger.warn("Config.Security",`函数返回非法类型: ${k}`);
                    delete obj[k];
                  }
                }catch(e){
                  Logger.error("Config.Security",`执行失败: ${k}`,e.message);
                  delete obj[k];
                }
              }else if(obj[k] && typeof obj[k]==="object") hydrate(obj[k]);
            }
          };
          hydrate(sys);
          Utils.mergeDefaults(cfg, sys);
        }
        if(Config.dns && typeof Config.dns==="object") cfg.dns = Utils.mergeDefaults(cfg.dns || {}, Config.dns);
      }catch(e){Logger.warn("Config.MergeSystem",e.message||e);}
    }

    static _regionGroupNames(groups){
      try{return Utils.unique(groups.map(g=>g?.name).filter(Boolean));}catch(e){Logger.warn("Config.RegionNames",e.message||e);return[];}
    }

    static _ensureSystemProxies(cfg){
      if(!Array.isArray(cfg.proxies)) cfg.proxies = [];
    }

    static _buildProxyGroups(cfg,regionNames,regionGroups,otherNames,context){
      const base=Utils.getProxyGroupBase();
      const groups=[];
      const services=Array.isArray(Config.services)?Config.services:[];
      
      // 默认优先级顺序：手动选择 > 自动选择 > AI优选
      const defaultOrder = ["手动选择", "自动选择", "AI优选", "DIRECT"];
      const allProxies = cfg.proxies || [];

      // 获取功能组管理器
      const functionalMgr = context?.functionalGroupManager;

      // ========== 不再为每个服务创建独立分组 ==========
      // 所有服务规则将通过功能组来路由
      
      // ========== 1. 创建 10 个功能组(智能筛选节点) ==========
      const functionalGroups = Array.isArray(Config.functionalGroups) ? Config.functionalGroups : [];
      functionalGroups.forEach(fg => {
        try {
          if (!fg?.name || !fg?.id) return;
          
          // 使用功能组管理器筛选合适的节点
          let selectedNodes = [];
          if (functionalMgr && allProxies.length > 0) {
            selectedNodes = functionalMgr.selectNodesForGroup(fg.id, allProxies);
          }
          
          // 构建代理列表: 手动选择 + 自动选择 + AI优选 + 其他优先选项 + 筛选的节点 + 地理分组
          const customOrder = Array.isArray(fg.proxiesOrder) ? fg.proxiesOrder : [];
          // 确保正确的优先级顺序：手动选择 > 自动选择 > AI优选
          const proxies = ["手动选择", "自动选择", "AI优选", ...customOrder.filter(p => p !== "手动选择" && p !== "自动选择" && p !== "AI优选")];
          const allOptions = Utils.unique([...proxies, ...selectedNodes, ...regionNames]);
          
          groups.push({
            ...base, 
            name: fg.name, 
            type: "select", 
            proxies: allOptions, 
            icon: ICON_VAL(fg.icon)
          });
          
          Logger.debug("ProxyGroups", `功能组 ${fg.name}: ${selectedNodes.length} 个筛选节点`);
        } catch (e) {
          Logger.warn("Config.FunctionalGroup", fg?.id, e.message || e);
        }
      });

      // ========== 2. 创建 1 个官方默认分组（国内网站）==========
      (Config.common?.defaultProxyGroups||[]).forEach(g=>{
        if(!g?.name) return;
        const customProxies = Array.isArray(g.proxies) ? g.proxies : [];
        
        // 国内网站组：只需要 DIRECT 和手动选择，不需要国际节点
        const proxies = Utils.unique(customProxies);
        
        groups.push({
          ...base,
          name:g.name,
          type:"select",
          proxies:proxies,
          icon:ICON_VAL(g.icon)
        });
      });
      
      // ========== 3. 添加地理分组（select 类型）==========
      if(regionGroups.length){
        groups.push(...regionGroups);
      }
      
      // ========== 4. 调整分组顺序：核心组置顶 ==========
      // 修复：按正确的优先级顺序排列 - 手动选择 > 自动选择 > AI优选
      try{
         // 先移除这三个核心组
         const bestIdx = groups.findIndex(g => g && g.name === "AI优选");
         const best = bestIdx > -1 ? groups.splice(bestIdx, 1)[0] : null;
         
         const autoIdx = groups.findIndex(g => g && g.name === "自动选择");
         const auto = autoIdx > -1 ? groups.splice(autoIdx, 1)[0] : null;
         
         const manualIdx = groups.findIndex(g => g && g.name === "手动选择");
         const manual = manualIdx > -1 ? groups.splice(manualIdx, 1)[0] : null;
         
         // 按正确的优先级顺序插入到最前面：手动选择 > 自动选择 > AI优选
         if(best) groups.unshift(best);      // 第三优先级：AI优选
         if(auto) groups.unshift(auto);      // 第二优先级：自动选择
         if(manual) groups.unshift(manual);  // 第一优先级：手动选择（最高）
       }catch(e){
         Logger.error("ProxyGroups", `分组排序失败: ${e.message}`);
       }
      
      Logger.info("ProxyGroups", `构建完成: 共 ${groups.length} 个分组`);
      return groups;
    }

    static _sortRules(rules){
      if(!Array.isArray(rules) || !rules.length) return rules || [];
      const normal = [], matchRules = [];
      for(const r of rules){
        if(typeof r !== "string"){ normal.push(r); continue; }
        const type = r.split(",")[0].trim().toUpperCase();
        if(type === "MATCH") matchRules.push(r); else normal.push(r);
      }
      return [...normal, ...matchRules];
    }

    static _autoDiscoverRules(ruleProviders,rules,opts,baseRP){
      const defs=opts.defaults||{};
      Object.entries(defs).forEach(([key,en])=>{
        if(!en) return;
        let url="",behavior="classical",format="text";
        if(typeof URLS.rulesets[key]==="function"){url=URLS.rulesets[key](); if(url.endsWith(".mrs")){behavior="domain";format="mrs";}}
        else if(URLS.rulesets.loyalsoldier && typeof URLS.rulesets.loyalsoldier[key]==="function"){url=URLS.rulesets.loyalsoldier[key]();}
        if(url && !ruleProviders[key]){
          const ext=format==="mrs"?"mrs":"list";
          ruleProviders[key]={...baseRP,behavior,format,url,path:`./ruleset/${key}.${ext}`};
          const target=/ads|ban|reject/i.test(key)?"REJECT":"手动选择";
          rules.push(`RULE-SET,${key},${target}`);
        }
      });
    }

    static _buildRules(cfg,regionNames,context){
      const ruleProviders={}, rules=[];
      const baseRP={type:"http",interval:Config.common?.ruleProvider?.interval??86400,format:"text",proxy:"自动优选"};
      const opts=Config.ruleOptions||{};
      
      // 1. 添加 LAN 和私有网络规则（最高优先级）
      rules.push("GEOSITE,private,DIRECT");
      rules.push("GEOIP,private,DIRECT,no-resolve");
      
      // 2. 添加 REJECT 规则（广告、追踪器）
      if(opts.acl4ssr!==false && !ruleProviders.acl4ssr_ban){
        ruleProviders.acl4ssr_ban={...baseRP,behavior:"classical",url:URLS.rulesets.acl4ssr.ban(),path:"./ruleset/acl4ssr_ban.list"};
        rules.push("RULE-SET,acl4ssr_ban,REJECT");
      }
      if(opts.anti_ad!==false && !ruleProviders.anti_ad){
        ruleProviders.anti_ad={...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.anti_ad(),path:"./ruleset/anti_ad.yaml"};
        rules.push("RULE-SET,anti_ad,REJECT");
      }
      if(opts.loyalsoldier!==false && !ruleProviders.ls_reject){
        ruleProviders.ls_reject={...baseRP,behavior:"classical",url:URLS.rulesets.loyalsoldier.reject(),path:"./ruleset/ls_reject.list"};
        rules.push("RULE-SET,ls_reject,REJECT");
      }
      
      // 2.1 添加 Blackmatrix7 规则集（广告、隐私、劫持）
      if(opts.blackmatrix7!==false){
        if(!ruleProviders.bm7_advertising){
          ruleProviders.bm7_advertising={...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.blackmatrix7.advertising(),path:"./ruleset/bm7_advertising.yaml"};
          rules.push("RULE-SET,bm7_advertising,REJECT");
        }
        if(!ruleProviders.bm7_privacy){
          ruleProviders.bm7_privacy={...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.blackmatrix7.privacy(),path:"./ruleset/bm7_privacy.yaml"};
          rules.push("RULE-SET,bm7_privacy,REJECT");
        }
        if(!ruleProviders.bm7_hijacking){
          ruleProviders.bm7_hijacking={...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.blackmatrix7.hijacking(),path:"./ruleset/bm7_hijacking.yaml"};
          rules.push("RULE-SET,bm7_hijacking,REJECT");
        }
      }
      
      // 3. 添加应用程序和进程规则
      if(Array.isArray(Config.preRules)) rules.push(...Config.preRules);
      
      // 4. 添加特定服务规则（路由到功能组）
      // 构建服务到功能组的映射
      const serviceToFunctionalGroup = new Map();
      (Config.functionalGroups || []).forEach(fg => {
        if (fg.services && Array.isArray(fg.services)) {
          fg.services.forEach(svcId => {
            serviceToFunctionalGroup.set(svcId, fg.name);
          });
        }
      });
      
      (Config.services||[]).forEach(svc=>{
        if(svc.id && opts[svc.id]===false) return;
        
        // 查找该服务属于哪个功能组
        const functionalGroup = serviceToFunctionalGroup.get(svc.id);
        
        if(svc.rule && Array.isArray(svc.rule)) {
          svc.rule.forEach(rule => {
            if (functionalGroup) {
              // 将规则路由到功能组
              const parts = rule.split(',');
              if (parts.length >= 2) {
                parts[parts.length - 1] = functionalGroup; // 替换目标为功能组名称
                rules.push(parts.join(','));
              } else {
                rules.push(rule); // 保持原样
              }
            } else {
              // 如果没有功能组,保持原样
              rules.push(rule);
            }
          });
        }
        
        const rp=svc.ruleProvider;
        if(rp?.name && !ruleProviders[rp.name]){
          const url=typeof rp.url==="function"?rp.url():rp.url;
          if(!url) {
            Logger.warn("RuleProvider", `规则提供者 ${rp.name} 缺少 URL`);
            return;
          }
          const isMrs=url.endsWith(".mrs");
          ruleProviders[rp.name]={...baseRP,behavior:rp.behavior||"domain",format:isMrs?"mrs":(rp.format||"yaml"),url,path:`./ruleset/${rp.name}.${isMrs?"mrs":(rp.format||"yaml")}`};
        }
      });
      
      // 4.1 添加 Blackmatrix7 规则集（特定服务）
      if(opts.blackmatrix7!==false){
        const bm7Services = [
          {name:"bm7_openai", url:URLS.rulesets.blackmatrix7.openai(), target:"AI组"},
          {name:"bm7_claude", url:URLS.rulesets.blackmatrix7.claude(), target:"AI组"},
          {name:"bm7_gemini", url:URLS.rulesets.blackmatrix7.gemini(), target:"AI组"},
          {name:"bm7_youtube", url:URLS.rulesets.blackmatrix7.youtube(), target:"流媒体组"},
          {name:"bm7_netflix", url:URLS.rulesets.blackmatrix7.netflix(), target:"流媒体组"},
          {name:"bm7_disney", url:URLS.rulesets.blackmatrix7.disney(), target:"流媒体组"},
          {name:"bm7_spotify", url:URLS.rulesets.blackmatrix7.spotify(), target:"音乐组"},
          {name:"bm7_tiktok", url:URLS.rulesets.blackmatrix7.tiktok(), target:"流媒体组"},
          {name:"bm7_telegram", url:URLS.rulesets.blackmatrix7.telegram(), target:"社交组"},
          {name:"bm7_github", url:URLS.rulesets.blackmatrix7.github(), target:"开发组"},
          {name:"bm7_google", url:URLS.rulesets.blackmatrix7.google(), target:"搜索组"},
          {name:"bm7_microsoft", url:URLS.rulesets.blackmatrix7.microsoft(), target:"邮件组"},
          {name:"bm7_apple", url:URLS.rulesets.blackmatrix7.apple(), target:"邮件组"}
        ];
        bm7Services.forEach(svc=>{
          if(!ruleProviders[svc.name]){
            ruleProviders[svc.name]={...baseRP,behavior:"domain",format:"yaml",url:svc.url,path:`./ruleset/${svc.name}.yaml`};
            rules.push(`RULE-SET,${svc.name},${svc.target}`);
          }
        });
      }
      
      // 5. 添加国内路由规则（确保在国外代理规则之前）
      const coreSets={
        applications:{behavior:"classical",url:URLS.rulesets.applications()},
        acl4ssr_china:{behavior:"domain",url:URLS.rulesets.acl4ssr.china()},
        ls_cn:{behavior:"domain",url:URLS.rulesets.loyalsoldier.cn()}
      };
      Object.entries(coreSets).forEach(([name,meta])=>{
        ruleProviders[name]={...baseRP,...meta,path:`./ruleset/${name}.list`};
      });
      
      // 添加国内路由规则
      rules.push("RULE-SET,acl4ssr_china,国内网站");
      rules.push("RULE-SET,ls_cn,国内网站");
      rules.push("GEOSITE,cn,国内网站");
      rules.push("GEOIP,cn,国内网站,no-resolve");
      
      // 6. 添加广告拦截器规则（使用简化的函数）
      injectAdBlockRules(ruleProviders);
      
      // 7. 添加 MATCH 兜底规则（最低优先级）
      if(Array.isArray(Config.common?.postRules)) {
        // 从 postRules 中分离 MATCH 规则
        const nonMatchRules = Config.common.postRules.filter(r => !r.toUpperCase().startsWith('MATCH'));
        const matchRules = Config.common.postRules.filter(r => r.toUpperCase().startsWith('MATCH'));
        rules.push(...nonMatchRules);
        rules.push(...matchRules);
      }
      
      // 使用规则排序管理器进行最终排序
      const sorted = RuleOrderManager.prioritizeRules(rules);
      
      Logger.info("RuleBuilder", `构建完成: ${sorted.length} 条规则, ${Object.keys(ruleProviders).length} 个规则提供者`);
      
      return {rules:sorted,ruleProviders};
    }
  }

  Logger.info("Script", `Mihomo Optimized v4.0 加载完成 - 环境: ${Env.get()}`);

  /* ========== 12. 脚本入口 (Entry Point) ========== */

  /**
   * 主覆写函数 (符合 Mihomo 规范)
   * @param {Object} config 原始配置
   * @param {string} profileName 配置集名称
   */
  function main(config, profileName) {
    if (!config || typeof config !== "object") {
      return config;
    }
    
    try {
      const central = CentralManager.getInstance();
      central.initialize();
      return central.processConfiguration(config);
    } catch (e) {
      Logger.error("Main", "配置处理失败", e.message || e);
      try {
        // 异常降级：在代理列表首位插入可视化错误提示
        const fallback = { ...config };
        if (!Array.isArray(fallback.proxies)) fallback.proxies = [];
        const msg = e?.message || "未知错误";
        fallback.proxies.unshift(ErrorConfigFactory.createErrorConfig(msg));
        return fallback;
      } catch (err) {
        Logger.error("Main", "降级失败", err.message || err);
        return config;
      }
    }
  }

  // 兼容性导出：确保在所有环境下正确挂载 (Verge, Android, iOS)
  root.main = main;
  root.CentralManager = CentralManager;
  root.ConfigBuilder = ConfigBuilder;
  root.AIEngine = AIEngine;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { main, CentralManager, ConfigBuilder, AIEngine };
  }

  return {
    main, CentralManager, ConfigBuilder, AIEngine
  };
})();
