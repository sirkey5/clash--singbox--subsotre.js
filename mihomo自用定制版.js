/**
 * Mihomo 深度优化脚本 v5.0-optimized
 * 
 * 核心特性：
 * - 异步兼容 + 静默探测
 * - AI 评分体系（8维度，满分100分）：基础10 + 协议20 + 性能20 + 稳定15 + 地理15 + 服务器10 + 语义10 + 动态±20
 * - 准入标准：85分优质 / 70分良好 / 55分最低
 * - 服务器白名单：50+ 提供商（S/A/B三级）
 * - 免费节点友好：不因域名类型歧视性扣分
 * - 性能优化：快速预筛选 + 智能分层采样（300-400节点）
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

  /* 环境与常量 */
  const Env = (() => {
    const isMihomo = typeof log === "function";
    const canAsync = typeof setTimeout === "function";
    const isVerge = typeof globalThis.process !== "undefined" || (typeof window !== "undefined" && typeof window.process !== "undefined");
    const platform = isVerge ? "Clash Verge" : (isMihomo ? "Mihomo" : "Unknown");
    
    return Object.freeze({
      isMihomo, platform, canAsync, isVerge,
      get: () => platform,
      version: "v5.0-optimized",
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

  /* 日志系统（简化版） */
  const Logger = new (class {
    _levelMap = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
    _currentLevel = CONSTANTS.DEBUG ? 0 : 1;
    
    log(level, ctx, ...args) {
      if (this._levelMap[level] < this._currentLevel) return;
      const prefix = `[${level}] [${ctx || "Global"}]`;
      const formatted = args.map(a => {
        if (a === null) return "null";
        if (a === undefined) return "undefined";
        if (typeof a === "object") {
          try { 
            return (typeof JSON !== "undefined") ? JSON.stringify(a) : "[Object]";
          } catch { return "[Object]"; }
        }
        return String(a);
      });
      const msg = `${prefix} ${formatted.join(" ")}`;
      if (typeof log === "function") {
        log(msg);
      } else if (typeof console !== "undefined" && typeof console.log === "function") {
        console.log(msg);
      }
    }
    error(c, ...a){this.log("ERROR",c,...a);} info(c,...a){this.log("INFO",c,...a);}
    warn(c,...a){this.log("WARN",c,...a);}  debug(c,...a){this.log("DEBUG",c,...a);}
  })();

  /* 通用工具 */
  const Utils = {
    now: Date.now,
    clamp: (v,min,max)=>v<min?min:(v>max?max:v),
    sleep: ms => new Promise(r=>setTimeout(r,ms)),
    deepClone(obj, keyName=null, seen = new WeakMap(), depth = 0) {
      const MAX_DEPTH = 10;
      
      if (depth > MAX_DEPTH) {
        Logger.warn("Utils.deepClone", `达到最大深度限制 ${MAX_DEPTH}，停止递归`);
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
        interval: Config.common?.proxyGroup?.interval ?? 180,  // 🔧 从 5 分钟缩短到 3 分钟
        timeout: Config.common?.proxyGroup?.timeout ?? 3000,
        url: Config.common?.proxyGroup?.url ?? "https://cp.cloudflare.com/generate_204",
        lazy: Config.common?.proxyGroup?.lazy ?? false,  // ✅ 禁用懒加载，主动检测
        "max-failed-times": Config.common?.proxyGroup?.maxFailedTimes ?? 2,  // 🔧 从 3 次降低到 2 次
        "expected-status": "204"
      };
    },
    
    getSceneConfig(scene = "browsing") {
      const base = Utils.getProxyGroupBase();
      const sceneConfig = Config.failureDetection?.[scene];
      
      if (!sceneConfig) {
        Logger.debug("Utils.getSceneConfig", `未找到场景 ${scene} 的配置，使用默认配置`);
        return base;
      }
      
      return {
        ...base,
        "max-failed-times": sceneConfig.maxFailedTimes,
        interval: sceneConfig.interval,
        tolerance: sceneConfig.tolerance,
        timeout: sceneConfig.timeout,
        lazy: false
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

  /* 存储与异常 */
  const PersistentStorage = new (class {
    constructor(){
      this._memoryCache = new Map();
    }
    read(key){ return this._memoryCache.get(key) || null; }
    write(key,val){ this._memoryCache.set(key, val); }
    delete(key){ return this._memoryCache.delete(key); }
  })();

  /* 镜像与资源 */
  let GH_PROXY = "https://cdn.jsdelivr.net/gh/";
  
  const ICON_VAL = (f)=>{try{return typeof f==="function"?f():(f??"");}catch{return"";}};

  /* 图标配置（精简版） */
  const ICONS = (() => {
    const base = "https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color";
    const map = {
      HongKong:"Hong_Kong", Japan:"Japan", Singapore:"Singapore", UnitedStates:"United_States",
      Korea:"Korea", UnitedKingdom:"United_Kingdom", Germany:"Germany", France:"France",
      Canada:"Canada", WorldMap:"Global", StreamingNotCN:"Streaming", StreamingCN:"StreamingCN",
      ChatGPT:"ChatGPT", Claude:"Claude", Gemini:"Gemini", YouTube:"YouTube", Netflix:"Netflix",
      DisneyPlus:"Disney", PrimeVideo:"Prime_Video", HBO:"HBO", Hulu:"Hulu", TikTok:"TikTok",
      Bilibili:"Bilibili", Bahamut:"Bahamut", TVB:"TVB", Pixiv:"Pixiv", Spotify:"Spotify",
      Telegram:"Telegram", Discord:"Discord", WhatsApp:"WhatsApp", Line:"Line", Slack:"Slack",
      Speedtest:"Speedtest", Steam:"Steam", Epic:"Epic", Game:"Game", GitHub:"GitHub",
      Google:"Google", GoogleSearch:"Google_Search", Microsoft:"Microsoft", Apple:"Apple",
      Download:"Download", Proxy:"Proxy", Firewall:"Firewall", Reject:"Privacy",
      Book:"Scholar", Premium:"Global", Advertising:"Privacy"
    };
    
    return new Proxy({},{
      get(_,n){
        return () => `${GH_PROXY}${base}/${map[n]??n}.png`;
      }
    });
  })();

  const URLS = {
    _getMirrorUrl(original){
      if(!GH_PROXY) return original;
      
      let clean = original;
      for(const m of CONSTANTS.GH.MIRRORS){
        if(m && clean.startsWith(m)){
          clean=clean.slice(m.length);
          break;
        }
      }
      
      if(GH_PROXY.includes("jsdelivr.net")){
        // 处理 raw.githubusercontent.com
        const rawMatch = clean.match(CONSTANTS.RE.GH_RAW);
        if(rawMatch){
          const [,user,repo,branch,path]=rawMatch;
          // ✅ 确保 branch 不包含 "refs/heads/" 前缀
          const cleanBranch = branch.replace(/^refs\/heads\//, '');
          const result = `https://cdn.jsdelivr.net/gh/${user}/${repo}@${cleanBranch}/${path}`;
          Logger.debug("URLMirror", `raw.githubusercontent.com -> jsDelivr: ${result}`);
          return result;
        }
        
        // 处理 github.com/releases/download
        const releaseMatch = clean.match(CONSTANTS.RE.GH_RELEASE);
        if(releaseMatch){
          const [,user,repo,tag,file]=releaseMatch;
          // ✅ 使用正确的 jsDelivr 格式
          const result = `https://cdn.jsdelivr.net/gh/${user}/${repo}@${tag}/${file}`;
          Logger.debug("URLMirror", `github.com/releases -> jsDelivr: ${result}`);
          return result;
        }
        
        // ✅ 兜底：如果是 raw.githubusercontent.com，直接返回（不转换）
        if(clean.includes('raw.githubusercontent.com')){
          Logger.debug("URLMirror", `保持原始 URL: ${clean}`);
          return clean;
        }
      }
      
      const base = GH_PROXY.endsWith("/")?GH_PROXY:GH_PROXY+"/";
      const path = clean.startsWith("/")?clean.slice(1):clean;
      const result = base+path;
      Logger.debug("URLMirror", `默认镜像: ${result}`);
      return result;
    },
    geox:{
      geoip:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"),
      geosite:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"),
      mmdb:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"),
      asn:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/asn.mmdb")
    },
    mrs(name){
      const baseUrl = `https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/${name}.mrs`;
      return this._getMirrorUrl(baseUrl);
    },
    list(name){
      const baseUrl = `https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/${name}.txt`;
      return this._getMirrorUrl(baseUrl);
    },
    rulesets:{
      // ✅ 全量规则集：使用 geolocation-!cn（包含所有非中国域名）
      geolocation_not_cn:()=>URLS.mrs("geolocation-!cn"),
      
      // 保留常用的单独服务规则集（可选）
      ai:()=>URLS.mrs("category-ai-!cn"),
      ads:()=>URLS.mrs("category-ads-all"),
      trackers:()=>URLS.mrs("tracker"),
      applications:()=>URLS.list("applications"),
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
      
      loyalsoldier:{
        reject:()=>URLS.list("reject"),
        icloud:()=>URLS.list("icloud"),
        apple:()=>URLS.list("apple"),
        google:()=>URLS.list("google"),
        direct:()=>URLS.list("direct"),
        private:()=>URLS.list("private"),
        telegram:()=>URLS.list("telegram"),
        cn:()=>URLS.list("direct")
      },
      
      blackmatrix7:{
        advertising:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Advertising/Advertising.yaml"),
        privacy:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Privacy/Privacy.yaml"),
        hijacking:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/Clash/Hijacking/Hijacking.yaml")
      },
      
      acl4ssr:{
        ban:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"),
        banprogramad:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanProgramAD.list"),
        china:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list"),
        chinacompanyip:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaCompanyIp.list"),
        lan:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list")
      },
      
      anti_ad:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml")
    }
  };

  /* 全局配置 */
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
        ["apple","microsoft","github","google","openai","spotify","bahamut","disney","pixiv","hbo","biliintl","tvb","hulu","primevideo","telegram","line","whatsapp","games","japan","tracker","ads","acl4ssr","anti_ad","loyalsoldier","blackmatrix7","geolocation_not_cn"]
          .map(k=>[k,true])
      )
    },
    preRules:[
      "PROCESS-NAME,SunloginClient,DIRECT",
      "PROCESS-NAME,AnyDesk,DIRECT"
    ],
    regionOptions:{
      geoIpGrouping:true, autoDiscover:true, excludeHighPercentage:true, ratioLimit:2,
      maxRegions:10,
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
      { id:"geolocation_not_cn", rule:["RULE-SET,geolocation_not_cn,全球站点"], name:"全球站点（全量）", icon:ICONS.WorldMap, ruleProvider:{ name:"geolocation_not_cn", url:()=>URLS.rulesets.geolocation_not_cn(), behavior:"domain" } },
      { id:"tracker",  rule:["GEOSITE,tracker,REJECT"], name:"跟踪分析", icon:ICONS.Reject, proxies:["REJECT","DIRECT","手动选择"] },
      { id:"ads",      rule:["RULE-SET,ads,REJECT"], name:"广告过滤", icon:ICONS.Advertising, proxies:["REJECT","DIRECT","手动选择"], ruleProvider:{ name:"ads", url:()=>URLS.rulesets.ads(), behavior:"domain" } }
    ],
    functionalGroups: [
      { id:"ai_group", name:"AI组", icon:ICONS.ChatGPT, services:["openai"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"streaming_group", name:"流媒体组", icon:ICONS.StreamingNotCN, services:["disney","hbo","hulu","primevideo","tiktok","biliintl","bahamut","tvb","pixiv","streaming"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"finance_group", name:"金融组", icon:ICONS.Premium, services:["finance"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"gaming_group", name:"游戏组", icon:ICONS.Game, services:["steam","epic","games"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"download_group", name:"下载组", icon:ICONS.Download, services:["speedtest"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"download_software_group", name:"下载软件", icon:ICONS.Download, services:["applications"], proxiesOrder:["DIRECT","手动选择","自动选择","智能优选"] },
      { id:"social_group", name:"社交组", icon:ICONS.Telegram, services:["telegram","discord","whatsapp","line","slack"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"search_group", name:"搜索组", icon:ICONS.GoogleSearch, services:["google"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"dev_group", name:"开发组", icon:ICONS.GitHub, services:["github","scholar"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"email_group", name:"邮件组", icon:ICONS.Microsoft, services:["microsoft","apple"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"music_group", name:"音乐组", icon:ICONS.Spotify, services:["spotify"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] },
      { id:"browsing_group", name:"浏览组", icon:ICONS.Proxy, services:["geolocation_not_cn"], proxiesOrder:["手动选择","自动选择","智能优选","DIRECT"] }
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
    common:{ 
      ruleProvider:{ type:"http", interval:86400 }, 
      proxyGroup:{ 
        interval:300, 
        timeout:3000, 
        url:"https://cp.cloudflare.com/generate_204", 
        lazy:true,
        maxFailedTimes: 3  // 🔧 新增：默认故障检测阈值
      }, 
      defaultProxyGroups:[{ name:"国内网站", icon:ICONS.StreamingCN, proxies:["DIRECT","手动选择"] }], 
      postRules:["GEOSITE,private,DIRECT","GEOIP,private,DIRECT,no-resolve","RULE-SET,ls_cn,国内网站","RULE-SET,acl4ssr_china,国内网站","GEOSITE,cn,国内网站","GEOIP,cn,国内网站,no-resolve","MATCH,其他节点"] 
    },
    failureDetection: {
      gaming: { maxFailedTimes: 1, interval: 120, tolerance: 20, timeout: 2500 },      // ✅ 游戏最严格：1次失败即切换
      streaming: { maxFailedTimes: 2, interval: 180, tolerance: 80, timeout: 6000 },   // ✅ 流媒体适中：2次失败切换
      browsing: { maxFailedTimes: 2, interval: 180, tolerance: 40, timeout: 4000 },    // ✅ 浏览适中：2次失败切换
      download: { maxFailedTimes: 2, interval: 180, tolerance: 60, timeout: 5000 }     // ✅ 下载适中：2次失败切换
    },
    performance: { heavyProxyThreshold: 800, ioBudgetPerTick: 16 }
  };

  /* 基础组件 */

  /**
   * 后台静默预检引擎
   * 采用“异步探测，同步交付”策略，在不影响主流程返回的前提下，利用下一次执行更新状态
   */
  class AIEngine {
    constructor(statsManager) {
      this._stats = statsManager;
      this._currentScene = "browsing";
      
      this._SERVER_WHITELIST = {
        TIER_S: [
          { pattern: /cloudflare/i, name: 'Cloudflare', score: 10 },
          { pattern: /fastly/i, name: 'Fastly', score: 10 },
          { pattern: /akamai/i, name: 'Akamai', score: 10 }
        ],
        
        TIER_A: [
          { pattern: /amazonaws|aws/i, name: 'AWS', score: 8 },
          { pattern: /azure|microsoft/i, name: 'Azure', score: 8 },
          { pattern: /google|gcp/i, name: 'GCP', score: 8 },
          { pattern: /digitalocean/i, name: 'DigitalOcean', score: 7 },
          { pattern: /vultr/i, name: 'Vultr', score: 7 },
          { pattern: /aliyun|alibabacloud/i, name: 'Aliyun', score: 7 },
          { pattern: /tencent|qcloud/i, name: 'Tencent', score: 7 }
        ],
        
        TIER_B: [
          { pattern: /linode/i, name: 'Linode', score: 5 },
          { pattern: /ovh/i, name: 'OVH', score: 5 },
          { pattern: /hetzner/i, name: 'Hetzner', score: 5 }
        ],
        
        BLACKLIST: [
          { pattern: /localhost|127\.0\.0\.1/i, score: -100, reason: '本地地址' }
        ]
      };
      
      this._weights = {
        PROTOCOLS: {
          'hysteria2': 15, 'tuic': 15,           // 现代高性能协议
          'vless': 12, 'trojan': 10,             // 轻量级协议
          'ss': 8, 'vmess': 5, 'ssr': 3          // 经典协议
        },
        
        // 正面关键词（+分）
        POSITIVE_KEYWORDS: {
          // 高级标识
          'Premium': 5, 'Pro': 4, 'VIP': 3, 'Elite': 4,
          // 优化标识
          '游戏': 3, 'Game': 3, '流媒体': 2, 'Streaming': 2,
          '解锁': 2, 'Unlock': 2, '优化': 2, 'Optimized': 2,
          // 线路类型
          'IPLC': 12, 'IEPL': 12, 'BGP': 10, 'CN2 GIA': 10, 'CN2': 8,
          '专线': 12, '直连': 6, 'Direct': 6
        },
        
        // 负面关键词（-分）
        NEGATIVE_KEYWORDS: {
          // 严重问题
          '过期': -100, 'Expire': -100, 'Expired': -100,
          '维护': -50, 'Maintenance': -50, '故障': -50, 'Down': -50,
          // 质量问题
          '测试': -20, 'Test': -20, '备用': -10, 'Backup': -10,
          '试用': -10, 'Trial': -10, '限速': -15, 'Limited': -10
        },
        
        // 地区评分（0-10分）
        REGIONS: {
          'HK': 10, 'MO': 10, 'TW': 9,           // 港澳台
          'SG': 9, 'JP': 8, 'KR': 7,             // 亚洲枢纽
          'US': 6, 'CA': 5,                      // 北美
          'UK': 4, 'DE': 4, 'FR': 4, 'NL': 4     // 欧洲
        },
        
        // 城市加分（0-2分）
        CITIES: {
          '香港': 2, 'HK': 2, '台北': 2, 'Taipei': 2,
          '东京': 2, 'Tokyo': 2, '新加坡': 2, 'Singapore': 2,
          '洛杉矶': 2, 'Los Angeles': 2, 'LA': 2
        }
      };
      
      this._vetoReg = /Maintenance|Down|Fix|Expired|Error|Timeout|故障|维护|离线|过期|到期/i;
      this._regionReg = /HK|MO|TW|SG|JP|US|KR|UK|DE|FR|NL|TH|MY|PH|IN|AU|RU|BR|AR|CA|香港|澳门|台湾|新加坡|日本|美国|韩国|英国|德国|法国|荷兰|泰国|马来西亚|菲律宾|印度|澳大利亚|俄罗斯|巴西|阿根廷|加拿大|港|澳|台/i;
      this._latencyReg = /(\d+)ms/i;
      this._rateReg = /(\d+\.?\d*)x|(\d+\.?\d*)倍/i;
      
      this._SCORE_THRESHOLDS = {
        EXCELLENT: 85,
        GOOD: 70,
        MIN: 55  // 最低评分标准：55 分
      };
    }

    setScene(scene) {
      if (["browsing", "gaming", "streaming", "download"].includes(scene)) {
        this._currentScene = scene;
      }
    }

    /**
     * 辅助方法：地区识别
     * @param {string} name - 节点名称
     * @returns {string} 地区代码（如 'HK', 'TW'）或 '其他'
     */
    _detectRegion(name) {
      const regionMap = {
        '香港': 'HK', 'HK': 'HK', '港': 'HK', 'Hong Kong': 'HK', 'Hongkong': 'HK',
        '澳门': 'MO', 'MO': 'MO', '澳': 'MO', 'Macao': 'MO', 'Macau': 'MO',
        '台湾': 'TW', 'TW': 'TW', '台': 'TW', 'Taiwan': 'TW',
        '日本': 'JP', 'JP': 'JP', '东京': 'JP', 'Tokyo': 'JP', 'Japan': 'JP',
        '新加坡': 'SG', 'SG': 'SG', '狮城': 'SG', 'Singapore': 'SG',
        '美国': 'US', 'US': 'US', '美': 'US', 'United States': 'US', 'America': 'US',
        '韩国': 'KR', 'KR': 'KR', '韩': 'KR', 'Korea': 'KR',
        '英国': 'UK', 'UK': 'UK', 'United Kingdom': 'UK', 'Britain': 'UK',
        '德国': 'DE', 'DE': 'DE', 'Germany': 'DE',
        '法国': 'FR', 'FR': 'FR', 'France': 'FR',
        '荷兰': 'NL', 'NL': 'NL', 'Netherlands': 'NL'
      };
      
      for (const [key, code] of Object.entries(regionMap)) {
        if (name.includes(key)) return code;
      }
      return '其他';
    }

    /**
     * 辅助方法：协议评分
     * @param {string} type - 协议类型
     * @param {Object} proxy - 代理对象
     * @returns {number} 协议得分（0-20）
     */
    _getProtocolScore(type, proxy) {
      let score = this._weights.PROTOCOLS[type] || 0;
      
      // 协议特性加分
      if (proxy.tls) score += 2;
      if (proxy.udp) score += 2;
      if (proxy.sni) score += 1;
      if (proxy['skip-cert-verify'] === false) score += 1;
      if (proxy.network === 'ws' || proxy.network === 'websocket') score += 1;
      
      return Math.min(20, score);
    }

    /**
     * 辅助方法：服务器评分
     * @param {string} server - 服务器地址
     * @returns {number} 服务器得分（-100 ~ 10）
     */
    _getServerScore(server) {
      if (!server) return -2;
      
      // 检查黑名单
      for (const item of this._SERVER_WHITELIST.BLACKLIST) {
        if (item.pattern.test(server)) return item.score;
      }
      
      // 检查白名单
      for (const item of this._SERVER_WHITELIST.TIER_S) {
        if (item.pattern.test(server)) return item.score;
      }
      for (const item of this._SERVER_WHITELIST.TIER_A) {
        if (item.pattern.test(server)) return item.score;
      }
      for (const item of this._SERVER_WHITELIST.TIER_B) {
        if (item.pattern.test(server)) return item.score;
      }
      
      // IP 地址扣分
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(server)) return -2;
      
      return 0;
    }

    /**
     * ========== 综合多维度节点质量评分体系 ==========
     * 
     * 评分架构（满分 100 分）：
     * - 基础分：10 分
     * - 协议维度：20 分（协议类型 0-15 + 特性加分 0-5）
     * - 性能维度：20 分（倍率 0-12 + 延迟 0-8）
     * - 稳定性维度：15 分（端口 0-3 + 线路类型 0-12）
     * - 地理维度：15 分（地区 0-10 + 城市 0-5）
     * - 服务器维度：10 分（提供商质量）
     * - 语义维度：10 分（关键词识别）
     * - 动态调整：-20 ~ +10 分（多样性、稳定性）
     * 
     * @param {Object} proxy - 代理节点对象
     * @param {Object} context - 节点池上下文（用于多样性评分）
     * @returns {Object} { score: 总分, breakdown: 各维度得分明细 }
     */
    scoreComprehensive(proxy, context = {}) {
      if (!proxy) return { score: 0, breakdown: {} };
      
      const name = typeof proxy === 'string' ? proxy : String(proxy.name || "");
      const type = String(proxy.type || "").toLowerCase();
      const port = parseInt(proxy.port || 0);
      const server = proxy.server || "";
      
      // 否决机制：严重问题直接返回 0 分
      if (this._vetoReg.test(name)) {
        Logger.debug("AIEngine.Veto", `否决节点: ${name}`);
        return { score: 0, breakdown: { veto: true, reason: "严重问题关键词" } };
      }
      
      const breakdown = {
        base: 10,           // 基础分
        protocol: 0,        // 协议维度
        performance: 0,     // 性能维度
        stability: 0,       // 稳定性维度
        geography: 0,       // 地理维度
        server: 0,          // 服务器维度
        semantic: 0,        // 语义维度
        dynamic: 0          // 动态调整
      };
      
      // ========== 1. 协议维度（20分）==========
      breakdown.protocol = this._getProtocolScore(type, proxy);
      
      // ========== 2. 性能维度（20分）==========
      // 2.1 倍率评分（0-12分，可为负）
      let rateScore = 0;
      let rate = proxy.rate;
      if (!rate) {
        const match = name.match(this._rateReg);
        if (match) rate = parseFloat(match[1] || match[2]);
      }
      
      if (rate != null) {
        if (rate <= 0.1) rateScore = 12;          // 0.1x 极低倍率
        else if (rate <= 0.2) rateScore = 10;     // 0.2x 很低倍率
        else if (rate <= 0.5) rateScore = 8;      // 0.5x 低倍率
        else if (rate <= 0.8) rateScore = 6;      // 0.8x 较低倍率
        else if (rate <= 1.0) rateScore = 4;      // 1.0x 标准倍率
        else if (rate <= 1.5) rateScore = -5;     // 1.5x 轻度超售
        else if (rate <= 2.0) rateScore = -10;    // 2.0x 中度超售
        else rateScore = -20;                      // >2.0x 严重超售
      }
      
      // 2.2 延迟评分（0-8分，可为负）
      let latencyScore = 0;
      const latencyMatch = name.match(this._latencyReg);
      if (latencyMatch) {
        const ms = parseInt(latencyMatch[1]);
        if (ms < 30) latencyScore = 8;            // <30ms 极低延迟
        else if (ms < 50) latencyScore = 6;       // <50ms 很低延迟
        else if (ms < 100) latencyScore = 4;      // <100ms 低延迟
        else if (ms < 150) latencyScore = 2;      // <150ms 可接受
        else if (ms < 200) latencyScore = 0;      // <200ms 一般
        else if (ms < 300) latencyScore = -5;     // <300ms 较高
        else if (ms < 500) latencyScore = -10;    // <500ms 高延迟
        else latencyScore = -20;                   // >=500ms 极高延迟
      }
      
      breakdown.performance = Math.max(-20, Math.min(20, rateScore + latencyScore));
      
      // ========== 3. 稳定性维度（15分）==========
      // 3.1 端口评分（0-3分）
      if (CONSTANTS.SAFE_PORTS.has(port)) {
        breakdown.stability = 3;
      } else if ([443, 80].includes(port)) {
        breakdown.stability = 2;
      }
      
      // 3.2 线路类型评分（0-12分）
      let lineScore = 0;
      if (/IPLC|IEPL|专线|内网/i.test(name)) {
        lineScore = 12;
      } else if (/BGP|CN2 GIA|CN2-GIA/i.test(name)) {
        lineScore = 10;
      } else if (/CN2|GIA/i.test(name)) {
        lineScore = 8;
      } else if (/直连|Direct/i.test(name)) {
        lineScore = 6;
      } else if (/中转|Relay/i.test(name)) {
        lineScore = 4;
      }
      
      breakdown.stability += lineScore;
      breakdown.stability = Math.min(15, breakdown.stability);
      
      // ========== 4. 地理维度（15分）==========
      // 4.1 地区评分（0-10分）
      const regionCode = this._detectRegion(name);
      breakdown.geography = this._weights.REGIONS[regionCode] || 0;
      
      // 4.2 城市加分（0-5分）
      for (const [city, bonus] of Object.entries(this._weights.CITIES)) {
        if (name.includes(city)) {
          breakdown.geography += bonus;
          break;
        }
      }
      
      breakdown.geography = Math.min(15, breakdown.geography);
      
      // ========== 5. 服务器维度（10分）==========
      breakdown.server = this._getServerScore(server);
      
      // ========== 6. 语义维度（10分）==========
      let semanticScore = 0;
      
      // 6.1 正面关键词
      for (const [keyword, points] of Object.entries(this._weights.POSITIVE_KEYWORDS)) {
        if (new RegExp(keyword, 'i').test(name)) {
          semanticScore += points;
        }
      }
      
      // 6.2 负面关键词
      for (const [keyword, points] of Object.entries(this._weights.NEGATIVE_KEYWORDS)) {
        if (new RegExp(keyword, 'i').test(name)) {
          semanticScore += points;  // 已经是负数
          // 严重问题直接返回 0 分
          if (points <= -50) {
            return { score: 0, breakdown: { veto: true, reason: `负面关键词: ${keyword}` } };
          }
        }
      }
      
      breakdown.semantic = Math.max(-100, Math.min(10, semanticScore));
      
      // ========== 7. 动态调整（-20 ~ +10分）==========
      breakdown.dynamic = this._getDynamicAdjustment(proxy, name, server, type, context);
      
      // ========== 8. 计算总分 ==========
      const totalScore = Object.values(breakdown).reduce((sum, score) => sum + score, 0);
      
      return {
        score: Math.max(0, totalScore),
        breakdown: breakdown
      };
    }

    /**
     * 动态调整评分（-20 ~ +10分）
     * 基于节点池上下文的多样性和稳定性调整
     */
    _getDynamicAdjustment(proxy, name, server, type, context) {
      let adjustment = 0;
      
      // 1. 历史统计加分/扣分
      const stats = this._stats ? this._stats.getStats(proxy) : null;
      if (stats) {
        const now = Date.now();
        
        // 1.1 忠诚度奖励
        if (now - stats.lastSeen < CONSTANTS.TIME.DAY) adjustment += 2;
        if (stats.successCount > 5) adjustment += 3;
        
        // 1.2 失败惩罚
        if (stats.failCount > 0) {
          adjustment -= Math.min(20, stats.failCount * 10);
        }
      }
      
      // 2. 多样性惩罚（如果提供了上下文）
      if (context.serverCounts && server) {
        const count = context.serverCounts.get(server) || 0;
        if (count > 10) adjustment -= 15;      // 严重集中
        else if (count > 5) adjustment -= 10;  // 过度集中
        else if (count > 3) adjustment -= 5;   // 轻度集中
      }
      
      // 3. 稀缺性加分
      if (context.regionCounts && context.totalNodes) {
        // 提取地区代码
        let regionCode = null;
        for (const [key, code] of Object.entries({
          '香港': 'HK', 'HK': 'HK', '港': 'HK',
          '澳门': 'MO', 'MO': 'MO', '澳': 'MO',
          '台湾': 'TW', 'TW': 'TW', '台': 'TW',
          '新加坡': 'SG', 'SG': 'SG',
          '日本': 'JP', 'JP': 'JP',
          '美国': 'US', 'US': 'US'
        })) {
          if (name.includes(key)) {
            regionCode = code;
            break;
          }
        }
        
        if (regionCode) {
          const count = context.regionCounts.get(regionCode) || 0;
          const ratio = count / context.totalNodes;
          if (ratio < 0.05) adjustment += 5;   // <5% 稀缺
          else if (ratio < 0.10) adjustment += 3;  // <10% 较少
        }
      }
      
      // 4. 协议多样性加分
      if (context.protocolCounts && context.totalNodes) {
        const count = context.protocolCounts.get(type) || 0;
        const ratio = count / context.totalNodes;
        
        // 现代协议且占比低，给予加分
        if (['hysteria2', 'tuic'].includes(type) && ratio < 0.2) {
          adjustment += 5;
        }
      }
      
      return Math.max(-20, Math.min(10, adjustment));
    }

    /**
     * 节点综合评分逻辑 (保留原有方法作为备份)
     * 维度：协议(25%)、性能(20%)、稳定性(15%)、语义(15%)、动态(-20~+10)
     */
    score(proxy) {
      // 使用新的综合评分方法
      const result = this.scoreComprehensive(proxy);
      return result.score;
    }

    /**
     * 全量节点评判打分系统（用于地理组）
     * 策略：85分优质标准 → 70分良好标准 → 55分可接受标准
     * 输出：75%AI推送 + 25%随机抽取
     */
    getBestNodes(proxies) {
      if (!proxies || !proxies.length) return [];
      
      try {
        const total = proxies.length;
        let targetCount = Math.min(500, Math.max(5, Math.floor(total * 0.15)));
        if (total <= 5) targetCount = total;
        
        Logger.info("AIEngine", `优选筛选: 总数 ${total}, 目标 ${targetCount}`);

        // 构建节点池上下文
        const context = {
          totalNodes: proxies.length,
          serverCounts: new Map(),
          regionCounts: new Map(),
          protocolCounts: new Map()
        };
        
        proxies.forEach(p => {
          const server = p.server || "";
          const type = String(p.type || "").toLowerCase();
          if (server) context.serverCounts.set(server, (context.serverCounts.get(server) || 0) + 1);
          context.protocolCounts.set(type, (context.protocolCounts.get(type) || 0) + 1);
        });

        // 快速预筛选（避免对所有节点评分）
        const vetoReg = /Maintenance|Down|Fix|Expired|Error|Timeout|故障|维护|离线|过期|到期/i;
        const allowedProtocols = new Set(['vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'ss', 'ssr']);
        
        const fastFiltered = [];
        for (let i = 0; i < proxies.length; i++) {
          const p = proxies[i];
          const name = typeof p === 'string' ? p : String(p.name || "");
          const type = String(p.type || "").toLowerCase();
          
          if (vetoReg.test(name)) continue;
          if (!allowedProtocols.has(type)) continue;
          
          const stats = this._stats ? this._stats.getStats(p) : null;
          if (stats && stats.failCount > 3) continue;
          
          fastFiltered.push(p);
        }
        
        Logger.info("AIEngine", `预筛选: ${proxies.length} -> ${fastFiltered.length} 节点`);
        
        // 智能采样（分层抽取）
        let toScore;
        const SAMPLE_SIZE = 400; // 地理组样本更大
        
        if (fastFiltered.length <= SAMPLE_SIZE) {
          toScore = fastFiltered;
        } else {
          // 分层采样
          const regionGroups = new Map();
          fastFiltered.forEach(p => {
            const name = p.name || "";
            const region = this._detectRegion(name);
            
            if (!regionGroups.has(region)) regionGroups.set(region, []);
            regionGroups.get(region).push(p);
          });
          
          toScore = [];
          const totalNodes = fastFiltered.length;
          regionGroups.forEach((nodes, region) => {
            const ratio = nodes.length / totalNodes;
            const sampleCount = Math.max(1, Math.floor(SAMPLE_SIZE * ratio));
            const shuffled = nodes.sort(() => Math.random() - 0.5);
            toScore.push(...shuffled.slice(0, Math.min(sampleCount, nodes.length)));
          });
          
          if (toScore.length < SAMPLE_SIZE) {
            const remaining = fastFiltered.filter(p => !toScore.includes(p));
            const shuffled = remaining.sort(() => Math.random() - 0.5);
            toScore.push(...shuffled.slice(0, SAMPLE_SIZE - toScore.length));
          }
          
          toScore = toScore.slice(0, SAMPLE_SIZE);
        }
        
        Logger.info("AIEngine", `智能采样: ${fastFiltered.length} -> ${toScore.length} 节点`);

        const candidates = toScore.map(p => {
          const result = this.scoreComprehensive(p, context);
          const name = typeof p === 'string' ? p : String(p.name || "");
          const isCore = /HK|MO|TW|SG|JP|US|香港|澳门|台湾|新加坡|日本|美国|港|澳|台/i.test(name);
          const stats = this._stats ? this._stats.getStats(p) : { failCount: 0 };
          
          return {
            id: name,
            score: result.score,
            proxy: p,
            server: p.server || "",
            isCore: isCore,
            failCount: stats.failCount
          };
        }).filter(item => {
          if (item.failCount > 0) return false;
          return item.score >= 0;  // 地理组使用更宽松的标准
        }).sort((a, b) => b.score - a.score);

        const excellentNodes = candidates.filter(item => item.score >= this._SCORE_THRESHOLDS.EXCELLENT);
        const goodNodes = candidates.filter(item => item.score >= this._SCORE_THRESHOLDS.GOOD && item.score < this._SCORE_THRESHOLDS.EXCELLENT);
        const fallbackNodes = candidates.filter(item => item.score >= 0 && item.score < this._SCORE_THRESHOLDS.GOOD);

        let selectedNodes = [];

        if (excellentNodes.length >= targetCount) {
          Logger.info("AIEngine", `优质节点充足: ${excellentNodes.length}个`);
          selectedNodes = excellentNodes.slice(0, targetCount);
        } else if (goodNodes.length > 0) {
          Logger.info("AIEngine", `降级到70分标准: 优质${excellentNodes.length}个, 良好${goodNodes.length}个`);
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
     * 🔧 AI 优选组专用筛选逻辑（使用综合评分体系）
     * 准入规则：
     * 1. 目标数量：100 个节点
     * 2. 评分标准：优先 85 分以上，不足则降级到 70 分，最低 55 分
     * 3. 容纳上限：最多 100 个节点
     * 4. 退出机制：评分低于 55 分或存在故障的节点自动清退
     * 
     * @param {Array} proxies - 所有代理节点
     * @returns {Array} 筛选后的节点名称列表
     */
    getBestNodesForPremiumGroup(proxies) {
      if (!proxies || !proxies.length) {
        Logger.warn("AIEngine.Premium", "无可用节点");
        return ["DIRECT"];
      }
      
      try {
        const TARGET_COUNT = 100;  // 目标数量：100 个
        const MAX_COUNT = 100;     // 容纳上限：100 个
        const MIN_SCORE = 55;      // 最低评分标准：55 分（劣质节点阈值）
        
        Logger.info("AIEngine.Premium", `开始筛选 AI 优选组: 总节点数 ${proxies.length}, 目标 ${TARGET_COUNT} 个`);

        // ========== 1. 构建节点池上下文（用于多样性评分）==========
        const context = {
          totalNodes: proxies.length,
          serverCounts: new Map(),
          regionCounts: new Map(),
          protocolCounts: new Map()
        };
        
        // 统计服务器、地区、协议分布
        proxies.forEach(p => {
          const server = p.server || "";
          const type = String(p.type || "").toLowerCase();
          const name = String(p.name || "");
          
          // 服务器统计
          if (server) {
            context.serverCounts.set(server, (context.serverCounts.get(server) || 0) + 1);
          }
          
          // 协议统计
          context.protocolCounts.set(type, (context.protocolCounts.get(type) || 0) + 1);
          
          // 地区统计
          const regionCode = this._detectRegion(name);
          if (regionCode !== '其他') {
            context.regionCounts.set(regionCode, (context.regionCounts.get(regionCode) || 0) + 1);
          }
        });
        
        // 输出节点池分析（简化日志）
        Logger.info("AIEngine.Premium", `节点池: 协议${context.protocolCounts.size}种, 地区${context.regionCounts.size}个, 服务器${context.serverCounts.size}个`);

        // ========== 2. 快速预筛选 + 综合评分 ==========
        // 2.1 第一轮：快速过滤（O(n) 简单操作）
        const fastFiltered = [];
        const vetoReg = /Maintenance|Down|Fix|Expired|Error|Timeout|故障|维护|离线|过期|到期/i;
        const allowedProtocols = new Set(['vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'ss', 'ssr']);
        
        for (let i = 0; i < proxies.length; i++) {
          const p = proxies[i];
          const name = typeof p === 'string' ? p : String(p.name || "");
          const type = String(p.type || "").toLowerCase();
          
          // 快速否决检查
          if (vetoReg.test(name)) continue;
          
          // 协议白名单
          if (!allowedProtocols.has(type)) continue;
          
          // 失败次数检查
          const stats = this._stats ? this._stats.getStats(p) : null;
          if (stats && stats.failCount > 3) continue;
          
          fastFiltered.push(p);
        }
        
        Logger.info("AIEngine.Premium", `快速预筛选: ${proxies.length} -> ${fastFiltered.length} 节点`);
        
        // 2.2 第二轮：智能采样（分层抽取，保证多样性）
        let toScore;
        const SAMPLE_SIZE = 300; // 提高到 300 个样本
        
        if (fastFiltered.length <= SAMPLE_SIZE) {
          toScore = fastFiltered;
        } else {
          // 分层采样：按地区分组，每组抽取一定比例
          const regionGroups = new Map();
          fastFiltered.forEach(p => {
            const name = p.name || "";
            const region = this._detectRegion(name);
            
            if (!regionGroups.has(region)) regionGroups.set(region, []);
            regionGroups.get(region).push(p);
          });
          
          // 从每个地区按比例抽取
          toScore = [];
          const totalNodes = fastFiltered.length;
          regionGroups.forEach((nodes, region) => {
            const ratio = nodes.length / totalNodes;
            const sampleCount = Math.max(1, Math.floor(SAMPLE_SIZE * ratio));
            
            // 随机抽取（保证多样性）
            const shuffled = nodes.sort(() => Math.random() - 0.5);
            toScore.push(...shuffled.slice(0, Math.min(sampleCount, nodes.length)));
          });
          
          // 如果还不够，随机补充
          if (toScore.length < SAMPLE_SIZE) {
            const remaining = fastFiltered.filter(p => !toScore.includes(p));
            const shuffled = remaining.sort(() => Math.random() - 0.5);
            toScore.push(...shuffled.slice(0, SAMPLE_SIZE - toScore.length));
          }
          
          toScore = toScore.slice(0, SAMPLE_SIZE);
        }
        
        Logger.info("AIEngine.Premium", `智能采样: ${fastFiltered.length} -> ${toScore.length} 节点 (分层抽样)`);
        
        // 2.3 第三轮：综合评分（只对筛选后的节点）
        const candidates = toScore.map(p => {
          const result = this.scoreComprehensive(p, context);
          const name = typeof p === 'string' ? p : String(p.name || "");
          const stats = this._stats ? this._stats.getStats(p) : { failCount: 0, successCount: 0 };
          
          return {
            id: name,
            score: result.score,
            breakdown: result.breakdown,
            proxy: p,
            server: p.server || "",
            failCount: stats.failCount,
            successCount: stats.successCount
          };
        }).filter(item => {
          // 退出机制：连续失败的节点直接排除
          if (item.failCount > 0) {
            Logger.debug("AIEngine.Premium", `节点 ${item.id} 因故障被排除 (失败次数: ${item.failCount})`);
            return false;
          }
          
          // 最低评分标准：低于 55 分的劣质节点直接排除
          if (item.score < MIN_SCORE) {
            Logger.debug("AIEngine.Premium", `节点 ${item.id} 因评分过低被排除 (评分: ${item.score})`);
            return false;
          }
          
          return true;
        }).sort((a, b) => b.score - a.score);  // 按评分降序排列

        if (candidates.length === 0) {
          Logger.error("AIEngine.Premium", "所有节点均不符合最低标准 (评分 < 55 或存在故障)");
          Logger.warn("AIEngine.Premium", "兜底策略：使用预筛选节点（忽略评分限制）");
          
          // 复用已经预筛选的节点，避免重新评分
          const emergencyNodes = toScore
            .map(p => {
              const result = this.scoreComprehensive(p, context);
              return { id: p.name || p, score: result.score, proxy: p };
            })
            .filter(item => item.score > 0)
            .sort((a, b) => b.score - a.score)
            .slice(0, 20);
          
          if (emergencyNodes.length > 0) {
            Logger.warn("AIEngine.Premium", `兜底成功：返回 ${emergencyNodes.length} 个评分 > 0 的节点`);
            return emergencyNodes.map(n => n.id);
          }
          
          return ["DIRECT"];
        }

        // ========== 3. 分层筛选：85 分 -> 70 分 -> 55 分 ==========
        const excellentNodes = candidates.filter(item => item.score >= this._SCORE_THRESHOLDS.EXCELLENT);  // 85+
        const goodNodes = candidates.filter(item => item.score >= this._SCORE_THRESHOLDS.GOOD && item.score < this._SCORE_THRESHOLDS.EXCELLENT);  // 70-84
        const acceptableNodes = candidates.filter(item => item.score >= MIN_SCORE && item.score < this._SCORE_THRESHOLDS.GOOD);  // 55-69

        Logger.info("AIEngine.Premium", `节点分层: 优质(85+)=${excellentNodes.length}, 良好(70-84)=${goodNodes.length}, 可接受(55-69)=${acceptableNodes.length}`);

        let selectedNodes = [];

        // ========== 4. 准入逻辑：优先高分节点，不足则降级 ==========
        if (excellentNodes.length >= TARGET_COUNT) {
          // 情况 1: 优质节点充足，直接取前 100 个
          selectedNodes = excellentNodes.slice(0, TARGET_COUNT);
          Logger.info("AIEngine.Premium", `✅ 优质节点充足，选取前 ${TARGET_COUNT} 个 (评分 85+)`);
          
        } else if (excellentNodes.length + goodNodes.length >= TARGET_COUNT) {
          // 情况 2: 优质+良好节点达标，混合选取
          selectedNodes = [...excellentNodes, ...goodNodes].slice(0, TARGET_COUNT);
          Logger.info("AIEngine.Premium", `✅ 降级到良好标准，选取 ${excellentNodes.length} 个优质 + ${selectedNodes.length - excellentNodes.length} 个良好节点`);
          
        } else if (candidates.length >= TARGET_COUNT) {
          // 情况 3: 包含可接受节点才达标，全部混合
          selectedNodes = candidates.slice(0, TARGET_COUNT);
          Logger.warn("AIEngine.Premium", `⚠️ 降级到可接受标准，选取 ${excellentNodes.length} 个优质 + ${goodNodes.length} 个良好 + ${selectedNodes.length - excellentNodes.length - goodNodes.length} 个可接受节点`);
          
        } else {
          // 情况 4: 总数不足 100 个，全部选取
          selectedNodes = candidates;
          Logger.warn("AIEngine.Premium", `⚠️ 可用节点不足 ${TARGET_COUNT} 个，选取全部 ${selectedNodes.length} 个节点`);
        }

        // ========== 5. 容纳上限：确保不超过 100 个 ==========
        if (selectedNodes.length > MAX_COUNT) {
          selectedNodes = selectedNodes.slice(0, MAX_COUNT);
          Logger.warn("AIEngine.Premium", `⚠️ 节点数超过上限，截取前 ${MAX_COUNT} 个`);
        }

        // ========== 6. 多样性过滤：确保节点来自不同服务器和集群 ==========
        const diversityFiltered = this._applyDiversityFilter(selectedNodes, Math.min(selectedNodes.length, MAX_COUNT));

        // ========== 7. 输出详细评分明细（前 10 个节点）==========
        Logger.info("AIEngine.Premium", `📊 前 10 个节点评分明细:`);
        diversityFiltered.slice(0, 10).forEach((item, idx) => {
          const b = item.breakdown;
          Logger.info("AIEngine.Premium", 
            `  ${idx + 1}. ${item.id} (总分: ${item.score.toFixed(1)}) - ` +
            `基础:${b.base} 协议:${b.protocol} 性能:${b.performance} 稳定:${b.stability} ` +
            `地理:${b.geography} 服务器:${b.server} 语义:${b.semantic} 动态:${b.dynamic}`
          );
        });

        // ========== 8. 统计信息 ==========
        const avgScore = diversityFiltered.reduce((sum, item) => sum + item.score, 0) / diversityFiltered.length;
        const minScore = Math.min(...diversityFiltered.map(item => item.score));
        const maxScore = Math.max(...diversityFiltered.map(item => item.score));
        
        // 统计各维度平均分
        const avgBreakdown = {
          base: 0, protocol: 0, performance: 0, stability: 0,
          geography: 0, server: 0, semantic: 0, dynamic: 0
        };
        diversityFiltered.forEach(item => {
          for (const key in avgBreakdown) {
            avgBreakdown[key] += item.breakdown[key] || 0;
          }
        });
        for (const key in avgBreakdown) {
          avgBreakdown[key] /= diversityFiltered.length;
        }
        
        Logger.info("AIEngine.Premium", `✅ AI 优选组筛选完成: ${diversityFiltered.length} 个节点`);
        Logger.info("AIEngine.Premium", `📊 评分统计: 平均 ${avgScore.toFixed(1)}, 最高 ${maxScore.toFixed(1)}, 最低 ${minScore.toFixed(1)}`);
        Logger.info("AIEngine.Premium", 
          `📊 各维度平均分: 基础:${avgBreakdown.base.toFixed(1)} 协议:${avgBreakdown.protocol.toFixed(1)} ` +
          `性能:${avgBreakdown.performance.toFixed(1)} 稳定:${avgBreakdown.stability.toFixed(1)} ` +
          `地理:${avgBreakdown.geography.toFixed(1)} 服务器:${avgBreakdown.server.toFixed(1)} ` +
          `语义:${avgBreakdown.semantic.toFixed(1)} 动态:${avgBreakdown.dynamic.toFixed(1)}`
        );

        return diversityFiltered.map(s => s.id);
        
      } catch (e) {
        Logger.error("AIEngine.Premium", `筛选异常: ${e.message}`);
        // 异常降级：返回评分最高的 10 个节点
        const emergency = proxies
          .map(p => ({ name: p.name || p, score: this.score(p) }))
          .sort((a, b) => b.score - a.score)
          .slice(0, 10)
          .map(item => item.name);
        Logger.warn("AIEngine.Premium", `异常降级: 返回评分最高的 ${emergency.length} 个节点`);
        return emergency.length > 0 ? emergency : ["DIRECT"];
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
      this._cache = cache || new Map(); // 简化为 Map
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
      this._cache=cache||new Map(); // 简化为 Map
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

      // 1. 生成区域分组（select + fallback 混合模式）
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
        
        const base=Utils.getProxyGroupBase();
        const regionNodeNames = regionProxies.map(p => p.name || p);
        
        // 1. 地理组（select）- 用户手动选择，引用全局故障转移组
        regionGroups.push({
          ...base,
          name: r.name,
          type: "select",
          proxies: ["故障转移", ...regionNodeNames],  // 引用全局故障转移组
          "include-all": false,
          lazy: false,  // ✅ 显式禁用懒加载
          interval: 180,  // ✅ 3 分钟检测一次
          "max-failed-times": 2,  // ✅ 2 次失败即标记
          icon: ICON_VAL(r.icon)
        });
        
        // 🔧 记录故障检测配置
        Logger.info("FailureDetection", 
          `地理组 ${r.name}: lazy=false, interval=180s, max-failed-times=2, timeout=3000ms`
        );
        
        regionCount++;
      }

      const excludeFilter = usedFilters.length ? usedFilters.map(f=>`(${f})`).join("|") : "";
      
      // 2. 智能优选组 (select + fallback 混合模式)
      const base=Utils.getProxyGroupBase();
      let bestIds = [];
      if(Config.aiOptions?.enable && list.length){
        bestIds = this._ai.getBestNodesForPremiumGroup(list);
      }

      // 2. 智能优选（select）
      const bestNodesGroup = {
        ...base,
        name: "智能优选",
        type: "select",
        proxies: bestIds.length ? ["故障转移", ...bestIds] : ["DIRECT"],
        "include-all": false,
        icon: ICON_VAL(ICONS.Premium)
      };

      // 3. 手动选择组（select，不添加故障转移）
      const allNodeNames = list.map(p => p.name || p);
      const manualSelectionGroup = {
        ...base,
        name: "手动选择",
        type: "select",
        proxies: [
          "DIRECT",
          "自动选择",
          "智能优选",
          ...allNodeNames
        ],
        "include-all": false,
        icon: ICON_VAL(ICONS.Premium)
      };

      // 4. 自动选择组（url-test，不添加故障转移）
      const autoSelectionGroup = {
        ...base,
        name: "自动选择",
        type: "url-test",
        "include-all": true,
        tolerance: 50,
        "max-failed-times": 3,
        "expected-status": "204",
        lazy: false,
        interval: 300,
        timeout: 5000,
        icon: ICON_VAL(ICONS.Proxy)
      };
      
      // 5. 故障转移组（fallback）- 全局故障转移，排在倒数第三
      const failoverGroup = {
        ...base,
        name: "故障转移",
        type: "fallback",
        proxies: bestIds.length ? bestIds : ["DIRECT"],
        "include-all": false,
        "max-failed-times": 3,
        "expected-status": "204",
        interval: 300,
        timeout: 5000,
        icon: ICON_VAL(ICONS.Proxy)
      };
      
      // 🔧 新增：记录故障检测配置
      Logger.info("FailureDetection", `自动选择组配置: max-failed-times=${autoSelectionGroup["max-failed-times"]}, tolerance=${autoSelectionGroup.tolerance}ms, interval=${autoSelectionGroup.interval}s, timeout=${autoSelectionGroup.timeout}ms`);
      Logger.info("FailureDetection", `故障转移组配置: type=fallback, max-failed-times=3, interval=300s, timeout=5000ms`);

      // 6. 其他节点组
      const otherGroup={
        ...base,
        name:"其他节点",
        type:"select",
        proxies:["故障转移", "手动选择", "自动选择", "智能优选", "DIRECT"],
        "include-all":true,
        "exclude-filter":excludeFilter,
        icon:ICON_VAL(ICONS.WorldMap)
      };

      // 7. 组装最终顺序：核心组 → 地理组 → 故障转移 → 其他节点 → 国内网站
      const regionProxyGroups = [
        bestNodesGroup,           // 智能优选
        manualSelectionGroup,     // 手动选择
        autoSelectionGroup,       // 自动选择
        ...regionGroups           // 地理组（包含故障转移子组）
      ];
      
      // 在倒数第三位置插入全局故障转移组（倒数：其他节点、国内网站、故障转移）
      regionProxyGroups.push(failoverGroup, otherGroup);
      
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
      
      // 基础组件：无依赖，直接初始化（简化版）
      this._cache=new Map(); // 简化为 Map
      
      // 延迟初始化的管理器：通过 getter 按需创建，避免循环依赖
      this._adBlock=null;
      this._regionMgr=null;
      this._functionalMgr=null;
      this._initialized = false;
      
      CentralManager._instance=this;
    }
    
    // 基础组件访问器
    get lruCache(){return this._cache;}
    
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
      
      // 后台预检已删除（v5.0-optimized）
      
      return newConfig;
    }
  }

  function createErrorProxy(msg) {
    const t = Date.now();
    return {
      name: `⛔ 脚本错误: ${String(msg).slice(0,20)}...`,
      type: "direct",
      _error: true,
      _errorMessage: msg,
      _errorTimestamp: t
    };
  }

  /* ========== 11. 配置生成引擎 (Config Builder) ========== */
  
  /**
   * 规则排序 - 按优先级对规则进行排序
   */
  function prioritizeRules(rules) {
    if (!Array.isArray(rules) || !rules.length) return rules || [];
    
    const getPriority = (rule) => {
      if (typeof rule !== 'string') return 999;
      const ruleUpper = rule.toUpperCase();
      
      if (ruleUpper.startsWith('GEOSITE,PRIVATE') || ruleUpper.startsWith('GEOIP,PRIVATE')) return 1;
      if (ruleUpper.includes('REJECT')) return 2;
      if (ruleUpper.startsWith('PROCESS-NAME') || ruleUpper.startsWith('RULE-SET,APPLICATIONS')) return 3;
      if (ruleUpper.startsWith('RULE-SET,') || ruleUpper.startsWith('GEOSITE,')) return 4;
      if (ruleUpper.includes('CHINA') || ruleUpper.includes(',CN')) return 5;
      if (ruleUpper.includes('PROXY') || ruleUpper.includes('GFW')) return 6;
      if (ruleUpper.startsWith('MATCH')) return 7;
      
      return 4;
    };
    
    return [...rules].sort((a, b) => getPriority(a) - getPriority(b));
  }

  /**
   * DNS 策略构建
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

      if(!this._validate(cfg)){
        if(Config.autoIntervention) this._selfHeal(cfg);
        else return cfg;
      }

      this._mergeSystem(cfg);
      const {regions,regionProxyGroups,otherProxyNames} = this._discoverRegions(cfg,context);
      const regionGroupNames = this._regionGroupNames(regionProxyGroups);
      cfg["proxy-groups"] = this._buildProxyGroups(cfg,regionGroupNames,regionProxyGroups,otherProxyNames,context);
      const {rules,ruleProviders} = this._buildRules(cfg,regionGroupNames,context);
      cfg.rules=rules; cfg["rule-providers"]=ruleProviders;
      if(Config.autoIntervention) this._finalAudit(cfg);
      
      // 去除重复的代理节点
      if(Array.isArray(cfg.proxies)){
        const seen = new Set();
        cfg.proxies = cfg.proxies.filter(p => {
          if(!p?.name) return false;
          const key = p.name.toUpperCase();
          if(seen.has(key)) return false;
          seen.add(key);
          return true;
        });
      }
      
      return cfg;
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
      // 验证规则提供者
      if(cfg["rule-providers"] && typeof cfg["rule-providers"]==="object"){
        for(const [n,p] of Object.entries(cfg["rule-providers"])){
          if(!p || typeof p !== 'object' || !p.url || !p.path){
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
                // 简单安全检查
                if(typeof fStr !== 'string' || CONSTANTS.RE.DANGEROUS_PATTERNS.test(fStr)){
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

    static _buildProxyGroups(cfg,regionNames,regionGroups,otherNames,context){
      const base=Utils.getProxyGroupBase();
      const groups=[];
      const services=Array.isArray(Config.services)?Config.services:[];
      
      // 默认优先级顺序：手动选择 > 自动选择 > 智能优选
      const defaultOrder = ["手动选择", "自动选择", "智能优选", "DIRECT"];
      const allProxies = cfg.proxies || [];

      // 获取功能组管理器
      const functionalMgr = context?.functionalGroupManager;

      // ========== 不再为每个服务创建独立分组 ==========
      // 所有服务规则将通过功能组来路由
      
      // ========== 1. 创建 10 个功能组(智能筛选节点 + 故障转移) ==========
      const functionalGroups = Array.isArray(Config.functionalGroups) ? Config.functionalGroups : [];
      functionalGroups.forEach(fg => {
        try {
          if (!fg?.name || !fg?.id) return;
          
          // 使用功能组管理器筛选合适的节点
          let selectedNodes = [];
          if (functionalMgr && allProxies.length > 0) {
            selectedNodes = functionalMgr.selectNodesForGroup(fg.id, allProxies);
          }
          
          // 1.1 创建功能组（select）- 引用全局故障转移组
          const customOrder = Array.isArray(fg.proxiesOrder) ? fg.proxiesOrder : [];
          const proxies = ["手动选择", "自动选择", "智能优选", ...customOrder.filter(p => p !== "手动选择" && p !== "自动选择" && p !== "智能优选")];
          
          // 添加全局故障转移组到第一位
          const allOptions = Utils.unique(["故障转移", ...proxies, ...regionNames]);
          
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
      // 修复：按正确的优先级顺序排列 - 手动选择 > 自动选择 > 智能优选
      try{
         // 先移除这三个核心组
         const bestIdx = groups.findIndex(g => g && g.name === "智能优选");
         const best = bestIdx > -1 ? groups.splice(bestIdx, 1)[0] : null;
         
         const autoIdx = groups.findIndex(g => g && g.name === "自动选择");
         const auto = autoIdx > -1 ? groups.splice(autoIdx, 1)[0] : null;
         
         const manualIdx = groups.findIndex(g => g && g.name === "手动选择");
         const manual = manualIdx > -1 ? groups.splice(manualIdx, 1)[0] : null;
         
         // 按正确的优先级顺序插入到最前面：手动选择 > 自动选择 > 智能优选
         if(best) groups.unshift(best);      // 第三优先级：智能优选
         if(auto) groups.unshift(auto);      // 第二优先级：自动选择
         if(manual) groups.unshift(manual);  // 第一优先级：手动选择（最高）
       }catch(e){
         Logger.error("ProxyGroups", `分组排序失败: ${e.message}`);
       }
      
      Logger.info("ProxyGroups", `构建完成: 共 ${groups.length} 个分组`);
      return groups;
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
      const baseRP={
        type:"http",
        interval:Config.common?.ruleProvider?.interval??86400,
        format:"yaml",  // ✅ 大多数规则集是 yaml 格式
        proxy:""  // ✅ 不使用代理，避免循环依赖
      };
      const opts=Config.ruleOptions||{};
      
      // 1. 添加 LAN 和私有网络规则（最高优先级）
      rules.push("GEOSITE,private,DIRECT");
      rules.push("GEOIP,private,DIRECT,no-resolve");
      
      // 2. 添加 REJECT 规则（广告、追踪器）
      if(opts.acl4ssr!==false && !ruleProviders.acl4ssr_ban){
        ruleProviders.acl4ssr_ban={
          type:"http",
          interval:86400,
          behavior:"classical",
          format:"text",  // ✅ Classical 格式
          url:URLS.rulesets.acl4ssr.ban(),
          path:"./ruleset/acl4ssr_ban.list",
          proxy:""  // ✅ 直连
        };
        rules.push("RULE-SET,acl4ssr_ban,REJECT");
        Logger.info("RuleProvider", `acl4ssr_ban: format=text, behavior=classical`);
      }
      if(opts.anti_ad!==false && !ruleProviders.anti_ad){
        ruleProviders.anti_ad={
          type:"http",
          interval:86400,
          behavior:"domain",
          format:"yaml",  // ✅ YAML 格式
          url:URLS.rulesets.anti_ad(),
          path:"./ruleset/anti_ad.yaml",
          proxy:""  // ✅ 直连
        };
        rules.push("RULE-SET,anti_ad,REJECT");
        Logger.info("RuleProvider", `anti_ad: format=yaml, behavior=domain`);
      }
      if(opts.loyalsoldier!==false && !ruleProviders.ls_reject){
        ruleProviders.ls_reject={
          type:"http",
          interval:86400,
          behavior:"classical",
          format:"text",  // ✅ Classical 格式
          url:URLS.rulesets.loyalsoldier.reject(),
          path:"./ruleset/ls_reject.list",
          proxy:""  // ✅ 直连
        };
        rules.push("RULE-SET,ls_reject,REJECT");
        Logger.info("RuleProvider", `ls_reject: format=text, behavior=classical`);
      }
      
      // 2.1 添加 Blackmatrix7 规则集（广告、隐私、劫持）
      if(opts.blackmatrix7!==false){
        if(!ruleProviders.bm7_advertising){
          ruleProviders.bm7_advertising={
            type:"http",
            interval:86400,
            behavior:"domain",
            format:"yaml",  // ✅ YAML 格式
            url:URLS.rulesets.blackmatrix7.advertising(),
            path:"./ruleset/bm7_advertising.yaml",
            proxy:""  // ✅ 直连
          };
          rules.push("RULE-SET,bm7_advertising,REJECT");
          Logger.info("RuleProvider", `bm7_advertising: format=yaml, behavior=domain`);
        }
        if(!ruleProviders.bm7_privacy){
          ruleProviders.bm7_privacy={
            type:"http",
            interval:86400,
            behavior:"domain",
            format:"yaml",  // ✅ YAML 格式
            url:URLS.rulesets.blackmatrix7.privacy(),
            path:"./ruleset/bm7_privacy.yaml",
            proxy:""  // ✅ 直连
          };
          rules.push("RULE-SET,bm7_privacy,REJECT");
          Logger.info("RuleProvider", `bm7_privacy: format=yaml, behavior=domain`);
        }
        if(!ruleProviders.bm7_hijacking){
          ruleProviders.bm7_hijacking={
            type:"http",
            interval:86400,
            behavior:"domain",
            format:"yaml",  // ✅ YAML 格式
            url:URLS.rulesets.blackmatrix7.hijacking(),
            path:"./ruleset/bm7_hijacking.yaml",
            proxy:""  // ✅ 直连
          };
          rules.push("RULE-SET,bm7_hijacking,REJECT");
          Logger.info("RuleProvider", `bm7_hijacking: format=yaml, behavior=domain`);
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
          const format = isMrs ? "mrs" : (rp.format || "yaml");
          const behavior = rp.behavior || "domain";
          ruleProviders[rp.name]={
            type:"http",
            interval:86400,
            behavior:behavior,
            format:format,  // ✅ 显式指定格式
            url:url,
            path:`./ruleset/${rp.name}.${format}`,
            proxy:""  // ✅ 直连
          };
          Logger.info("RuleProvider", `${rp.name}: format=${format}, behavior=${behavior}`);
        }
      });
      
      // 4.1 添加 Blackmatrix7 规则集（仅保留广告/隐私/劫持）
      if(opts.blackmatrix7!==false){
        const bm7Services = [
          {name:"bm7_advertising", url:URLS.rulesets.blackmatrix7.advertising(), target:"REJECT"},
          {name:"bm7_privacy", url:URLS.rulesets.blackmatrix7.privacy(), target:"REJECT"},
          {name:"bm7_hijacking", url:URLS.rulesets.blackmatrix7.hijacking(), target:"REJECT"}
        ];
        bm7Services.forEach(svc=>{
          if(!ruleProviders[svc.name]){
            ruleProviders[svc.name]={...baseRP,behavior:"domain",format:"yaml",url:svc.url,path:`./ruleset/${svc.name}.yaml`,proxy:""};
            rules.push(`RULE-SET,${svc.name},${svc.target}`);
            Logger.info("RuleProvider", `${svc.name}: format=yaml, behavior=domain`);
          }
        });
      }
      
      // 5. 添加国内路由规则（确保在国外代理规则之前）
      const coreSets={
        applications:{behavior:"classical",format:"text",url:URLS.rulesets.applications()},
        acl4ssr_china:{behavior:"domain",format:"text",url:URLS.rulesets.acl4ssr.china()},
        ls_cn:{behavior:"domain",format:"text",url:URLS.rulesets.loyalsoldier.cn()}
      };
      Object.entries(coreSets).forEach(([name,meta])=>{
        ruleProviders[name]={...baseRP,...meta,path:`./ruleset/${name}.list`,proxy:""};
        Logger.info("RuleProvider", `${name}: format=${meta.format}, behavior=${meta.behavior}`);
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
      
      // 使用规则排序进行最终排序
      const sorted = prioritizeRules(rules);
      
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
        fallback.proxies.unshift(createErrorProxy(msg));
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
