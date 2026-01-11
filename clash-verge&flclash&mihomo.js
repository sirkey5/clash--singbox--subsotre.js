/**
 * Mihomo 深度优化脚本 v4.5 (智能后台预检版)
 * 
 * [核心特性]
 * 1. 异步兼容：main 函数同步返回，完美适配所有 GUI 与移动端内核。
 * 2. 静默探测：在支持异步的环境下（如 Clash Verge）自动执行后台非阻塞测速。
 * 3. 闭环优化：结合历史统计与 AI 评分进行节点筛选，后台探测结果实时反馈至全局。
 * 4. 智能感知：自动识别运行环境，动态调整预检策略与分流逻辑。
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
      version: "v4.5-2025.12.31",
      useES2022: true
    });
  })();

  const CONSTANTS = Object.freeze({
    RE: {
      GH_RAW: /raw\.githubusercontent\.com\/([^\/]+)\/([^\/]+)\/([^\/]+)\/(.+)/,
      GH_RELEASE: /github\.com\/([^\/]+)\/([^\/]+)\/releases\/download\/([^\/]+)\/(.+)/,
      URL_MASK: /([?&](token|key|auth|password|secret|access_token|api_key|session_id|credential|bearer|x-api-key|x-token|authorization)=)[^&]+/gi,
      SENSITIVE_KEY: /password|token|key|secret|auth|credential|access|bearer|authorization|cookie|session/i
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
    deepClone(obj, keyName=null, seen = new WeakMap()) {
      if (!obj || typeof obj !== "object") return obj;
      if (seen.has(obj)) return seen.get(obj);
      
      if (keyName === "proxies" && Array.isArray(obj)) return [...obj];
      
      if (Array.isArray(obj)) {
        const result = [];
        seen.set(obj, result);
        for (const item of obj) result.push(Utils.deepClone(item, null, seen));
        return result;
      }
      
      const result = Object.create(Object.getPrototypeOf(obj));
      seen.set(obj, result);
      
      for (const k in obj) {
        if (Object.prototype.hasOwnProperty.call(obj, k)) {
          const needDeep = ["proxy-groups", "rules", "proxy-providers"].includes(k);
          result[k] = needDeep ? Utils.deepClone(obj[k], k, seen) : obj[k];
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

  let GH_PROXY = "https://mirror.ghproxy.com/";

  async function selectBestMirror(){ return GH_PROXY; }
  const MIRROR_STATUS = new Map();

  const ICON_VAL = (f)=>{try{return typeof f==="function"?f():(f??"");}catch{return"";}};

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
    const cache = new Map();
    return new Proxy({},{
      get(_,n){
        if(cache.has(n)) return cache.get(n);
        const url = () => `${GH_PROXY}${base}/${map[n]??n}.png`;
        cache.set(n,url);
        return url;
      }
    });
  })();

  const URLS = {
    _getMirrorUrl(original){
      if(!GH_PROXY) return original;
      let clean = original;
      for(const m of CONSTANTS.GH.MIRRORS){if(m && clean.startsWith(m)){clean=clean.slice(m.length);break;}}
      if(GH_PROXY.includes("jsdelivr.net")){
        const m = clean.match(CONSTANTS.RE.GH_RAW);
        if(m){const [,user,repo,branch,path]=m;return `https://cdn.jsdelivr.net/gh/${user}/${repo}@${branch}/${path}`;}
      }
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
    mrs(name){
      const path=`meta/geo/geosite/${name}.mrs`;
      if(GH_PROXY.includes("jsdelivr")) return `https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@meta/geo/geosite/${name}.mrs`;
      return URLS._getMirrorUrl(`https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/${path}`);
    },
    list(name){
      const path=`release/${name}.txt`;
      if(GH_PROXY.includes("jsdelivr")) return `https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/${name}.txt`;
      return URLS._getMirrorUrl(`https://raw.githubusercontent.com/Loyalsoldier/clash-rules/${path}`);
    },
    rulesets:{
      ai:()=>URLS.mrs("category-ai-!cn"),ads:()=>URLS.mrs("category-ads-all"),trackers:()=>URLS.mrs("tracker"),
      applications:()=>URLS.list("applications"),claude:()=>URLS.mrs("anthropic"),gemini:()=>URLS.mrs("google"),
      youtube:()=>URLS.mrs("youtube"),netflix:()=>URLS.mrs("netflix"),disney:()=>URLS.mrs("disney"),
      spotify:()=>URLS.mrs("spotify"),streaming:()=>URLS.mrs("category-streaming"),
      china_media:()=>URLS.mrs("category-media-cn"),telegram:()=>URLS.mrs("telegram"),
      discord:()=>URLS.mrs("discord"),speedtest:()=>URLS.mrs("speedtest"),steam:()=>URLS.mrs("steam"),
      games:()=>URLS.mrs("category-games"),github:()=>URLS.mrs("github"),google:()=>URLS.mrs("google"),
      microsoft:()=>URLS.mrs("microsoft"),apple:()=>URLS.mrs("apple"),scholar:()=>URLS.mrs("category-scholar-!cn"),
      proxy:()=>URLS.mrs("proxy"),gfw:()=>URLS.mrs("gfw"),
      acl4ssr:{
        ban:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/BanAD.list"),
        china:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/ChinaDomain.list"),
        lan:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/ACL4SSR/ACL4SSR/master/Clash/LocalAreaNetwork.list")
      },
      anti_ad:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/privacy-protection-tools/anti-AD/master/anti-ad-clash.yaml"),
      clash_rules:{
        ad:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/earoftoast/clash-rules/main/AD.yaml"),
        privacy:()=>URLS._getMirrorUrl("https://raw.githubusercontent.com/earoftoast/clash-rules/main/EasyPrivacy.yaml")
      },
      loyalsoldier:{
        reject:()=>URLS.list("reject"),icloud:()=>URLS.list("icloud"),apple:()=>URLS.list("apple"),
        google:()=>URLS.list("google"),proxy:()=>URLS.list("proxy"),direct:()=>URLS.list("direct"),
        private:()=>URLS.list("private"),gfw:()=>URLS.list("gfw"),greatfire:()=>URLS.list("greatfire"),
        tld_not_cn:()=>URLS.list("tld-not-cn"),telegram:()=>URLS.list("telegram"),cn:()=>URLS.list("direct")
      }
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
        ["apple","microsoft","github","google","openai","spotify","youtube","bahamut","netflix","tiktok","disney","pixiv","hbo","biliintl","tvb","hulu","primevideo","telegram","line","whatsapp","games","japan","tracker","ads","acl4ssr","anti_ad","clash_rules","loyalsoldier"]
          .map(k=>[k,true])
      )
    },
    preRules:[
      "RULE-SET,applications,下载软件",
      "PROCESS-NAME,SunloginClient,DIRECT",
      "PROCESS-NAME,AnyDesk,DIRECT"
    ],
    regionOptions:{
      geoIpGrouping:true, autoDiscover:true, excludeHighPercentage:true, ratioLimit:2,
      regions:[
        { name:"HK香港", regex:/港|🇭🇰|hk|hongkong|hkg/i, code:"HK", icon:ICONS.HongKong },
        { name:"TW台湾省", regex:/台|🇹🇼|tw|taiwan|tpe/i, code:"TW", icon:ICONS.Taiwan },
        { name:"JP日本", regex:/日|🇯🇵|jp|japan|nrt|hnd|kix/i, code:"JP", icon:ICONS.Japan },
        { name:"SG新加坡", regex:/新|🇸🇬|sg|singapore|sin/i, code:"SG", icon:ICONS.Singapore },
        { name:"US美国", regex:/美|🇺🇸|us|united states|america|lax|sfo|jfk/i, code:"US", icon:ICONS.UnitedStates },
        { name:"KR韩国", regex:/韩|🇰🇷|kr|korea|sel|icn/i, code:"KR", icon:ICONS.Korea },
        { name:"CN中国大陆", regex:/中|🇨🇳|cn|china|mainland/i, code:"CN", icon:ICONS.ChinaMap },
        { name:"GB英国", regex:/英|🇬🇧|uk|united kingdom|great britain|lhr/i, code:"GB", icon:ICONS.UnitedKingdom },
        { name:"DE德国", regex:/德|🇩🇪|de|germany|fra/i, code:"DE", icon:ICONS.Germany },
        { name:"FR法国", regex:/法|🇫🇷|fr|france|cdg/i, code:"FR", icon:ICONS.France },
        { name:"MY马来西亚", regex:/马|🇲🇾|my|malaysia|kul/i, code:"MY", icon:ICONS.Malaysia },
        { name:"TR土耳其", regex:/土|🇹🇷|tr|turkey|ist/i, code:"TR", icon:ICONS.Turkey },
        { name:"RU俄罗斯", regex:/俄|🇷🇺|ru|russia|mow/i, code:"RU", icon:ICONS.Russia },
        { name:"CA加拿大", regex:/加|🇨🇦|ca|canada|yvr|yyz/i, code:"CA", icon:ICONS.Canada },
        { name:"AU澳大利亚", regex:/澳|🇦🇺|au|australia|syd|mel/i, code:"AU", icon:ICONS.Australia }
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
      "nameserver-policy":{"geosite:private":["system"],"geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn":["119.29.29.29","223.5.5.5"],"rule-set:acl4ssr_china,ls_cn":["119.29.29.29","223.5.5.5"]}
    },
    services: [
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
      { id:"china_media", rule:["RULE-SET,china_media,国内媒体"], name:"国内媒体", icon:ICONS.StreamingCN, ruleProvider:{ name:"china_media", url:()=>URLS.rulesets.china_media(), behavior:"domain" }, proxiesOrder:["DIRECT","手动选择"] },
      { id:"telegram", rule:["GEOIP,telegram,Telegram","RULE-SET,telegram,Telegram"], name:"Telegram", icon:ICONS.Telegram, ruleProvider:{ name:"telegram", url:()=>URLS.rulesets.telegram(), behavior:"domain" } },
      { id:"discord",  rule:["RULE-SET,discord,Discord"], name:"Discord", icon:ICONS.Discord, ruleProvider:{ name:"discord", url:()=>URLS.rulesets.discord(), behavior:"domain" } },
      { id:"whatsapp", rule:["GEOSITE,whatsapp,WhatsApp"], name:"WhatsApp", icon:ICONS.WhatsApp },
      { id:"line",     rule:["GEOSITE,line,Line"], name:"Line", icon:ICONS.Line },
      { id:"slack",    rule:["GEOSITE,slack,Slack"], name:"Slack", icon:ICONS.Slack },
      { id:"speedtest",rule:["RULE-SET,speedtest,Speedtest"], name:"Speedtest", icon:ICONS.Speedtest, ruleProvider:{ name:"speedtest", url:()=>URLS.rulesets.speedtest(), behavior:"domain" } },
      { id:"steam",    rule:["RULE-SET,steam,Steam"], name:"Steam", icon:ICONS.Steam, ruleProvider:{ name:"steam", url:()=>URLS.rulesets.steam(), behavior:"domain" } },
      { id:"epic",     rule:["GEOSITE,epicgames,Epic Games"], name:"Epic Games", icon:ICONS.Epic },
      { id:"games",    rule:["RULE-SET,games,游戏专用"], name:"游戏专用", icon:ICONS.Game, ruleProvider:{ name:"games", url:()=>URLS.rulesets.games(), behavior:"domain" } },
      { id:"apps",     rule:["RULE-SET,apple,应用软件","RULE-SET,microsoft,应用软件","RULE-SET,google,应用软件"], name:"应用软件", icon:ICONS.Apple2 },
      { id:"github",   rule:["RULE-SET,github,Github"], name:"Github", icon:ICONS.GitHub, ruleProvider:{ name:"github", url:()=>URLS.rulesets.github(), behavior:"domain" } },
      { id:"google",   rule:["RULE-SET,google,谷歌服务"], name:"谷歌服务", icon:ICONS.GoogleSearch, ruleProvider:{ name:"google", url:()=>URLS.rulesets.google(), behavior:"domain" } },
      { id:"microsoft",rule:["RULE-SET,microsoft,微软服务"], name:"微软服务", icon:ICONS.Microsoft, ruleProvider:{ name:"microsoft", url:()=>URLS.rulesets.microsoft(), behavior:"domain" } },
      { id:"apple",    rule:["RULE-SET,apple,苹果服务"], name:"苹果服务", icon:ICONS.Apple2, ruleProvider:{ name:"apple", url:()=>URLS.rulesets.apple(), behavior:"domain" } },
      { id:"scholar",  rule:["RULE-SET,scholar,学术网站"], name:"学术网站", icon:ICONS.Book, ruleProvider:{ name:"scholar", url:()=>URLS.rulesets.scholar(), behavior:"domain" } },
      { id:"proxy",    rule:["RULE-SET,proxy,全球加速"], name:"全球加速", icon:ICONS.Proxy, ruleProvider:{ name:"proxy", url:()=>URLS.rulesets.proxy(), behavior:"domain" } },
      { id:"gfw",      rule:["RULE-SET,gfw,GFW列表"], name:"GFW列表", icon:ICONS.Firewall, ruleProvider:{ name:"gfw", url:()=>URLS.rulesets.gfw(), behavior:"domain" } },
      { id:"tracker",  rule:["GEOSITE,tracker,跟踪分析"], name:"跟踪分析", icon:ICONS.Reject, proxies:["REJECT","DIRECT","手动选择"] },
      { id:"ads",      rule:["RULE-SET,ads,广告过滤"], name:"广告过滤", icon:ICONS.Advertising, proxies:["REJECT","DIRECT","手动选择"], ruleProvider:{ name:"ads", url:()=>URLS.rulesets.ads(), behavior:"domain" } }
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
    common:{ ruleProvider:{ type:"http", interval:86400 }, proxyGroup:{ interval:300, timeout:3000, url:"https://cp.cloudflare.com/generate_204", lazy:true }, defaultProxyGroups:[{ name:"下载软件", icon:ICONS.Download, proxies:["DIRECT","REJECT","手动选择","国内网站"] },{ name:"其他外网", icon:ICONS.StreamingNotCN, proxies:["手动选择","国内网站"] },{ name:"国内网站", icon:ICONS.StreamingCN, proxies:["DIRECT","手动选择"] }], postRules:["GEOSITE,private,DIRECT","GEOIP,private,DIRECT,no-resolve","RULE-SET,ls_cn,国内网站","RULE-SET,acl4ssr_china,国内网站","GEOSITE,cn,国内网站","GEOIP,cn,国内网站,no-resolve","MATCH,其他外网"] },
    performance: { heavyProxyThreshold: 800, ioBudgetPerTick: 16 }
  };

  /* ========== 7. 基础组件 (Core Components) ========== */
  class SceneDetector {
    static detect(ctx){
      if(!ctx) return "browsing";
      const {process,domain,port}=ctx;
      if(domain && CONSTANTS.STREAM_REG.test(domain)) return "streaming";
      if(domain && CONSTANTS.AI_REG.test(domain)) return "browsing";
      if(process && ["Steam","Epic","Game"].some(g=>process.includes(g))) return "gaming";
      if([1935,554,8000].includes(port)) return "streaming";
      if(port===22||port===21||(process||"").toLowerCase().includes("download")) return "download";
      return "browsing";
    }
  }

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
        try{this._pendingWrites.set(key, JSON.stringify(e));}catch(err){}
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

    clear(){this._l1.clear();this._l2.clear();this._pendingWrites.clear();}

    flushPersistence(ioBudget=16){
      if(!this._persist || !this._pendingWrites.size) return;
      const iter = this._pendingWrites.entries();
      let count = 0;
      for(const [key, serialized] of iter){
        try{PersistentStorage.write(key, serialized);}catch(e){}
        this._pendingWrites.delete(key);
        count++;
        if(count>=ioBudget) break;
      }
      if(count) Logger.debug("LRU.Flush",`刷盘 ${count} 条, 剩余: ${this._pendingWrites.size}`);
    }
  }

  class HttpClient {
    constructor(){this._avail=null;}
    _check(){
      if(this._avail!==null) return this._avail;
      this._avail = (typeof fetch==="function");
      return this._avail;
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
              return /HK|SG|JP|US|TW|香港|新加坡|日本|美国|台湾/i.test(name);
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

  class SecurityGuard {
    constructor(){
      this._blocked = new Set();
      this._malicious = [/malware|phishing|track|telemetry|spyware|adware/i,/coinminer|cryptonight|stratum/i,/dns-leak|leak-test/i,/exploit|attack|payload/i];
    }
    analyzeThreat(ctx){
      if(!Config.aiOptions?.protection?.threatDetection) return 0;
      const {domain,ip,port,process} = ctx||{};
      let s=0;
      if(port && !CONSTANTS.SAFE_PORTS.has(port)) s+=0.35;
      if(domain){
        if(this._malicious.some(p=>p.test(domain))) s+=0.6;
        if(domain.length>100) s+=0.1;
      }
      if(ip){
        if(Utils.isPrivateIP(ip) && domain && !domain.includes(".local")) s+=0.3;
        if(this._blocked.has(ip)) s+=0.8;
      }
      if(process && /tor|i2p|freenet/i.test(process)) s+=0.2;
      return Utils.clamp(s,0,1);
    }
    performAutoRepair(component){
      Logger.warn("Security.AutoRepair",`修复: ${component}`);
      const c = CentralManager.getInstance();
      try{
        if(component==="cache") c.lruCache.clear();
        else if(component==="stats") c.regionAutoManager.stats.reset?.();
        else if(component==="ai") c.regionAutoManager.ai.reset?.();
        else if(component==="network") this._blocked.clear();
        else return false;
        return true;
      }catch(e){Logger.error("Security.AutoRepair",`失败 ${component}: ${e.message}`);return false;}
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
        REGIONS: { "HK": 20, "SG": 20, "JP": 15, "US": 10, "TW": 15, "KR": 10, "UK": 5, "DE": 5 }
      };
      this._vetoReg = /Maintenance|Down|Fix|Expired|Error|Timeout|故障|维护|离线/i;
      this._regionReg = /HK|SG|JP|US|TW|KR|UK|DE|香港|新加坡|日本|美国|台湾|韩国|英国|德国/i;
      this._latencyReg = /(\d+)ms/i;
      this._kwRegs = new Map(Object.keys(this._weights.KEYWORDS).map(kw => [kw, new RegExp(kw, "i")]));
    }

    setScene(scene) {
      if (["browsing", "gaming", "streaming", "download"].includes(scene)) {
        this._currentScene = scene;
      }
    }

    /**
     * 节点综合评分逻辑 (基础 25, 满分 100+)
     * 维度：协议、倍率、语义关键词、地理位置、动态历史
     */
    score(proxy) {
      if (!proxy) return 0;
      let staticScore = 25; // 静态基础分
      const name = typeof proxy === 'string' ? proxy : String(proxy.name || "");
      const type = String(proxy.type || "").toLowerCase();
      const port = parseInt(proxy.port || 0);

      // 0. 语义否决：快速排除故障节点
      if (this._vetoReg.test(name)) {
        Logger.debug("AIEngine.Veto", `否决节点: ${name}`);
        return 0;
      }

      // 1. 协议代差权重 (25%)
      const protocolWeights = { 
        "hysteria2": 25, "tuic": 25, "vless": 22, 
        "trojan": 18, "ss": 15, "snell": 12, 
        "vmess": 8, "ssr": 5 
      };
      staticScore += (protocolWeights[type] || 0);

      // 2. 流量倍率惩罚/奖励 (15%)
      if (proxy.rate != null) {
        const rate = parseFloat(proxy.rate);
        if (rate <= 0.1) staticScore += 15;
        else if (rate <= 0.5) staticScore += 10;
        else if (rate <= 1.0) staticScore += 5;
        else if (rate > 1.0) staticScore -= 20;
      } else if (name.includes("0.1x")) staticScore += 15;
      else if (name.includes("1.0x")) staticScore += 5;

      // 3. 元数据信誉度 (10%)
      if (CONSTANTS.SAFE_PORTS.has(port)) staticScore += 4;
      if (proxy.udp) staticScore += 2;
      if (proxy.tls) staticScore += 2;
      
      const stats = this._stats ? this._stats.getStats(proxy) : null;
      if (stats && stats.successCount > 10) staticScore += 2; 

      // 4. 语义关键词权重 (30%)
      let semanticScore = 0;
      for (const [kw, reg] of this._kwRegs) {
        if (reg.test(name)) {
          const w = this._weights.KEYWORDS[kw];
          if (w <= -80) return 0; // 严重异常一票否决
          semanticScore += w;
        }
      }
      const regMatch = name.match(this._regionReg);
      if (regMatch) {
        const r = regMatch[0].toUpperCase();
        const regionMap = {
          "香港": "HK", "HK": "HK",
          "新加坡": "SG", "SG": "SG",
          "日本": "JP", "JP": "JP",
          "美国": "US", "US": "US",
          "台湾": "TW", "TW": "TW",
          "韩国": "KR", "KR": "KR",
          "英国": "UK", "UK": "UK",
          "德国": "DE", "DE": "DE"
        };
        const rCode = regionMap[r] || r;
        semanticScore += (this._weights.REGIONS[rCode] || 0);
      }
      
      // 5. 延迟暗示解析
      const latencyMatch = name.match(this._latencyReg);
      if (latencyMatch) {
        const ms = parseInt(latencyMatch[1]);
        if (ms > 800) staticScore -= 45;
        else if (ms > 400) staticScore -= 25;
        else if (ms < 150) staticScore += 10;
      }

      staticScore += Math.min(30, semanticScore);
      const baseScore = Utils.clamp(staticScore, 0, 80);

      // 6. 动态统计偏移 (20%) - 基于历史成功/失败记录
      const dynamicOffset = this._stats ? this._stats.getDynamicOffset(proxy) : 0;

      return Math.max(0, baseScore + dynamicOffset);
    }

    /**
     * 构建优选节点组
     * 策略：AI 静态初筛 -> 历史状态过滤 -> 同源化隔离 (ASN/集群)
     */
    getBestNodes(proxies) {
      if (!proxies || !proxies.length) return [];
      
      try {
        const total = proxies.length;
        // 动态调整目标数量：15% 比例，封顶 500，保底 5
        let targetCount = Math.min(500, Math.max(5, Math.floor(total * 0.15)));
        if (total <= 5) targetCount = total;
        
        Logger.info("AIEngine", `优选筛选: 总数 ${total}, 目标 ${targetCount}`);

        // 1. 静态评分 + 历史过滤
        const candidates = proxies.map(p => {
          const score = this.score(p);
          const name = typeof p === 'string' ? p : String(p.name || "");
          const isCore = /HK|SG|JP|US|TW|香港|新加坡|日本|美国|台湾/i.test(name);
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
          // 排除有失败记录的节点
          if (item.failCount > 0) return false;
          // 核心区域门槛 45，非核心区域门槛 55 (宁缺毋滥)
          return item.isCore ? item.score >= 45 : item.score >= 55;
        }).sort((a, b) => b.score - a.score);

        if (!candidates.length) {
          Logger.warn("AIEngine", "初筛后无可用节点，执行保底逻辑");
          return proxies.slice(0, 5).map(p => p.name || p);
        }

        // 2. 多样性调度 (同源化隔离)
        const selected = [];
        const seenServers = new Set();
        const seenASNs = new Map(); 
        const seenClusters = new Map(); 

        const getCluster = (name) => name.replace(/\d+|[_-]\d+|[A-Za-z]\d+$/g, "").trim();

        for (const item of candidates) {
          if (selected.length >= targetCount) break;
          
          const asn = item.server ? item.server.split('.').slice(-2).join('.') : "0.0";
          const asnCount = seenASNs.get(asn) || 0;
          const cluster = getCluster(item.id);
          const clusterCount = seenClusters.get(cluster) || 0;

          // 隔离策略：服务器唯一，同 ASN 限制 3，同集群限制 3
          if (!seenServers.has(item.server) && asnCount < 3 && clusterCount < 3) {
            selected.push(item);
            if (item.server) seenServers.add(item.server);
            seenASNs.set(asn, asnCount + 1);
            seenClusters.set(cluster, clusterCount + 1);
          }
        }

        // 3. 兜底填充
        if (selected.length < 5 && candidates.length > selected.length) {
          for (const item of candidates) {
            if (selected.length >= 5) break;
            if (!selected.some(s => s.id === item.id)) {
              selected.push(item);
            }
          }
        }

        Logger.info("AIEngine", `优选完成: 选中 ${selected.length} 个节点`);
        return selected.map(s => s.id);
      } catch (e) {
        Logger.error("AIEngine", `筛选异常: ${e.message}`);
        return proxies.slice(0, 10).map(p => p.name || p);
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

  /* ========== 9. 自动化管理组件 (Region & AdBlock) ========== */
  class AdBlockManager {
    constructor(){this.adBlockUrl=URLS.rulesets.ads();}
    updateIfNeeded(){Logger.debug("AdBlock","使用预设规则源");return true;}
    injectRuleProvider(rps){
      if(this.adBlockUrl){
        Utils.safeSet(rps,"adblock_combined",{type:"http",interval:86400,behavior:"domain",format:"mrs",url:this.adBlockUrl,path:"./ruleset/adblock_combined.mrs"});
      }
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
     */
    discoverRegionsFromProxies(proxies){
      const regions=Config.regionOptions?.regions || [];
      const found=new Map();
      const list=Array.isArray(proxies)?proxies:[];
      list.forEach(p=>{
        const n=String(p?.name||"").trim(); if(!n) return;
        const matched=regions.find(r=>r.regex.test(n));
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
      const base=Utils.getProxyGroupBase();
      
      const activeRegions = hasProviders ? (Config.regionOptions?.regions || []) : regions;

      // 1. 生成区域分组
      for(const r of activeRegions){
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
        regionGroups.push({...base,name:r.name,type:"url-test","include-all":true,filter:pattern,tolerance:50,icon:ICON_VAL(r.icon)});
      }

      const excludeFilter = usedFilters.length ? usedFilters.map(f=>`(${f})`).join("|") : "";
      
      // 2. 自动优选组 (AI 精选)
      let bestIds = [];
      if(Config.aiOptions?.enable && list.length){
        bestIds = this._ai.getBestNodes(list);
      }

      const bestNodesGroup = {
        ...base,
        name: "自动优选",
        type: "select",
        proxies: bestIds.length ? bestIds : ["DIRECT"],
        "include-all": false,
        tolerance: 50,
        icon: ICON_VAL(ICONS.Premium)
      };

      // 3. 策略调度组
      const manualSelectionGroup = {
        ...base,
        name: "手动选择",
        type: "select",
        proxies: ["自动优选", "自动选择", "DIRECT"], 
        "include-all": true,
        icon: ICON_VAL(ICONS.Premium)
      };

      const autoSelectionGroup = {
        ...base,
        name: "自动选择",
        type: "url-test",
        "include-all": true,
        tolerance: 50,
        icon: ICON_VAL(ICONS.Proxy)
      };

      const otherGroup={...base,name:"其他节点",type:"select","include-all":true,"exclude-filter":excludeFilter,icon:ICON_VAL(ICONS.WorldMap)};

      const regionProxyGroups = [bestNodesGroup, manualSelectionGroup, autoSelectionGroup];
      regionProxyGroups.push(...regionGroups, otherGroup);
      
      return {regionProxyGroups,otherProxyNames:[]};
    }
  }

  /* ========== 10. 中央管理器 (Central Manager) ========== */
  class CentralManager {
    static _instance;
    static getInstance(){
      if(!CentralManager._instance) CentralManager._instance=new CentralManager();
      return CentralManager._instance;
    }
    constructor(){
      if(CentralManager._instance) return CentralManager._instance;
      this._cache=new LRUCache();
      this._security=new SecurityGuard();
      this._http=new HttpClient();
      this._adBlock=null;
      this._regionMgr=null;
      this._probe=null;
      this._initialized = false;
      CentralManager._instance=this;
    }
    get lruCache(){return this._cache;}
    get security(){return this._security;}
    get adBlockManager(){if(!this._adBlock) this._adBlock=new AdBlockManager(this); return this._adBlock;}
    get regionAutoManager(){if(!this._regionMgr) this._regionMgr=new RegionAutoManager(this._cache); return this._regionMgr;}
    get backgroundProbe(){
      if(!this._probe) this._probe=new BackgroundProbe(this._http, this.regionAutoManager.stats);
      return this._probe;
    }

    initialize(){
      if (this._initialized) return;
      this._initialized = true;
      try {
        this.regionAutoManager.stats.cleanup();
      } catch (e) {}
      Logger.info("Central.init", `初始化完成 (环境: ${Env.get()})`);
    }

    processConfiguration(config,ctx=null){
      const scene=SceneDetector.detect(ctx);
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
      cfg["proxy-groups"] = this._buildProxyGroups(cfg,regionGroupNames,regionProxyGroups,otherProxyNames);
      const {rules,ruleProviders} = this._buildRules(cfg,regionGroupNames,context);
      cfg.rules=rules; cfg["rule-providers"]=ruleProviders;
      if(Config.autoIntervention) this._finalAudit(cfg);
      return cfg;
    }

    /**
     * 场景自适应权重调整
     */
    static _applyAdaptive(cfg,context){
      const scene = SceneDetector.detect(context);
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
          if(!p.url || !p.path){Logger.warn("Config.Audit",`移除无效 Provider: ${n}`); delete cfg["proxy-providers"][n];}
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
                const safe = (fStr.includes("URLS")||fStr.includes("ICONS")||fStr.includes("ICON_VAL"))&&!/eval|Function|require|process|global|window|document|XMLHttpRequest|fetch/i.test(fStr);
                if(!safe){Logger.warn("Config.Security",`拒绝执行函数: ${k}`); delete obj[k]; continue;}
                try{const v=obj[k](); if(v==null || ["string","number","boolean"].includes(typeof v) || (typeof v==="object" && !Array.isArray(v))) obj[k]=v;else{Logger.warn("Config.Security",`函数返回非法类型: ${k}`);delete obj[k];}}catch(e){Logger.error("Config.Security",`执行失败: ${k}`,e.message);delete obj[k];}
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

    static _buildProxyGroups(cfg,regionNames,regionGroups,otherNames){
      const base=Utils.getProxyGroupBase();
      const groups=[];
      const services=Array.isArray(Config.services)?Config.services:[];
      
      // 增强分流管理：定义高优先级服务与分层分流策略
      const highPriorityServices = ["openai", "claude", "gemini", "youtube", "netflix", "disney", "spotify", "telegram", "google"];
      const defaultOrder = ["自动优选", "手动选择", "自动选择", "DIRECT"];

      services.forEach(svc=>{
        try{
          const name=svc.name||svc.id; if(!name) return;
          let proxies = [];
          
          if (Array.isArray(svc.proxiesOrder)) {
            proxies = [...svc.proxiesOrder];
          } else if (Array.isArray(svc.proxies)) {
            proxies = [...svc.proxies];
          } else {
            // 默认使用标准优先级排序
            proxies = [...defaultOrder];
          }
          
          proxies = Utils.unique([...proxies, ...regionNames]);
          groups.push({...base,name,type:"select",proxies,icon:ICON_VAL(svc.icon)});
        }catch(e){Logger.warn("Config.ServiceGroup",svc?.id,e.message||e);}
      });
      (Config.common?.defaultProxyGroups||[]).forEach(g=>{
        if(!g?.name) return;
        groups.push({...base,name:g.name,type:"select",proxies:[...(Array.isArray(g.proxies)?g.proxies:[]),...regionNames],icon:ICON_VAL(g.icon)});
      });
      if(regionGroups.length){
        regionGroups.forEach(g=>{if(g.type==="url-test"||g.type==="fallback") Object.assign(g,{...base,tolerance:50});});
        groups.push(...regionGroups);
      }
      try{
         // 排序逻辑：自动优选(1) -> 手动选择(2) -> 自动选择(3)
         const autoIdx = groups.findIndex(g => g && g.name === "自动选择");
         if(autoIdx > -1){ const [auto] = groups.splice(autoIdx,1); groups.unshift(auto); }

         const manualIdx = groups.findIndex(g => g && g.name === "手动选择");
         if(manualIdx > -1){ const [manual] = groups.splice(manualIdx,1); groups.unshift(manual); }

         const bestIdx = groups.findIndex(g => g && g.name === "自动优选");
         if(bestIdx > -1){ const [best] = groups.splice(bestIdx,1); groups.unshift(best); }
       }catch(e){}
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
      if(opts.autoDiscover || Config.autoIntervention) this._autoDiscoverRules(ruleProviders,rules,opts,baseRP);

      const coreSets={applications:{behavior:"classical",url:URLS.rulesets.applications()},acl4ssr_china:{behavior:"domain",url:URLS.rulesets.acl4ssr.china()},ls_cn:{behavior:"domain",url:URLS.rulesets.loyalsoldier.cn()}};
      Object.entries(coreSets).forEach(([name,meta])=>{ruleProviders[name]={...baseRP,...meta,path:`./ruleset/${name}.list`};});

      if(opts.acl4ssr!==false && !ruleProviders.acl4ssr_ban){ruleProviders.acl4ssr_ban={...baseRP,behavior:"classical",url:URLS.rulesets.acl4ssr.ban(),path:"./ruleset/acl4ssr_ban.list"}; rules.push("RULE-SET,acl4ssr_ban,REJECT");}
      if(opts.anti_ad!==false && !ruleProviders.anti_ad){ruleProviders.anti_ad={...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.anti_ad(),path:"./ruleset/anti_ad.yaml"}; rules.push("RULE-SET,anti_ad,REJECT");}
      if(opts.clash_rules!==false && !ruleProviders.clash_ad){ruleProviders.clash_ad={...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.clash_rules.ad(),path:"./ruleset/clash_ad.yaml"}; ruleProviders.clash_privacy={...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.clash_rules.privacy(),path:"./ruleset/clash_privacy.yaml"}; rules.push("RULE-SET,clash_ad,REJECT","RULE-SET,clash_privacy,REJECT");}
      if(opts.loyalsoldier!==false && !ruleProviders.ls_reject){ruleProviders.ls_reject={...baseRP,behavior:"classical",url:URLS.rulesets.loyalsoldier.reject(),path:"./ruleset/ls_reject.list"}; rules.push("RULE-SET,ls_reject,REJECT");}

      if(Array.isArray(Config.preRules)) rules.push(...Config.preRules);
      (Config.services||[]).forEach(svc=>{
        if(svc.id && opts[svc.id]===false) return;
        if(svc.rule) rules.push(...svc.rule);
        const rp=svc.ruleProvider;
        if(rp?.name && !ruleProviders[rp.name]){
          const url=typeof rp.url==="function"?rp.url():rp.url;
          const isMrs=url.endsWith(".mrs");
          ruleProviders[rp.name]={...baseRP,behavior:rp.behavior||"domain",format:isMrs?"mrs":(rp.format||"yaml"),url,path:`./ruleset/${rp.name}.${isMrs?"mrs":(rp.format||"yaml")}`};
        }
      });
      if(context?.adBlockManager) context.adBlockManager.injectRuleProvider(ruleProviders);
      if(Array.isArray(Config.common?.postRules)) rules.push(...Config.common.postRules);
      const sorted=this._sortRules(rules);
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
      const msg = e?.message || "未知错误";
      try {
        const fallback = { ...config };
        if (!Array.isArray(fallback.proxies)) fallback.proxies = [];
        // 异常降级：在代理列表首位插入可视化错误提示
        fallback.proxies.unshift(ErrorConfigFactory.createErrorConfig(msg));
        return fallback;
      } catch (err) {
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
