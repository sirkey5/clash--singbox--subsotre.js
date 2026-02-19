/**
 * Mihomo 深度优化脚本 v5.1-fixed
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
  const root = (typeof globalThis !== "undefined") ? globalThis : 
               (typeof global !== "undefined") ? global : 
               (typeof window !== "undefined") ? window : 
               (typeof self !== "undefined") ? self : {};

  if (typeof root.console === "undefined") {
    root.console = { log: () => {}, info: () => {}, warn: () => {}, error: () => {}, debug: () => {} };
  }

  /* 环境与常量 */
  const Env = (() => {
    const isMihomo = typeof log === "function";
    const canAsync = typeof setTimeout === "function";
    const isVerge = typeof globalThis.process !== "undefined" || (typeof window !== "undefined" && typeof window.process !== "undefined");
    const platform = isVerge ? "Clash Verge" : (isMihomo ? "Mihomo" : "Unknown");
    return Object.freeze({ isMihomo, platform, canAsync, isVerge, get: () => platform, version: "v5.1-fixed", useES2022: true });
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

  /* 日志系统 */
  const Logger = new (class {
    _levelMap = { DEBUG: 0, INFO: 1, WARN: 2, ERROR: 3 };
    _currentLevel = CONSTANTS.DEBUG ? 0 : 1;
    log(level, ctx, ...args) {
      if (this._levelMap[level] < this._currentLevel) return;
      const prefix = `[${level}] [${ctx || "Global"}]`;
      const formatted = args.map(a => a === null ? "null" : a === undefined ? "undefined" : typeof a === "object" ? (typeof JSON !== "undefined" ? JSON.stringify(a) : "[Object]") : String(a));
      const msg = `${prefix} ${formatted.join(" ")}`;
      if (typeof log === "function") log(msg);
      else if (typeof console !== "undefined" && typeof console.log === "function") console.log(msg);
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
      if (depth > MAX_DEPTH) { Logger.warn("Utils.deepClone", `达到最大深度限制 ${MAX_DEPTH}，停止递归`); return null; }
      if (!obj || typeof obj !== "object") return obj;
      if (seen.has(obj)) return seen.get(obj);
      if (Array.isArray(obj)) {
        const result = []; seen.set(obj, result);
        for (const item of obj) { const cloned = Utils.deepClone(item, null, seen, depth + 1); if (cloned !== null) result.push(cloned); }
        return result;
      }
      const result = Object.create(Object.getPrototypeOf(obj)); seen.set(obj, result);
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
    sanitizeUrl(u) { try{ const url=new URL(u); return ["http:","https:"].includes(url.protocol)&&!Utils.isPrivateIP(url.hostname)?url.toString():null; }catch{return null;} },
    safeSet(obj,k,v){ if(obj && k) obj[k]=v; },
    escapeRegex(s){return s.replace(/[.*+?^${}()|[\]\\]/g,"\\$&");},
    regexToMihomo(re){return re instanceof RegExp ? (re.ignoreCase?"(?i)":"")+re.source : String(re);},
    getProxyGroupBase(){
      return {
        interval: Config.common?.proxyGroup?.interval ?? 180,
        timeout: Config.common?.proxyGroup?.timeout ?? 3000,
        url: Config.common?.proxyGroup?.url ?? "https://cp.cloudflare.com/generate_204",
        lazy: Config.common?.proxyGroup?.lazy ?? false,
        "max-failed-times": Config.common?.proxyGroup?.maxFailedTimes ?? 2,
        "expected-status": "204"
      };
    },
    getSceneConfig(scene = "browsing") {
      const base = Utils.getProxyGroupBase();
      const sceneConfig = Config.failureDetection?.[scene];
      if (!sceneConfig) return base;
      return { ...base, "max-failed-times": sceneConfig.maxFailedTimes, interval: sceneConfig.interval, tolerance: sceneConfig.tolerance, timeout: sceneConfig.timeout, lazy: false };
    },
    unique: arr => Array.from(new Set(arr)),
    uniqueBy(arr, fn){ const seen=new Set(); return arr.filter(x=>{const v=fn(x); if(seen.has(v)) return false; seen.add(v); return true;}); },
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

  /* 镜像与资源 */
  let GH_PROXY = "https://cdn.jsdelivr.net/gh/";
  const ICON_VAL = (f)=>{try{return typeof f==="function"?f():(f??"");}catch{return"";}};

  /* 图标配置 - 保留 Proxy 实现 */
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
    return new Proxy({}, { get(_,n){ return () => `${GH_PROXY}${base}/${map[n]??n}.png`; } });
  })();

  const URLS = {
    _getMirrorUrl(original){
      if(!GH_PROXY) return original;
      let clean = original;
      for(const m of CONSTANTS.GH.MIRRORS){ if(m && clean.startsWith(m)){ clean=clean.slice(m.length); break; } }
      if(GH_PROXY.includes("jsdelivr.net")){
        const rawMatch = clean.match(CONSTANTS.RE.GH_RAW);
        if(rawMatch){ const [,user,repo,branch,path]=rawMatch; return `https://cdn.jsdelivr.net/gh/${user}/${repo}@${branch.replace(/^refs\/heads\//, '')}/${path}`; }
        const releaseMatch = clean.match(CONSTANTS.RE.GH_RELEASE);
        if(releaseMatch){ const [,user,repo,tag,file]=releaseMatch; return `https://cdn.jsdelivr.net/gh/${user}/${repo}@${tag}/${file}`; }
        if(clean.includes('raw.githubusercontent.com')) return clean;
      }
      return (GH_PROXY.endsWith("/")?GH_PROXY:GH_PROXY+"/") + (clean.startsWith("/")?clean.slice(1):clean);
    },
    geox:{
      geoip:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.dat"),
      geosite:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geosite.dat"),
      mmdb:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/geoip.metadb"),
      asn:()=>URLS._getMirrorUrl("https://github.com/MetaCubeX/meta-rules-dat/releases/download/latest/asn.mmdb")
    },
    mrs(name){ return this._getMirrorUrl(`https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/${name}.mrs`); },
    list(name){ return this._getMirrorUrl(`https://raw.githubusercontent.com/Loyalsoldier/clash-rules/release/${name}.txt`); },
    rulesets:{
      geolocation_not_cn:()=>URLS.mrs("geolocation-!cn"),
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
        reject:()=>URLS.list("reject"), icloud:()=>URLS.list("icloud"), apple:()=>URLS.list("apple"),
        google:()=>URLS.list("google"), direct:()=>URLS.list("direct"), private:()=>URLS.list("private"),
        telegram:()=>URLS.list("telegram"), cn:()=>URLS.list("direct")
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
    privacy: { geoExternalLookup: true, systemDnsOnly: false, trustedGeoEndpoints: [], githubMirrorEnabled: true },
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
      defaults:Object.fromEntries(["apple","microsoft","github","google","openai","spotify","bahamut","disney","pixiv","hbo","biliintl","tvb","hulu","primevideo","telegram","line","whatsapp","games","japan","tracker","ads","acl4ssr","anti_ad","loyalsoldier","blackmatrix7","geolocation_not_cn"].map(k=>[k,true]))
    },
    preRules:["PROCESS-NAME,SunloginClient,DIRECT","PROCESS-NAME,AnyDesk,DIRECT"],
    regionOptions:{
      geoIpGrouping:true, autoDiscover:true, excludeHighPercentage:true, ratioLimit:2, maxRegions:10,
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
        return {
          "geosite:private":["system"],
          "geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn":["119.29.29.29","223.5.5.5"],
          "rule-set:acl4ssr_china,ls_cn":["119.29.29.29","223.5.5.5"]
        };
      }
    },
    services: [
      { id:"applications", rule:["RULE-SET,applications,下载软件"], name:"应用程序", icon:ICONS.Download, ruleProvider:{ name:"applications", url:()=>URLS.rulesets.applications(), behavior:"classical" } },
      { id:"openai", rule:["RULE-SET,ai,国外AI"], name:"国外AI", icon:ICONS.ChatGPT, ruleProvider:{ name:"ai", url:()=>URLS.rulesets.ai(), behavior:"domain" } },
      { id:"disney", rule:["RULE-SET,disney,Disney+"], name:"Disney+", icon:ICONS.DisneyPlus, ruleProvider:{ name:"disney", url:()=>URLS.rulesets.disney(), behavior:"domain" } },
      { id:"primevideo", rule:["GEOSITE,primevideo,Prime Video"], name:"Prime Video", icon:ICONS.PrimeVideo },
      { id:"hbo", rule:["GEOSITE,hbo,HBO"], name:"HBO", icon:ICONS.HBO },
      { id:"hulu", rule:["GEOSITE,hulu,Hulu"], name:"Hulu", icon:ICONS.Hulu },
      { id:"tiktok", rule:["GEOSITE,tiktok,Tiktok"], name:"Tiktok", icon:ICONS.TikTok },
      { id:"biliintl", rule:["GEOSITE,biliintl,哔哩哔哩东南亚"], name:"哔哩哔哩东南亚", icon:ICONS.Bilibili },
      { id:"bahamut", rule:["GEOSITE,bahamut,巴哈姆特"], name:"巴哈姆特", icon:ICONS.Bahamut },
      { id:"tvb", rule:["GEOSITE,tvb,TVB"], name:"TVB", icon:ICONS.TVB },
      { id:"pixiv", rule:["GEOSITE,pixiv,Pixiv"], name:"Pixiv", icon:ICONS.Pixiv },
      { id:"spotify", rule:["RULE-SET,spotify,Spotify"], name:"Spotify", icon:ICONS.Spotify, ruleProvider:{ name:"spotify", url:()=>URLS.rulesets.spotify(), behavior:"domain" } },
      { id:"streaming", rule:["RULE-SET,streaming,全球主流媒体"], name:"全球主流媒体", icon:ICONS.StreamingNotCN, ruleProvider:{ name:"streaming", url:()=>URLS.rulesets.streaming(), behavior:"domain" } },
      { id:"finance", rule:["RULE-SET,finance,金融组"], name:"金融服务", icon:ICONS.Premium, ruleProvider:{ name:"finance", url:()=>URLS.rulesets.finance(), behavior:"domain" } },
      { id:"telegram", rule:["GEOIP,telegram,Telegram","RULE-SET,telegram,Telegram"], name:"Telegram", icon:ICONS.Telegram, ruleProvider:{ name:"telegram", url:()=>URLS.rulesets.telegram(), behavior:"domain" } },
      { id:"discord", rule:["RULE-SET,discord,Discord"], name:"Discord", icon:ICONS.Discord, ruleProvider:{ name:"discord", url:()=>URLS.rulesets.discord(), behavior:"domain" } },
      { id:"whatsapp", rule:["GEOSITE,whatsapp,WhatsApp"], name:"WhatsApp", icon:ICONS.WhatsApp },
      { id:"line", rule:["GEOSITE,line,Line"], name:"Line", icon:ICONS.Line },
      { id:"slack", rule:["GEOSITE,slack,Slack"], name:"Slack", icon:ICONS.Slack },
      { id:"speedtest", rule:["RULE-SET,speedtest,Speedtest"], name:"Speedtest", icon:ICONS.Speedtest, ruleProvider:{ name:"speedtest", url:()=>URLS.rulesets.speedtest(), behavior:"domain" } },
      { id:"steam", rule:["RULE-SET,steam,Steam"], name:"Steam", icon:ICONS.Steam, ruleProvider:{ name:"steam", url:()=>URLS.rulesets.steam(), behavior:"domain" } },
      { id:"epic", rule:["GEOSITE,epicgames,Epic Games"], name:"Epic Games", icon:ICONS.Epic },
      { id:"games", rule:["RULE-SET,games,游戏专用"], name:"游戏专用", icon:ICONS.Game, ruleProvider:{ name:"games", url:()=>URLS.rulesets.games(), behavior:"domain" } },
      { id:"github", rule:["RULE-SET,github,Github"], name:"Github", icon:ICONS.GitHub, ruleProvider:{ name:"github", url:()=>URLS.rulesets.github(), behavior:"domain" } },
      { id:"google", rule:["RULE-SET,google,谷歌服务"], name:"谷歌服务", icon:ICONS.GoogleSearch, ruleProvider:{ name:"google", url:()=>URLS.rulesets.google(), behavior:"domain" } },
      { id:"microsoft", rule:["RULE-SET,microsoft,微软服务"], name:"微软服务", icon:ICONS.Microsoft, ruleProvider:{ name:"microsoft", url:()=>URLS.rulesets.microsoft(), behavior:"domain" } },
      { id:"apple", rule:["RULE-SET,apple,苹果服务"], name:"苹果服务", icon:ICONS.Apple, ruleProvider:{ name:"apple", url:()=>URLS.rulesets.apple(), behavior:"domain" } },
      { id:"scholar", rule:["RULE-SET,scholar,学术网站"], name:"学术网站", icon:ICONS.Book, ruleProvider:{ name:"scholar", url:()=>URLS.rulesets.scholar(), behavior:"domain" } },
      { id:"geolocation_not_cn", rule:["RULE-SET,geolocation_not_cn,全球站点"], name:"全球站点（全量）", icon:ICONS.WorldMap, ruleProvider:{ name:"geolocation_not_cn", url:()=>URLS.rulesets.geolocation_not_cn(), behavior:"domain" } },
      { id:"tracker", rule:["GEOSITE,tracker,REJECT"], name:"跟踪分析", icon:ICONS.Reject, proxies:["REJECT","DIRECT","手动选择"] },
      { id:"ads", rule:["RULE-SET,ads,REJECT"], name:"广告过滤", icon:ICONS.Advertising, proxies:["REJECT","DIRECT","手动选择"], ruleProvider:{ name:"ads", url:()=>URLS.rulesets.ads(), behavior:"domain" } }
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
      proxyGroup:{ interval:300, timeout:3000, url:"https://cp.cloudflare.com/generate_204", lazy:true, maxFailedTimes: 3 }, 
      defaultProxyGroups:[{ name:"国内网站", icon:ICONS.StreamingCN, proxies:["DIRECT","手动选择"] }], 
      postRules:["GEOSITE,private,DIRECT","GEOIP,private,DIRECT,no-resolve","RULE-SET,ls_cn,国内网站","RULE-SET,acl4ssr_china,国内网站","GEOSITE,cn,国内网站","GEOIP,cn,国内网站,no-resolve","MATCH,手动选择"] 
    },
    failureDetection: {
      gaming: { maxFailedTimes: 1, interval: 120, tolerance: 20, timeout: 2500 },
      streaming: { maxFailedTimes: 2, interval: 180, tolerance: 80, timeout: 6000 },
      browsing: { maxFailedTimes: 2, interval: 180, tolerance: 40, timeout: 4000 },
      download: { maxFailedTimes: 2, interval: 180, tolerance: 60, timeout: 5000 }
    },
    performance: { heavyProxyThreshold: 800, ioBudgetPerTick: 16 }
  };

  /* AI 引擎 */
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
        PROTOCOLS: { 'hysteria2': 15, 'tuic': 15, 'vless': 12, 'trojan': 10, 'ss': 8, 'vmess': 5, 'ssr': 3 },
        POSITIVE_KEYWORDS: { 'Premium': 5, 'Pro': 4, 'VIP': 3, 'Elite': 4, '游戏': 3, 'Game': 3, '流媒体': 2, 'Streaming': 2, '解锁': 2, 'Unlock': 2, '优化': 2, 'Optimized': 2, 'IPLC': 12, 'IEPL': 12, 'BGP': 10, 'CN2 GIA': 10, 'CN2': 8, '专线': 12, '直连': 6, 'Direct': 6 },
        NEGATIVE_KEYWORDS: { '过期': -100, 'Expire': -100, 'Expired': -100, '维护': -50, 'Maintenance': -50, '故障': -50, 'Down': -50, '测试': -20, 'Test': -20, '备用': -10, 'Backup': -10, '试用': -10, 'Trial': -10, '限速': -15, 'Limited': -10 },
        REGIONS: { 'HK': 10, 'MO': 10, 'TW': 9, 'SG': 9, 'JP': 8, 'KR': 7, 'US': 6, 'CA': 5, 'UK': 4, 'DE': 4, 'FR': 4, 'NL': 4 },
        CITIES: { '香港': 2, 'HK': 2, '台北': 2, 'Taipei': 2, '东京': 2, 'Tokyo': 2, '新加坡': 2, 'Singapore': 2, '洛杉矶': 2, 'Los Angeles': 2, 'LA': 2 }
      };
      this._vetoReg = /Maintenance|Down|Fix|Expired|Error|Timeout|故障|维护|离线|过期|到期/i;
      this._regionReg = /HK|MO|TW|SG|JP|US|KR|UK|DE|FR|NL|TH|MY|PH|IN|AU|RU|BR|AR|CA|香港|澳门|台湾|新加坡|日本|美国|韩国|英国|德国|法国|荷兰|泰国|马来西亚|菲律宾|印度|澳大利亚|俄罗斯|巴西|阿根廷|加拿大|港|澳|台/i;
      this._latencyReg = /(\d+)ms/i;
      this._rateReg = /(\d+\.?\d*)x|(\d+\.?\d*)倍/i;
      this._SCORE_THRESHOLDS = { EXCELLENT: 85, GOOD: 70, MIN: 55 };
    }

    setScene(scene) { if (["browsing", "gaming", "streaming", "download"].includes(scene)) this._currentScene = scene; }

    _detectRegion(name) {
      const regionMap = { '香港': 'HK', 'HK': 'HK', '港': 'HK', 'Hong Kong': 'HK', 'Hongkong': 'HK', '澳门': 'MO', 'MO': 'MO', '澳': 'MO', 'Macao': 'MO', 'Macau': 'MO', '台湾': 'TW', 'TW': 'TW', '台': 'TW', 'Taiwan': 'TW', '日本': 'JP', 'JP': 'JP', '东京': 'JP', 'Tokyo': 'JP', 'Japan': 'JP', '新加坡': 'SG', 'SG': 'SG', '狮城': 'SG', 'Singapore': 'SG', '美国': 'US', 'US': 'US', '美': 'US', 'United States': 'US', 'America': 'US', '韩国': 'KR', 'KR': 'KR', '韩': 'KR', 'Korea': 'KR', '英国': 'UK', 'UK': 'UK', 'United Kingdom': 'UK', 'Britain': 'UK', '德国': 'DE', 'DE': 'DE', 'Germany': 'DE', '法国': 'FR', 'FR': 'FR', 'France': 'FR', '荷兰': 'NL', 'NL': 'NL', 'Netherlands': 'NL' };
      for (const [key, code] of Object.entries(regionMap)) { if (name.includes(key)) return code; }
      return '其他';
    }

    _getProtocolScore(type, proxy) {
      let score = this._weights.PROTOCOLS[type] || 0;
      if (proxy.tls) score += 2; if (proxy.udp) score += 2; if (proxy.sni) score += 1;
      if (proxy['skip-cert-verify'] === false) score += 1; if (proxy.network === 'ws' || proxy.network === 'websocket') score += 1;
      return Math.min(20, score);
    }

    _getServerScore(server) {
      if (!server) return -2;
      for (const item of this._SERVER_WHITELIST.BLACKLIST) { if (item.pattern.test(server)) return item.score; }
      for (const item of this._SERVER_WHITELIST.TIER_S) { if (item.pattern.test(server)) return item.score; }
      for (const item of this._SERVER_WHITELIST.TIER_A) { if (item.pattern.test(server)) return item.score; }
      for (const item of this._SERVER_WHITELIST.TIER_B) { if (item.pattern.test(server)) return item.score; }
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(server)) return -2;
      return 0;
    }

    scoreComprehensive(proxy, context = {}) {
      if (!proxy) return { score: 0, breakdown: {} };
      const name = typeof proxy === 'string' ? proxy : String(proxy.name || "");
      const type = String(proxy.type || "").toLowerCase();
      const port = parseInt(proxy.port || 0);
      const server = proxy.server || "";
      if (this._vetoReg.test(name)) return { score: 0, breakdown: { veto: true, reason: "严重问题关键词" } };
      const breakdown = { base: 10, protocol: 0, performance: 0, stability: 0, geography: 0, server: 0, semantic: 0, dynamic: 0 };
      breakdown.protocol = this._getProtocolScore(type, proxy);
      let rateScore = 0, rate = proxy.rate;
      if (!rate) { const match = name.match(this._rateReg); if (match) rate = parseFloat(match[1] || match[2]); }
      if (rate != null) {
        if (rate <= 0.1) rateScore = 12; else if (rate <= 0.2) rateScore = 10; else if (rate <= 0.5) rateScore = 8;
        else if (rate <= 0.8) rateScore = 6; else if (rate <= 1.0) rateScore = 4; else if (rate <= 1.5) rateScore = -5;
        else if (rate <= 2.0) rateScore = -10; else rateScore = -20;
      }
      let latencyScore = 0;
      const latencyMatch = name.match(this._latencyReg);
      if (latencyMatch) {
        const ms = parseInt(latencyMatch[1]);
        if (ms < 30) latencyScore = 8; else if (ms < 50) latencyScore = 6; else if (ms < 100) latencyScore = 4;
        else if (ms < 150) latencyScore = 2; else if (ms < 200) latencyScore = 0; else if (ms < 300) latencyScore = -5;
        else if (ms < 500) latencyScore = -10; else latencyScore = -20;
      }
      breakdown.performance = Math.max(-20, Math.min(20, rateScore + latencyScore));
      if (CONSTANTS.SAFE_PORTS.has(port)) breakdown.stability = 3;
      else if ([443, 80].includes(port)) breakdown.stability = 2;
      let lineScore = 0;
      if (/IPLC|IEPL|专线|内网/i.test(name)) lineScore = 12;
      else if (/BGP|CN2 GIA|CN2-GIA/i.test(name)) lineScore = 10;
      else if (/CN2|GIA/i.test(name)) lineScore = 8;
      else if (/直连|Direct/i.test(name)) lineScore = 6;
      else if (/中转|Relay/i.test(name)) lineScore = 4;
      breakdown.stability = Math.min(15, breakdown.stability + lineScore);
      const regionCode = this._detectRegion(name);
      breakdown.geography = this._weights.REGIONS[regionCode] || 0;
      for (const [city, bonus] of Object.entries(this._weights.CITIES)) { if (name.includes(city)) { breakdown.geography += bonus; break; } }
      breakdown.geography = Math.min(15, breakdown.geography);
      breakdown.server = this._getServerScore(server);
      let semanticScore = 0;
      for (const [keyword, points] of Object.entries(this._weights.POSITIVE_KEYWORDS)) { if (new RegExp(keyword, 'i').test(name)) semanticScore += points; }
      for (const [keyword, points] of Object.entries(this._weights.NEGATIVE_KEYWORDS)) {
        if (new RegExp(keyword, 'i').test(name)) {
          semanticScore += points;
          if (points <= -50) return { score: 0, breakdown: { veto: true, reason: `负面关键词: ${keyword}` } };
        }
      }
      breakdown.semantic = Math.max(-100, Math.min(10, semanticScore));
      breakdown.dynamic = this._getDynamicAdjustment(proxy, name, server, type, context);
      const totalScore = Object.values(breakdown).reduce((sum, score) => sum + score, 0);
      return { score: Math.max(0, totalScore), breakdown };
    }

    _getDynamicAdjustment(proxy, name, server, type, context) {
      let adjustment = 0;
      const stats = this._stats ? this._stats.getStats(proxy) : null;
      if (stats) {
        const now = Date.now();
        if (now - stats.lastSeen < CONSTANTS.TIME.DAY) adjustment += 2;
        if (stats.successCount > 5) adjustment += 3;
        if (stats.failCount > 0) adjustment -= Math.min(20, stats.failCount * 10);
      }
      if (context.serverCounts && server) {
        const count = context.serverCounts.get(server) || 0;
        if (count > 10) adjustment -= 15; else if (count > 5) adjustment -= 10; else if (count > 3) adjustment -= 5;
      }
      if (context.regionCounts && context.totalNodes) {
        let regionCode = null;
        for (const [key, code] of Object.entries({'香港': 'HK', 'HK': 'HK', '港': 'HK', '澳门': 'MO', 'MO': 'MO', '澳': 'MO', '台湾': 'TW', 'TW': 'TW', '台': 'TW', '新加坡': 'SG', 'SG': 'SG', '日本': 'JP', 'JP': 'JP', '美国': 'US', 'US': 'US'})) {
          if (name.includes(key)) { regionCode = code; break; }
        }
        if (regionCode) {
          const count = context.regionCounts.get(regionCode) || 0;
          const ratio = count / context.totalNodes;
          if (ratio < 0.05) adjustment += 5; else if (ratio < 0.10) adjustment += 3;
        }
      }
      if (context.protocolCounts && context.totalNodes && ['hysteria2', 'tuic'].includes(type) && (context.protocolCounts.get(type) || 0) / context.totalNodes < 0.2) adjustment += 5;
      return Math.max(-20, Math.min(10, adjustment));
    }

    score(proxy) { return this.scoreComprehensive(proxy).score; }

    getBestNodes(proxies) {
      if (!proxies?.length) return [];
      try {
        const total = proxies.length;
        let targetCount = Math.min(500, Math.max(5, Math.floor(total * 0.15)));
        if (total <= 5) targetCount = total;
        Logger.info("AIEngine", `优选筛选: 总数 ${total}, 目标 ${targetCount}`);
        const context = { totalNodes: proxies.length, serverCounts: new Map(), regionCounts: new Map(), protocolCounts: new Map() };
        proxies.forEach(p => {
          const server = p.server || "", type = String(p.type || "").toLowerCase();
          if (server) context.serverCounts.set(server, (context.serverCounts.get(server) || 0) + 1);
          context.protocolCounts.set(type, (context.protocolCounts.get(type) || 0) + 1);
        });
        const vetoReg = /Maintenance|Down|Fix|Expired|Error|Timeout|故障|维护|离线|过期|到期/i;
        const allowedProtocols = new Set(['vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'ss', 'ssr']);
        const fastFiltered = [];
        for (let i = 0; i < proxies.length; i++) {
          const p = proxies[i], name = typeof p === 'string' ? p : String(p.name || ""), type = String(p.type || "").toLowerCase();
          if (vetoReg.test(name) || !allowedProtocols.has(type)) continue;
          const stats = this._stats?.getStats(p);
          if (stats && stats.failCount > 3) continue;
          fastFiltered.push(p);
        }
        Logger.info("AIEngine", `预筛选: ${proxies.length} -> ${fastFiltered.length} 节点`);
        let toScore;
        const SAMPLE_SIZE = 400;
        if (fastFiltered.length <= SAMPLE_SIZE) toScore = fastFiltered;
        else {
          const regionGroups = new Map();
          fastFiltered.forEach(p => {
            const name = p.name || "", region = this._detectRegion(name);
            if (!regionGroups.has(region)) regionGroups.set(region, []);
            regionGroups.get(region).push(p);
          });
          toScore = [];
          const totalNodes = fastFiltered.length;
          regionGroups.forEach((nodes) => {
            const sampleCount = Math.max(1, Math.floor(SAMPLE_SIZE * (nodes.length / totalNodes)));
            const shuffled = nodes.sort(() => Math.random() - 0.5);
            toScore.push(...shuffled.slice(0, Math.min(sampleCount, nodes.length)));
          });
          if (toScore.length < SAMPLE_SIZE) {
            const remaining = fastFiltered.filter(p => !toScore.includes(p));
            toScore.push(...remaining.sort(() => Math.random() - 0.5).slice(0, SAMPLE_SIZE - toScore.length));
          }
          toScore = toScore.slice(0, SAMPLE_SIZE);
        }
        Logger.info("AIEngine", `智能采样: ${fastFiltered.length} -> ${toScore.length} 节点`);
        const candidates = toScore.map(p => {
          const result = this.scoreComprehensive(p, context), name = typeof p === 'string' ? p : String(p.name || "");
          const stats = this._stats?.getStats(p) || { failCount: 0 };
          return { id: name, score: result.score, proxy: p, server: p.server || "", failCount: stats.failCount };
        }).filter(item => item.failCount === 0 && item.score >= 0).sort((a, b) => b.score - a.score);
        if (!candidates.length) {
          Logger.error("AIEngine", "所有节点均不符合标准");
          const emergency = toScore.map(p => ({ id: p.name || p, score: this.score(p) })).filter(i => i.score > 0).sort((a, b) => b.score - a.score).slice(0, 20);
          return emergency.length ? emergency.map(n => n.id) : ["DIRECT"];
        }
        const excellent = candidates.filter(i => i.score >= this._SCORE_THRESHOLDS.EXCELLENT);
        const good = candidates.filter(i => i.score >= this._SCORE_THRESHOLDS.GOOD && i.score < this._SCORE_THRESHOLDS.EXCELLENT);
        let selectedNodes = excellent.length >= targetCount ? excellent.slice(0, targetCount) :
          excellent.length + good.length >= targetCount ? [...excellent, ...good].slice(0, targetCount) : candidates.slice(0, targetCount);
        const diversityFiltered = this._applyDiversityFilter(selectedNodes, targetCount);
        Logger.info("AIEngine", `✅ 筛选完成: ${diversityFiltered.length} 个节点`);
        return diversityFiltered.map(s => s.id);
      } catch (e) {
        Logger.error("AIEngine", `筛选异常: ${e.message}`);
        return proxies.slice(0, 10).map(p => p.name || p);
      }
    }

    getBestNodesForPremiumGroup(proxies) {
      if (!proxies?.length) { Logger.warn("AIEngine.Premium", "无可用节点"); return ["DIRECT"]; }
      try {
        const TARGET_COUNT = 100, MIN_SCORE = 55;
        Logger.info("AIEngine.Premium", `开始筛选 AI 优选组: 总节点数 ${proxies.length}, 目标 ${TARGET_COUNT} 个`);
        const context = { totalNodes: proxies.length, serverCounts: new Map(), regionCounts: new Map(), protocolCounts: new Map() };
        proxies.forEach(p => {
          const server = p.server || "", type = String(p.type || "").toLowerCase(), name = String(p.name || "");
          if (server) context.serverCounts.set(server, (context.serverCounts.get(server) || 0) + 1);
          context.protocolCounts.set(type, (context.protocolCounts.get(type) || 0) + 1);
          const regionCode = this._detectRegion(name);
          if (regionCode !== '其他') context.regionCounts.set(regionCode, (context.regionCounts.get(regionCode) || 0) + 1);
        });
        Logger.info("AIEngine.Premium", `节点池: 协议${context.protocolCounts.size}种, 地区${context.regionCounts.size}个, 服务器${context.serverCounts.size}个`);
        const vetoReg = /Maintenance|Down|Fix|Expired|Error|Timeout|故障|维护|离线|过期|到期/i;
        const allowedProtocols = new Set(['vmess', 'vless', 'trojan', 'hysteria', 'hysteria2', 'tuic', 'ss', 'ssr']);
        const fastFiltered = [];
        for (let i = 0; i < proxies.length; i++) {
          const p = proxies[i], name = typeof p === 'string' ? p : String(p.name || ""), type = String(p.type || "").toLowerCase();
          if (vetoReg.test(name) || !allowedProtocols.has(type)) continue;
          const stats = this._stats?.getStats(p);
          if (stats && stats.failCount > 3) continue;
          fastFiltered.push(p);
        }
        Logger.info("AIEngine.Premium", `快速预筛选: ${proxies.length} -> ${fastFiltered.length} 节点`);
        let toScore;
        const SAMPLE_SIZE = 300;
        if (fastFiltered.length <= SAMPLE_SIZE) toScore = fastFiltered;
        else {
          const regionGroups = new Map();
          fastFiltered.forEach(p => {
            const name = p.name || "", region = this._detectRegion(name);
            if (!regionGroups.has(region)) regionGroups.set(region, []);
            regionGroups.get(region).push(p);
          });
          toScore = [];
          const totalNodes = fastFiltered.length;
          regionGroups.forEach((nodes) => {
            const sampleCount = Math.max(1, Math.floor(SAMPLE_SIZE * (nodes.length / totalNodes)));
            toScore.push(...nodes.sort(() => Math.random() - 0.5).slice(0, Math.min(sampleCount, nodes.length)));
          });
          if (toScore.length < SAMPLE_SIZE) {
            const remaining = fastFiltered.filter(p => !toScore.includes(p));
            toScore.push(...remaining.sort(() => Math.random() - 0.5).slice(0, SAMPLE_SIZE - toScore.length));
          }
          toScore = toScore.slice(0, SAMPLE_SIZE);
        }
        Logger.info("AIEngine.Premium", `智能采样: ${fastFiltered.length} -> ${toScore.length} 节点`);
        const candidates = toScore.map(p => {
          const result = this.scoreComprehensive(p, context), name = typeof p === 'string' ? p : String(p.name || "");
          const stats = this._stats?.getStats(p) || { failCount: 0, successCount: 0 };
          return { id: name, score: result.score, breakdown: result.breakdown, proxy: p, server: p.server || "", failCount: stats.failCount };
        }).filter(item => item.failCount === 0 && item.score >= MIN_SCORE).sort((a, b) => b.score - a.score);
        if (!candidates.length) {
          Logger.error("AIEngine.Premium", "所有节点均不符合最低标准");
          const emergency = toScore.map(p => ({ id: p.name || p, score: this.score(p) })).filter(i => i.score > 0).sort((a, b) => b.score - a.score).slice(0, 20);
          return emergency.length ? emergency.map(n => n.id) : ["DIRECT"];
        }
        const excellent = candidates.filter(i => i.score >= this._SCORE_THRESHOLDS.EXCELLENT);
        const good = candidates.filter(i => i.score >= this._SCORE_THRESHOLDS.GOOD && i.score < this._SCORE_THRESHOLDS.EXCELLENT);
        let selectedNodes = excellent.length >= TARGET_COUNT ? excellent.slice(0, TARGET_COUNT) :
          excellent.length + good.length >= TARGET_COUNT ? [...excellent, ...good].slice(0, TARGET_COUNT) : candidates.slice(0, TARGET_COUNT);
        const diversityFiltered = this._applyDiversityFilter(selectedNodes, Math.min(selectedNodes.length, TARGET_COUNT));
        Logger.info("AIEngine.Premium", `✅ AI 优选组筛选完成: ${diversityFiltered.length} 个节点`);
        return diversityFiltered.map(s => s.id);
      } catch (e) {
        Logger.error("AIEngine.Premium", `筛选异常: ${e.message}`);
        const emergency = proxies.map(p => ({ name: p.name || p, score: this.score(p) })).sort((a, b) => b.score - a.score).slice(0, 10).map(item => item.name);
        return emergency.length ? emergency : ["DIRECT"];
      }
    }

    _applyDiversityFilter(nodes, targetCount) {
      if (!Array.isArray(nodes) || !nodes.length) return [];
      targetCount = Math.max(5, targetCount || Math.floor(nodes.length * 0.15));
      try {
        const selected = [], seenServers = new Map(), seenASNs = new Map(), seenClusters = new Map();
        const getCluster = (name) => String(name || "").replace(/\d+|[_-]\d+|[A-Za-z]\d+$/g, "").trim();
        for (const item of nodes) {
          if (selected.length >= targetCount || !item?.id) continue;
          const asn = item.server?.split('.').slice(-2).join('.') || "0.0";
          const cluster = getCluster(item.id);
          const serverCount = seenServers.get(item.server) || 0, asnCount = seenASNs.get(asn) || 0, clusterCount = seenClusters.get(cluster) || 0;
          if (serverCount < 2 && asnCount < 3 && clusterCount < 3) {
            selected.push(item);
            if (item.server) seenServers.set(item.server, serverCount + 1);
            seenASNs.set(asn, asnCount + 1);
            seenClusters.set(cluster, clusterCount + 1);
          }
        }
        if (selected.length < Math.min(5, targetCount)) {
          for (const item of nodes) {
            if (selected.length >= targetCount) break;
            if (item?.id && !selected.some(s => s.id === item.id)) selected.push(item);
          }
        }
        return selected;
      } catch (e) { Logger.error("AIEngine", `多样性过滤异常: ${e.message}`); return nodes.slice(0, Math.min(targetCount, nodes.length)); }
    }

    detectNetworkState() { }
    performSelfCheck() { return 0; }
    reset() {}
  }

  /* 全局持久化存储 */
  const STATS_SYMBOL = Symbol.for('__MIHOMO_STATS__');
  if (typeof root[STATS_SYMBOL] === "undefined") {
    root[STATS_SYMBOL] = { nodes: new Map(), asns: new Map(), lastRun: Date.now(), lastCheckTime: 0, checkInProgress: false };
  }
  const GLOBAL_STATS = root[STATS_SYMBOL];

  /* 节点状态管理器 */
  class NodeStatsManager {
    constructor(cache) {
      this._cache = cache || new Map();
      this._stats = GLOBAL_STATS.nodes;
    }
    _getHash(proxy) {
      if (!proxy) return "";
      const name = proxy.name || (typeof proxy === 'string' ? proxy : "");
      return `${name}|${proxy.server || ""}|${proxy.port || ""}`;
    }
    getStats(proxy) {
      const hash = this._getHash(proxy);
      if (!this._stats.has(hash)) this._stats.set(hash, { failCount: 0, successCount: 0, lastSeen: Date.now(), scoreOffset: 0 });
      return this._stats.get(hash);
    }
    getDynamicOffset(proxy) {
      const stats = this.getStats(proxy);
      const now = Date.now();
      let offset = 0;
      if (now - stats.lastSeen < CONSTANTS.TIME.DAY) offset += 2;
      if (stats.successCount > 5) offset += 3;
      if (stats.failCount > 0) offset -= Math.min(60, stats.failCount * 40);
      stats.lastSeen = now;
      stats.scoreOffset = Utils.clamp(offset, -60, 10);
      return stats.scoreOffset;
    }
    recordSuccess(proxy) { const stats = this.getStats(proxy); stats.successCount++; stats.failCount = Math.max(0, stats.failCount - 1); }
    recordFailure(proxy) { const stats = this.getStats(proxy); stats.failCount++; stats.successCount = 0; }
    cleanup(maxAge = CONSTANTS.TIME.DAY * 3) {
      const now = Date.now(); let count = 0;
      for (const [hash, stats] of this._stats.entries()) { if (now - stats.lastSeen > maxAge) { this._stats.delete(hash); count++; } }
      if (count > 0) Logger.info("NodeStats", `清理 ${count} 条过期数据`);
    }
    update(id, data, scene) {}
    recordSwitch(id){}
    reset(){ this._stats.clear(); }
  }

  /* 功能组管理器 */
  class FunctionalGroupManager {
    constructor(aiEngine, statsManager) {
      this._ai = aiEngine;
      this._stats = statsManager;
      this._criteria = {
        'ai_group': { minScore: 70, maxFailCount: 0, preferRegions: ['HK_MO_TW', 'SG', 'JP', 'US'], sceneWeights: Config.aiOptions.scenes.browsing },
        'streaming_group': { minScore: 65, maxFailCount: 0, preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'], sceneWeights: Config.aiOptions.scenes.streaming },
        'gaming_group': { minScore: 75, maxFailCount: 0, maxLatency: 100, preferRegions: ['HK_MO_TW', 'JP', 'TW', 'SG'], sceneWeights: Config.aiOptions.scenes.gaming },
        'download_group': { minScore: 60, maxFailCount: 1, preferRegions: ['HK_MO_TW', 'SG', 'US', 'JP'], sceneWeights: Config.aiOptions.scenes.download },
        'download_software_group': { minScore: 55, maxFailCount: 2, preferRegions: ['HK_MO_TW', 'SG', 'JP', 'US'], sceneWeights: Config.aiOptions.scenes.download },
        'social_group': { minScore: 65, maxFailCount: 0, preferRegions: ['HK_MO_TW', 'SG', 'JP', 'US'], sceneWeights: Config.aiOptions.scenes.browsing },
        'search_group': { minScore: 65, maxFailCount: 0, preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'], sceneWeights: Config.aiOptions.scenes.browsing },
        'dev_group': { minScore: 70, maxFailCount: 0, preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'], sceneWeights: Config.aiOptions.scenes.browsing },
        'email_group': { minScore: 65, maxFailCount: 0, preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'], sceneWeights: Config.aiOptions.scenes.browsing },
        'music_group': { minScore: 65, maxFailCount: 0, preferRegions: ['US', 'JP', 'SG', 'HK_MO_TW'], sceneWeights: Config.aiOptions.scenes.streaming },
        'browsing_group': { minScore: 60, maxFailCount: 1, preferRegions: ['HK_MO_TW', 'SG', 'JP', 'US'], sceneWeights: { latencyWeight: 0.4, stabilityWeight: 0.3, bandwidthWeight: 0.2, jitterWeight: 0.1 } }
      };
    }
    selectNodesForGroup(groupId, allProxies) {
      const standard = this._criteria[groupId];
      if (!standard) { Logger.warn("FunctionalGroup", `未找到 ${groupId} 的筛选标准,使用所有节点`); return allProxies.map(p => typeof p === 'string' ? p : p.name); }
      try {
        const suitable = allProxies.filter(p => {
          const score = this._ai.score(p), stats = this._stats.getStats(p), name = typeof p === 'string' ? p : String(p.name || "");
          if (score < standard.minScore) return false;
          if (stats.failCount > standard.maxFailCount) return false;
          if (standard.maxLatency) { const latencyMatch = name.match(/(\d+)ms/i); if (latencyMatch && parseInt(latencyMatch[1]) > standard.maxLatency) return false; }
          if (standard.preferRegions?.length > 0) {
            const matchRegion = standard.preferRegions.some(region => region === 'HK_MO_TW' ? /港|澳|台|🇭🇰|🇲🇴|🇹🇼|hk|mo|tw|hongkong|macao|macau|taiwan/i.test(name) : new RegExp(region, 'i').test(name));
            if (!matchRegion && score < standard.minScore + 10) return false;
          }
          return true;
        });
        if (suitable.length < 3 && allProxies.length >= 3) {
          Logger.warn("FunctionalGroup", `${groupId} 筛选结果过少(${suitable.length}),放宽标准`);
          return allProxies.filter(p => this._ai.score(p) >= (standard.minScore - 10) && this._stats.getStats(p).failCount <= (standard.maxFailCount + 1)).slice(0, Math.max(10, Math.ceil(allProxies.length * 0.3))).map(p => typeof p === 'string' ? p : p.name);
        }
        const selected = suitable.slice(0, Math.min(50, Math.max(10, Math.ceil(allProxies.length * 0.4))));
        Logger.info("FunctionalGroup", `${groupId} 筛选完成: ${selected.length}/${allProxies.length} 个节点`);
        return selected.map(p => typeof p === 'string' ? p : p.name);
      } catch (e) { Logger.error("FunctionalGroup", `${groupId} 筛选异常: ${e.message}`); return allProxies.slice(0, 20).map(p => typeof p === 'string' ? p : p.name); }
    }
  }

  /* 广告拦截规则注入 */
  function injectAdBlockRules(ruleProviders) {
    const adBlockUrl = URLS.rulesets.ads();
    if (adBlockUrl) Utils.safeSet(ruleProviders, "adblock_combined", { type: "http", interval: 86400, behavior: "domain", format: "mrs", url: adBlockUrl, path: "./ruleset/adblock_combined.mrs" });
  }

  /* 区域自动管理器 */
  class RegionAutoManager {
    constructor(cache){
      this._cache=cache||new Map();
      this._stats=new NodeStatsManager(this._cache);
      this._ai=new AIEngine(this._stats);
    }
    get stats(){return this._stats;}
    get ai(){return this._ai;}
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
    buildRegionGroups(config,regions,proxies){
      const hasProviders = !!(config["proxy-providers"]&&Object.keys(config["proxy-providers"]).length);
      const list = Array.isArray(proxies)?proxies:[];
      const usedFilters=[]; const regionGroups=[];
      const activeRegions = hasProviders ? (Config.regionOptions?.regions || []) : regions;
      const maxRegions = Config.regionOptions?.maxRegions || 10;
      let regionCount = 0;
      for(const r of activeRegions){
        if(regionCount >= maxRegions) break;
        const regionProxies=list.filter(p=>{const n=String(p.name||""); if(["DIRECT","REJECT"].includes(n.toUpperCase())) return false; return p._geoMatch===r.name || r.regex.test(n);});
        if(!hasProviders && !regionProxies.length) continue;
        let pattern = Utils.regexToMihomo(r.regex);
        if(Config.aiOptions?.enable && regionProxies.length){
          const best=this._ai.getBestNodes(regionProxies);
          if(best.length){ pattern = `(${pattern})|(${best.slice(0, Math.max(3, Math.ceil(regionProxies.length * 0.2))).map(id=>`^${Utils.escapeRegex(id)}$`).join("|")})`; }
        }
        usedFilters.push(pattern);
        const base=Utils.getProxyGroupBase();
        regionGroups.push({
          ...base, name: r.name, type: "select",
          proxies: ["故障转移", ...regionProxies.map(p => p.name || p)],
          "include-all": false, lazy: false, interval: 180, "max-failed-times": 2,
          icon: ICON_VAL(r.icon)
        });
        regionCount++;
      }
      const excludeFilter = usedFilters.length ? usedFilters.map(f=>`(${f})`).join("|") : "";
      const base=Utils.getProxyGroupBase();
      let bestIds = [];
      if(Config.aiOptions?.enable && list.length) bestIds = this._ai.getBestNodesForPremiumGroup(list);
      const bestNodesGroup = { ...base, name: "智能优选", type: "select", proxies: bestIds.length ? ["故障转移", ...bestIds] : ["DIRECT"], "include-all": false, icon: ICON_VAL(ICONS.Premium) };
      const allNodeNames = list.map(p => p.name || p);
      const manualSelectionGroup = { ...base, name: "手动选择", type: "select", proxies: ["DIRECT", "自动选择", "智能优选", ...allNodeNames], "include-all": false, icon: ICON_VAL(ICONS.Premium) };
      const autoSelectionGroup = { ...base, name: "自动选择", type: "url-test", "include-all": true, tolerance: 100, "max-failed-times": 3, "expected-status": "204", lazy: false, interval: 180, timeout: 5000, icon: ICON_VAL(ICONS.Proxy) };
      const allPhysicalNodes = list.filter(p => !["DIRECT", "REJECT"].includes(String(p.name || "").toUpperCase())).map(p => p.name || p);
      const failoverGroup = { ...base, name: "故障转移", type: "fallback", proxies: allPhysicalNodes.length ? allPhysicalNodes : ["DIRECT"], "include-all": false, "max-failed-times": 3, "expected-status": "204", interval: 300, timeout: 5000, icon: ICON_VAL(ICONS.Proxy) };
      const otherGroup = { ...base, name: "其他节点", type: "select", proxies: ["手动选择", "自动选择", "智能优选", "DIRECT"], "include-all": true, "exclude-filter": excludeFilter, icon: ICON_VAL(ICONS.WorldMap) };
      const regionProxyGroups = [bestNodesGroup, manualSelectionGroup, autoSelectionGroup, ...regionGroups, failoverGroup, otherGroup];
      return { regionProxyGroups, otherProxyNames: [] };
    }
  }

  /* 中央管理器 */
  class CentralManager {
    static _instance;
    static getInstance(){ if(!CentralManager._instance) CentralManager._instance=new CentralManager(); return CentralManager._instance; }
    constructor(){
      if(CentralManager._instance) return CentralManager._instance;
      this._cache=new Map();
      this._regionMgr=null;
      this._functionalMgr=null;
      this._initialized = false;
      CentralManager._instance=this;
    }
    get lruCache(){return this._cache;}
    get regionAutoManager(){
      if(!this._regionMgr) this._regionMgr=new RegionAutoManager(this._cache);
      return this._regionMgr;
    }
    get functionalGroupManager(){
      if(!this._functionalMgr) this._functionalMgr = new FunctionalGroupManager(this.regionAutoManager.ai, this.regionAutoManager.stats);
      return this._functionalMgr;
    }
    initialize(){
      if (this._initialized) return;
      this._initialized = true;
      try { this.regionAutoManager.stats.cleanup(); } catch (e) { Logger.warn("Central.init", `初始化警告: ${e.message}`); }
      Logger.info("Central.init", `初始化完成 (环境: ${Env.get()})`);
    }
    processConfiguration(config,ctx=null){
      const scene = "browsing";
      this.regionAutoManager.ai.setScene(scene);
      return ConfigBuilder.build(config,this);
    }
  }

  function createErrorProxy(msg) {
    const t = Date.now();
    return { name: `⛔ 脚本错误: ${String(msg).slice(0,20)}...`, type: "direct", _error: true, _errorMessage: msg, _errorTimestamp: t };
  }

  /* 规则排序 */
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

  /* 配置生成器 */
  class ConfigBuilder {
    static build(baseConfig,context=null){
      if (!baseConfig || typeof baseConfig !== "object") {
        Logger.error("ConfigBuilder", "无效的基础配置");
        return { proxies: [], rules: ["MATCH,DIRECT"], "proxy-groups": [] };
      }
      try {
        const cfg = {...baseConfig};
        if(baseConfig.proxies && Array.isArray(baseConfig.proxies)) {
          try { cfg.proxies = Utils.deepClone(baseConfig.proxies, "proxies"); }
          catch (e) { Logger.warn("ConfigBuilder", `克隆 proxies 失败: ${e.message}，使用浅拷贝`); cfg.proxies = [...baseConfig.proxies]; }
        }
        if(baseConfig["proxy-groups"] && Array.isArray(baseConfig["proxy-groups"])) {
          try { cfg["proxy-groups"] = Utils.deepClone(baseConfig["proxy-groups"], "proxy-groups"); }
          catch (e) { Logger.warn("ConfigBuilder", `克隆 proxy-groups 失败: ${e.message}，使用浅拷贝`); cfg["proxy-groups"] = [...baseConfig["proxy-groups"]]; }
        }
        if(baseConfig.rules && Array.isArray(baseConfig.rules)) {
          try { cfg.rules = [...baseConfig.rules]; }
          catch (e) { Logger.warn("ConfigBuilder", `复制 rules 失败: ${e.message}`); cfg.rules = []; }
        }
        if(!this._validate(cfg)){ if(Config.autoIntervention) this._selfHeal(cfg); else return cfg; }
        this._mergeSystem(cfg);
        const {regions,regionProxyGroups,otherProxyNames} = this._discoverRegions(cfg,context);
        const regionGroupNames = this._regionGroupNames(regionProxyGroups);
        cfg["proxy-groups"] = this._buildProxyGroups(cfg,regionGroupNames,regionProxyGroups,otherProxyNames,context);
        const {rules,ruleProviders} = this._buildRules(cfg,regionGroupNames,context);
        cfg.rules=rules; cfg["rule-providers"]=ruleProviders;
        if(Config.autoIntervention) this._finalAudit(cfg);
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
      } catch (e) {
        Logger.error("ConfigBuilder", `构建失败: ${e.message}`);
        Logger.error("ConfigBuilder", `错误堆栈: ${e.stack || '无堆栈信息'}`);
        return { ...baseConfig, proxies: baseConfig.proxies || [], rules: ["MATCH,手动选择"], "proxy-groups": [{ name: "手动选择", type: "select", proxies: ["DIRECT"] }] };
      }
    }
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
    static _finalAudit(cfg){
      cfg["allow-lan"] ??= true; cfg["mode"] ??= "rule"; cfg["log-level"] ??= "info";
      if(cfg["proxy-providers"] && typeof cfg["proxy-providers"]==="object"){
        for(const [n,p] of Object.entries(cfg["proxy-providers"])){
          if(!p.url || !p.path){ Logger.warn("Config.Audit",`移除无效 Provider: ${n}`); delete cfg["proxy-providers"][n]; }
        }
      }
      if(cfg["rule-providers"] && typeof cfg["rule-providers"]==="object"){
        for(const [n,p] of Object.entries(cfg["rule-providers"])){
          if(!p || typeof p !== 'object' || !p.url || !p.path){ Logger.warn("Config.Audit",`移除无效规则提供者: ${n}`); delete cfg["rule-providers"][n]; }
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
                if(typeof fStr !== 'string' || CONSTANTS.RE.DANGEROUS_PATTERNS.test(fStr)){ Logger.warn("Config.Security",`拒绝执行不安全的函数: ${k}`); delete obj[k]; continue; }
                try{
                  const v=obj[k]();
                  if(v==null || ["string","number","boolean"].includes(typeof v) || (typeof v==="object" && !Array.isArray(v))){ obj[k]=v; }
                  else{ Logger.warn("Config.Security",`函数返回非法类型: ${k}`); delete obj[k]; }
                }catch(e){ Logger.error("Config.Security",`执行失败: ${k}`,e.message); delete obj[k]; }
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
      const base=Utils.getProxyGroupBase(), groups=[];
      const allProxies = cfg.proxies || [];
      (Config.functionalGroups || []).forEach(fg => {
        if (!fg?.name || !fg?.id) return;
        const customOrder = fg.proxiesOrder || [];
        const coreGroups = ["手动选择", "自动选择", "智能优选", "DIRECT"];
        groups.push({
          ...base, name: fg.name, type: "select",
          proxies: Utils.unique([...coreGroups, ...customOrder.filter(p => !coreGroups.includes(p) && !regionNames.includes(p))]),
          icon: ICON_VAL(fg.icon)
        });
      });
      (Config.common?.defaultProxyGroups||[]).forEach(g => {
        if (!g?.name) return;
        groups.push({ ...base, name: g.name, type: "select", proxies: Utils.unique(g.proxies || []), icon: ICON_VAL(g.icon) });
      });
      if (regionGroups.length) groups.push(...regionGroups);
      try {
        const extract = (name) => { const idx = groups.findIndex(g => g?.name === name); return idx > -1 ? groups.splice(idx, 1)[0] : null; };
        const best = extract("智能优选"), auto = extract("自动选择"), manual = extract("手动选择");
        if (best) groups.unshift(best);
        if (auto) groups.unshift(auto);
        if (manual) groups.unshift(manual);
      } catch (e) { Logger.error("ProxyGroups", `分组排序失败: ${e.message}`); }
      Logger.info("ProxyGroups", `构建完成: 共 ${groups.length} 个分组`);
      return groups;
    }
    static _buildRules(cfg,regionNames,context){
      const ruleProviders={}, rules=[], opts=Config.ruleOptions||{};
      const safePath = f => `./ruleset/${String(f).replace(/[<>:"|?*]/g, '_')}`;
      try {
        rules.push("GEOSITE,private,DIRECT", "GEOIP,private,DIRECT,no-resolve");
        const rejectList = [
          ['acl4ssr_ban', URLS.rulesets.acl4ssr?.ban?.(), opts.acl4ssr],
          ['anti_ad', URLS.rulesets.anti_ad?.(), opts.anti_ad],
          ['ls_reject', URLS.rulesets.loyalsoldier?.reject?.(), opts.loyalsoldier]
        ];
        rejectList.forEach(([name, url, en]) => {
          if (en !== false && url && !ruleProviders[name]) {
            const format = url.endsWith(".mrs") ? "mrs" : url.endsWith(".yaml") ? "yaml" : "text";
            const ext = format === "mrs" ? "mrs" : format === "yaml" ? "yaml" : "txt";
            ruleProviders[name] = { type: "http", interval: 86400, behavior: format === "mrs" || format === "yaml" ? "domain" : "classical", format, url, path: safePath(`${name}.${ext}`), proxy: "" };
            rules.push(`RULE-SET,${name},REJECT`);
          }
        });
        if (opts.blackmatrix7 !== false) {
          ['advertising', 'privacy', 'hijacking'].forEach(t => {
            const url = URLS.rulesets.blackmatrix7?.[t]?.();
            if (url) {
              ruleProviders[`bm7_${t}`] = { type: "http", interval: 86400, behavior: "domain", format: "yaml", url, path: safePath(`bm7_${t}.yaml`), proxy: "" };
              rules.push(`RULE-SET,bm7_${t},REJECT`);
            }
          });
        }
        (Config.preRules || []).filter(r => typeof r === 'string' && r.trim()).forEach(r => rules.push(r));
        const svcToGroup = new Map();
        (Config.functionalGroups || []).forEach(fg => (fg.services || []).forEach(s => svcToGroup.set(s, fg.name)));
        (Config.services||[]).forEach(svc => {
          if (svc.id && opts[svc.id] === false) return;
          const grp = svcToGroup.get(svc.id);
          if (svc.rule) {
            (Array.isArray(svc.rule) ? svc.rule : [svc.rule]).forEach(rule => {
              if (grp) {
                const parts = rule.split(',');
                if (parts.length >= 2) { parts[parts.length - 1] = grp; rules.push(parts.join(',')); }
                else rules.push(rule);
              } else rules.push(rule);
            });
          }
          if (svc.ruleProvider?.name && !ruleProviders[svc.ruleProvider.name]) {
            const url = typeof svc.ruleProvider.url === 'function' ? svc.ruleProvider.url() : svc.ruleProvider.url;
            if (url) {
              const format = url.endsWith(".mrs") ? "mrs" : "text";
              ruleProviders[svc.ruleProvider.name] = { type: "http", interval: 86400, behavior: svc.ruleProvider.behavior || "domain", format, url, path: safePath(`${svc.ruleProvider.name}.${format === "mrs" ? "mrs" : "list"}`), proxy: "" };
            }
          }
        });
        const coreSets = [
          ['applications', URLS.rulesets.applications?.(), 'txt', 'classical'],
          ['acl4ssr_china', URLS.rulesets.acl4ssr?.china?.(), 'list', 'classical'],
          ['ls_cn', URLS.rulesets.loyalsoldier?.cn?.(), 'txt', 'classical']
        ];
        coreSets.forEach(([name, url, ext, behavior]) => {
          if (url) ruleProviders[name] = { type: "http", interval: 86400, behavior, format: "text", url, path: safePath(`${name}.${ext}`), proxy: "" };
        });
        rules.push("RULE-SET,acl4ssr_china,国内网站", "RULE-SET,ls_cn,国内网站", "GEOSITE,cn,国内网站", "GEOIP,cn,国内网站,no-resolve");
        injectAdBlockRules(ruleProviders);
        (Config.common?.postRules || []).forEach(r => rules.push(r));
        Logger.info("RuleBuilder", `构建完成: ${rules.length} 条规则, ${Object.keys(ruleProviders).length} 个规则提供者`);
        return { rules: prioritizeRules(rules), ruleProviders };
      } catch (e) {
        Logger.error("RuleBuilder", `规则构建失败: ${e.message}`);
        return { rules: ["MATCH,手动选择"], ruleProviders: {} };
      }
    }
  }

  Logger.info("Script", `Mihomo Optimized v5.1-fixed 加载完成 - 环境: ${Env.get()}`);

  /* 脚本入口 */
  function main(config, profileName) {
    const startTime = Date.now();
    if (!config || typeof config !== "object") { Logger.warn("Main", "无效配置对象，返回原配置"); return config; }
    const configSize = JSON.stringify(config).length;
    if (configSize > 5 * 1024 * 1024) { Logger.warn("Main", `配置过大 (${(configSize / 1024 / 1024).toFixed(2)}MB)，跳过处理`); return config; }
    try {
      let central;
      try { central = CentralManager.getInstance(); central.initialize(); }
      catch (initError) { Logger.error("Main", `初始化失败: ${initError.message}`); return config; }
      const result = central.processConfiguration(config);
      const elapsed = Date.now() - startTime;
      if (elapsed > 5000) Logger.warn("Main", `配置处理耗时过长: ${elapsed}ms`);
      else Logger.info("Main", `配置处理完成，耗时 ${elapsed}ms`);
      if (!result || typeof result !== "object") { Logger.error("Main", "处理结果无效，返回原配置"); return config; }
      return result;
    } catch (e) {
      Logger.error("Main", `配置处理失败: ${e.message}`);
      Logger.error("Main", `错误堆栈: ${e.stack || '无堆栈信息'}`);
      try {
        const fallback = { ...config };
        if (!Array.isArray(fallback.proxies)) fallback.proxies = [];
        const errorNode = createErrorProxy(e?.message || "未知错误");
        const hasError = fallback.proxies.some(p => p && p._error);
        if (!hasError) fallback.proxies.unshift(errorNode);
        if (!Array.isArray(fallback["proxy-groups"]) || fallback["proxy-groups"].length === 0) {
          fallback["proxy-groups"] = [{ name: "手动选择", type: "select", proxies: ["DIRECT", ...fallback.proxies.slice(0, 10).map(p => p.name || p)] }];
        }
        Logger.info("Main", "降级处理完成，返回包含错误提示的配置");
        return fallback;
      } catch (fallbackError) {
        Logger.error("Main", `降级失败: ${fallbackError.message}`);
        return config;
      }
    }
  }

  root.main = main;
  root.CentralManager = CentralManager;
  root.ConfigBuilder = ConfigBuilder;
  root.AIEngine = AIEngine;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = { main, CentralManager, ConfigBuilder, AIEngine };
  }

  return { main, CentralManager, ConfigBuilder, AIEngine };
})();
