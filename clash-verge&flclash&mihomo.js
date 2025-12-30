"use strict";

/**
 * Sirkey Mihomo 覆写脚本 (Ultimate-Optimized v4.0)
 *
 * 核心优化三大能力：
 * 1. 智能事件驱动系统：全局事件总线 + 优先级调度 + 资源感知
 * 2. 智能权衡决策引擎：多目标冲突协调 + 动态阈值 + 风险回退
 * 3. 自适应自愈闭环：健康度评估 + 趋势预测 + 渐进式恢复
 *
 * @version 4.0-Ultimate-Optimized-Intelligent-Event-Driven-Adaptive-SelfHealing
 */

const Sirkey = (() => {
  /* ========== 环境与常量 ========== */
  const Env = (() => {
    const isMihomo = typeof log === "function" && typeof $proxy === "undefined";
    const isNode = !isMihomo && typeof process !== "undefined" && !!process.versions?.node;
    const isBrowser = !isMihomo && !isNode && typeof window !== "undefined" && !!window.document;
    const platform = isMihomo ? "Mihomo" : (isNode ? "Node" : (isBrowser ? "Browser" : "Unknown"));
    return Object.freeze({
      isNode, isBrowser, isMihomo, platform,
      isCJS: () => typeof module !== "undefined" && !!module.exports,
      get: () => platform,
      version: "2025.12.30-Ultimate-Optimized-v4.0",
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
    DEBUG: false,
    // Mihomo内置特殊代理名称（不可在proxies数组中定义）
    BUILTIN_PROXIES: new Set(["DIRECT", "REJECT"])
  });

  /* ========== Deferred Task Engine（轻量级延迟调度） ========== */
  const DeferredTaskEngine = (() => {
    function defer(fn){
      try{
        if(typeof Promise!=="undefined" && Promise.resolve){
          Promise.resolve().then(fn);
        }else{
          setTimeout(fn,0);
        }
      }catch{
        try{setTimeout(fn,0);}catch{}
      }
    }
    return { defer };
  })();

  /* ========== 数据脱敏与日志 ========== */
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
    log(level, ctx, ...args) {
      if (this._levelMap[level] < this._currentLevel) return;
      const prefix = `[${level}] [${ctx || "Global"}]`;
      const sanitized = args.map(a => {
        if (a === null) return "null";
        if (a === undefined) return "undefined";
        if (typeof a === "object") {
          try { return JSON.stringify(DataMasker.maskObject(a)); } catch { return "[Object]"; }
        }
        return DataMasker.maskIPStr(String(a));
      });
      const msg = `${prefix} ${sanitized.join(" ")}`;
      if (typeof log === "function") log(msg);
      else if (typeof console !== "undefined") (console[level.toLowerCase()] || console.log)(prefix, ...sanitized);
    }
    error(c, ...a){this.log("ERROR",c,...a);} info(c,...a){this.log("INFO",c,...a);}
    warn(c,...a){this.log("WARN",c,...a);}  debug(c,...a){this.log("DEBUG",c,...a);}
  })();

  /* ========== 通用工具 ========== */
  const Utils = {
    now: Date.now,
    clamp: (v,min,max)=>v<min?min:(v>max?max:v),
    sleep: ms => new Promise(r=>setTimeout(r,ms)),
    deepClone(obj, keyName=null) {
      if (!obj || typeof obj !== "object") return obj;
      if (keyName === "proxies" && Array.isArray(obj)) return [...obj];
      if (Array.isArray(obj)) return obj.map(v => Utils.deepClone(v));
      const c = Object.create(Object.getPrototypeOf(obj));
      for (const k in obj) if (Object.prototype.hasOwnProperty.call(obj,k)) {
        const needDeep = ["proxy-groups","rules","proxy-providers"].includes(k);
        c[k] = needDeep ? Utils.deepClone(obj[k],k) : obj[k];
      }
      return c;
    },
    isIPv4: ip => CONSTANTS.IPV4_REG.test(ip),
    isPrivateIP(ip) {
      if (!Utils.isIPv4(ip)) return false;
      const [a,b]=ip.split(".").map(Number);
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
    /**
     * 检查是否为Mihomo内置特殊代理名称
     * @param {string} name 代理名称
     * @returns {boolean} 是否为内置代理
     */
    isBuiltinProxy(name){
      if(typeof name !== "string") return false;
      return CONSTANTS.BUILTIN_PROXIES.has(name.toUpperCase());
    },
    /**
     * 过滤掉内置特殊代理名称（用于proxies数组）
     * @param {Array} proxies 代理数组
     * @returns {Array} 过滤后的代理数组
     */
    filterBuiltinProxies(proxies){
      if(!Array.isArray(proxies)) return [];
      return proxies.filter(p=>{
        const name = typeof p?.name === "string" ? p.name.trim() : "";
        if(Utils.isBuiltinProxy(name)){
          Logger.debug("Utils.FilterBuiltin",`移除内置代理: ${name}`);
          return false;
        }
        return true;
      });
    },
    /**
     * 验证并去重proxy名称
     * @param {Array} proxies 代理数组
     * @returns {Object} {valid: Array, invalid: Array, duplicates: Map}
     */
    validateProxyNames(proxies){
      if(!Array.isArray(proxies)) return {valid:[], invalid:[], duplicates:new Map()};
      const seen=new Map();
      const valid=[];
      const invalid=[];
      const duplicates=new Map();

      proxies.forEach((p, idx)=>{
        if(!p || typeof p !== "object"){
          invalid.push({idx, reason:"非对象类型"});
          return;
        }
        const name = typeof p.name === "string" ? p.name.trim() : "";
        if(!name){
          invalid.push({idx, reason:"缺少name字段或name为空"});
          return;
        }
        // 检查内置代理
        if(Utils.isBuiltinProxy(name)){
          invalid.push({idx, name, reason:"内置特殊代理名称不可定义"});
          return;
        }
        // 检查重复
        if(seen.has(name)){
          const existing = seen.get(name);
          duplicates.set(name, [...(duplicates.get(name)||[existing]), idx]);
          invalid.push({idx, name, reason:"名称重复"});
          return;
        }
        seen.set(name, idx);
        valid.push(p);
      });

      return {valid, invalid, duplicates};
    },
    /**
     * 安全地添加代理名称到列表，自动去重和过滤内置代理
     * @param {Array} list 现有列表
     * @param {Array} names 要添加的名称列表
     * @returns {Array} 处理后的列表
     */
    safeAddNames(list, names){
      if(!Array.isArray(list)) list = [];
      if(!Array.isArray(names)) names = [];
      const existing = new Set(list);
      const result = [...list];
      for(const name of names){
        const n = typeof name === "string" ? name.trim() : "";
        if(!n) continue;
        if(Utils.isBuiltinProxy(n)){
          continue; // 内置代理不需要添加，Mihomo会自动处理
        }
        if(!existing.has(n)){
          existing.add(n);
          result.push(n);
        }
      }
      return result;
    },
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

  /* ========== 持久化存储 ========== */
  const PersistentStorage = new (class {
    _fs=null; _path=null; _baseDir=""; _cacheDir="sirkey_cache"; _inited=false; _isNode=false;
    _writeQueue = [];
    _flushScheduled = false;
    _init() {
      if (this._inited) return;
      this._isNode = typeof process !== "undefined" && !!process.versions?.node;
      if (this._isNode) {
        try{
          const req = typeof require === "function" ? require : null;
          if (req) {
            this._fs = req("fs"); this._path = req("path");
            this._baseDir = process.env.CLASH_HOME_DIR || process.cwd();
            const dir = this._path.join(this._baseDir,this._cacheDir);
            if (!this._fs.existsSync(dir)) this._fs.mkdirSync(dir,{recursive:true});
          }
        }catch(e){Logger.warn("Storage","Node 初始化失败",e.message);}
      }
      this._inited=true;
    }
    _safePath(key){
      if(!this._path||!this._baseDir) return null;
      const safe = key.replace(/[^a-z0-9_-]/gi,"_").substring(0,128);
      const root = this._path.resolve(this._baseDir,this._cacheDir);
      const target = this._path.resolve(root,`${safe}.json`);
      if (!target.startsWith(root)) {Logger.error("Storage.Security",`非法路径: ${key}`); return null;}
      return target;
    }
    read(key){
      this._init();
      const p=this._safePath(key);
      if(this._fs && p){
        try{
          if(this._fs.existsSync(p)) return this._fs.readFileSync(p,"utf8");
        }catch(e){Logger.debug("Storage.Read",`失败: ${key}`,e.message);}
      }
      if(typeof $persistentStore!=="undefined" && typeof $persistentStore.read==="function") return $persistentStore.read(key);
      return null;
    }
    write(key,val){
      this._writeQueue.push({key,val});
      if(!this._flushScheduled){
        this._flushScheduled=true;
        setTimeout(()=>this._flush(), 100);
      }
    }
    _flush(){
      this._init();
      const batch = this._writeQueue.splice(0, 16);
      if(!batch.length){this._flushScheduled=false;return;}

      for(const {key,val} of batch){
        const p=this._safePath(key);
        if(this._fs && p){
          try{
            this._fs.writeFileSync(p,val,"utf8");
          }catch(e){Logger.error("Storage.Write",`失败:${key}`,e.message);}
        }
        if(typeof $persistentStore!=="undefined" && typeof $persistentStore.write==="function") $persistentStore.write(val,key);
      }

      if(this._writeQueue.length) setTimeout(()=>this._flush(), 50);
      else this._flushScheduled=false;
    }
    delete(key){
      this._init();
      const p=this._safePath(key);
      if(this._fs && p && this._fs.existsSync(p)){
        try{this._fs.unlinkSync(p);return true;}catch{return false;}
      }
      return false;
    }
  })();

  /* ========== 错误类型 ========== */
  class SirkeyError extends Error { constructor(m,c="INTERNAL_ERROR"){super(m);this.name="SirkeyError";this.code=c;this.timestamp=Date.now();} }
  class ConfigurationError extends SirkeyError { constructor(m){super(m,"CONFIG_ERROR");} }
  class InvalidRequestError extends SirkeyError { constructor(m){super(m,"INVALID_REQUEST");} }

  /* ========== GitHub 镜像系统 ========== */
  let GH_PROXY = (() => {
    try{
      const raw = PersistentStorage.read("last_gh_proxy_v2");
      if(raw){
        const meta = JSON.parse(raw);
        if(CONSTANTS.GH.MIRRORS.includes(meta.url)){
          const stale = Date.now()-meta.ts>CONSTANTS.TIME.DAY;
          Logger.info("Mirror",`恢复镜像: ${meta.url||"直连"} (${meta.latency}ms,${stale?"过期":"有效"})`);
          return meta.url;
        }
      }
    }catch(e){}
    return "";
  })();
  const MIRROR_STATUS = new Map();

  async function selectBestMirror(httpClient=null){
    if (!Config.privacy?.githubMirrorEnabled || Env.isMihomo) return GH_PROXY;

    const mirrors = CONSTANTS.GH.MIRRORS;
    const testPath = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam.mrs";
    const http = httpClient || CentralManager.getInstance().httpClient;

    const results = await Promise.all(mirrors.map(async base=>{
      const url = base? `${base}${testPath}` : testPath;
      const status = MIRROR_STATUS.get(base)||{failCount:0,lastCheck:0};
      const start=Date.now();
      try{
        if(status.failCount>=3 && Date.now()-status.lastCheck<600000) return {base,latency:9999,valid:false};
        const resp = await http.safeFetch(url,{method:"HEAD"},3000);
        if(resp.ok){
          const latency = Date.now()-start;
          MIRROR_STATUS.set(base,{failCount:0,lastCheck:Date.now(),latency});
          return {base,latency,valid:true};
        }
      }catch(e){}
      MIRROR_STATUS.set(base,{failCount:status.failCount+1,lastCheck:Date.now(),latency:9999});
      return {base,latency:9999,valid:false};
    }));

    const best = results.filter(r=>r.valid).sort((a,b)=>a.latency-b.latency)[0];
    if(best){
      GH_PROXY = best.base;
      Logger.info("Mirror",`最佳镜像: ${GH_PROXY||"直连"} (${best.latency}ms)`);
      const meta={url:GH_PROXY,latency:best.latency,ts:Date.now(),v:2};
      PersistentStorage.write("last_gh_proxy_v2",JSON.stringify(meta));
    }else{
      GH_PROXY="";
      Logger.warn("Mirror","镜像不可用，回退直连");
      PersistentStorage.write("last_gh_proxy_v2",JSON.stringify({url:"",latency:0,ts:Date.now(),v:2}));
    }
    return GH_PROXY;
  }

  /* ========== ICON / URL 体系 ========== */
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

  /* ========== 全局配置 ========== */
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
      { id:"biliintl",rule:["GEOSITE,biliintl,哔哩哔哩东南亚"], name:"哔哩哔哩东南亚", icon:ICONS.Bilibili, proxiesOrder:["默认节点","DIRECT"] },
      { id:"bahamut", rule:["GEOSITE,bahamut,巴哈姆特"], name:"巴哈姆特", icon:ICONS.Bahamut, proxiesOrder:["默认节点","DIRECT"] },
      { id:"tvb",     rule:["GEOSITE,tvb,TVB"], name:"TVB", icon:ICONS.TVB },
      { id:"pixiv",   rule:["GEOSITE,pixiv,Pixiv"], name:"Pixiv", icon:ICONS.Pixiv },
      { id:"spotify", rule:["RULE-SET,spotify,Spotify"], name:"Spotify", icon:ICONS.Spotify, ruleProvider:{ name:"spotify", url:()=>URLS.rulesets.spotify(), behavior:"domain" } },
      { id:"streaming", rule:["RULE-SET,streaming,全球主流媒体"], name:"全球主流媒体", icon:ICONS.StreamingNotCN, ruleProvider:{ name:"streaming", url:()=>URLS.rulesets.streaming(), behavior:"domain" } },
      { id:"china_media", rule:["RULE-SET,china_media,国内媒体"], name:"国内媒体", icon:ICONS.StreamingCN, ruleProvider:{ name:"china_media", url:()=>URLS.rulesets.china_media(), behavior:"domain" }, proxiesOrder:["DIRECT","默认节点"] },
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
      { id:"tracker",  rule:["GEOSITE,tracker,跟踪分析"], name:"跟踪分析", icon:ICONS.Reject, proxies:["REJECT","DIRECT","默认节点"] },
      { id:"ads",      rule:["RULE-SET,ads,广告过滤"], name:"广告过滤", icon:ICONS.Advertising, proxies:["REJECT","DIRECT","默认节点"], ruleProvider:{ name:"ads", url:()=>URLS.rulesets.ads(), behavior:"domain" } }
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
    common:{ ruleProvider:{ type:"http", interval:86400 }, proxyGroup:{ interval:300, timeout:3000, url:"https://cp.cloudflare.com/generate_204", lazy:true }, defaultProxyGroups:[{ name:"下载软件", icon:ICONS.Download, proxies:["DIRECT","REJECT","默认节点","国内网站"] },{ name:"其他外网", icon:ICONS.StreamingNotCN, proxies:["默认节点","国内网站"] },{ name:"国内网站", icon:ICONS.StreamingCN, proxies:["DIRECT","默认节点"] }], postRules:["GEOSITE,private,DIRECT","GEOIP,private,DIRECT,no-resolve","RULE-SET,ls_cn,国内网站","RULE-SET,acl4ssr_china,国内网站","GEOSITE,cn,国内网站","GEOIP,cn,国内网站,no-resolve","MATCH,其他外网"] },
    performance: { heavyProxyThreshold: 800, ioBudgetPerTick: 16 }
  };

  /* ========== Scene / Geo / AI ========== */
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

  /* ========== 自适应自愈闭环 ========== */
  const SelfHealingEngine = (() => {
    const _healthStates = new Map();
    const _trends = new Map();

    function calculateHealthScore(stats) {
      const now = Date.now();
      const recentLatency = stats.latencyHistory?.slice(-5).map(h=>h.v) || [];
      const recentLoss = stats.lossHistory?.slice(-5).map(h=>h.v) || [];
      const avgLatency = recentLatency.reduce((a,b)=>a+b,0)/(recentLatency.length||1);
      const avgLoss = recentLoss.reduce((a,b)=>a+b,0)/(recentLoss.length||1);

      let score = 100;
      if (avgLatency > 2000) score -= 30;
      else if (avgLatency > 1000) score -= 15;
      else if (avgLatency > 500) score -= 5;

      if (avgLoss > 0.3) score -= 30;
      else if (avgLoss > 0.1) score -= 10;
      else if (avgLoss > 0.05) score -= 5;

      if (stats.failCount > 3) score -= 20;
      if (stats.isolatedUntil > now) score -= 50;

      return Math.max(0, score);
    }

    function predictTrend(nodeId) {
      const state = _healthStates.get(nodeId);
      if (!state || state.history.length < 3) return "stable";

      const recent = state.history.slice(-3).map(h => h.score);
      const trend = recent[2] - recent[0];

      if (trend > 10) return "improving";
      if (trend < -10) return "degrading";
      return "stable";
    }

    function shouldRelease(nodeId, stats) {
      const now = Date.now();
      if (stats.isolatedUntil <= now) {
        const health = calculateHealthScore(stats);
        const trend = predictTrend(nodeId);

        if (trend === "improving" && health > 60) {
          Logger.info("SelfHealing",`节点 ${nodeId} 健康趋势改善，解除隔离 (健康度: ${health})`);
          return true;
        }
        if (health > 80) {
          Logger.info("SelfHealing",`节点 ${nodeId} 健康度优秀，解除隔离 (健康度: ${health})`);
          return true;
        }
      }
      return false;
    }

    function updateHealthState(nodeId, stats) {
      const health = calculateHealthScore(stats);
      const history = _healthStates.get(nodeId)?.history || [];
      history.push({ score: health, time: Date.now() });
      if (history.length > 20) history.shift();

      _healthStates.set(nodeId, { health, history });
      _trends.set(nodeId, predictTrend(nodeId));
    }

    return { calculateHealthScore, predictTrend, shouldRelease, updateHealthState };
  })();

  /* ========== LRU 三层缓存 ========== */
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
      this._avail = (typeof fetch==="function" || typeof $httpClient!=="undefined");
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
            const resp=await fetch(url,{...opt,signal:ctrl?.signal});
            Logger.debug("HttpClient",`Fetch ${url} ok in ${Date.now()-start}ms`);
            return resp;
          }finally{if(timer)clearTimeout(timer);}
        }
        if(typeof $httpClient!=="undefined"){
          return new Promise((res,rej)=>{
            const m=(opt.method||"GET").toLowerCase();
            $httpClient[m]({url,headers:opt.headers,timeout:timeout/1000,body:opt.body},(err,resp,data)=>{
              if(err) return rej(new SirkeyError(err,"HTTP_FETCH_ERROR"));
              Logger.debug("HttpClient",`$httpClient ${url} ok in ${Date.now()-start}ms`);
              res({ok:resp.status>=200&&resp.status<300,status:resp.status,text:async()=>data,json:async()=>JSON.parse(data)});
            });
          });
        }
      }catch(e){Logger.error("HttpClient",`失败 ${url}: ${e.message}`); throw e;}
      throw new SirkeyError("Env HTTP exec error","HTTP_CLIENT_EXEC_ERROR");
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

  /* ========== GeoIP + 统计 + AI ========== */
  class GeoIPService {
    constructor(http,cache){
      this._http=http; this._cache=cache;
      this._api="http://ip-api.com/batch?fields=status,message,country,countryCode,query";
    }
    _allowLookup(data){
      const sec = CentralManager.getInstance().security;
      const risk = sec.analyzeThreat(data);
      if(risk>0.6) {Logger.warn("GeoIP.Privacy",`高风险请求,跳过外查(${risk.toFixed(2)})`);return false;}
      return true;
    }
    lookupBatch(proxies){
      if(!Config.privacy?.geoExternalLookup) return new Map();
      if(!this._allowLookup({proxies})) return new Map();
      const servers = Utils.unique((proxies||[]).map(p=>p.server).filter(ip=>ip&&!Utils.isPrivateIP(ip)));
      const res=new Map(), toLookup=[];
      for(const s of servers){
        const cached=this._cache.get(`geo:${s}`);
        if(cached) res.set(s,cached); else toLookup.push(s);
      }
      if(toLookup.length) this._doAsyncLookup(toLookup);
      return res;
    }
    async _doAsyncLookup(list){
      for(let i=0;i<list.length;i+=100){
        const batch=list.slice(i,i+100);
        try{
          const resp=await this._http.safeFetch(this._api,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(batch)});
          const data=await resp.json();
          if(Array.isArray(data)){
            data.forEach(it=>{
              if(it.status==="success"){
                const info={country:it.country,code:it.countryCode};
                this._cache.set(`geo:${it.query}`,info,CONSTANTS.TIME.DAY);
              }
            });
          }
        }catch(e){}
      }
    }
  }

  class NodeStatsManager {
    constructor(cache){
      this._cache=cache; this._prefix="node_stats:"; this._limit=15;
    }
    _key(id){return this._prefix+id;}
    getStats(id){
      const def={latencyHistory:[],lossHistory:[],jitterHistory:[],availabilityHistory:[],bandwidthHistory:[],sceneStats:{gaming:[],streaming:[],browsing:[],download:[]},lastUpdate:0,failCount:0,isolatedUntil:0,switchHistory:[],threatScore:0,lockedUntil:0};
      return this._cache.get(this._key(id)) || def;
    }
    _push(list,v,now,max){list.push({v,t:now}); if(list.length>max) list.shift();}
    update(id,data,scene="browsing"){
      const s=this.getStats(id); const now=Date.now();
      if(data.latency!=null){
        this._push(s.latencyHistory,data.latency,now,this._limit);
        if(s.latencyHistory.length>1){
          const prev=s.latencyHistory[s.latencyHistory.length-2].v;
          this._push(s.jitterHistory,Math.abs(data.latency-prev),now,this._limit);
        }
      }
      if(data.loss!=null) this._push(s.lossHistory,data.loss,now,this._limit);
      if(data.availability!=null) this._push(s.availabilityHistory,data.availability?1:0,now,this._limit);
      if(data.bandwidth!=null) this._push(s.bandwidthHistory,data.bandwidth,now,this._limit);
      if(s.sceneStats[scene]){s.sceneStats[scene].push({l:data.latency,t:now}); if(s.sceneStats[scene].length>20) s.sceneStats[scene].shift();}
      if(data.fail){
        s.failCount++;
        if(s.failCount>=3){
          const h=Config.aiOptions?.protection?.failIsolationH||12;
          s.isolatedUntil=now+h*CONSTANTS.TIME.HOUR;
          Logger.info("AI.Stats",`节点 ${id} 连续失败, 隔离 ${h}h`);
        }
      }else s.failCount=0;

      const curThreat = typeof s.threatScore === "number" ? s.threatScore : 0;
      if((data.latency>5000)||(data.loss>0.5)){s.threatScore = Utils.clamp(curThreat + 0.3, 0, 1);}
      else{s.threatScore = Math.max(0, curThreat - 0.05);}

      s.lastUpdate=now;
      this._cache.set(this._key(id),s,CONSTANTS.TIME.WEEK);

      SelfHealingEngine.updateHealthState(id, s);
      if(SelfHealingEngine.shouldRelease(id, s)){s.isolatedUntil=0;this._cache.set(this._key(id),s,CONSTANTS.TIME.WEEK);}
    }
    recordSwitch(id){
      const s=this.getStats(id); const now=Date.now();
      s.switchHistory.push(now); s.switchHistory=s.switchHistory.filter(t=>now-t<CONSTANTS.TIME.DAY);
      this._cache.set(this._key(id),s,CONSTANTS.TIME.WEEK);
    }
    lockNode(id,h=24){
      const s=this.getStats(id); s.lockedUntil=Date.now()+h*CONSTANTS.TIME.HOUR;
      this._cache.set(this._key(id),s,CONSTANTS.TIME.WEEK);
    }
    unlockNode(id){
      const s=this.getStats(id); s.lockedUntil=0; this._cache.set(this._key(id),s,CONSTANTS.TIME.WEEK);
    }
    reset(){Logger.warn("NodeStats","重置全部统计"); this._cache.clear();}
  }

  class AIEngine {
    constructor(stats,cache){
      this._stats=stats; this._cache=cache; this._scene="browsing"; this._netState="stable";
      this._weights=Config.aiOptions?.scoring || {latencyWeight:0.35,bandwidthWeight:0.15,stabilityWeight:0.25,jitterWeight:0.15,uptimeWeight:0.1};
    }
    ewma(hist,alpha=0.3){
      if(!hist?.length) return null;
      let avg=hist[0].v;
      for(let i=1;i<hist.length;i++) avg=alpha*hist[i].v+(1-alpha)*avg;
      return avg;
    }
    setScene(scene){
      if(Config.aiOptions?.scenes?.[scene]){this._scene=scene; Logger.info("AI.Scene",`切换: ${scene}`);}
    }
    detectNetworkState(nodeIds){
      if(!nodeIds?.length) return;
      const losses=nodeIds.map(id=>this.ewma(this._stats.getStats(id).lossHistory,0.5)||0);
      const avg=losses.reduce((a,b)=>a+b,0)/(losses.length||1);
      this._netState = avg>0.08?"congested":avg>0.03?"volatile":"stable";
      Logger.debug("AI.Network",`环境:${this._netState}, avgLoss=${(avg*100).toFixed(2)}%`);
    }
    _dynWeights(){
      let w={...this._weights};
      const sceneCfg=Config.aiOptions?.scenes?.[this._scene];
      if(sceneCfg) w={...sceneCfg,uptimeWeight:sceneCfg.uptimeWeight??0.1};
      const compMap={congested:{stabilityWeight:0.25,latencyWeight:-0.15},volatile:{jitterWeight:0.2,stabilityWeight:0.1,latencyWeight:-0.1},stable:{latencyWeight:0.05,bandwidthWeight:0.05}};
      const comp=compMap[this._netState]||{};
      for(const[k,v] of Object.entries(comp)) w[k]=Math.max(0,(w[k]||0)+v);
      const sum=Object.values(w).reduce((a,b)=>a+b,0)||1;
      Object.keys(w).forEach(k=>w[k]/=sum);
      return w;
    }
    _metrics(stats){
      const alpha=Config.aiOptions?.evaluation?.ewmaAlpha??0.3;
      return {latency:this.ewma(stats.latencyHistory,alpha)??1500,loss:this.ewma(stats.lossHistory,alpha)??0.5,jitter:this.ewma(stats.jitterHistory,alpha)??500,bandwidth:this.ewma(stats.bandwidthHistory,alpha)??1,uptime:stats.availabilityHistory.length?stats.availabilityHistory.reduce((a,b)=>a+b.v,0)/stats.availabilityHistory.length:0.5};
    }
    _bases(allStats){
      let base={latency:1500,loss:0.1,jitter:500};
      if(allStats.length>5){
        const n=allStats.length;
        const idx80=Math.floor(n*0.8);
        const latencyArr=[];const lossArr=[];const jitterArr=[];
        for(let i=0;i<n;i++){
          const s=allStats[i];
          latencyArr.push(s.latency||0);
          lossArr.push(s.loss||0);
          jitterArr.push(s.jitter||0);
        }
        latencyArr.sort((a,b)=>a-b);
        lossArr.sort((a,b)=>a-b);
        jitterArr.sort((a,b)=>a-b);
        base={latency:Math.max(latencyArr[idx80]||300,300),loss:Math.max(lossArr[idx80]||0.02,0.02),jitter:Math.max(jitterArr[idx80]||50,50)};
      }
      return base;
    }
    _predictFailure(stats){
      if(stats.latencyHistory.length<5) return 0;
      const lat = stats.latencyHistory.slice(-5).map(h=>h.v);
      const loss = stats.lossHistory.slice(-5).map(h=>h.v);
      let trend=0;
      for(let i=1;i<lat.length;i++) trend += lat[i]>lat[i-1]?1:-0.5;
      const avgLoss = loss.reduce((a,b)=>a+b,0)/(loss.length||1);
      let score = (trend/4)*0.4 + (avgLoss/0.2)*0.6;
      return Utils.clamp(score,0,1);
    }

    calculateScore(id,allStats=[]){
      const stats=this._stats.getStats(id);
      const metrics=this._metrics(stats);
      const base=this._bases(allStats);
      const scores={sLatency:Math.max(0,100*(1-metrics.latency/base.latency)),sLoss:Math.max(0,100*(1-metrics.loss/base.loss)),sJitter:Math.max(0,100*(1-metrics.jitter/base.jitter)),sBandwidth:Math.min(100,(metrics.bandwidth/50)*100),sUptime:metrics.uptime*100};
      const w=this._dynWeights();
      const total = scores.sLatency*(w.latencyWeight||0)+scores.sBandwidth*(w.bandwidthWeight||0)+scores.sLoss*(w.stabilityWeight||0)+scores.sJitter*(w.jitterWeight||0)+scores.sUptime*(w.uptimeWeight||0);

      const now=Date.now();
      let status="normal",reason="Baseline";
      const failRisk=this._predictFailure(stats);

      if(stats.threatScore>0.7){status="blocked";reason="Security Threat";}
      else if(failRisk>0.8){status="isolated";reason="High Failure Risk";}
      else if(failRisk>0.4){status="observation";reason="Degrading Performance";}

      if(status==="normal"||status==="observation"){
        if(total>=85 && metrics.loss<0.01){status="premium";reason="Excellent Absolute Performance";}
        else if(total<35 || metrics.loss>0.2 || metrics.latency>2500){status="inferior";reason="Poor Absolute Performance";}
      }

      if(stats.lockedUntil>now){status="locked";reason="Manual Lock";}
      else if(stats.isolatedUntil>now){
        const improvedLatency = metrics.latency <= base.latency;
        const improvedLoss = metrics.loss <= base.loss;
        const significantlyBetter = metrics.latency <= base.latency * 0.7 && metrics.loss <= base.loss * 0.7;
        if(significantlyBetter || (improvedLatency && improvedLoss && failRisk<0.3)){
          stats.isolatedUntil=0; Logger.info("AI.Recovery",`节点 ${id} 自适应恢复 (lat=${Math.round(metrics.latency)}ms, loss=${(metrics.loss*100).toFixed(1)}%)`);
        }else{status="isolated";reason="Auto Isolation";}
      }

      return {score:Math.round(total),status,reason,data:metrics};
    }

    performSelfCheck(nodeIds){
      let issues=0; const now=Date.now();
      nodeIds.forEach(id=>{
        const s=this._stats.getStats(id);
        if(s.latencyHistory.length<10) return;
        const recent=s.latencyHistory.slice(-3).map(h=>h.v);
        const old=s.latencyHistory.slice(-10,-3).map(h=>h.v);
        const avgR = recent.reduce((a,b)=>a+b,0)/(recent.length||1);
        const avgO = old.reduce((a,b)=>a+b,0)/(old.length||1);
        if(avgR>avgO*2 && (now-s.lastUpdate)<300000){Logger.warn("AI.SelfCheck",`节点 ${id} 漂移`); issues++;}
      });
      return issues;
    }

    getBestNodes(nodeIds,minCount=1,allStats=[],currentId=null){
      if(!nodeIds?.length) return [];
      const scored=nodeIds.map(id=>({id,...this.calculateScore(id,allStats)}));
      const scoresSorted = scored.map(s=>s.score).sort((a,b)=>a-b);
      const hi = Utils.percentile(scoresSorted,0.7);
      const lo = Utils.percentile(scoresSorted,0.3);

      const scoredAdjusted = scored.map(s=>{
        const out={...s};
        if(["blocked","isolated","locked"].includes(out.status)) return out;
        if(out.score>=hi){out.status="premium";out.reason="Adaptive Top-Tier";}
        else if(out.score<=lo){out.status="inferior";out.reason="Adaptive Low-Tier";}
        return out;
      });

      const evalOpt=Config.aiOptions?.evaluation || {baseTolerance:50};
      const sorted=scoredAdjusted.sort((a,b)=>b.score-a.score);
      const cur=currentId?sorted.find(s=>s.id===currentId):null;
      if(cur && cur.status!=="isolated" && cur.status!=="inferior"){
        const best=sorted[0];
        if(best.id!==currentId && (best.score-cur.score)<evalOpt.baseTolerance){
          Logger.debug("AI.Smooth",`分差 ${(best.score-cur.score).toFixed(1)} < ${evalOpt.baseTolerance}, 保留当前节点`);
          const idx=sorted.findIndex(s=>s.id===currentId);
          if(idx>-1){const [c]=sorted.splice(idx,1);sorted.unshift(c);}
        }
      }

      let sel=sorted.filter(s=>s.status==="premium");
      if(sel.length<minCount){Logger.info("AI.Degrade","Adaptive premium 不足, 放宽至 normal+premium"); sel=sorted.filter(s=>s.status==="premium"||s.status==="normal");}
      if(sel.length<minCount){Logger.warn("AI.Degrade","再放宽, 排除 isolated/inferior/blocked/locked"); sel=sorted.filter(s=>!["isolated","inferior","blocked","locked"].includes(s.status));}
      return sel;
    }

    canSwitch(id){
      const s=this._stats.getStats(id);
      const now=Date.now();
      const p=Config.aiOptions?.protection || {cooldown:300,maxSwitches24h:20};
      const last=s.switchHistory.slice(-1)[0]||0;
      if(now-last<p.cooldown*1000) return false;
      if(s.switchHistory.length>=p.maxSwitches24h) return false;
      return true;
    }
    recordGroupSwitch(group){
      this._cache.set(`AI.Cooldown.${group}`,Date.now(),CONSTANTS.TIME.DAY);
      Logger.info("AI.Protection",`记录组 ${group} 切换`);
    }
    reset(){
      Logger.warn("AIEngine","重置引擎状态");
      this._scene="browsing"; this._netState="stable";
    }
  }

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
    constructor(http,cache){
      this._cache=cache||new LRUCache();
      this._geo=new GeoIPService(http,this._cache);
      this._stats=new NodeStatsManager(this._cache);
      this._ai=new AIEngine(this._stats,this._cache);
    }
    get stats(){return this._stats;}
    get ai(){return this._ai;}
    get geoService(){return this._geo;}

    discoverRegionsFromProxies(proxies){
      const regions=Config.regionOptions?.regions || [];
      const found=new Map();
      const list=Array.isArray(proxies)?proxies:[];
      if(Config.regionOptions?.geoIpGrouping){
        const geo=this._geo.lookupBatch(list);
        list.forEach(p=>{
          const server=p?.server; const info=geo.get(server);
          if(info){
            const matched = regions.find(r=>r.code===info.code || r.name.includes(info.country));
            if(matched){found.set(matched.name,matched);p._geoMatch=matched.name;}
            else{const name=`${info.code}${info.country}`; const r={name,code:info.code,regex:new RegExp(info.code,"i"),icon:ICON_VAL(ICONS.WorldMap)}; found.set(name,r); p._geoMatch=name;}
          }
        });
      }
      list.forEach(p=>{
        if(p._geoMatch) return;
        const n=String(p?.name||"").trim(); if(!n) return;
        const matched=regions.find(r=>r.regex.test(n));
        if(matched){found.set(matched.name,matched);p._geoMatch=matched.name;return;}
        const hints=n.match(/\b[A-Za-z]{2}\b/g)||[];
        const extra={es:"ES西班牙",it:"IT意大利",nl:"NL荷兰",ch:"CH瑞士",se:"SE瑞典",no:"NO挪威"};
        for(const h of hints){
          const k=h.toLowerCase();
          if(extra[k]){const r={name:extra[k],code:k.toUpperCase(),regex:new RegExp(`\\b${k}\\b`,"i"),icon:ICON_VAL(ICONS.WorldMap)}; found.set(extra[k],r);p._geoMatch=extra[k];break;}
        }
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

      // 预过滤：移除内置特殊代理
      const filteredList = Utils.filterBuiltinProxies(list);
      const usedFilters=[]; const regionGroups=[];
      const allIds=filteredList.map(p=>p.name).filter(Boolean);
      const heavyThreshold = Config.performance?.heavyProxyThreshold ?? 800;
      const isHeavyPool = filteredList.length > heavyThreshold;
      if(isHeavyPool) Logger.warn("RegionAuto",`检测到大节点池 (${filteredList.length}), 启用优化策略`);

      if(Config.aiOptions?.enable && allIds.length) this._ai.detectNetworkState(allIds);

      const activeRegions = hasProviders ? (Config.regionOptions?.regions || []) : regions;
      const globalStats = allIds.map(id=>{const s=this._stats.getStats(id);return {id,latency:this._ai.ewma(s.latencyHistory,0.3)??1500,loss:this._ai.ewma(s.lossHistory,0.3)??0.5,jitter:this._ai.ewma(s.jitterHistory,0.3)??500};});

      for(const r of activeRegions){
        // 使用Utils.isBuiltinProxy检查，增强可维护性
        const regionProxies=filteredList.filter(p=>{
          const n=String(p?.name||"").trim();
          if(Utils.isBuiltinProxy(n)) return false;
          return p._geoMatch===r.name || r.regex.test(n);
        });
        if(!hasProviders && !regionProxies.length) continue;

        let selected=regionProxies;
        if(Config.aiOptions?.enable && regionProxies.length){
          const ids=regionProxies.map(p=>p.name);
          const best=this._ai.getBestNodes(ids,1,globalStats, this._cache.get(`AI.LastSelected.${r.name}`));
          if(best.length){
            this._cache.set(`AI.LastSelected.${r.name}`,best[0].id,CONSTANTS.TIME.DAY);
            const set=new Set(best.map(b=>b.id));
            selected=regionProxies.filter(p=>set.has(p.name));
          }
        }
        const pattern = selected.length ? `(${Utils.regexToMihomo(r.regex)})|(${selected.map(p=>`^${Utils.escapeRegex(p.name)}$`).join("|")})` : Utils.regexToMihomo(r.regex);
        usedFilters.push(pattern);
        regionGroups.push({...Utils.getProxyGroupBase(),name:r.name,type:"url-test","include-all":true,filter:pattern,tolerance:50,icon:ICON_VAL(r.icon)});
      }

      const excludeFilter = usedFilters.length ? usedFilters.map(f=>`(${f})`).join("|") : "";
      const base=Utils.getProxyGroupBase();
      const autoGroup={...base,name:"自动选择",type:"url-test","include-all":true,tolerance:50,icon:ICON_VAL(ICONS.Proxy)};
      const otherGroup={...base,name:"其他节点",type:"select","include-all":true,"exclude-filter":excludeFilter,icon:ICON_VAL(ICONS.WorldMap)};

      const regionProxyGroups = [];
      if(Config.adaptive || Config.autoIntervention){
        if(Config.aiOptions?.enable && allIds.length){
          const bestGlobal = this._ai.getBestNodes(allIds, Math.min(5, allIds.length), globalStats, null);
          if(bestGlobal.length){
            const bestIds = bestGlobal.map(b=>b.id);
            regionProxyGroups.push({...base,name:"最佳节点-AUTO",type:"url-test",proxies:bestIds,tolerance:30,icon:ICON_VAL(ICONS.Premium)},{...base,name:"最佳节点",type:"select",proxies:["最佳节点-AUTO", ...bestIds],icon:ICON_VAL(ICONS.Premium)});
          }
        }
      }

      regionProxyGroups.push(autoGroup, ...regionGroups, otherGroup);
      return {regionProxyGroups,otherProxyNames:[]};
    }
  }

  /* ========== SmartLifecycleManager ========== */
  class SmartLifecycleManager {
    constructor(central){this._c=central;this._tasks=new Map();this._last=new Map();this._running=new Map();}
    addTask(name,fn,interval){this._tasks.set(name,{fn,interval});}
    trigger(event){
      const now=Date.now();
      for(const [name,start] of this._running){
        if(now-start>600000){Logger.warn("Lifecycle",`任务 ${name} 超时, 释放锁`);this._running.delete(name);}
      }
      for(const [name,task] of this._tasks){
        if(this._running.has(name)) continue;
        const last=this._last.get(name)||0;
        if(now-last<task.interval) continue;
        try{
          this._running.set(name,now);
          const r=task.fn();
          if(r instanceof Promise){
            r.catch(e=>Logger.error("Lifecycle",`异步 ${name} 失败: ${e.message}`))
             .finally(()=>{this._running.delete(name);this._last.set(name,Date.now());});
          }else{
            this._running.delete(name); this._last.set(name,now);
          }
        }catch(e){
          this._running.delete(name);
          Logger.error("Lifecycle",`任务 ${name} 出错: ${e.message}`);
        }
      }
      this._manage();
    }
    _manage(){
      const stats=this._c.lruCache.getStats();
      const l1Thr=(stats._maxSize||500)*0.8;
      if(stats.l1Size>l1Thr){
        Logger.info("Lifecycle.Memory",`L1>阈值(${stats.l1Size}), 验证缓存`);
        this._c.lruCache.validate();
      }
      if(Env.isNode && typeof process!=="undefined" && process.memoryUsage){
        try{
          const {heapUsed,heapTotal,rss}=process.memoryUsage();
          const mb=v=>(v/1024/1024).toFixed(2);
          if(heapUsed>250*1024*1024 || (heapTotal && heapUsed/heapTotal>0.75)){
            Logger.warn("Lifecycle.Memory",`内存高: heapUsed=${mb(heapUsed)}MB, rss=${mb(rss)}MB — 清理`);
            this._c.lruCache.clear();
            if(this._c.regionAutoManager?.stats?.reset) this._c.regionAutoManager.stats.reset();
            if(this._c.regionAutoManager?.ai?.reset) this._c.regionAutoManager.ai.reset();
          }
        }catch(e){}
      }
    }
  }

  /* ========== HealthMonitor ========== */
  class HealthMonitor {
    constructor(stats,interval=500){this._stats=stats;this._int=interval;this._last=0;}
    fastCheck(id){
      try{
        const s=this._stats.getStats(id);
        const hist = Array.isArray(s.availabilityHistory) ? s.availabilityHistory : [];
        if(!hist.length) return true;
        const ok = hist.reduce((a,b)=>a+(b.v?1:0),0)/hist.length;
        return ok >= 0.7;
      }catch{return true;}
    }
    runCheck(){
      const now=Date.now();
      if(now-this._last<this._int) return;
      this._last=now;
    }
  }

  /* ========== 中央管理器 ========== */
  class CentralManager {
    static _instance;
    static getInstance(){
      if(!CentralManager._instance) CentralManager._instance=new CentralManager();
      return CentralManager._instance;
    }
    constructor(){
      if(CentralManager._instance) return CentralManager._instance;
      this._http=new HttpClient();
      this._cache=new LRUCache();
      this._security=new SecurityGuard();
      this._adBlock=null;
      this._regionMgr=null;
      this._health=null;
      this._lifecycle=null;
      this._initialized = false;
      CentralManager._instance=this;
    }
    get httpClient(){return this._http;}
    get lruCache(){return this._cache;}
    get security(){return this._security;}
    get adBlockManager(){if(!this._adBlock) this._adBlock=new AdBlockManager(this); return this._adBlock;}
    get regionAutoManager(){if(!this._regionMgr) this._regionMgr=new RegionAutoManager(this._http,this._cache); return this._regionMgr;}
    get healthMonitor(){if(!this._health) this._health=new HealthMonitor(this.regionAutoManager?.stats); return this._health;}
    get lifecycle(){if(!this._lifecycle) this._lifecycle=new SmartLifecycleManager(this); return this._lifecycle;}

    initialize(){
      if (this._initialized) return;
      this._initialized = true;
      try{
        selectBestMirror(this.httpClient).catch(e=>Logger.error("Central.init","镜像探测异常",e.message));
        const lc=this.lifecycle;
        lc.addTask("AI_SelfCheck",()=>{
          Logger.info("AI.SelfCheck","执行自检");
          const nodeIds=Array.from(this.lruCache._l1.keys())
            .filter(k=>k.startsWith("node_stats:"))
            .map(k=>k.replace("node_stats:",""));
          this.regionAutoManager.ai.performSelfCheck(nodeIds);
        },300000);
        lc.addTask("Mirror_Health_Check",()=>{selectBestMirror(this.httpClient);},3600000);
        if(Config.autoIntervention){
          lc.addTask("Self_Monitoring",()=>{
            Logger.info("Central.Monitor","组件状态检查");
            if(!this.regionAutoManager.stats) this.security.performAutoRepair("stats");
            if(!this.httpClient._check()) this.security.performAutoRepair("network");
          },600000);
        }
        lc.addTask("Cache_Validation",()=>{this.lruCache.validate();},(Config.aiOptions?.cache?.verifyInterval||3600)*1000);
        lc.addTask("Health_Check",()=>{this.healthMonitor.runCheck();},1000);
        lc.addTask("LRU_Persistence_Flush",()=>{
          const budget = Config.performance?.ioBudgetPerTick ?? 16;
          this.lruCache.flushPersistence(budget);
        },2000);
        Logger.info("Central.init",`初始化完成 - 镜像: ${GH_PROXY||"直连"}`);
      }catch(e){Logger.error("Central.init",`失败: ${e.message}`);}
    }

    processConfiguration(config,ctx=null){
      const scene=SceneDetector.detect(ctx);
      this.regionAutoManager.ai.setScene(scene);
      const risk=this._security.analyzeThreat(ctx);
      if(risk>0.7) Logger.warn("Central.Security",`高风险(request score=${risk.toFixed(2)})`);
      const stats=this._cache.getStats();
      Logger.info("Central.Cache",`命中率 ${(stats.ratio*100).toFixed(2)}%, L1/L2 ${stats.l1Size}/${stats.l2Size}`);

      DeferredTaskEngine.defer(() => {
        try{this.lifecycle.trigger("processConfiguration");}catch(e){}
      });

      return ConfigBuilder.build(config,this);
    }

    _safeFetch(url,opt={},timeout=5000){return this._http.safeFetch(url,opt,timeout);}
  }

  const ErrorConfigFactory = {
    createErrorConfig(msg,opts={}){
      const t=Date.now();
      return {name:`⛔ 脚本错误: ${String(msg).slice(0,20)}...`,type:"direct",...opts,_error:true,_errorMessage:msg,_errorTimestamp:t,_scriptError:{timestamp:t,message:msg,fallback:true,version:"ultimate_optimized_v4.0"}};
    }
  };

  /* ========== ConfigBuilder ========== */
  class ConfigBuilder {
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

      // 最终验证 - 确保符合Mihomo官方规范
      const validation = this._finalValidate(cfg);
      if(!validation.valid && Config.autoIntervention){
        // 如果有严重错误，尝试自动修复
        Logger.warn("ConfigBuilder","检测到配置错误，尝试自动修复");
        // 再次清理和验证
        if(Array.isArray(cfg.proxies)){
          cfg.proxies = Utils.filterBuiltinProxies(cfg.proxies);
          const {valid} = Utils.validateProxyNames(cfg.proxies);
          cfg.proxies = valid;
        }
      }

      return cfg;
    }

    static _applyAdaptive(cfg,context){
      const scene = SceneDetector.detect(context);
      const opts=Config.aiOptions;
      if(opts?.enable && opts.scenes?.[scene]){
        Logger.info("Config.Adaptive",`场景: ${scene}, 调整权重`);
        opts.scoring = {...opts.scoring,...opts.scenes[scene]};
      }
    }
    static _selfHeal(cfg){
      Logger.info("Config.SelfHeal","补全基础配置");
      cfg.proxies = Array.isArray(cfg.proxies) ? cfg.proxies : [];
      cfg["proxy-groups"] = Array.isArray(cfg["proxy-groups"]) ? cfg["proxy-groups"] : [];
      cfg.rules = Array.isArray(cfg.rules) ? cfg.rules : [];

      // 预处理：移除proxies中的内置特殊代理
      cfg.proxies = Utils.filterBuiltinProxies(cfg.proxies);

      // 检查是否需要注入紧急代理
      // 注意：不注入"DIRECT"或"REJECT"，因为它们是Mihomo内置的
      if(cfg.proxies.length===0 && !cfg["proxy-providers"]){
        Logger.warn("Config.SelfHeal","无可用代理，请检查订阅或proxy-providers配置");
        // 创建一个错误标记的代理用于提示
        cfg.proxies.push({
          name:"⚠️ 无可用代理",
          type:"direct",
          _error:true,
          _message:"请检查订阅链接或proxy-providers配置"
        });
      }
    }
    static _finalAudit(cfg){
      cfg["allow-lan"] ??= true; cfg["mode"] ??= "rule"; cfg["log-level"] ??= "info";
      if(cfg["proxy-providers"] && typeof cfg["proxy-providers"]==="object"){
        for(const [n,p] of Object.entries(cfg["proxy-providers"])){
          if(!p.url || !p.path){Logger.warn("Config.Audit",`移除无效 Provider: ${n}`); delete cfg["proxy-providers"][n];}
        }
      }
      if(Array.isArray(cfg.rules)) cfg.rules=cfg.rules.filter(r=>typeof r==="string" && r.split(",").length>=2);
    }

    /**
     * 最终配置验证 - 检查Mihomo规范合规性
     * @param {Object} cfg 配置对象
     * @returns {Object} {valid: boolean, errors: Array[], warnings: Array[]}
     */
    static _finalValidate(cfg){
      const errors = [];
      const warnings = [];

      // 验证proxies中的名称唯一性和合规性
      if(Array.isArray(cfg.proxies)){
        const {invalid, duplicates} = Utils.validateProxyNames(cfg.proxies);
        if(invalid.length > 0){
          invalid.forEach(inv => {
            errors.push(`代理配置错误: ${inv.name || '未知'} - ${inv.reason}`);
          });
        }
        if(duplicates.size > 0){
          duplicates.forEach((idxs, name) => {
            errors.push(`重复的代理名称: ${name} (出现在 ${idxs.length} 处)`);
          });
        }
      }

      // 验证proxy-groups中的名称唯一性
      if(Array.isArray(cfg["proxy-groups"])){
        const groupNames = new Map();
        cfg["proxy-groups"].forEach((g, idx) => {
          if(!g || !g.name){
            warnings.push(`ProxyGroup[${idx}] 缺少name字段`);
            return;
          }
          if(groupNames.has(g.name)){
            errors.push(`重复的ProxyGroup名称: ${g.name} (索引 ${groupNames.get(g.name)} 和 ${idx})`);
          }else{
            groupNames.set(g.name, idx);
          }

          // 验证proxy-group中的proxies引用
          if(Array.isArray(g.proxies)){
            const proxySet = new Set((cfg.proxies||[]).map(p=>p.name));
            const builtin = new Set([...CONSTANTS.BUILTIN_PROXIES]);
            g.proxies.forEach(pname => {
              if(!builtin.has(pname) && !proxySet.has(pname)){
                // 检查是否是另一个proxy-group的名称
                if(!groupNames.has(pname)){
                  warnings.push(`ProxyGroup "${g.name}" 引用了不存在的代理/组: ${pname}`);
                }
              }
            });
          }
        });
      }

      // 验证内置代理没有被错误地添加到proxies数组
      if(Array.isArray(cfg.proxies)){
        const foundBuiltins = cfg.proxies.filter(p => Utils.isBuiltinProxy(p.name));
        if(foundBuiltins.length > 0){
          const names = foundBuiltins.map(p => p.name).join(", ");
          errors.push(`内置特殊代理不能在proxies数组中定义: ${names}`);
        }
      }

      if(errors.length > 0){
        Logger.error("Config.FinalValidate",`发现 ${errors.length} 个错误:`);
        errors.forEach(err => Logger.error("Config.FinalValidate", `  - ${err}`));
      }
      if(warnings.length > 0){
        Logger.warn("Config.FinalValidate",`发现 ${warnings.length} 个警告:`);
        warnings.forEach(warn => Logger.warn("Config.FinalValidate", `  - ${warn}`));
      }

      return {
        valid: errors.length === 0,
        errors,
        warnings
      };
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
      const regionAuto = context?.regionAutoManager || new RegionAutoManager(context?.httpClient,context?.lruCache);
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

      // 验证并清理proxies数组中的内置特殊代理和重复名称
      const originalLength = cfg.proxies.length;
      cfg.proxies = Utils.filterBuiltinProxies(cfg.proxies);

      // 验证代理名称
      const {valid, invalid, duplicates} = Utils.validateProxyNames(cfg.proxies);
      if(invalid.length > 0){
        const reasons = invalid.map(i => `${i.name || '未知'}(${i.reason})`).join(", ");
        Logger.warn("Config.EnsureSystemProxies",`检测到 ${invalid.length} 个无效代理: ${reasons}`);
      }
      if(duplicates.size > 0){
        const dupList = Array.from(duplicates.entries()).map(([name, idxs]) => `${name}(${idxs.length}个)`).join(", ");
        Logger.warn("Config.EnsureSystemProxies",`检测到重复代理名称: ${dupList}`);
      }

      // 只保留有效的代理
      cfg.proxies = valid;

      if(cfg.proxies.length !== originalLength){
        Logger.info("Config.EnsureSystemProxies",`清理代理: ${originalLength} → ${cfg.proxies.length}`);
      }
    }

    static _buildProxyGroups(cfg,regionNames,regionGroups,otherNames){
      const base=Utils.getProxyGroupBase();
      const groups=[];

      // 使用safeAddNames安全地添加代理名称，自动过滤内置代理
      const defaultProxiesWithDirect = Utils.safeAddNames(regionNames, ["DIRECT"]);
      groups.push({...base,name:"默认节点",type:"select",proxies:defaultProxiesWithDirect,icon:ICON_VAL(ICONS.Proxy)});

      const updateProxies = regionNames.length ? Utils.safeAddNames(regionNames, ["DIRECT"]) : ["DIRECT"];
      groups.push({...base,name:"🚀 规则更新",type:"select",proxies:updateProxies,icon:ICON_VAL(ICONS.Update)});

      const services=Array.isArray(Config.services)?Config.services:[];
      const defaultOrder=["默认节点","国内网站","DIRECT","REJECT"];
      services.forEach(svc=>{
        try{
          const name=svc.name||svc.id; if(!name) return;
          const baseOrder = Array.isArray(svc.proxiesOrder)?svc.proxiesOrder:(Array.isArray(svc.proxies)?svc.proxies:defaultOrder);
          const proxies=Utils.safeAddNames(regionNames, baseOrder);
          groups.push({...base,name,type:"select",proxies,icon:ICON_VAL(svc.icon)});
        }catch(e){Logger.warn("Config.ServiceGroup",svc?.id,e.message||e);}
      });
      (Config.common?.defaultProxyGroups||[]).forEach(g=>{
        if(!g?.name) return;
        const proxies=Utils.safeAddNames(regionNames, Array.isArray(g.proxies)?g.proxies:[]);
        groups.push({...base,name:g.name,type:"select",proxies,icon:ICON_VAL(g.icon)});
      });
      if(regionGroups.length){
        regionGroups.forEach(g=>{if(g.type==="url-test"||g.type==="fallback") Object.assign(g,{...base,tolerance:50});});
        groups.push(...regionGroups);
      }
      try{const idx = groups.findIndex(g => g && g.name === "最佳节点"); if(idx > 0){const [best] = groups.splice(idx,1); groups.unshift(best);}}catch(e){}
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
          const target=/ads|ban|reject/i.test(key)?"REJECT":"默认节点";
          rules.push(`RULE-SET,${key},${target}`);
        }
      });
    }

    static _buildRules(cfg,regionNames,context){
      const ruleProviders={}, rules=[];
      const baseRP={type:"http",interval:Config.common?.ruleProvider?.interval??86400,format:"text",proxy:"🚀 规则更新"};
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

  return {
    Env,CONSTANTS,DataMasker,Logger,Utils,SirkeyError,ConfigurationError,InvalidRequestError,GH_PROXY:()=>GH_PROXY,selectBestMirror,ICON_VAL,ICONS,URLS,Config,NodeStatsManager,AIEngine,RegionAutoManager,AdBlockManager,LRUCache,HttpClient,SecurityGuard,CentralManager,ConfigBuilder,ErrorConfigFactory,DeferredTaskEngine,SmartLifecycleManager,HealthMonitor,SelfHealingEngine
  };
})();

function main(config, profileName){
  if(!config || typeof config!=="object"){Sirkey.Logger.error("Main","配置无效"); return config;}
  try{
    const central=Sirkey.CentralManager.getInstance();
    central.initialize();
    return central.processConfiguration(config);
  }catch(e){
    const msg=e?.message||"未知错误";
    Sirkey.Logger.error("Main",`构建失败: ${msg}`);
    try{
      const fallback={...config};
      if(!Array.isArray(fallback.proxies)) fallback.proxies=[];
      fallback.proxies.unshift(Sirkey.ErrorConfigFactory.createErrorConfig(msg));
      return fallback;
    }catch(err){
      Sirkey.Logger.error("Main","回退失败，返回原始配置");
      return config;
    }
  }
}

const EXPORTS = {main,CentralManager:Sirkey.CentralManager,ConfigBuilder:Sirkey.ConfigBuilder,buildConfigForParser:(cfg)=>Sirkey.ConfigBuilder.build(cfg,Sirkey.CentralManager.getInstance()),RegionAutoManager:Sirkey.RegionAutoManager,GeoIPService:Sirkey.GeoIPService,LRUCache:Sirkey.LRUCache,Utils:Sirkey.Utils,DataMasker:Sirkey.DataMasker,CONSTANTS:Sirkey.CONSTANTS,Config:Sirkey.Config,AIEngine:Sirkey.AIEngine,NodeStatsManager:Sirkey.NodeStatsManager,getGHProxy:Sirkey.GH_PROXY,selectBestMirror:Sirkey.selectBestMirror,Logger:Sirkey.Logger,URLS:Sirkey.URLS,DeferredTaskEngine:Sirkey.DeferredTaskEngine,SmartLifecycleManager:Sirkey.SmartLifecycleManager,HealthMonitor:Sirkey.HealthMonitor,SelfHealingEngine:Sirkey.SelfHealingEngine};

if(Sirkey.Env.isCJS()) module.exports=EXPORTS;
if(Sirkey.Env.isNode){Object.assign(global,EXPORTS);}
if(Sirkey.Env.isBrowser){window.__MihomoScript__=EXPORTS;}

Sirkey.Logger.info("Script",`Ultimate Optimized v4.0 加载完成 - 环境: ${Sirkey.Env.get()}`);
