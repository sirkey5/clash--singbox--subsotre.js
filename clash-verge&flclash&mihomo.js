"use strict";

/**
 * Sirkey Mihomo 覆写脚本 (Compact+Enhanced, Fixed+Compliant+Adaptive+SmartDeferred)
 *
 * 关键特性与目标：
 * - 保留系统 / 安全 / 规则层的静态语义，不做自适应改动
 * - 仅对 AI / 统计 / 缓存 层做智能自适应与事件驱动优化
 * - 引入“智能事件驱动（Deferred Task Engine）”：
 *   1. main() 热路径尽量保持纯配置构建，快速返回，避免阻塞 flclash GUI
 *   2. 所有重任务（AI 自检 / L3 持久化刷盘 / 缓存校验 / 自监控）延迟到 main() 返回后执行
 *   3. 通过 Promise 微任务 / setTimeout 等机制在当前调用栈结束后再调度生命周期任务
 *
 * 关键增强（基于 3.1.3）：
 * - 引入 DeferredTaskEngine：保证 lifecycle.trigger() 不在 main() 同步路径执行
 * - 生命周期任务仍然完整保留（包括 LRU_Persistence_Flush），不关闭 L3 持久化、不削弱 AI 逻辑
 * - 在不损失 AI 评分、自适应 Top-K、节点隔离恢复 等能力的前提下，显著降低 flclash 启动卡死风险
 *
 * 官方规范与兼容性：
 * - 严格遵守 Mihomo 官方覆写脚本规范：导出 main(config, profileName)，返回最终配置对象
 * - 不引入非标准字段到配置根级别，不破坏原有 rules / proxy-groups / dns / system 语义
 * - 兼容多平台：Mihomo / Node / 浏览器 调试环境
 *
 * @version 3.1.4-Sirkey-Compact-Fixed-Compliant-Adaptive-Hardened-Deferred
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
      version: "2025.12.29-Sirkey-Compact-Fixed-Compliant-Adaptive-Hardened-3.1.4",
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
    TIME: {
      DAY: 86400000,
      HALF_DAY: 43200000,
      WEEK: 604800000,
      HOUR: 3600000
    },
    GH: { MIRRORS: ["", "https://mirror.ghproxy.com/", "https://ghproxy.net/", "https://github.moeyy.xyz/", "https://gh.api.99988866.xyz/", "https://cdn.jsdelivr.net/gh/"] },
    UA: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    STREAM_REG: /youtube|netflix|stream|video|live|hls|dash|disney|hbo|hulu|tiktok|bilibili|amazon|prime|apple.*tv/i,
    AI_REG: /openai|claude|gemini|ai|chatgpt|api\.openai|anthropic|googleapis|perplex|mistral|cohere/i,
    SAFE_PORTS: new Set([80,443,8080,8081,8088,8880,8443,2052,2053,2082,2083,2086,2087,2095,2096]),
    IPV4_REG: /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)$/,
    DEBUG: false
  });

  /* ========== 数据脱敏与日志 ========== */
  const DataMasker = {
    maskUrl: (url) => (typeof url === "string" ? url.replace(CONSTANTS.RE.URL_MASK, "$1***") : url),
    maskIPStr(str) {
      return typeof str === "string"
        ? str.replace(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g, ip => Utils.isPrivateIP(ip) ? ip : ip.replace(/\d{1,3}$/, "***"))
        : str;
    },
    mask(str) {
      if (typeof str !== "string") return str;
      let res = str.replace(CONSTANTS.RE.URL_MASK, "$1***");
      res = res.replace(
        /([?&; ])(password|token|key|secret|auth|credential|access|bearer|authorization|cookie|session)([:= ])[^;& ]+/gi,
        "$1$2$3***"
      );
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
        if (tv === undefined) {
          target[k] = Utils.deepClone(v);
        } else if (isPlain(tv) && isPlain(v)) {
          Utils.mergeDefaults(tv, v);
        }
      }
      return target;
    },
    /**
     * 简单分位数计算：percent ∈ (0,1)，在排序数组中取对应位置的值
     */
    percentile(sortedArr, percent) {
      if (!sortedArr?.length) return null;
      const p = Utils.clamp(percent, 0, 1);
      const idx = Math.min(sortedArr.length - 1, Math.max(0, Math.floor(sortedArr.length * p)));
      return sortedArr[idx];
    }
  };

  /* ========== 持久化存储 (Node + $persistentStore) ========== */
  const PersistentStorage = new (class {
    _fs=null; _path=null; _baseDir=""; _cacheDir="sirkey_cache"; _inited=false; _isNode=false;
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
      this._init();
      const p=this._safePath(key);
      if(this._fs && p){
        try{
          if(this._isNode && this._fs.promises){
            this._fs.promises.writeFile(p,val,"utf8").catch(e=>Logger.error("Storage.Write",`异步失败:${key}`,e.message));
            return true;
          }
          this._fs.writeFileSync(p,val,"utf8");
          return true;
        }catch(e){Logger.error("Storage.Write",`失败:${key}`,e.message);}
      }
      if(typeof $persistentStore!=="undefined" && typeof $persistentStore.write==="function") return $persistentStore.write(val,key);
      return false;
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

  /* ========== GitHub 镜像系统 (自适应 + 记忆) ========== */
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
      const legacy = PersistentStorage.read("last_gh_proxy");
      if(legacy && CONSTANTS.GH.MIRRORS.includes(legacy)) return legacy;
    }catch(e){Logger.debug("Mirror","读取失败",e.message);}
    return "";
  })();
  const MIRROR_STATUS = new Map();

  /**
   * 关键修复点：
   * - 在 Mihomo 环境中完全禁止在线镜像探测，避免在 main()/initialize() 调用链上发起 HTTP 请求，
   *   防止 flclash 等客户端 GUI 阻塞。
   */
  async function selectBestMirror(httpClient=null){
    if (!Config.privacy?.githubMirrorEnabled || Env.isMihomo) {
      Logger.info("Mirror","Mihomo 环境或已禁用镜像探测，使用缓存/直连");
      return GH_PROXY;
    }

    const mirrors = CONSTANTS.GH.MIRRORS;
    const testPath = "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/steam.mrs";
    const http = httpClient || CentralManager.getInstance().httpClient;
    Logger.info("Mirror","启动镜像探测...");
    const results = await Promise.all(mirrors.map(async base=>{
      const url = base? `${base}${testPath}` : testPath;
      const status = MIRROR_STATUS.get(base)||{failCount:0,lastCheck:0};
      const start=Date.now();
      try{
        if(status.failCount>=3 && Date.now()-status.lastCheck<600000) return {base,latency:9999,valid:false,skip:true};
        const resp = await http.safeFetch(url,{method:"HEAD"},3000);
        if(resp.ok){
          const latency = Date.now()-start;
          MIRROR_STATUS.set(base,{failCount:0,lastCheck:Date.now(),latency});
          return {base,latency,valid:true};
        }
      }catch(e){Logger.debug("Mirror",`探测失败:${base||"直连"} - ${e.message}`);}
      MIRROR_STATUS.set(base,{failCount:status.failCount+1,lastCheck:Date.now(),latency:9999});
      return {base,latency:9999,valid:false};
    }));
    const best = results.filter(r=>r.valid).sort((a,b)=>a.latency-b.latency)[0];
    if(best){
      const old = GH_PROXY;
      GH_PROXY = best.base;
      Logger.info("Mirror",`最佳镜像: ${GH_PROXY||"直连"} (${best.latency}ms)`);
      const stored = PersistentStorage.read("last_gh_proxy_v2");
      let needWrite = true;
      if(stored){
        try{
          const meta=JSON.parse(stored);
          if(meta.url===GH_PROXY && Date.now()-meta.ts<CONSTANTS.TIME.HALF_DAY) needWrite=false;
        }catch{}
      }
      if(needWrite){
        const meta={url:GH_PROXY,latency:best.latency,ts:Date.now(),v:2};
        PersistentStorage.write("last_gh_proxy_v2",JSON.stringify(meta));
        PersistentStorage.delete("last_gh_proxy");
      }
    }else{
      GH_PROXY="";
      Logger.warn("Mirror","镜像不可用，回退直连");
      PersistentStorage.write("last_gh_proxy_v2",JSON.stringify({url:"",latency:0,ts:Date.now(),v:2}));
    }
    return GH_PROXY;
  }

  /* ========== ICON / URL 体系 (统一抽象) ========== */
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
      for(const m of CONSTANTS.GH.MIRRORS){
        if(m && clean.startsWith(m)){clean=clean.slice(m.length);break;}
      }
      if(GH_PROXY.includes("jsdelivr.net")){
        const m = clean.match(CONSTANTS.RE.GH_RAW);
        if(m){
          const [,user,repo,branch,path]=m;
          return `https://cdn.jsdelivr.net/gh/${user}/${repo}@${branch}/${path}`;
        }
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
      china_media:()=>URLS.mrs("category-media-cn"),
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
      }
    }
  };

  /* ========== 全局配置 (保持原功能 + 性能策略) ========== */
  const Config = {
    autoIntervention: true,
    adaptive: true,
    enable: true,
    privacy: {
      geoExternalLookup: true,
      systemDnsOnly: false,
      trustedGeoEndpoints: [],
      githubMirrorEnabled: true
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
      cache:{
        levels:3,
        strategy:"LRU+TTL",
        verifyInterval:3600,
        // 保留持久化能力，交由 L3 事件驱动刷盘，避免 main() 热路径同步 I/O
        persistence:true
      },
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
      "fake-ip-filter":[
        "*","+.lan","+.local","+.market.xiaomi.com","+.msftconnecttest.com","+.msftncsi.com",
        "msftconnecttest.com","msftncsi.com","+.xboxlive.com","+.battlenet.com.cn","+.wotgame.cn",
        "+.wggames.cn","+.wowsgame.cn","+.wargaming.net","geosite:cn","geosite:private"
      ],
      "default-nameserver":["223.5.5.5","119.29.29.29","1.1.1.1","8.8.8.8"],
      nameserver:["https://223.5.5.5/dns-query","https://119.29.29.29/dns-query","https://8.8.8.8/dns-query"],
      fallback:["https://1.1.1.1/dns-query","https://9.9.9.9/dns-query"],
      "fallback-filter":{
        geoip:true,"geoip-code":"CN",ipcidr:["240.0.0.0/4"],
        domain:["+.google.com","+.facebook.com","+.youtube.com","+.githubusercontent.com"]
      },
      "proxy-server-nameserver":[
        "https://223.5.5.5/dns-query","https://119.29.29.29/dns-query","https://8.8.8.8/dns-query"
      ],
      "nameserver-policy":{
        "geosite:private":["system"],
        "geosite:cn,steam@cn,category-games@cn,microsoft@cn,apple@cn":["119.29.29.29","223.5.5.5"],
        "rule-set:acl4ssr_china,ls_cn":["119.29.29.29","223.5.5.5"]
      }
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
        "force-domain":["+.v2ex.com","+.apple.com"],
        "skip-domain":["Mijia Cloud","+.push.apple.com","geosite:private"]
      },
      "geox-url":{
        geoip:()=>URLS.geox.geoip(),
        geosite:()=>URLS.geox.geosite(),
        mmdb:()=>URLS.geox.mmdb(),
        asn:()=>URLS.geox.asn()
      }
    },
    common:{
      ruleProvider:{ type:"http", interval:86400 },
      proxyGroup:{ interval:300, timeout:3000, url:"https://cp.cloudflare.com/generate_204", lazy:true },
      defaultProxyGroups:[
        { name:"下载软件", icon:ICONS.Download, proxies:["DIRECT","REJECT","默认节点","国内网站"] },
        { name:"其他外网", icon:ICONS.StreamingNotCN, proxies:["默认节点","国内网站"] },
        { name:"国内网站", icon:ICONS.StreamingCN, proxies:["DIRECT","默认节点"] }
      ],
      postRules:[
        "GEOSITE,private,DIRECT",
        "GEOIP,private,DIRECT,no-resolve",
        "RULE-SET,ls_cn,国内网站",
        "RULE-SET,acl4ssr_china,国内网站",
        "GEOSITE,cn,国内网站",
        "GEOIP,cn,国内网站,no-resolve",
        "MATCH,其他外网"
      ]
    },
    performance: {
      // 节点数量超过该阈值时，可按需在未来扩展降级策略（当前主要用于日志与监控）
      heavyProxyThreshold: 800,
      // 单次生命周期 tick 中允许的持久化 I/O 条数，避免单次刷盘过重
      ioBudgetPerTick: 16
    }
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

  /* ========== LRU 三层缓存：L1/L2 + 事件驱动持久化 L3 ========== */

  class LRUCache {
    constructor({maxSize=300,ttl=3600000,persist=null}={}) {
      this._l1=new Map();
      this._l2=new Map();
      this._maxSize=maxSize;
      this._ttl=ttl;
      this._h=0;
      this._m=0;

      this._persist = (persist !== null)
        ? !!persist
        : !!(Config.aiOptions?.cache?.persistence);

      // 待持久化队列：key -> serializedEntry
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

      // 不在 get() 中进行 L3 磁盘读取，避免同步 I/O 卡顿
      return null;
    }

    set(key,val,ttl, persist=true){
      const e=this._entry(val,ttl);
      this._l1.set(key,e);
      this._evict();

      // 这里只入队，不直接写盘，真正写盘由 lifecycle 的 LRU_Persistence_Flush 任务控制
      if(persist && this._persist){
        try{
          const serialized = JSON.stringify(e);
          this._pendingWrites.set(key, serialized);
        }catch(err){
          Logger.error("LRU.PersistQueue",`序列化失败:${key}`,err.message);
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

    /**
     * 由生命周期任务调用：在 I/O 配额内，将 pendingWrites 批量刷盘。
     * 这是“第三层缓存（磁盘持久化）”的实际执行点。
     * 注意：此函数只在 Deferred 生命周期任务中调用，不在 main() 同步路径执行。
     */
    flushPersistence(ioBudget=16){
      if(!this._persist) return;
      if(!this._pendingWrites.size) return;
      const iter = this._pendingWrites.entries();
      let count = 0;
      for(const [key, serialized] of iter){
        try{
          PersistentStorage.write(key, serialized);
        }catch(e){
          Logger.error("LRU.Flush",`写入失败:${key}`,e.message);
        }
        this._pendingWrites.delete(key);
        count++;
        if(count>=ioBudget) break;
      }
      if(count) Logger.debug("LRU.Flush",`刷盘 ${count} 条, 剩余队列: ${this._pendingWrites.size}`);
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
              res({
                ok:resp.status>=200 && resp.status<300,
                status:resp.status,
                text:async()=>data,
                json:async()=>JSON.parse(data)
              });
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
      this._malicious = [
        /malware|phishing|track|telemetry|spyware|adware/i,
        /coinminer|cryptonight|stratum/i,
        /dns-leak|leak-test/i,
        /exploit|attack|payload/i
      ];
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

  /* ========== GeoIP + 统计 + AI (高内聚，AI 层自适应增强) ========== */

  class GeoIPService {
    constructor(http,cache){
      this._http=http; this._cache=cache;
      this._api="http://ip-api.com/batch?fields=status,message,country,countryCode,query";
    }
    _allowLookup(data){
      const sec = CentralManager.getInstance().security;
      const risk = sec.analyzeThreat(data);
      if(risk>0.6) {Logger.warn("GeoIP.Privacy",`高风险请求, 跳过外查(${risk.toFixed(2)})`);return false;}
      return true;
    }
    lookupBatch(proxies){
      if(!Config.privacy?.geoExternalLookup) return new Map();
      if(!this._allowLookup({proxies})) return new Map();
      const servers = Utils.unique((proxies||[]).map(p=>p.server).filter(ip=>ip && !Utils.isPrivateIP(ip)));
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
          const resp=await this._http.safeFetch(this._api,{
            method:"POST",
            headers:{"Content-Type":"application/json"},
            body:JSON.stringify(batch)
          });
          const data=await resp.json();
          if(Array.isArray(data)){
            data.forEach(it=>{
              if(it.status==="success"){
                const info={country:it.country,code:it.countryCode};
                this._cache.set(`geo:${it.query}`,info,CONSTANTS.TIME.DAY);
              }
            });
          }
        }catch(e){Logger.warn("GeoIP","后台批量失败",e.message);}
      }
    }
  }

  class NodeStatsManager {
    constructor(cache){
      this._cache=cache;
      this._prefix="node_stats:";
      this._limit=15;
    }
    _key(id){return this._prefix+id;}
    getStats(id){
      const def={
        latencyHistory:[],lossHistory:[],jitterHistory:[],availabilityHistory:[],bandwidthHistory:[],
        sceneStats:{gaming:[],streaming:[],browsing:[],download:[]},
        lastUpdate:0,failCount:0,isolatedUntil:0,switchHistory:[],threatScore:0,lockedUntil:0
      };
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
      if(s.sceneStats[scene]){
        s.sceneStats[scene].push({l:data.latency,t:now});
        if(s.sceneStats[scene].length>20) s.sceneStats[scene].shift();
      }
      if(data.fail){
        s.failCount++;
        if(s.failCount>=3){
          const h=Config.aiOptions?.protection?.failIsolationH||12;
          s.isolatedUntil=now+h*CONSTANTS.TIME.HOUR;
          Logger.info("AI.Stats",`节点 ${id} 连续失败, 隔离 ${h}h`);
        }
      }else s.failCount=0;

      // 修复：threatScore 归一化到 [0,1]，避免一次异常即永久 blocked
      const curThreat = typeof s.threatScore === "number" ? s.threatScore : 0;
      if((data.latency>5000)||(data.loss>0.5)){
        s.threatScore = Utils.clamp(curThreat + 0.3, 0, 1);
      }else{
        s.threatScore = Math.max(0, curThreat - 0.05);
      }

      s.lastUpdate=now;
      this._cache.set(this._key(id),s,CONSTANTS.TIME.WEEK);
    }
    recordSwitch(id){
      const s=this.getStats(id); const now=Date.now();
      s.switchHistory.push(now);
      s.switchHistory=s.switchHistory.filter(t=>now-t<CONSTANTS.TIME.DAY);
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
      this._stats=stats;
      this._cache=cache;
      this._scene="browsing";
      this._netState="stable";
      this._weights=Config.aiOptions?.scoring || {latencyWeight:0.35,bandwidthWeight:0.15,stabilityWeight:0.25,jitterWeight:0.15,uptimeWeight:0.1};
    }
    ewma(hist,alpha=0.3){
      if(!hist?.length) return null;
      let avg=hist[0].v;
      for(let i=1;i<hist.length;i++) avg=alpha*hist[i].v+(1-alpha)*avg;
      return avg;
    }
    setScene(scene){
      if(Config.aiOptions?.scenes?.[scene]){
        this._scene=scene;
        Logger.info("AI.Scene",`切换: ${scene}`);
      }
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
      const compMap={
        congested:{stabilityWeight:0.25,latencyWeight:-0.15},
        volatile:{jitterWeight:0.2,stabilityWeight:0.1,latencyWeight:-0.1},
        stable:{latencyWeight:0.05,bandwidthWeight:0.05}
      };
      const comp=compMap[this._netState]||{};
      for(const[k,v] of Object.entries(comp)) w[k]=Math.max(0,(w[k]||0)+v);
      const sum=Object.values(w).reduce((a,b)=>a+b,0)||1;
      Object.keys(w).forEach(k=>w[k]/=sum);
      return w;
    }
    _metrics(stats){
      const alpha=Config.aiOptions?.evaluation?.ewmaAlpha??0.3;
      return {
        latency:this.ewma(stats.latencyHistory,alpha) ?? 1500,
        loss:this.ewma(stats.lossHistory,alpha) ?? 0.5,
        jitter:this.ewma(stats.jitterHistory,alpha) ?? 500,
        bandwidth:this.ewma(stats.bandwidthHistory,alpha) ?? 1,
        uptime: stats.availabilityHistory.length
          ? stats.availabilityHistory.reduce((a,b)=>a+b.v,0)/stats.availabilityHistory.length
          : 0.5
      };
    }
    _bases(allStats){
      let base={latency:1500,loss:0.1,jitter:500};
      if(allStats.length>5){
        const p80=(k)=>{
          const arr=allStats.map(s=>s[k]||0).sort((a,b)=>a-b);
          return arr[Math.floor(arr.length*0.8)]||base[k];
        };
        base={
          latency:Math.max(p80("latency"),300),
          loss:Math.max(p80("loss"),0.02),
          jitter:Math.max(p80("jitter"),50)
        };
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
      const scores={
        sLatency:Math.max(0,100*(1-metrics.latency/base.latency)),
        sLoss:Math.max(0,100*(1-metrics.loss/base.loss)),
        sJitter:Math.max(0,100*(1-metrics.jitter/base.jitter)),
        sBandwidth:Math.min(100,(metrics.bandwidth/50)*100),
        sUptime:metrics.uptime*100
      };
      const w=this._dynWeights();
      const total = scores.sLatency*(w.latencyWeight||0)
        + scores.sBandwidth*(w.bandwidthWeight||0)
        + scores.sLoss*(w.stabilityWeight||0)
        + scores.sJitter*(w.jitterWeight||0)
        + scores.sUptime*(w.uptimeWeight||0);

      const now=Date.now();
      let status="normal",reason="Baseline";
      const failRisk=this._predictFailure(stats);

      if(stats.threatScore>0.7){status="blocked";reason="Security Threat";}
      else if(failRisk>0.8){status="isolated";reason="High Failure Risk";}
      else if(failRisk>0.4){status="observation";reason="Degrading Performance";}

      if(status==="normal" || status==="observation"){
        if(total>=85 && metrics.loss<0.01){
          status="premium";reason="Excellent Absolute Performance";
        }else if(total<35 || metrics.loss>0.2 || metrics.latency>2500){
          status="inferior";reason="Poor Absolute Performance";
        }
      }

      if(stats.lockedUntil>now){
        status="locked";reason="Manual Lock";
      }else if(stats.isolatedUntil>now){
        const improvedLatency = metrics.latency <= base.latency;
        const improvedLoss = metrics.loss <= base.loss;
        const significantlyBetter = metrics.latency <= base.latency * 0.7 && metrics.loss <= base.loss * 0.7;
        if(significantlyBetter || (improvedLatency && improvedLoss && failRisk<0.3)){
          stats.isolatedUntil=0;
          Logger.info("AI.Recovery",`节点 ${id} 自适应恢复 (lat=${Math.round(metrics.latency)}ms, loss=${(metrics.loss*100).toFixed(1)}%)`);
        }else{
          status="isolated";reason="Auto Isolation";
        }
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
        if(avgR>avgO*2 && (now-s.lastUpdate)<300000){
          Logger.warn("AI.SelfCheck",`节点 ${id} 漂移`);
          issues++;
        }
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
      if(sel.length<minCount){
        Logger.info("AI.Degrade","Adaptive premium 不足, 放宽至 normal+premium");
        sel=sorted.filter(s=>s.status==="premium"||s.status==="normal");
      }
      if(sel.length<minCount){
        Logger.warn("AI.Degrade","再放宽, 排除 isolated/inferior/blocked/locked");
        sel=sorted.filter(s=>!["isolated","inferior","blocked","locked"].includes(s.status));
      }
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
        Utils.safeSet(rps,"adblock_combined",{
          type:"http",interval:86400,behavior:"domain",format:"mrs",
          url:this.adBlockUrl,path:"./ruleset/adblock_combined.mrs"
        });
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
          const server=p?.server;
          const info=geo.get(server);
          if(info){
            const matched = regions.find(r=>r.code===info.code || r.name.includes(info.country));
            if(matched){found.set(matched.name,matched);p._geoMatch=matched.name;}
            else{
              const name=`${info.code}${info.country}`;
              const r={name,code:info.code,regex:new RegExp(info.code,"i"),icon:ICON_VAL(ICONS.WorldMap)};
              found.set(name,r); p._geoMatch=name;
            }
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
          if(extra[k]){
            const r={name:extra[k],code:k.toUpperCase(),regex:new RegExp(`\\b${k}\\b`,"i"),icon:ICON_VAL(ICONS.WorldMap)};
            found.set(extra[k],r);p._geoMatch=extra[k];break;
          }
        }
      });
      return found;
    }
    mergeNewRegions(base,discovered){
      const merged=[...(base || [])];
      discovered.forEach(r=>{ if(!merged.some(m=>m.name===r.name)) merged.push(r); });
      return merged;
    }

    buildRegionGroups(config,regions,proxies){
      const hasProviders = !!(config["proxy-providers"] && Object.keys(config["proxy-providers"]).length);
      const list = Array.isArray(proxies)?proxies:[];
      const usedFilters=[]; const regionGroups=[];
      const allIds=list.map(p=>p.name).filter(Boolean);

      const heavyThreshold = Config.performance?.heavyProxyThreshold ?? 800;
      const isHeavyPool = list.length > heavyThreshold;
      if (isHeavyPool) {
        Logger.warn("RegionAuto",`检测到大节点池 (${list.length} > ${heavyThreshold})，启用温和优化策略`);
      }

      if(Config.aiOptions?.enable && allIds.length){
        this._ai.detectNetworkState(allIds);
      }

      const activeRegions = hasProviders ? (Config.regionOptions?.regions || []) : regions;
      const globalStats = allIds.map(id=>{
        const s=this._stats.getStats(id);
        return {
          id,
          latency:this._ai.ewma(s.latencyHistory,0.3)??1500,
          loss:this._ai.ewma(s.lossHistory,0.3)??0.5,
          jitter:this._ai.ewma(s.jitterHistory,0.3)??500
        };
      });

      for(const r of activeRegions){
        const regionProxies=list.filter(p=>{
          const n=String(p.name||""); if(["DIRECT","REJECT"].includes(n.toUpperCase())) return false;
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
        const pattern = selected.length
          ? `(${Utils.regexToMihomo(r.regex)})|(${selected.map(p=>`^${Utils.escapeRegex(p.name)}$`).join("|")})`
          : Utils.regexToMihomo(r.regex);
        usedFilters.push(pattern);
        regionGroups.push({
          ...Utils.getProxyGroupBase(),
          name:r.name,
          type:"url-test",
          "include-all":true,
          filter:pattern,
          tolerance:50,
          icon:ICON_VAL(r.icon)
        });
      }

      const excludeFilter = usedFilters.length ? usedFilters.map(f=>`(${f})`).join("|") : "";
      const base=Utils.getProxyGroupBase();
      const autoGroup={...base,name:"自动选择",type:"url-test","include-all":true,tolerance:50,icon:ICON_VAL(ICONS.Proxy)};
      const otherGroup={...base,name:"其他节点",type:"select","include-all":true,"exclude-filter":excludeFilter,icon:ICON_VAL(ICONS.WorldMap)};

      const regionProxyGroups = [];
      const otherProxyNames = [];

      // 自适应 & “最佳节点”组构建（最佳节点-AUTO + 最佳节点 select）
      if(Config.adaptive || Config.autoIntervention){
        if(Config.aiOptions?.enable && allIds.length){
          const bestGlobal = this._ai.getBestNodes(allIds, Math.min(5, allIds.length), globalStats, null);
          if(bestGlobal.length){
            const bestIds = bestGlobal.map(b=>b.id);

            const bestAutoGroup = {
              ...base,
              name:"最佳节点-AUTO",
              type:"url-test",
              proxies:bestIds,
              tolerance:30,
              icon:ICON_VAL(ICONS.Premium)
            };

            const bestSelectGroup = {
              ...base,
              name:"最佳节点",
              type:"select",
              proxies:["最佳节点-AUTO", ...bestIds],
              icon:ICON_VAL(ICONS.Premium)
            };

            regionProxyGroups.push(bestAutoGroup, bestSelectGroup);
          }
        }
      }

      regionProxyGroups.push(autoGroup, ...regionGroups, otherGroup);

      return {regionProxyGroups,otherProxyNames};
    }
  }

  /* ========== 生命周期管理 (事件驱动) ========== */

  class SmartLifecycleManager {
    constructor(central){this._c=central;this._tasks=new Map();this._last=new Map();this._running=new Map();}
    addTask(name,fn,interval){this._tasks.set(name,{fn,interval});}
    /**
     * 核心：trigger() 只在 Deferred 调度中调用，不在 main() 同步路径内高频调用。
     */
    trigger(event){
      const now=Date.now();
      Logger.debug("Lifecycle",`事件: ${event}`);
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
            if(this._c.regionAutoManager.stats.reset) this._c.regionAutoManager.stats.reset();
            if(this._c.regionAutoManager.ai.reset) this._c.regionAutoManager.ai.reset();
            if(typeof global!=="undefined" && typeof global.gc==="function"){
              Logger.info("Lifecycle.Memory","触发 GC");
              global.gc();
            }
          }
        }catch(e){Logger.debug("Lifecycle.Memory","监控失败",e.message);}
      }
    }
  }

  class HealthMonitor {
    constructor(stats,interval=500){this._stats=stats;this._int=interval;this._last=0;}
    fastCheck(id){
      try{
        const s=this._stats.getStats(id);
        const hist = Array.isArray(s.availabilityHistory) ? s.availabilityHistory : [];
        if(!hist.length) return true;
        const ok = hist.reduce((a,b)=>a+(b.v?1:0),0)/hist.length;
        return ok >= 0.7;
      }catch{
        return true;
      }
    }
    runCheck(){
      const now=Date.now();
      if(now-this._last<this._int) return;
      this._last=now;
    }
    start(){} stop(){}
  }

  /* ========== Deferred Task Engine（智能事件驱动） ========== */

  const DeferredTaskEngine = (() => {
    /**
     * 使用最小侵入式的 Deferred 调度：
     * - 优先使用 Promise.then（微任务），否则回退 setTimeout 0
     * - 确保所有重任务在 main() 返回后执行，避免阻塞 flclash GUI
     */
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

  /* ========== ConfigBuilder ========== */

  class ConfigBuilder {
    static build(baseConfig,context=null){
      const cfg = {...baseConfig};
      if(baseConfig.proxies) cfg.proxies=Utils.deepClone(baseConfig.proxies,"proxies");
      if(baseConfig["proxy-groups"]) cfg["proxy-groups"] = Utils.deepClone(baseConfig["proxy-groups"],"proxy-groups");
      if(baseConfig.rules) cfg.rules=[...baseConfig.rules];

      if(Config.adaptive && context){
        this._applyAdaptive(cfg,context);
      }

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
      if(cfg.proxies.length===0 && !cfg["proxy-providers"]){
        Logger.warn("Config.SelfHeal","注入紧急 DIRECT");
        cfg.proxies.push({name:"DIRECT",type:"direct"});
      }
    }
    static _finalAudit(cfg){
      cfg["allow-lan"] ??= true;
      cfg["mode"] ??= "rule";
      cfg["log-level"] ??= "info";
      if(cfg["proxy-providers"] && typeof cfg["proxy-providers"]==="object"){
        for(const [n,p] of Object.entries(cfg["proxy-providers"])){
          if(!p.url || !p.path){
            Logger.warn("Config.Audit",`移除无效 Provider: ${n}`);
            delete cfg["proxy-providers"][n];
          }
        }
      }
      if(Array.isArray(cfg.rules)){
        cfg.rules=cfg.rules.filter(r=>typeof r==="string" && r.split(",").length>=2);
      }
    }
    static _validate(cfg){
      const p=cfg.proxies||[];
      const pCount=Array.isArray(p)?p.length:0;
      const prov=cfg["proxy-providers"];
      const provCount = prov && typeof prov==="object"?Object.keys(prov).length:0;
      if(!pCount && !provCount){
        Logger.warn("ConfigBuilder","未发现代理/提供商");
        return false;
      }
      return true;
    }

    static _discoverRegions(cfg,context){
      const regionAuto = context?.regionAutoManager || new RegionAutoManager(context?.httpClient,context?.lruCache);
      let regions = Config.regionOptions?.regions || [];
      const proxies = cfg.proxies || [];
      if(Config.regionOptions?.autoDiscover || Config.autoIntervention){
        try{
          const discovered = regionAuto.discoverRegionsFromProxies(proxies);
          regions = regionAuto.mergeNewRegions(regions,discovered);
        }catch(e){Logger.warn("Config.RegionDiscover",e.message||e);}
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
                const safe = (fStr.includes("URLS")||fStr.includes("ICONS")||fStr.includes("ICON_VAL"))
                  && !/eval|Function|require|process|global|window|document|XMLHttpRequest|fetch/i.test(fStr);
                if(!safe){Logger.warn("Config.Security",`拒绝执行函数: ${k}`); delete obj[k]; continue;}
                try{
                  const v=obj[k]();
                  if(v==null || ["string","number","boolean"].includes(typeof v) || (typeof v==="object" && !Array.isArray(v))) obj[k]=v;
                  else{Logger.warn("Config.Security",`函数返回非法类型: ${k}`);delete obj[k];}
                }catch(e){Logger.error("Config.Security",`执行失败: ${k}`,e.message);delete obj[k];}
              }else if(obj[k] && typeof obj[k]==="object") hydrate(obj[k]);
            }
          };
          hydrate(sys);
          Utils.mergeDefaults(cfg, sys);
        }
        if(Config.dns && typeof Config.dns==="object"){
          cfg.dns = Utils.mergeDefaults(cfg.dns || {}, Config.dns);
        }
      }catch(e){Logger.warn("Config.MergeSystem",e.message||e);}
    }

    static _regionGroupNames(groups){
      try{return Utils.unique(groups.map(g=>g?.name).filter(Boolean));}
      catch(e){Logger.warn("Config.RegionNames",e.message||e);return[];}
    }

    static _ensureSystemProxies(cfg){
      if(!Array.isArray(cfg.proxies)) cfg.proxies = [];
    }

    static _buildProxyGroups(cfg,regionNames,regionGroups,otherNames){
      const base=Utils.getProxyGroupBase();

      const groups=[];

      groups.push({
        ...base,
        name:"默认节点",
        type:"select",
        proxies:[...regionNames,"DIRECT"],
        icon:ICON_VAL(ICONS.Proxy)
      });
      groups.push({
        ...base,
        name:"🚀 规则更新",
        type:"select",
        proxies:regionNames.length?[...regionNames]:["DIRECT"],
        icon:ICON_VAL(ICONS.Update)
      });
      const services=Array.isArray(Config.services)?Config.services:[];
      const defaultOrder=["默认节点","国内网站","DIRECT","REJECT"];
      services.forEach(svc=>{
        try{
          const name=svc.name||svc.id; if(!name) return;
          const baseOrder = Array.isArray(svc.proxiesOrder)?svc.proxiesOrder:
            (Array.isArray(svc.proxies)?svc.proxies:defaultOrder);
          const proxies=Utils.unique([...(baseOrder||[]),...regionNames]);
          groups.push({
            ...base,
            name,
            type:"select",
            proxies,
            icon:ICON_VAL(svc.icon)
          });
        }catch(e){Logger.warn("Config.ServiceGroup",svc?.id,e.message||e);}
      });
      (Config.common?.defaultProxyGroups||[]).forEach(g=>{
        if(!g?.name) return;
        groups.push({
          ...base,
          name:g.name,
          type:"select",
          proxies:[...(Array.isArray(g.proxies)?g.proxies:[]),...regionNames],
          icon:ICON_VAL(g.icon)
        });
      });
      if(regionGroups.length){
        regionGroups.forEach(g=>{
          if(g.type==="url-test"||g.type==="fallback") Object.assign(g,{...base,tolerance:50});
        });
        groups.push(...regionGroups);
      }

      // 将“最佳节点”分组移动到所有分组最前方，提升可见性与可用性
      try{
        const idx = groups.findIndex(g => g && g.name === "最佳节点");
        if (idx > 0) {
          const [best] = groups.splice(idx, 1);
          groups.unshift(best);
        }
      }catch(e){
        Logger.warn("Config.GroupOrder", e.message || e);
      }

      return groups;
    }

    static _sortRules(rules){
      if(!Array.isArray(rules) || !rules.length) return rules || [];
      const normal = [];
      const matchRules = [];
      for(const r of rules){
        if(typeof r !== "string"){ normal.push(r); continue; }
        const type = r.split(",")[0].trim().toUpperCase();
        if(type === "MATCH") matchRules.push(r);
        else normal.push(r);
      }
      return [...normal, ...matchRules];
    }

    static _autoDiscoverRules(ruleProviders,rules,opts,baseRP){
      const defs=opts.defaults||{};
      Object.entries(defs).forEach(([key,en])=>{
        if(!en) return;
        let url="",behavior="classical",format="text";
        if(typeof URLS.rulesets[key]==="function"){
          url=URLS.rulesets[key]();
          if(url.endsWith(".mrs")){behavior="domain";format="mrs";}
        }else if(URLS.rulesets.loyalsoldier && typeof URLS.rulesets.loyalsoldier[key]==="function"){
          url=URLS.rulesets.loyalsoldier[key]();
        }
        if(url && !ruleProviders[key]){
          const ext=format==="mrs"?"mrs":"list";
          ruleProviders[key]={...baseRP,behavior,format,url,path:`./ruleset/${key}.${ext}`};
          const target=/ads|ban|reject/i.test(key)?"REJECT":"默认节点";
          rules.push(`RULE-SET,${key},${target}`);
        }
      });
    }

    static _buildRules(cfg,regionNames,context){
      const ruleProviders={}; const rules=[];
      const baseRP={type:"http",interval:Config.common?.ruleProvider?.interval??86400,format:"text",proxy:"🚀 规则更新"};
      const opts=Config.ruleOptions||{};
      if(opts.autoDiscover || Config.autoIntervention) this._autoDiscoverRules(ruleProviders,rules,opts,baseRP);

      const coreSets={
        applications:{behavior:"classical",url:URLS.rulesets.applications()},
        acl4ssr_china:{behavior:"domain",url:URLS.rulesets.acl4ssr.china()},
        ls_cn:{behavior:"domain",url:URLS.rulesets.loyalsoldier.cn()}
      };
      Object.entries(coreSets).forEach(([name,meta])=>{
        ruleProviders[name]={...baseRP,...meta,path:`./ruleset/${name}.list`};
      });

      if(opts.acl4ssr!==false && !ruleProviders.acl4ssr_ban){
        ruleProviders.acl4ssr_ban={
          ...baseRP,behavior:"classical",url:URLS.rulesets.acl4ssr.ban(),path:"./ruleset/acl4ssr_ban.list"
        };
        rules.push("RULE-SET,acl4ssr_ban,REJECT");
      }
      if(opts.anti_ad!==false && !ruleProviders.anti_ad){
        ruleProviders.anti_ad={
          ...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.anti_ad(),path:"./ruleset/anti_ad.yaml"
        };
        rules.push("RULE-SET,anti_ad,REJECT");
      }
      if(opts.clash_rules!==false && !ruleProviders.clash_ad){
        ruleProviders.clash_ad={
          ...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.clash_rules.ad(),path:"./ruleset/clash_ad.yaml"
        };
        ruleProviders.clash_privacy={
          ...baseRP,behavior:"domain",format:"yaml",url:URLS.rulesets.clash_rules.privacy(),path:"./ruleset/clash_privacy.yaml"
        };
        rules.push("RULE-SET,clash_ad,REJECT","RULE-SET,clash_privacy,REJECT");
      }
      if(opts.loyalsoldier!==false && !ruleProviders.ls_reject){
        ruleProviders.ls_reject={
          ...baseRP,behavior:"classical",url:URLS.rulesets.loyalsoldier.reject(),path:"./ruleset/ls_reject.list"
        };
        rules.push("RULE-SET,ls_reject,REJECT");
      }

      if(Array.isArray(Config.preRules)) rules.push(...Config.preRules);

      (Config.services||[]).forEach(svc=>{
        if(svc.id && opts[svc.id]===false) return;
        if(svc.rule) rules.push(...svc.rule);
        const rp=svc.ruleProvider;
        if(rp?.name && !ruleProviders[rp.name]){
          const url=typeof rp.url==="function"?rp.url():rp.url;
          const isMrs=url.endsWith(".mrs");
          ruleProviders[rp.name]={
            ...baseRP,
            behavior:rp.behavior||"domain",
            format:isMrs?"mrs":(rp.format||"yaml"),
            url,
            path:`./ruleset/${rp.name}.${isMrs?"mrs":(rp.format||"yaml")}`
          };
        }
      });

      if(context?.adBlockManager) context.adBlockManager.injectRuleProvider(ruleProviders);

      if(Array.isArray(Config.common?.postRules)) rules.push(...Config.common.postRules);

      const sorted=this._sortRules(rules);
      return {rules:sorted,ruleProviders};
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
    get healthMonitor(){if(!this._health) this._health=new HealthMonitor(this.regionAutoManager.stats); return this._health;}
    get lifecycle(){if(!this._lifecycle) this._lifecycle=new SmartLifecycleManager(this); return this._lifecycle;}

    /**
     * 初始化只做一次，且只注册任务，不执行任务。
     */
    initialize(){
      if (this._initialized) return;
      this._initialized = true;
      try{
        // Mihomo 环境下不会真正发 HTTP 探测，selectBestMirror 内部已做判断
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

    /**
     * 核心：processConfiguration 不再同步触发 lifecycle.trigger，而是通过 DeferredTaskEngine 延迟执行。
     */
    processConfiguration(config,ctx=null){
      const scene=SceneDetector.detect(ctx);
      this.regionAutoManager.ai.setScene(scene);
      const risk=this._security.analyzeThreat(ctx);
      if(risk>0.7) Logger.warn("Central.Security",`高风险(request score=${risk.toFixed(2)})`);
      const stats=this._cache.getStats();
      Logger.info("Central.Cache",`命中率 ${(stats.ratio*100).toFixed(2)}%, L1/L2 ${stats.l1Size}/${stats.l2Size}`);

      // Deferred 调度生命周期任务，确保不阻塞 main()
      DeferredTaskEngine.defer(() => {
        try{
          this.lifecycle.trigger("processConfiguration");
        }catch(e){
          Logger.error("Central.Deferred","Lifecycle 触发失败",e.message);
        }
      });

      return ConfigBuilder.build(config,this);
    }

    _safeFetch(url,opt={},timeout=5000){return this._http.safeFetch(url,opt,timeout);}
  }

  /* ========== 错误配置工厂 ========== */

  const ErrorConfigFactory = {
    createErrorConfig(msg,opts={}){
      const t=Date.now();
      return {
        name:`⛔ 脚本错误: ${String(msg).slice(0,20)}...`,
        type:"direct",
        ...opts,
        _error:true,_errorMessage:msg,_errorTimestamp:t,
        _scriptError:{timestamp:t,message:msg,fallback:true,version:"optimized_compact_fixed_compliant_adaptive_hardened_deferred_3.1.4"}
      };
    }
  };

  return {
    Env,CONSTANTS,DataMasker,Logger,Utils,
    SirkeyError,ConfigurationError,InvalidRequestError,
    GH_PROXY:()=>GH_PROXY,selectBestMirror,
    ICON_VAL,ICONS,URLS,Config,
    NodeStatsManager,AIEngine,RegionAutoManager,
    AdBlockManager,LRUCache,HttpClient,SecurityGuard,
    SmartLifecycleManager,HealthMonitor,CentralManager,
    ConfigBuilder,ErrorConfigFactory,
    DeferredTaskEngine
  };
})();

/* ========== 主入口（符合 Mihomo 覆写规范） ========== */
function main(config, profileName){
  if(!config || typeof config!=="object"){
    Sirkey.Logger.error("Main","配置无效");
    return config;
  }
  try{
    const central=Sirkey.CentralManager.getInstance();
    central.initialize();
    // main() 热路径：仅构建配置 + 启动 Deferred 任务，不做任何同步重任务
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

/* ========== 导出 ========== */
const EXPORTS = {
  main,
  CentralManager:Sirkey.CentralManager,
  ConfigBuilder:Sirkey.ConfigBuilder,
  buildConfigForParser:(cfg)=>Sirkey.ConfigBuilder.build(cfg,Sirkey.CentralManager.getInstance()),
  RegionAutoManager:Sirkey.RegionAutoManager,
  GeoIPService:Sirkey.GeoIPService,
  LRUCache:Sirkey.LRUCache,
  Utils:Sirkey.Utils,
  DataMasker:Sirkey.DataMasker,
  CONSTANTS:Sirkey.CONSTANTS,
  Config:Sirkey.Config,
  AIEngine:Sirkey.AIEngine,
  NodeStatsManager:Sirkey.NodeStatsManager,
  getGHProxy:Sirkey.GH_PROXY,
  selectBestMirror:Sirkey.selectBestMirror,
  Logger:Sirkey.Logger,
  URLS:Sirkey.URLS,
  DeferredTaskEngine:Sirkey.DeferredTaskEngine
};

if(Sirkey.Env.isCJS()) module.exports=EXPORTS;
if(Sirkey.Env.isNode){Object.assign(global,EXPORTS);}
if(Sirkey.Env.isBrowser){window.__MihomoScript__=EXPORTS;}

Sirkey.Logger.info("Script",`Compact Fixed Compliant Adaptive Hardened Deferred 3.1.4 版加载完成 - 环境: ${Sirkey.Env.get()}`);
