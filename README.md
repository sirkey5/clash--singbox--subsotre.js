# clash-verge&Flclash&mihomo.js 智能分流配置脚本 - 使用说明

## 📖 简介

- **clash-verge&flclash&mihomo.js**：是一个专为 mihomo（Clash 变种）设计的**智能分流配置脚本**
- **singbox全自动节点分流管理插件.js**：是给singbox做的一个全自动节点的管理与分流的插件。
- **singbox全自动节点分流管理混入脚本.js**：是给singbox做的一个全自动节点的管理与分流的配置混入脚本。
- **substore过滤无效节点脚本.js**：一个智能、高效、稳定的SubStore节点过滤脚本，用于过滤无效节点、验证节点连通性、自动去重，并为节点添加地理标识。
- **除substore脚本外，上述三个脚本的逻辑与功能都是出自同源逻辑，只是针对各自的适用场景做了分别的优化与适配。**
- **它们都能够自动管理您的代理节点，根据网络质量、地理位置和访问需求，智能选择最佳节点，让您的网络访问更加流畅、稳定。**






---

## 📌 简介

**clash-verge&flclash&mihomo.js** 是一款专为 **Mihomo / Clash.Meta** 设计的智能覆写脚本，旨在在不改变用户原始配置结构的前提下，实现：

高性能 · 高智能 · 高可靠 · 全自动化的 Mihomo 覆写脚本

- 更智能的节点选择  
- 更精确的区域识别  
- 更稳定的网络行为  
- 更强的自适应能力  
- 更安全的配置合并  
- 更高效的缓存与性能优化  

本脚本采用 **三层架构（Core / Runtime / AI）**，并通过 **LRU 缓存、AI 评分、区域聚合、生命周期管理、威胁检测** 等机制，构建一个高度自动化、可持续运行的智能配置系统。

---

## ✨ 核心特性

### 🔥 1. 智能节点选择（AI Engine）
- EWMA 平滑算法  
- 多维度评分（延迟、丢包、抖动、带宽、可用性）  
- 场景感知（游戏 / 流媒体 / 浏览 / 下载）  
- 网络状态自适应（稳定 / 波动 / 拥堵）  
- 节点隔离、恢复、降级、平滑切换  

### 🌏 2. 自动区域识别（Region Auto Manager）
- GeoIP 批量查询（带隐私保护）  
- 正则匹配 + 国家代码推断  
- 自动构建区域分组  
- 自动生成“全球优选”、“自动选择”、“其他节点”等分组  

### ⚙️ 3. 高性能缓存系统（双层 LRU + TTL + 持久化）
- L1/L2 双层缓存  
- TTL 自动过期  
- Node 环境持久化加速冷启动  
- 自动内存回收与自修复  

### 🛡️ 4. 安全与隐私保护
- URL/敏感字段脱敏  
- 威胁评分（端口/域名/IP/进程）  
- 高风险请求自动阻断外查  
- 配置合并函数白名单（防止 RCE）  

### 🔧 5. 全自动规则管理
- 自动发现规则源  
- 支持 ACL4SSR / anti-AD / clash-rules / Loyalsoldier  
- 自动注入 rule-providers  
- 自动排序规则，保证最优匹配顺序  

### ♻️ 6. 生命周期管理（Lifecycle Manager）
- AI 自检  
- 镜像健康检查  
- 缓存验证  
- 内存监控与自恢复  
- 组件健康检查  

---

## 📦 安装与使用

### 1. 将脚本放入你的仓库
例如：

```
/scripts/sirkey-override.js
```

### 2. 在 Mihomo 配置中引用覆写脚本

在你的 `config.yaml` 中加入：

```yaml
script:
  path: ./scripts/sirkey-override.js
  arguments:
    profile: default
```

### 3. 使用方式

Mihomo 会自动调用脚本的：

```js
main(config, profileName)
```

脚本会对你的配置进行：

- 自动区域识别  
- 自动规则注入  
- 自动代理组构建  
- 自动 AI 节点选择  
- 自动安全检查  
- 自动缓存优化  

无需任何额外操作。

---

## 📁 项目结构（建议）

```
.
├── scripts/
│   └── sirkey-override.js
├── README.md
└── config.yaml
```

---

## 🧠 架构设计

### 三层架构：

```
Core 层：Env / Utils / Logger / Storage / HttpClient / LRUCache
Runtime 层：RegionAutoManager / NodeStatsManager / AIEngine / SecurityGuard
AI 层：智能评分 / 场景识别 / 网络状态分析 / 节点选择
```

### 中央管理器（CentralManager）

统一管理：

- HTTP 客户端  
- 缓存  
- 安全系统  
- 区域系统  
- AI 系统  
- 生命周期系统  

---

## 🧪 测试建议（可选）

为了确保脚本在你的环境中达到最佳效果，建议进行：

- 大规模节点测试（>1000 节点）  
- 高并发测试（1000 并发调用 main）  
- 内存压力测试  
- 异常输入测试  
- 规则覆盖测试  

---

## 🛠️ 配置项说明（节选）

### Config.aiOptions

| 字段 | 说明 |
|------|------|
| scoring | AI 评分权重 |
| scenes | 场景权重覆盖 |
| protection | 节点保护策略 |
| cache | 缓存策略 |
| trendAnalysis | 趋势分析开关 |

### Config.regionOptions

| 字段 | 说明 |
|------|------|
| geoIpGrouping | 是否启用 GeoIP 聚合 |
| autoDiscover | 是否自动发现区域 |
| excludeHighPercentage | 是否排除占比过高区域 |
| ratioLimit | 区域占比阈值 |

---

## 🧩 常见问题（FAQ）

### Q1：脚本会修改我的原始配置吗？  
不会。所有修改都在覆写层完成，不会写回你的原始文件。

### Q2：脚本是否会泄露隐私？  
不会。  
- 私网 IP 不会外查  
- 高风险请求会被阻断  
- 所有敏感字段会被脱敏  

### Q3：脚本是否会导致节点频繁切换？  
不会。  
AI 引擎内置平滑机制（score 差值阈值 + 冷却时间）。

---

## 🧑‍💻 贡献

欢迎提交：

- Bug 报告  
- 性能优化  
- 新规则源  
- 新区域识别逻辑  
- 新 AI 评分策略  

---

## 📜 许可证

MIT License

---

## ⭐ Star 支持

如果这个项目对你有帮助，欢迎点一个 ⭐ 支持！

---

