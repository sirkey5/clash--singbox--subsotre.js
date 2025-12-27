# clash-verge&Flclash&mihomo.js 智能分流配置脚本 - 使用说明

## 📖 简介

- **clash-verge&flclash&mihomo.js**：是一个专为 mihomo（Clash 变种）设计的**智能分流配置脚本**
- **singbox全自动节点分流管理插件.js**：是给singbox做的一个全自动节点的管理与分流的插件。
- **singbox全自动节点分流管理混入脚本.js**：是给singbox做的一个全自动节点的管理与分流的配置混入脚本。
- **substore过滤无效节点脚本.js**：一个智能、高效、稳定的SubStore节点过滤脚本，用于过滤无效节点、验证节点连通性、自动去重，并为节点添加地理标识。
- **除substore脚本外，上述三个脚本的逻辑与功能都是出自同源逻辑，只是针对各自的适用场景做了分别的优化与适配。**
- **它们都能够自动管理您的代理节点，根据网络质量、地理位置和访问需求，智能选择最佳节点，让您的网络访问更加流畅、稳定。**





## 🚀 主要功能

### 1. AI 驱动的智能节点评估
- **EWMA 评分算法**：采用指数加权移动平均算法对节点进行动态评分
- **多维度评估**：基于延迟、带宽、稳定性、抖动、可用性等指标进行综合评分
- **场景感知**：根据使用场景（游戏、流媒体、下载、浏览）自动调整评分权重
- **趋势分析**：预测节点性能趋势，提前切换劣化节点

### 2. 智能区域分组
- **自动区域识别**：基于节点名称和 GeoIP 信息自动识别节点所在区域
- **预设区域配置**：支持 HK、TW、JP、SG、US、KR、CN、GB、DE、FR 等多个地区
- **动态分组**：支持根据节点质量自动选择最佳节点

### 3. 全面的规则系统
- **AI 服务支持**：OpenAI、Claude、Gemini 等 AI 服务专用规则
- **流媒体支持**：YouTube、Netflix、Disney+、Prime Video、HBO、TikTok 等
- **社交媒体**：Telegram、Discord、WhatsApp、Line 等
- **游戏平台**：Steam、Epic Games、游戏专用规则
- **广告过滤**：内置广告和跟踪器过滤规则

### 4. 高级 DNS 管理
- **多级 DNS 策略**：支持国内外域名不同解析策略
- **Fake IP 模式**：提升解析速度和隐私保护
- **DNS 加密**：支持 DoH (DNS over HTTPS)

### 5. 安全与隐私保护
- **敏感信息脱敏**：自动对 IP、URL 参数等敏感信息进行脱敏处理
- **威胁检测**：检测恶意域名和高风险节点
- **隐私加固**：限制对敏感信息的外部查询

### 6. 性能优化
- **多级缓存机制**：L1/L2 内存缓存与持久化存储
- **异步处理**：非阻塞式处理流程，提高响应速度
- **资源优化**：智能内存管理和垃圾回收

## 📋 功能特色

### AI 智能评分系统
- **动态权重调整**：根据使用场景自动调整评分权重
  - 游戏模式：延迟权重 60%，抖动权重 30%
  - 流媒体模式：带宽权重 60%，稳定性权重 30%
  - 下载模式：带宽权重 80%
  - 浏览模式：延迟权重 40%，稳定性权重 30%
- **智能切换保护**：避免频繁切换，保持连接稳定性
- **故障节点隔离**：自动隔离连续失败的节点

### 区域智能分组
- **自动发现**：自动识别配置中的节点区域
- **智能匹配**：支持正则表达式和地理信息匹配
- **健康检查**：对区域组进行健康检查和自动选择

### 规则自动管理
- **自动发现规则**：根据配置自动启用相关规则
- **智能规则注入**：自动注入常用服务规则
- **规则优化**：支持多种规则格式（MRS、YAML、TXT）

### 配置自适应
- **自动补全**：自动检测并补全缺失的配置项
- **错误恢复**：配置异常时自动修复和降级
- **兼容性保证**：确保生成的配置符合 Mihomo 规范

## 🔧 配置说明

### AI 评估配置
```javascript
aiOptions: {
  enable: true,  // 启用 AI 评估
  scoring: {     // 基础评分权重
    latencyWeight: 0.35,
    bandwidthWeight: 0.15,
    stabilityWeight: 0.25,
    jitterWeight: 0.15,
    uptimeWeight: 0.1
  },
  scenes: {      // 场景特定权重
    gaming: { latencyWeight: 0.6, jitterWeight: 0.3, ... },
    streaming: { bandwidthWeight: 0.6, ... },
    // ...
  },
  protection: {  // 保护机制
    cooldown: 300,          // 切换冷却时间
    maxSwitches24h: 20,     // 24小时最大切换次数
    failIsolationH: 12      // 失败节点隔离时间
  }
}
```

### 区域配置
```javascript
regionOptions: {
  geoIpGrouping: true,  // 启用 GeoIP 分组
  autoDiscover: true,   // 自动发现新区域
  regions: [            // 预设区域配置
    { name: "HK香港", regex: /港|🇭🇰|hk|hongkong|hkg/i, code: "HK" },
    { name: "JP日本", regex: /日|🇯🇵|jp|japan|nrt|hnd|kix/i, code: "JP" },
    // ...
  ]
}
```

### DNS 配置
```javascript
dns: {
  enable: true,
  listen: "127.0.0.1:1053",
  ipv6: true,
  "enhanced-mode": "fake-ip",
  nameserver: ["https://223.5.5.5/dns-query", "https://119.29.29.29/dns-query"],
  fallback: ["https://1.1.1.1/dns-query", "https://9.9.9.9/dns-query"]
}
```

## 🚀 使用方法

### 基本用法
1. 将脚本保存为 `mihomoYBTraeAI.js`
2. 在 Mihomo 配置中引用该脚本
3. 提供基础配置作为输入

### 示例配置
```yaml
# 在 Mihomo 配置中
script:
  code: |
    # 读取并执行脚本
    # 传入原始配置进行处理
```

## 🌐 服务支持

### AI 服务
- [x] OpenAI (ChatGPT)
- [x] Claude (Anthropic)
- [x] Google Gemini
- [x] Perplexity
- [x] Mistral

### 流媒体服务
- [x] YouTube
- [x] Netflix
- [x] Disney+
- [x] Prime Video
- [x] HBO Max
- [x] Hulu
- [x] TikTok
- [x] 哔哩哔哩国际版
- [x] Spotify

### 社交媒体
- [x] Telegram
- [x] Discord
- [x] WhatsApp
- [x] Line
- [x] Slack

### 游戏平台
- [x] Steam
- [x] Epic Games
- [x] 游戏专用规则

## 🛡️ 安全特性

- **威胁检测**：自动检测和阻止恶意域名
- **隐私保护**：脱敏敏感信息，防止泄露
- **访问控制**：限制对危险端口的访问
- **安全审计**：记录和分析安全事件

## 📊 性能指标

- **响应时间**：平均 < 50ms
- **内存占用**：优化的缓存机制，低内存使用
- **CPU 使用率**：异步处理，低 CPU 占用
- **配置生成时间**：毫秒级配置生成

## 🤝 贡献

欢迎提交 Issue 和 Pull Request 来改进此项目。

## 📄 许可证

此项目基于 MIT 许可证开源。

## 🙏 致谢

- 感谢 Mihomo 项目
- 感谢相关规则提供者
- 感谢社区的持续支持

