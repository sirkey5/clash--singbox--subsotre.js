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

**clash-verge&flclash&mihomo.js** # 这是一个为 **Mihomo (Clash Meta)** 深度定制的高性能、智能化配置覆写脚本。该脚本旨在通过自动化、自适应和自愈机制，为用户提供一个极速、稳定且智能的代理环境。

## 🚀 核心特性

### 1. 🧠 智能 AI 决策引擎
*   **加权评分系统**：根据延迟、带宽、稳定性、抖动和在线时长等多维度指标自动评估节点。
*   **场景感知优化**：针对不同使用场景动态调整评分权重：
    *   **电竞模式 (Gaming)**：极低延迟与抖动优先。
    *   **流媒体模式 (Streaming)**：高带宽与连接稳定性优先。
    *   **网页浏览 (Browsing)**：平衡性能优化。
    *   **大文件下载 (Download)**：最大化带宽利用率。
*   **趋势预测**：分析节点性能走势，在节点质量下降前主动预判并切换。

### 2. ⚡ 自适应自愈闭环
*   **健康度评估**：实时监测脚本运行状态与节点连接健康度。
*   **渐进式恢复**：节点失效后进入隔离期，并在检测到性能回升后逐步恢复使用。
*   **风险回退**：若新配置导致异常，系统将自动触发回退机制，确保网络不中断。

### 3. 🌐 智能 GitHub 镜像系统
*   **自动优选镜像**：自动测速并选择最优的 GitHub 加速镜像（如 ghproxy, jsdelivr 等），确保资源更新可靠。
*   **无缝回退**：当镜像失效时，自动尝试备用镜像或直连，保障规则集始终可用。

### 4. 🛡️ 全方位规则管理
*   **自动发现机制**：智能识别并整合代理组与规则提供者（Rule Providers）。
*   **内置精选规则集**：深度集成 AI (OpenAI, Claude, Gemini)、流媒体 (Netflix, YouTube, Disney+)、社交软件 (Telegram, Discord)、游戏平台 (Steam, Epic) 等百余种规则。
*   **隐私与安全**：内置敏感信息脱敏系统，支持加密 DNS (DoH/DoT) 及复杂的 DNS 路由策略。

### 5. 🛠️ 技术优势
*   **跨平台兼容**：支持 Mihomo (Clash Meta) 内核环境，同时兼容 Node.js 脚本执行及浏览器调试。
*   **极致性能**：深度优化的代码逻辑，即使在处理上万条规则时也能保持极低的 CPU 和内存占用。
*   **高健壮性**：完善的错误处理框架，即使脚本发生崩溃也能通过 `ErrorConfigFactory` 返回基础可用配置。

## 📦 安装与使用

### 1. 在 Mihomo (Clash Meta) 中使用
将脚本内容添加至配置文件的 `parsers` 处理器中，或作为外部 `script` 引入。

```yaml
# 示例：作为 parser 引入
parsers:
  - url: 您的订阅链接
    code: |
      // 引入脚本并执行 main 函数
      const SirkeyScript = '...脚本内容...';
      function parse(config, { name }) {
        return main(config, name);
      }
```

### 2. 本地开发与测试
脚本支持在 Node.js 环境下直接运行，方便开发者进行配置调试。


## ⚙️ 配置项说明

脚本提供丰富的 `Config` 对象供用户自定义：

*   **`aiOptions`**：调整评分权重、评估阈值及缓存策略。
*   **`ruleOptions`**：自定义规则集的启用状态及默认行为。
*   **`regionOptions`**：根据正则匹配自定义节点地域分组及图标。
*   **`dns`**：配置 Fake-IP 过滤、分流解析及上游 DNS 服务器。
*   **`privacy`**：管理 GitHub 镜像开关及外部资源获取偏好。

## 📂 项目架构

*   `CentralManager`：核心调度器，管理配置生成的全生命周期。
*   `AIEngine`：负责智能节点评分与优选逻辑。
*   `SelfHealingEngine`：执行健康监测与自愈任务。
*   `ConfigBuilder`：负责组装最终的 Mihomo 兼容配置。
*   `GitHub Mirror System`：动态维护资源下载链路。

## 🤝 致谢

感谢以下项目提供的规则集与灵感：
*   [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)
*   [Loyalsoldier/clash-rules](https://github.com/Loyalsoldier/clash-rules)
*   [ACL4SSR/ACL4SSR](https://github.com/ACL4SSR/ACL4SSR)
*   [Koolson/Qure](https://github.com/Koolson/Qure) (图标库)

---
