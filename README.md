给Flclash和mihomo party，以及clash verge做节点配置的js脚本。

具体功能包含如下：
- 1.
智能节点选择 ：基于内置了一个 AI 模型，评估节点质量，自动选择最佳节点
- 2.
地理路由 ：根据目标 IP 地理信息智能选择地区节点
- 3.
多级缓存 ：实现 LRU 缓存机制，提高系统响应速度
- 4.
并发控制 ：通过并发池控制节点测试和请求处理
- 5.
故障降级 ：实现多级降级策略，确保系统稳定性
- 6.
数据持久化 ：支持节点数据的持久化存储和加载
- 7.
事件驱动 ：采用事件驱动架构，提高系统灵活性
- 8.
统计分析 ：提供丰富的统计功能，用于节点质量评估

相关功能的实现原理：

### 1. 整体架构概述
该代码是一个用于智能代理选择和配置生成的 JavaScript 模块，主要面向 Clash/Mihomo 核心的代理管理。它实现了基于 AI 的节点评估、地理路由、智能配置生成等功能。

### 2. 核心组件分析 2.1 常量定义 (CONSTANTS)
```
const CONSTANTS = {
  NODE_PREHEAT_COUNT: 3,
  BATCH_SIZE: 10,
  CONCURRENCY_LIMIT: 5,
  // ... 其他常量
};
```
实现原理：定义系统运行所需的各种常量参数，用于控制节点预热数量、批处理大小、并发限制等。
 2.2 事件发射器基类 (EventEmitter)
```
class EventEmitter {
  // 实现了基本的事件订阅和发布机制
}
```
实现原理：提供事件驱动的编程模型，允许组件之间进行松耦合通信。
 2.3 应用状态类 (AppState)
```
class AppState {
  constructor() {
    this.nodes = new Map();
    this.metrics = new Map();
    // ...
  }
}
```
实现原理：维护应用的全局状态，包括节点信息、指标数据等。
 2.4 LRU缓存类 (LRUCache)
```
class LRUCache {
  // 实现了基于 Map 的 LRU 缓存机制
}
```
实现原理：通过 Map 数据结构实现最近最少使用缓存淘汰策略，用于缓存 IP 地理信息、节点指标等。
 2.5 滚动统计类 (RollingStats)
```
class RollingStats {
  // 实现了滑动窗口统计
}
```
实现原理：维护一个固定大小的滑动窗口，用于计算延迟等指标的统计信息。
 2.6 成功率跟踪类 (SuccessRateTracker)
```
class SuccessRateTracker {
  // 跟踪请求成功率
}
```
实现原理：记录成功和失败次数，计算成功率。
 2.7 节点管理器类 (NodeManager)
```
class NodeManager {
  // 管理节点质量评分和历史记录
}
```
实现原理：维护节点的质量评分和历史记录，提供获取最佳节点的方法。
 2.8 中央管理器类 (CentralManager)
这是整个系统的核心类，包含以下主要功能：
 a. 网络请求与超时控制
```
async _safeFetch(url, options = {}, timeout = 
5000)
```
实现原理：封装 fetch API，添加超时控制和 AbortController 支持，防止请求长时间挂起。
 b. IP 地理信息查询
```
async getGeoInfo(ip, domain)
```
实现原理：通过 ip-api.com 和 ipinfo.io 等多个 API 获取 IP 地理信息，并实现多级降级策略和缓存机制。
 c. 数据持久化
```
async loadAIDBFromFile()
async saveAIDBToFile()
```
实现原理：实现 AI 节点数据的加载和保存功能，支持多环境存储（浏览器、Node.js 等）。
 d. 事件系统
```
setupEventListeners()
cleanupEventListeners()
```
实现原理：管理配置变更、网络状态等事件监听，确保资源正确释放。
 e. 节点评估机制
```
async preheatNodes()
async calculateNodeQualityScore()
autoEliminateNodes()
```
实现原理：通过预热节点、计算质量评分和自动淘汰低质量节点来维护节点池的健康状态。
 f. 地理感知路由
```
async handleRequestWithGeoRouting()
```
实现原理：根据目标 IP 的地理信息智能选择相应地区的节点。
 g. 代理请求处理
```
async handleProxyRequest()
```
实现原理：实现智能节点选择和请求转发逻辑。
 h. AI节点评分模型
```
aiScoreNode()
extractNodeFeatures()
predictNodeFuturePerformance()
```
实现原理：基于多维度指标（延迟、丢包、抖动、成功率等）预测节点未来表现，并计算评分调整值。
 i. 配置处理
```
processConfiguration()
```
实现原理：处理原始配置对象，生成最终的代理配置，包括代理组、规则等。

### 3. 工具函数模块 (Utils) 3.1 地区代理过滤
```
filterProxiesByRegion()
```
实现原理：根据地区正则表达式和倍率限制过滤代理节点。
 3.2 服务组创建
```
createServiceGroups()
```
实现原理：根据配置创建不同的服务组和规则。
 3.3 并发控制
```
runWithConcurrency()
asyncPool()
```
实现原理：实现并发任务执行控制，避免资源耗尽。
 3.4 重试机制
```
retry()
```
实现原理：实现指数退避重试机制，提高系统稳定性。
 3.5 统计计算
```
calculateWeightedAverage()
calculateStdDev()
calculateTrend()
calculatePercentile()
```
实现原理：提供各种统计计算方法，用于节点质量评估。

### 4. 配置系统 (Config) 4.1 规则选项
定义了各种服务的启用开关。
 4.2 地区配置
定义了不同地区节点的识别规则和倍率限制。
 4.3 DNS配置
配置了 DNS 相关参数，包括 nameserver、策略等。
 4.4 服务配置
定义了各种服务的规则、图标、URL 等信息。
 4.5 系统配置
配置了 Clash/Mihomo 核心的各种系统参数。

### 5. 主函数 (main)
```
function main(config)
```
实现原理：作为入口函数，创建 CentralManager 实例并处理配置。
