// SubStore 节点过滤脚本 - 超时修复版
// 版本: 17.0 (2026) - 修复订阅超时问题
// 主要改进:
// 1. 地理位置API超时从18秒降到3秒
// 2. DNS解析超时从5秒降到2秒
// 3. 增加整体超时保护机制
// 4. 优化并发策略
// 5. 添加快速失败机制

"use strict";

// ==================== 配置 ====================
const CONFIG = Object.freeze({
  INVALID_KEYWORDS: ["过期","失效","expired","invalid","到期","流量用尽","已用完","disabled"],
  MAX_MULTIPLIER: 10, 
  CONCURRENCY: 8,  // 提高并发数
  TIMEOUT: 5000,   // 降低基础超时
  RETRY_TIMES: 0,
  SUPPORTED_TYPES: new Set(["ss","ssr","vmess","trojan","vless","hysteria","hysteria2","tuic","wireguard","snell"]),
  PORT_BLACKLIST: new Set([25,135,137,138,139,445,1433,3306,3389,69,143,161,162,465,587,993,995,5432,6379,22,23,1935,554,37777,47808]),
  MAX_LATENCY: 1000, MIN_SPEED: 0.5, MIN_QUALITY_SCORE: 30,
  USER_AGENT: "SubStore/1.1 (Optimized)",
  
  // ===== 超时优化配置 =====
  GLOBAL_TIMEOUT: 25000,  // 全局超时25秒，留5秒给SubStore其他操作
  GEO_API_TIMEOUT: 3000,  // 地理API超时从18秒降到3秒
  DNS_TIMEOUT: 2000,      // DNS超时从5秒降到2秒
  MAX_GEO_API_CALLS: 20,  // 最多调用20次地理API，超出跳过
  
  GEO_APIS: [
    // 使用更快的API，按响应速度排序
    "https://ipwho.is/{ip}",
    "http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,isp&lang=zh-CN",
    "https://api.ip.sb/geoip/{ip}"
    // 移除较慢的API
  ],
  enableRemoteGeo: true,
  enableDNSResolve: true,  // 可选关闭DNS解析
  
  // 压缩的IP段数据（541个IP段）
  STATIC_IP_DATA: `185.209.49.0|185.209.49.255|阿联酋
94.140.0.0|94.140.0.255|阿联酋
31.56.237.0|31.56.237.255|德国
185.94.29.0|185.94.29.255|德国
147.45.196.0|147.45.196.255|德国
185.78.76.0|185.78.76.255|德国
80.66.85.0|80.66.85.255|德国
185.254.97.0|185.254.97.255|德国
194.58.33.0|194.58.33.255|德国
212.113.116.0|212.113.116.255|德国
87.251.87.0|87.251.87.255|德国
185.247.118.0|185.247.118.255|德国
5.39.249.0|5.39.249.255|德国
147.45.197.0|147.45.197.255|德国
217.110.20.0|217.110.20.255|德国
194.9.6.0|194.9.6.255|德国
95.179.164.0|95.179.164.255|德国
193.37.70.0|193.37.70.255|德国
45.32.153.0|45.32.153.255|德国
194.87.77.0|194.87.77.255|德国
88.99.252.0|88.99.252.255|德国
194.180.188.0|194.180.188.255|德国
88.198.18.0|88.198.18.255|德国
91.149.222.0|91.149.222.255|德国
91.228.154.0|91.228.154.255|德国
51.89.23.0|51.89.23.255|德国
159.69.180.0|159.69.180.255|德国
51.75.74.0|51.75.74.255|德国
139.59.152.0|139.59.152.255|德国
85.209.195.0|85.209.195.255|德国
54.38.159.0|54.38.159.255|德国
51.195.47.0|51.195.47.255|德国
51.75.75.0|51.75.75.255|德国
91.107.233.0|91.107.233.255|德国
167.172.163.0|167.172.163.255|德国
31.172.70.0|31.172.70.255|德国
193.226.77.0|193.226.77.255|德国
139.144.77.0|139.144.77.255|德国
199.59.229.0|199.59.229.255|德国
135.125.234.0|135.125.234.255|德国
51.195.119.0|51.195.119.255|德国
162.19.243.0|162.19.243.255|德国
162.19.253.0|162.19.253.255|德国
162.19.254.0|162.19.254.255|德国
51.195.42.0|51.195.42.255|德国
85.193.92.0|85.193.92.255|德国
92.51.36.0|92.51.36.255|德国
217.25.91.0|217.25.91.255|德国
194.35.119.0|194.35.119.255|德国
5.44.47.0|5.44.47.255|德国
95.140.154.0|95.140.154.255|德国
89.19.211.0|89.19.211.255|德国
90.156.228.0|90.156.228.255|德国
85.193.95.0|85.193.95.255|德国
31.56.113.0|31.56.113.255|芬兰
31.57.106.0|31.57.106.255|芬兰
185.106.94.0|185.106.94.255|芬兰
109.248.163.0|109.248.163.255|芬兰
185.188.181.0|185.188.181.255|芬兰
139.28.221.0|139.28.221.255|芬兰
37.27.85.0|37.27.85.255|芬兰
77.91.78.0|77.91.78.255|芬兰
185.17.2.0|185.17.2.255|芬兰
135.181.250.0|135.181.250.255|芬兰
95.217.195.0|95.217.195.255|芬兰
37.27.15.0|37.27.15.255|芬兰
95.214.9.0|95.214.9.255|芬兰
109.120.184.0|109.120.184.255|芬兰
37.27.90.0|37.27.90.255|芬兰
65.109.210.0|65.109.210.255|芬兰
65.109.202.0|65.109.202.255|芬兰
65.109.161.0|65.109.161.255|芬兰
185.40.7.0|185.40.7.255|芬兰
185.105.118.0|185.105.118.255|芬兰
65.108.242.0|65.108.242.255|芬兰
23.164.240.0|23.164.240.255|芬兰
91.149.219.0|91.149.219.255|芬兰
46.8.228.0|46.8.228.255|芬兰
193.84.2.0|193.84.2.255|芬兰
46.8.237.0|46.8.237.255|芬兰
109.206.236.0|109.206.236.255|芬兰
87.239.250.0|87.239.250.255|芬兰
104.252.127.0|104.252.127.255|芬兰
185.104.250.0|185.104.250.255|芬兰
31.57.118.0|31.57.118.255|美国
104.29.125.0|104.29.125.255|美国
162.159.160.0|162.159.160.255|美国
104.26.13.0|104.26.13.255|美国
170.114.52.0|170.114.52.255|美国
172.67.65.0|172.67.65.255|美国
172.67.79.0|172.67.79.255|美国
104.26.4.0|104.26.4.255|美国
66.98.121.0|66.98.121.255|美国
107.173.87.0|107.173.87.255|美国
172.93.43.0|172.93.43.255|美国
142.171.233.0|142.171.233.255|美国
173.44.141.0|173.44.141.255|美国
144.34.186.0|144.34.186.255|美国
192.9.137.0|192.9.137.255|美国
64.225.2.0|64.225.2.255|美国
194.113.211.0|194.113.211.255|美国
198.46.143.0|198.46.143.255|美国
23.95.113.0|23.95.113.255|美国
104.234.50.0|104.234.50.255|美国
35.247.124.0|35.247.124.255|美国
74.48.89.0|74.48.89.255|美国
104.19.213.0|104.19.213.255|美国
104.16.201.0|104.16.201.255|美国
104.18.189.0|104.18.189.255|美国
104.16.107.0|104.16.107.255|美国
104.16.101.0|104.16.101.255|美国
141.101.114.0|141.101.114.255|美国
104.18.209.0|104.18.209.255|美国
103.31.4.0|103.31.4.255|美国
104.16.131.0|104.16.131.255|美国
45.81.58.0|45.81.58.255|美国
77.74.228.0|77.74.228.255|美国
159.112.235.0|159.112.235.255|美国
205.233.181.0|205.233.181.255|美国
196.207.45.0|196.207.45.255|美国
104.24.137.0|104.24.137.255|美国
104.20.42.0|104.20.42.255|美国
184.174.80.0|184.174.80.255|美国
162.159.251.0|162.159.251.255|美国
104.25.179.0|104.25.179.255|美国
103.21.244.0|103.21.244.255|美国
172.67.122.0|172.67.122.255|美国
172.64.235.0|172.64.235.255|美国
154.211.8.0|154.211.8.255|美国
66.225.252.0|66.225.252.255|美国
155.46.167.0|155.46.167.255|美国
103.116.7.0|103.116.7.255|美国
45.150.164.0|45.150.164.255|美国
65.49.195.0|65.49.195.255|美国
72.18.81.0|72.18.81.255|美国
72.18.83.0|72.18.83.255|美国
45.151.133.0|45.151.133.255|美国
172.83.159.0|172.83.159.255|美国
173.249.210.0|173.249.210.255|美国
141.11.95.0|141.11.95.255|美国
192.9.138.0|192.9.138.255|美国
142.171.156.0|142.171.156.255|美国
23.105.199.0|23.105.199.255|美国
132.226.119.0|132.226.119.255|美国
107.182.179.0|107.182.179.255|美国
74.48.221.0|74.48.221.255|美国
142.171.85.0|142.171.85.255|美国
89.208.250.0|89.208.250.255|美国
47.251.70.0|47.251.70.255|美国
152.70.143.0|152.70.143.255|美国
129.159.37.0|129.159.37.255|美国
97.64.26.0|97.64.26.255|美国
74.48.179.0|74.48.179.255|美国
155.248.193.0|155.248.193.255|美国
104.234.36.0|104.234.36.255|美国
141.148.164.0|141.148.164.255|美国
172.96.194.0|172.96.194.255|美国
129.153.91.0|129.153.91.255|美国
74.48.4.0|74.48.4.255|美国
141.148.1.0|141.148.1.255|美国
141.148.181.0|141.148.181.255|美国
129.146.22.0|129.146.22.255|美国
23.94.94.0|23.94.94.255|美国
34.69.150.0|34.69.150.255|美国
34.83.245.0|34.83.245.255|美国
74.48.140.0|74.48.140.255|美国
64.176.210.0|64.176.210.255|美国
172.96.192.0|172.96.192.255|美国
138.2.231.0|138.2.231.255|美国
148.135.110.0|148.135.110.255|美国
54.189.161.0|54.189.161.255|美国
148.135.52.0|148.135.52.255|美国
195.123.241.0|195.123.241.255|美国
152.70.113.0|152.70.113.255|美国
155.248.214.0|155.248.214.255|美国
173.249.201.0|173.249.201.255|美国
144.34.163.0|144.34.163.255|美国
65.49.192.0|65.49.192.255|美国
146.235.209.0|146.235.209.255|美国
64.64.227.0|64.64.227.255|美国
129.146.6.0|129.146.6.255|美国
142.171.94.0|142.171.94.255|美国
104.18.41.0|104.18.41.255|美国
172.64.38.0|172.64.38.255|美国
172.64.40.0|172.64.40.255|美国
172.64.151.0|172.64.151.255|美国
104.18.32.0|104.18.32.255|美国
104.16.93.0|104.16.93.255|美国
104.18.206.0|104.18.206.255|美国
104.18.158.0|104.18.158.255|美国
104.16.175.0|104.16.175.255|美国
104.17.109.0|104.17.109.255|美国
108.162.198.0|108.162.198.255|美国
104.26.5.0|104.26.5.255|美国
198.41.223.0|198.41.223.255|美国
8.35.210.0|8.35.210.255|美国
172.64.229.0|172.64.229.255|美国
173.245.58.0|173.245.58.255|美国
104.18.45.0|104.18.45.255|美国
104.19.36.0|104.19.36.255|美国
162.159.153.0|162.159.153.255|美国
172.64.144.0|172.64.144.255|美国
162.159.43.0|162.159.43.255|美国
104.19.35.0|104.19.35.255|美国
8.39.125.0|8.39.125.255|美国
173.245.59.0|173.245.59.255|美国
104.19.43.0|104.19.43.255|美国
104.18.36.0|104.18.36.255|美国
104.19.58.0|104.19.58.255|美国
104.19.33.0|104.19.33.255|美国
172.64.146.0|172.64.146.255|美国
162.159.152.0|162.159.152.255|美国
104.19.60.0|104.19.60.255|美国
104.19.55.0|104.19.55.255|美国
162.159.32.0|162.159.32.255|美国
162.159.45.0|162.159.45.255|美国
162.159.36.0|162.159.36.255|美国
172.64.228.0|172.64.228.255|美国
104.26.9.0|104.26.9.255|美国
104.18.43.0|104.18.43.255|美国
162.159.41.0|162.159.41.255|美国
104.26.12.0|104.26.12.255|美国
104.26.6.0|104.26.6.255|美国
104.19.44.0|104.19.44.255|美国
104.19.63.0|104.19.63.255|美国
104.19.38.0|104.19.38.255|美国
104.19.32.0|104.19.32.255|美国
172.64.145.0|172.64.145.255|美国
104.18.42.0|104.18.42.255|美国
8.35.211.0|8.35.211.255|美国
104.26.1.0|104.26.1.255|美国
104.18.44.0|104.18.44.255|美国
162.159.39.0|162.159.39.255|美国
154.91.34.0|154.91.34.255|美国
162.159.128.0|162.159.128.255|美国
104.27.0.0|104.27.0.255|美国
104.20.192.0|104.20.192.255|美国
104.25.0.0|104.25.0.255|美国
198.41.211.0|198.41.211.255|美国
104.19.0.0|104.19.0.255|美国
104.23.128.0|104.23.128.255|美国
172.67.96.0|172.67.96.255|美国
104.20.96.0|104.20.96.255|美国
104.18.128.0|104.18.128.255|美国
104.24.64.0|104.24.64.255|美国
104.19.128.0|104.19.128.255|美国
173.245.49.0|173.245.49.255|美国
104.27.32.0|104.27.32.255|美国
172.67.192.0|172.67.192.255|美国
104.19.224.0|104.19.224.255|美国
104.25.32.0|104.25.32.255|美国
172.67.32.0|172.67.32.255|美国
104.24.224.0|104.24.224.255|美国
104.23.96.0|104.23.96.255|美国
104.19.64.0|104.19.64.255|美国
104.24.192.0|104.24.192.255|美国
104.22.64.0|104.22.64.255|美国
198.41.220.0|198.41.220.255|美国
104.20.64.0|104.20.64.255|美国
162.159.46.0|162.159.46.255|美国
104.19.96.0|104.19.96.255|美国
104.25.64.0|104.25.64.255|美国
104.20.224.0|104.20.224.255|美国
104.25.128.0|104.25.128.255|美国
198.41.208.0|198.41.208.255|美国
104.24.160.0|104.24.160.255|美国
104.20.128.0|104.20.128.255|美国
141.101.120.0|141.101.120.255|美国
141.101.113.0|141.101.113.255|美国
104.25.96.0|104.25.96.255|美国
104.22.32.0|104.22.32.255|美国
104.20.32.0|104.20.32.255|美国
104.27.96.0|104.27.96.255|美国
104.16.96.0|104.16.96.255|美国
104.18.0.0|104.18.0.255|美国
104.17.32.0|104.17.32.255|美国
104.19.192.0|104.19.192.255|美国
104.20.160.0|104.20.160.255|美国
104.17.0.0|104.17.0.255|美国
172.67.64.0|172.67.64.255|美国
104.16.128.0|104.16.128.255|美国
172.67.0.0|172.67.0.255|美国
104.19.160.0|104.19.160.255|美国
104.16.192.0|104.16.192.255|美国
104.16.0.0|104.16.0.255|美国
104.24.32.0|104.24.32.255|美国
104.16.224.0|104.16.224.255|美国
104.17.96.0|104.17.96.255|美国
104.16.32.0|104.16.32.255|美国
104.17.160.0|104.17.160.255|美国
104.17.192.0|104.17.192.255|美国
104.18.64.0|104.18.64.255|美国
104.17.64.0|104.17.64.255|美国
104.18.224.0|104.18.224.255|美国
104.18.96.0|104.18.96.255|美国
104.18.160.0|104.18.160.255|美国
104.17.224.0|104.17.224.255|美国
104.18.192.0|104.18.192.255|美国
104.16.64.0|104.16.64.255|美国
104.17.68.0|104.17.68.255|美国
104.16.242.0|104.16.242.255|美国
2.56.204.0|2.56.204.255|亚美尼亚
194.156.103.0|194.156.103.255|亚美尼亚
213.159.76.0|213.159.76.255|亚美尼亚
170.64.152.0|170.64.152.255|澳大利亚
170.64.227.0|170.64.227.255|澳大利亚
206.201.196.0|206.201.196.255|澳大利亚
103.11.212.0|103.11.212.255|澳大利亚
1.0.0.0|1.0.0.255|澳大利亚
91.215.153.0|91.215.153.255|保加利亚
78.128.127.0|78.128.127.255|保加利亚
31.56.48.0|31.56.48.255|法国
88.218.76.0|88.218.76.255|法国
88.218.78.0|88.218.78.255|法国
89.208.97.0|89.208.97.255|法国
141.145.216.0|141.145.216.255|法国
188.130.207.0|188.130.207.255|法国
95.182.96.0|95.182.96.255|法国
193.42.62.0|193.42.62.255|法国
46.8.224.0|46.8.224.255|法国
46.226.167.0|46.226.167.255|法国
193.70.0.0|193.70.0.255|法国
51.83.45.0|51.83.45.255|法国
54.36.103.0|54.36.103.255|法国
51.91.251.0|51.91.251.255|法国
51.178.141.0|51.178.141.255|法国
51.38.49.0|51.38.49.255|法国
141.94.220.0|141.94.220.255|法国
146.59.225.0|146.59.225.255|法国
152.228.134.0|152.228.134.255|法国
188.165.26.0|188.165.26.255|法国
188.165.137.0|188.165.137.255|法国
51.178.83.0|51.178.83.255|法国
141.94.205.0|141.94.205.255|法国
51.210.150.0|51.210.150.255|法国
152.228.135.0|152.228.135.255|法国
37.59.97.0|37.59.97.255|法国
38.180.62.0|38.180.62.255|法国
94.23.153.0|94.23.153.255|法国
132.226.163.0|132.226.163.255|巴西
38.180.78.0|38.180.78.255|巴西
172.93.32.0|172.93.32.255|加拿大
192.18.150.0|192.18.150.255|加拿大
148.113.204.0|148.113.204.255|加拿大
138.197.152.0|138.197.152.255|加拿大
23.227.39.0|23.227.39.255|加拿大
104.244.78.0|104.244.78.255|瑞士
94.247.42.0|94.247.42.255|瑞士
45.85.93.0|45.85.93.255|瑞士
91.192.102.0|91.192.102.255|瑞士
38.180.85.0|38.180.85.255|瑞士
176.10.125.0|176.10.125.255|瑞士
179.43.190.0|179.43.190.255|瑞士
185.195.69.0|185.195.69.255|瑞士
45.95.232.0|45.95.232.255|瑞士
194.87.97.0|194.87.97.255|瑞士
91.245.225.0|91.245.225.255|瑞士
95.183.51.0|95.183.51.255|瑞士
129.151.104.0|129.151.104.255|智利
212.113.106.0|212.113.106.255|奥地利
109.237.98.0|109.237.98.255|荷兰
89.169.13.0|89.169.13.255|荷兰
77.221.148.0|77.221.148.255|荷兰
85.192.29.0|85.192.29.255|荷兰
194.0.194.0|194.0.194.255|荷兰
195.123.219.0|195.123.219.255|荷兰
195.54.174.0|195.54.174.255|荷兰
89.35.131.0|89.35.131.255|荷兰
194.26.232.0|194.26.232.255|荷兰
195.200.26.0|195.200.26.255|荷兰
163.5.207.0|163.5.207.255|荷兰
2.59.183.0|2.59.183.255|荷兰
185.244.49.0|185.244.49.255|荷兰
185.229.225.0|185.229.225.255|荷兰
185.126.225.0|185.126.225.255|荷兰
146.0.79.0|146.0.79.255|荷兰
213.183.61.0|213.183.61.255|荷兰
213.183.59.0|213.183.59.255|荷兰
168.100.9.0|168.100.9.255|荷兰
185.70.185.0|185.70.185.255|荷兰
5.255.120.0|5.255.120.255|荷兰
185.23.238.0|185.23.238.255|荷兰
188.116.21.0|188.116.21.255|荷兰
188.212.124.0|188.212.124.255|荷兰
38.180.99.0|38.180.99.255|荷兰
195.226.194.0|195.226.194.255|荷兰
176.222.55.0|176.222.55.255|荷兰
103.90.75.0|103.90.75.255|荷兰
89.150.35.0|89.150.35.255|荷兰
147.45.136.0|147.45.136.255|荷兰
91.184.242.0|91.184.242.255|荷兰
185.31.200.0|185.31.200.255|荷兰
147.45.111.0|147.45.111.255|荷兰
185.94.164.0|185.94.164.255|荷兰
68.183.10.0|68.183.10.255|荷兰
147.45.167.0|147.45.167.255|荷兰
13.95.69.0|13.95.69.255|荷兰
109.248.162.0|109.248.162.255|荷兰
24.144.76.0|24.144.76.255|荷兰
147.45.145.0|147.45.145.255|荷兰
46.8.68.0|46.8.68.255|荷兰
94.103.95.0|94.103.95.255|荷兰
77.238.253.0|77.238.253.255|荷兰
89.110.125.0|89.110.125.255|荷兰
159.100.199.0|159.100.199.255|荷兰
192.236.249.0|192.236.249.255|荷兰
94.131.123.0|94.131.123.255|土耳其
45.89.52.0|45.89.52.255|土耳其
188.132.129.0|188.132.129.255|土耳其
104.239.87.0|104.239.87.255|土耳其
45.194.11.0|45.194.11.255|土耳其
193.188.21.0|193.188.21.255|瑞典
193.233.115.0|193.233.115.255|瑞典
172.232.157.0|172.232.157.255|瑞典
172.234.96.0|172.234.96.255|瑞典
89.22.231.0|89.22.231.255|瑞典
78.40.117.0|78.40.117.255|瑞典
45.153.187.0|45.153.187.255|瑞典
129.151.198.0|129.151.198.255|瑞典
94.228.164.0|94.228.164.255|瑞典
109.120.135.0|109.120.135.255|瑞典
147.45.72.0|147.45.72.255|瑞典
94.228.163.0|94.228.163.255|瑞典
193.233.114.0|193.233.114.255|瑞典
89.22.232.0|89.22.232.255|瑞典
13.48.175.0|13.48.175.255|瑞典
89.28.236.0|89.28.236.255|丹麦
193.17.183.0|193.17.183.255|西班牙
93.93.119.0|93.93.119.255|西班牙
185.114.72.0|185.114.72.255|西班牙
185.231.204.0|185.231.204.255|西班牙
45.86.229.0|45.86.229.255|西班牙
212.227.144.0|212.227.144.255|西班牙
185.114.73.0|185.114.73.255|西班牙
51.38.140.0|51.38.140.255|波兰
146.59.19.0|146.59.19.255|波兰
31.133.0.0|31.133.0.255|波兰
185.188.147.0|185.188.147.255|波兰
176.105.253.0|176.105.253.255|波兰
45.144.48.0|45.144.48.255|波兰
45.144.51.0|45.144.51.255|波兰
193.124.41.0|193.124.41.255|波兰
91.239.148.0|91.239.148.255|波兰
91.149.221.0|91.149.221.255|波兰
185.245.83.0|185.245.83.255|英国
94.131.122.0|94.131.122.255|英国
18.170.77.0|18.170.77.255|英国
45.61.138.0|45.61.138.255|英国
91.149.238.0|91.149.238.255|英国
194.146.24.0|194.146.24.255|英国
109.169.76.0|109.169.76.255|英国
5.144.182.0|5.144.182.255|英国
2.56.91.0|2.56.91.255|中国香港
199.59.231.0|199.59.231.255|中国香港
156.224.73.0|156.224.73.255|中国香港
154.218.15.0|154.218.15.255|中国香港
154.207.79.0|154.207.79.255|中国香港
54.229.164.0|54.229.164.255|爱尔兰
63.32.194.0|63.32.194.255|爱尔兰
194.87.245.0|194.87.245.255|爱尔兰
212.80.205.0|212.80.205.255|以色列
77.91.69.0|77.91.69.255|以色列
147.75.228.0|147.75.228.255|印度
147.75.230.0|147.75.230.255|印度
104.22.0.0|104.22.0.255|印度
185.84.162.0|185.84.162.255|俄罗斯
213.159.208.0|213.159.208.255|俄罗斯
31.129.49.0|31.129.49.255|俄罗斯
45.135.135.0|45.135.135.255|俄罗斯
176.109.106.0|176.109.106.255|俄罗斯
176.57.211.0|176.57.211.255|俄罗斯
147.45.147.0|147.45.147.255|俄罗斯
89.111.172.0|89.111.172.255|俄罗斯
185.254.190.0|185.254.190.255|俄罗斯
95.163.242.0|95.163.242.255|俄罗斯
147.45.175.0|147.45.175.255|俄罗斯
95.163.240.0|95.163.240.255|俄罗斯
89.248.207.0|89.248.207.255|俄罗斯
85.193.91.0|85.193.91.255|俄罗斯
185.211.170.0|185.211.170.255|俄罗斯
90.156.211.0|90.156.211.255|俄罗斯
194.67.204.0|194.67.204.255|俄罗斯
194.87.252.0|194.87.252.255|俄罗斯
185.251.89.0|185.251.89.255|俄罗斯
31.128.37.0|31.128.37.255|俄罗斯
5.182.84.0|5.182.84.255|俄罗斯
185.59.218.0|185.59.218.255|俄罗斯
213.241.198.0|213.241.198.255|俄罗斯
185.105.89.0|185.105.89.255|俄罗斯
94.242.53.0|94.242.53.255|俄罗斯
188.213.168.0|188.213.168.255|意大利
185.247.184.0|185.247.184.255|意大利
80.211.231.0|80.211.231.255|意大利
152.70.82.0|152.70.82.255|日本
38.180.28.0|38.180.28.255|日本
140.83.57.0|140.83.57.255|日本
138.2.10.0|138.2.10.255|日本
158.101.152.0|158.101.152.255|日本
138.3.222.0|138.3.222.255|日本
168.138.192.0|168.138.192.255|日本
138.2.49.0|138.2.49.255|日本
217.142.250.0|217.142.250.255|日本
121.165.101.0|121.165.101.255|韩国
129.154.54.0|129.154.54.255|韩国
138.2.122.0|138.2.122.255|韩国
52.141.25.0|52.141.25.255|韩国
61.32.240.0|61.32.240.255|韩国
5.34.209.0|5.34.209.255|拉脱维亚
37.128.207.0|37.128.207.255|拉脱维亚
195.135.253.0|195.135.253.255|拉脱维亚
185.242.106.0|185.242.106.255|拉脱维亚
37.128.204.0|37.128.204.255|拉脱维亚
193.124.22.0|193.124.22.255|拉脱维亚
195.135.252.0|195.135.252.255|拉脱维亚
85.159.228.0|85.159.228.255|拉脱维亚
91.197.3.0|91.197.3.255|拉脱维亚
216.173.69.0|216.173.69.255|拉脱维亚
185.237.218.0|185.237.218.255|拉脱维亚
45.86.86.0|45.86.86.255|摩尔多瓦
194.68.44.0|194.68.44.255|罗马尼亚
45.67.34.0|45.67.34.255|罗马尼亚
152.42.236.0|152.42.236.255|新加坡
51.79.158.0|51.79.158.255|新加坡
203.29.54.0|203.29.54.255|新加坡
103.172.111.0|103.172.111.255|新加坡
45.32.100.0|45.32.100.255|新加坡
146.235.19.0|146.235.19.255|新加坡
34.143.159.0|34.143.159.255|新加坡
168.138.165.0|168.138.165.255|新加坡
213.35.100.0|213.35.100.255|新加坡
45.76.183.0|45.76.183.255|新加坡
14.102.228.0|14.102.228.255|捷克
195.85.59.0|195.85.59.255|塞浦路斯
77.75.199.0|77.75.199.255|塞浦路斯
86.38.251.0|86.38.251.255|塞浦路斯
143.20.247.0|143.20.247.255|比利时
46.202.30.0|46.202.30.255|马耳他
62.72.166.0|62.72.166.255|约旦
185.176.26.0|185.176.26.255|哈萨克斯坦
89.116.161.0|89.116.161.255|立陶宛
89.116.180.0|89.116.180.255|乌克兰`,
  
  ENCRYPTION_VALIDATION: {
    enabled: true, strictMode: false,
    allowedCiphers: {
      ss: ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305', '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm'],
      ssr: ['aes-128-gcm', 'aes-256-gcm', 'chacha20-ietf-poly1305']
    },
    forbiddenCiphers: ['rc4', 'rc4-md5', 'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb', 'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr'],
    requireTLS: ['trojan', 'vless']
  },
  TRANSPORT_VALIDATION: { enabled: true, strictMode: false, warnOnly: false },
  PERFORMANCE_METRICS: {
    enabled: true, extractMultiplier: true, extractBandwidth: true, extractLatency: true,
    extractQuality: true, useInScoring: true, displayInName: false,
    scoringWeights: {
      multiplierWeight: 2, multiplierMaxScore: 20, bandwidthGbpsWeight: 10,
      bandwidthMbpsWeight: 0.1, bandwidthMaxScore: 30, lowLatencyThreshold: 50,
      lowLatencyScore: 15, mediumLatencyThreshold: 100, mediumLatencyScore: 10,
      highLatencyThreshold: 200, highLatencyScore: 5
    }
  },
  DNS_RESOLVE: {
    enabled: true,
    dohProviders: [
      'https://cloudflare-dns.com/dns-query?name={host}&type=A',
      'https://dns.google/resolve?name={host}&type=A'
    ],
    timeout: 2000, cacheEnabled: true, cacheTTL: 3600000
  },
  JUNK_DOMAINS_FILTER: { enabled: false, strictMode: false, allowCDN: true, customDomains: [] },
  JUNK_DOMAINS: new Set([]),
  REQUIRE_ALPN: false,
  CDN_RANGES: [
    { start: '104.16.0.0', end: '104.31.255.255', name: 'Cloudflare' },
    { start: '172.64.0.0', end: '172.71.255.255', name: 'Cloudflare' },
    { start: '162.159.0.0', end: '162.159.255.255', name: 'Cloudflare' }
  ]
});

const REGEX = Object.freeze({
  PRIVATE_IP: /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|169\.254\.|224\.|localhost|0\.0\.0\.0)/,
  MULTIPLIER: /(?:[xX✕✖⨉倍率]|rate)[:\s]*([0-9]+\.?[0-9]*|0*\.[0-9]+)/i,
  MULTIPLIER_ALT: /([0-9]+\.?[0-9]*|0*\.[0-9]+)\s*(?:[xX✕✖⨉倍率])/i,
  IPV4: /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/,
  IPV6: /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})/,
  DOMAIN: /^(?!-)[a-zA-Z0-9-]{1,63}(?:\.(?!-)[a-zA-Z0-9-]{1,63})+$/,
  UUID: /^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$/,
  WG_KEY: /^[A-Za-z0-9+/]{42,43}=?$/,
  MARKETING: /([\u2700-\u27BF]|[\uE000-\uF8FF]|\uD83C[\uDC00-\uDFFF]|\uD83D[\uDC00-\uDFFF]|[\u2011-\u26FF]|\uD83E[\uDD10-\uDDFF]){3,}/,
  CONTACT: /(?:t\.me|群|联系|客服|网站|购买|订阅|获取|发布)/i
});

// ==================== 全局超时控制 ====================
class TimeoutController {
  constructor(timeoutMs) {
    this.timeoutMs = timeoutMs;
    this.startTime = Date.now();
    this.aborted = false;
  }
  
  check() {
    if (this.aborted) return false;
    if (Date.now() - this.startTime > this.timeoutMs) {
      this.aborted = true;
      return false;
    }
    return true;
  }
  
  remaining() {
    return Math.max(0, this.timeoutMs - (Date.now() - this.startTime));
  }
  
  elapsed() {
    return Date.now() - this.startTime;
  }
}

// ==================== 区间树实现 ====================
class IntervalNode {
  constructor(start, end, data) {
    this.start = start; this.end = end; this.max = end; this.data = data;
    this.left = null; this.right = null; this.height = 1;
  }
}

class IntervalTree {
  constructor() { this.root = null; }
  
  _getHeight(node) { return node ? node.height : 0; }
  _getBalance(node) { return node ? this._getHeight(node.left) - this._getHeight(node.right) : 0; }
  
  _updateNode(node) {
    if (!node) return;
    node.height = 1 + Math.max(this._getHeight(node.left), this._getHeight(node.right));
    node.max = node.end;
    if (node.left && node.left.max > node.max) node.max = node.left.max;
    if (node.right && node.right.max > node.max) node.max = node.right.max;
  }
  
  _rotateRight(y) {
    const x = y.left, T2 = x.right;
    x.right = y; y.left = T2;
    this._updateNode(y); this._updateNode(x);
    return x;
  }
  
  _rotateLeft(x) {
    const y = x.right, T2 = y.left;
    y.left = x; x.right = T2;
    this._updateNode(x); this._updateNode(y);
    return y;
  }
  
  insert(start, end, data) { this.root = this._insertNode(this.root, start, end, data); }
  
  _insertNode(node, start, end, data) {
    if (!node) return new IntervalNode(start, end, data);
    if (start < node.start) node.left = this._insertNode(node.left, start, end, data);
    else node.right = this._insertNode(node.right, start, end, data);
    
    this._updateNode(node);
    const balance = this._getBalance(node);
    
    if (balance > 1 && start < node.left.start) return this._rotateRight(node);
    if (balance < -1 && start >= node.right.start) return this._rotateLeft(node);
    if (balance > 1 && start >= node.left.start) {
      node.left = this._rotateLeft(node.left);
      return this._rotateRight(node);
    }
    if (balance < -1 && start < node.right.start) {
      node.right = this._rotateRight(node.right);
      return this._rotateLeft(node);
    }
    return node;
  }
  
  search(point) { return this._searchNode(this.root, point); }
  
  _searchNode(node, point) {
    if (!node) return null;
    if (point >= node.start && point <= node.end) return node.data;
    if (point < node.start) {
      if (node.left && node.left.max >= point) return this._searchNode(node.left, point);
      return null;
    }
    return this._searchNode(node.right, point);
  }
  
  static fromRanges(ranges) {
    const tree = new IntervalTree();
    const sorted = ranges.sort((a, b) => a.start - b.start);
    sorted.forEach(range => tree.insert(range.start, range.end, range.data));
    return tree;
  }
}

// ==================== 工具函数 ====================
const utils = {
  cache: new Map(),
  geoApiCallCount: 0,  // 地理API调用计数器
  
  async limit(tasks, concurrency, timeoutController = null) {
    const results = [], executing = new Set();
    for (const task of tasks) {
      // 检查超时
      if (timeoutController && !timeoutController.check()) {
        console.log(`[超时控制] 任务被中断，已完成 ${results.length}/${tasks.length}`);
        break;
      }
      
      const p = Promise.resolve().then(() => task());
      results.push(p); executing.add(p);
      const clean = () => executing.delete(p);
      p.then(clean, clean);
      if (executing.size >= concurrency) await Promise.race(executing);
    }
    return Promise.allSettled(results);
  },

  isSubStore: typeof $httpClient !== "undefined" || typeof $proxies !== "undefined",
  
  async fetch(url, opt = {}) {
    const times = opt.retry || CONFIG.RETRY_TIMES || 0;
    for (let i = 0; i <= times; i++) {
      try {
        if (utils.cache.has(`fetch:${url}`)) return utils.cache.get(`fetch:${url}`);

        let result;
        if (typeof $httpClient !== "undefined") {
          result = await new Promise((resolve, reject) => {
            const options = {
              url, headers: { "User-Agent": CONFIG.USER_AGENT, ...opt.headers },
              timeout: opt.timeout || CONFIG.TIMEOUT
            };
            const method = (opt.method || "GET").toLowerCase();
            const handler = $httpClient[method] || $httpClient.get;
            
            handler.call($httpClient, options, (error, response, data) => {
              if (error) reject(new Error(typeof error === 'string' ? error : JSON.stringify(error)));
              else {
                const status = response ? (response.status || response.statusCode) : 200;
                resolve({
                  ok: status >= 200 && status < 300, status: status,
                  json: () => { try { return JSON.parse(data || "{}"); } catch (e) { return {}; } },
                  body: data || ""
                });
              }
            });
          });
        } else if (typeof fetch !== "undefined") {
          const controller = typeof AbortController !== "undefined" ? new AbortController() : null;
          const timeout = setTimeout(() => { if (controller) controller.abort(); }, opt.timeout || CONFIG.TIMEOUT);
          try {
            const res = await fetch(url, { 
              method: opt.method || "GET",
              headers: { "User-Agent": CONFIG.USER_AGENT, ...opt.headers },
              signal: controller ? controller.signal : undefined
            });
            const data = await res.text();
            result = {
              ok: res.ok, status: res.status,
              json: () => { try { return JSON.parse(data || "{}"); } catch (e) { return {}; } },
              body: data
            };
          } finally { clearTimeout(timeout); }
        }

        if (result && result.ok) {
          utils.cache.set(`fetch:${url}`, result);
          if (utils.cache.size > 200) {
            const firstKey = utils.cache.keys().next().value;
            utils.cache.delete(firstKey);
          }
        }
        if (result) return result;
        throw new Error("无可用网络请求组件");
      } catch (e) {
        if (i === times) throw e;
        await new Promise(r => setTimeout(r, 500));  // 减少重试等待时间
      }
    }
  },

  async race(promises, timeout = CONFIG.TIMEOUT) {
    return new Promise((resolve, reject) => {
      let settledCount = 0;
      const errors = [], len = promises.length;
      const timeoutId = setTimeout(() => reject(new Error("请求超时")), timeout);

      if (len === 0) { clearTimeout(timeoutId); reject(new Error("无任务")); return; }

      promises.forEach(p => {
        Promise.resolve(p).then(
          val => {
            if (val) { clearTimeout(timeoutId); resolve(val); }
            else handleFailure(new Error("返回空结果"));
          },
          err => handleFailure(err)
        );
      });

      function handleFailure(err) {
        settledCount++; errors.push(err);
        if (settledCount === len) {
          clearTimeout(timeoutId);
          reject(new Error("所有请求均已失败"));
        }
      }
    });
  },

  ipToLong(ip) {
    const parts = ip.split('.');
    return (parseInt(parts[0]) << 24) + (parseInt(parts[1]) << 16) + 
           (parseInt(parts[2]) << 8) + parseInt(parts[3]);
  },

  isInRange(ip, start, end) {
    const ipLong = utils.ipToLong(ip);
    const startLong = utils.ipToLong(start);
    const endLong = utils.ipToLong(end);
    return ipLong >= startLong && ipLong <= endLong;
  },
  
  getMainDomain(host) {
    if (!host || REGEX.IPV4.test(host) || REGEX.IPV6.test(host)) return host;
    const parts = host.split('.');
    if (parts.length <= 2) return host;
    const last2 = parts.slice(-2).join('.');
    if (['com.cn', 'net.cn', 'org.cn', 'gov.cn', 'edu.cn'].includes(last2)) {
      return parts.slice(-3).join('.');
    }
    return parts.slice(-2).join('.');
  },

  getSubnet(ip) {
    if (!ip || !REGEX.IPV4.test(ip)) return ip;
    return ip.split('.').slice(0, 3).join('.') + '.0';
  }
};

// ==================== 验证器类 ====================
class Validator {
  constructor(options = {}) {
    this.opt = { ...CONFIG, ...options };
    this.keywords = new Set([...(this.opt.INVALID_KEYWORDS || [])].map(k => k.toLowerCase()));
    this.ipTree = this._buildIPTree();
    
    this.countryMap = {
      cn: "中国", hk: "中国香港", mo: "中国澳門", tw: "中国台湾", jp: "日本", sg: "新加坡", 
      us: "美国", kr: "韩国", de: "德国", uk: "英国", fr: "法国", nl: "荷兰", ru: "俄罗斯", 
      au: "澳大利亚", ca: "加拿大", in: "印度", th: "泰国", my: "马来西亚", vn: "越南", 
      ph: "菲律宾", ch: "瑞士", se: "瑞典", no: "挪威", fi: "芬兰", dk: "丹麦", it: "意大利", 
      es: "西班牙", pt: "葡萄牙", br: "巴西", ar: "阿根廷", tr: "土耳其", ae: "阿联酋",
      HK: "中国香港", TW: "中国台湾", MO: "中国澳门", CN: "中国", JP: "日本", KR: "韩国", 
      SG: "新加坡", TH: "泰国", VN: "越南", IN: "印度", MY: "马来西亚", PH: "菲律宾", 
      ID: "印尼", AE: "阿联酋", SA: "沙特阿拉伯", IL: "以色列", TR: "土耳其", IR: "伊朗",
      GB: "英国", DE: "德国", FR: "法国", NL: "荷兰", ES: "西班牙", RU: "俄罗斯", IT: "意大利",
      CH: "瑞士", SE: "瑞典", NO: "挪威", FI: "芬兰", DK: "丹麦", PT: "葡萄牙",
      AT: "奥地利", PL: "波兰", BE: "比利时", IE: "爱尔兰", RO: "罗马尼亚", UA: "乌克兰",
      BG: "保加利亚", HU: "匈牙利", CZ: "捷克", GR: "希腊", SK: "斯洛伐克",
      US: "美国", CA: "加拿大", MX: "墨西哥", BR: "巴西", AR: "阿根廷", CL: "智利",
      AU: "澳大利亚", NZ: "新西兰", ZA: "南非", EG: "埃及", KE: "肯尼亚",
      "Hong Kong": "中国香港", "Taiwan": "中国台湾", "China": "中国", "Japan": "日本",
      "South Korea": "韩国", "Korea": "韩国", "Singapore": "新加坡", "Thailand": "泰国",
      "Vietnam": "越南", "India": "印度", "Malaysia": "马来西亚", "Philippines": "菲律宾",
      "Indonesia": "印尼", "United Arab Emirates": "阿联酋", "UAE": "阿联酋",
      "United Kingdom": "英国", "UK": "英国", "Germany": "德国", "France": "法国",
      "Netherlands": "荷兰", "Spain": "西班牙", "Russia": "俄罗斯", "Italy": "意大利",
      "Switzerland": "瑞士", "Sweden": "瑞典", "Norway": "挪威", "Finland": "芬兰",
      "Denmark": "丹麦", "Portugal": "葡萄牙", "Austria": "奥地利", "Poland": "波兰",
      "Belgium": "比利时", "Ireland": "爱尔兰", "Romania": "罗马尼亚", "Ukraine": "乌克兰",
      "United States": "美国", "USA": "美国", "America": "美国", "US": "美国",
      "Canada": "加拿大", "Mexico": "墨西哥", "Brazil": "巴西", "Argentina": "阿根廷",
      "Australia": "澳大利亚", "New Zealand": "新西兰", "South Africa": "南非"
    };
    
    // 完整的中文国家名到ISO代码映射表
    this.nameToIso = {
      // 亚洲
      "中国": "CN", "中国香港": "HK", "中国台湾": "TW", "中国澳门": "MO",
      "香港": "HK", "台湾": "TW", "澳门": "MO",
      "日本": "JP", "韩国": "KR", "朝鲜": "KP",
      "新加坡": "SG", "马来西亚": "MY", "泰国": "TH", "越南": "VN",
      "菲律宾": "PH", "印尼": "ID", "印度尼西亚": "ID", "印度": "IN",
      "巴基斯坦": "PK", "孟加拉": "BD", "斯里兰卡": "LK", "尼泊尔": "NP",
      "缅甸": "MM", "柬埔寨": "KH", "老挝": "LA", "文莱": "BN",
      "蒙古": "MN", "哈萨克斯坦": "KZ", "乌兹别克斯坦": "UZ", "吉尔吉斯斯坦": "KG",
      "阿联酋": "AE", "沙特阿拉伯": "SA", "阿曼": "OM", "也门": "YE",
      "卡塔尔": "QA", "科威特": "KW", "巴林": "BH", "以色列": "IL",
      "伊朗": "IR", "伊拉克": "IQ", "土耳其": "TR", "黎巴嫩": "LB",
      "约旦": "JO", "叙利亚": "SY", "阿富汗": "AF",
      
      // 欧洲
      "英国": "GB", "爱尔兰": "IE", "法国": "FR", "摩纳哥": "MC",
      "德国": "DE", "奥地利": "AT", "瑞士": "CH", "列支敦士登": "LI",
      "荷兰": "NL", "比利时": "BE", "卢森堡": "LU",
      "丹麦": "DK", "挪威": "NO", "瑞典": "SE", "芬兰": "FI", "冰岛": "IS",
      "西班牙": "ES", "葡萄牙": "PT", "安道尔": "AD",
      "意大利": "IT", "梵蒂冈": "VA", "圣马力诺": "SM",
      "希腊": "GR", "塞浦路斯": "CY", "马耳他": "MT",
      "波兰": "PL", "捷克": "CZ", "斯洛伐克": "SK", "匈牙利": "HU",
      "罗马尼亚": "RO", "保加利亚": "BG", "塞尔维亚": "RS", "克罗地亚": "HR",
      "斯洛文尼亚": "SI", "波黑": "BA", "黑山": "ME", "北马其顿": "MK", "阿尔巴尼亚": "AL",
      "爱沙尼亚": "EE", "拉脱维亚": "LV", "立陶宛": "LT",
      "乌克兰": "UA", "白俄罗斯": "BY", "摩尔多瓦": "MD",
      "俄罗斯": "RU",
      
      // 北美
      "美国": "US", "加拿大": "CA", "墨西哥": "MX",
      
      // 南美
      "巴西": "BR", "阿根廷": "AR", "智利": "CL", "秘鲁": "PE",
      "哥伦比亚": "CO", "委内瑞拉": "VE", "厄瓜多尔": "EC",
      
      // 大洋洲
      "澳大利亚": "AU", "新西兰": "NZ",
      
      // 非洲
      "南非": "ZA", "埃及": "EG", "摩洛哥": "MA", "尼日利亚": "NG",
      "肯尼亚": "KE", "加纳": "GH", "埃塞俄比亚": "ET",
    };
  }
  
  _buildIPTree() {
    const lines = this.opt.STATIC_IP_DATA.split('\n').filter(l => l.trim());
    const ranges = lines.map(line => {
      const [start, end, country] = line.split('|');
      return {
        start: utils.ipToLong(start),
        end: utils.ipToLong(end),
        data: country
      };
    });
    return IntervalTree.fromRanges(ranges);
  }
  
  getFlagEmoji(geo) {
    const name = (typeof geo === 'object' ? geo.tag : geo) || "";
    
    // 未知地点使用特殊图标
    if (name === "未知地点" || !name) {
      return "❓";  // 问号图标表示未知地点
    }
    
    let code = this.nameToIso[name];
    if (!code && name.length === 2 && /^[A-Z]{2}$/i.test(name)) code = name.toUpperCase();
    if (!code) return "❓";  // 无法识别也使用问号
    
    try {
      return code.toUpperCase().replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397));
    } catch (e) {
      return "❓";
    }
  }
  
  isValidBasic(p) {
    const name = p.name || "未知节点";
    const type = String(p.type).toLowerCase();

    if (!p.type || !p.name || !p.server || !p.port) return false;
    if (!this.opt.SUPPORTED_TYPES.has(type)) return false;

    switch(type) {
      case 'vmess':
      case 'vless':
        if (!p.uuid || !REGEX.UUID.test(p.uuid)) return false;
        break;
      case 'ss':
      case 'ssr':
        if (!p.cipher || !p.password) return false;
        if (this.opt.ENCRYPTION_VALIDATION.enabled) {
          const cipher = String(p.cipher).toLowerCase();
          if (this.opt.ENCRYPTION_VALIDATION.forbiddenCiphers.includes(cipher)) return false;
        }
        break;
      case 'trojan':
        if (!p.password) return false;
        break;
      case 'hysteria':
      case 'hysteria2':
      case 'tuic':
        if (!p.password && !p.token) return false;
        break;
      case 'wireguard':
        if (!p.publicKey || !p.privateKey) return false;
        if (!REGEX.WG_KEY.test(p.publicKey) || !REGEX.WG_KEY.test(p.privateKey)) return false;
        break;
    }

    const host = String(p.server).toLowerCase();
    if (REGEX.PRIVATE_IP.test(host)) return false;
    const isIP = REGEX.IPV4.test(host) || REGEX.IPV6.test(host);
    const isDomain = REGEX.DOMAIN.test(host);
    if (!isIP && !isDomain) return false;

    const port = Number(p.port);
    if (isNaN(port) || port < 1 || port > 65535 || this.opt.PORT_BLACKLIST.has(port)) return false;

    for (const k of this.keywords) {
      if (name.toLowerCase().includes(k)) return false;
    }
    
    const qualityScore = this.getQualityScore(p);
    if (qualityScore < this.opt.MIN_QUALITY_SCORE) return false;
    p._qualityScore = qualityScore;

    if (isIP && REGEX.IPV4.test(host)) {
      for (const range of CONFIG.CDN_RANGES) {
        if (utils.isInRange(host, range.start, range.end)) {
          p._isCDN = true;
          p._cdnProvider = range.name;
          break;
        }
      }
    }

    return true;
  }

  getQualityScore(p) {
    let s = 0;
    const type = String(p.type).toLowerCase();
    // 提高SS节点基础分，确保能通过MIN_QUALITY_SCORE检查
    const protocolScores = {
      hysteria2: 40, hysteria: 35, tuic: 35, vless: 30, trojan: 30,
      vmess: 25, ss: 25, wireguard: 25, ssr: 20
    };
    s += protocolScores[type] || 15;

    if (p.tls) s += 15;
    if (p.sni || p.servername) s += 5;
    if (p.alpn) s += 10;
    if (p.network === 'grpc') s += 10;
    if (p.network === 'h2') s += 10;
    if (p.network === 'ws' && p['ws-opts'] && p['ws-opts'].path) s += 5;
    if (p.udp) s += 10;
    if (p.port === 443) s += 10;
    else if ([80, 8080, 8388, 8443, 2053, 2083, 2087, 2096].includes(p.port)) s += 5;
    if (p._isCDN) s -= 10;
    if (p['client-fingerprint']) s += 5;
    if (p['skip-cert-verify'] === false) s += 5;

    return Math.max(0, s);
  }

  // ===== 优化的地理位置识别 =====
  async getGeoTag(p, timeoutController = null) {
    const server = String(p.server || "").toLowerCase();
    let fingerHost = p._resolvedIP || server;
    
    const cacheKey = `geo_v3:${fingerHost}`;
    if (utils.cache.has(cacheKey)) return utils.cache.get(cacheKey);

    let result = { tag: "未知地点", confidence: 0 };

    // 策略1: 直接IP地址识别
    if (REGEX.IPV4.test(server)) {
      const ipLong = utils.ipToLong(server);
      const staticCountry = this.ipTree.search(ipLong);
      if (staticCountry) {
        result = { tag: staticCountry, confidence: 80, source: "static-ip-range" };
        utils.cache.set(cacheKey, result);
        return result;
      }
      
      // CDN IP特殊处理
      if (p._isCDN) {
        let sniHost = p.sni || p.servername || 
          (p["ws-opts"] && p["ws-opts"].headers && (p["ws-opts"].headers.Host || p["ws-opts"].headers.host));
        
        if (sniHost && sniHost !== server && !REGEX.IPV4.test(sniHost) && !REGEX.IPV6.test(sniHost)) {
          const sniTld = String(sniHost).toLowerCase().split('.').pop();
          if (this.countryMap[sniTld]) {
            result = { tag: this.countryMap[sniTld], confidence: 75, source: "cdn-sni-tld" };
            utils.cache.set(cacheKey, result);
            return result;
          }
        }
        
        result = { tag: "未知地点", confidence: 0, source: "cdn-unknown" };
        utils.cache.set(cacheKey, result);
        return result;
      }
      
      // 远程API查询（带调用限制）
      if (this.opt.enableRemoteGeo && utils.geoApiCallCount < this.opt.MAX_GEO_API_CALLS) {
        // 检查剩余时间
        if (timeoutController && timeoutController.remaining() < 1000) {
          result = { tag: "未知地点", confidence: 0, source: "timeout-skip" };
          utils.cache.set(cacheKey, result);
          return result;
        }
        
        try {
          utils.geoApiCallCount++;
          const remoteGeo = await this.fetchRemoteGeo(server, timeoutController);
          if (remoteGeo && remoteGeo.country) {
            result = { tag: remoteGeo.country, confidence: 95, source: "remote-api", isp: remoteGeo.isp };
            utils.cache.set(cacheKey, result);
            return result;
          }
        } catch (e) {
          // 静默失败，不影响整体流程
        }
      }
    }
    
    // 策略2: 域名TLD识别
    if (!REGEX.IPV4.test(server) && !REGEX.IPV6.test(server) && REGEX.DOMAIN.test(server)) {
      const parts = server.split('.');
      const tld = parts[parts.length - 1];
      if (this.countryMap[tld]) {
        result = { tag: this.countryMap[tld], confidence: 85, source: "domain-tld" };
        utils.cache.set(cacheKey, result);
        return result;
      }
    }
    
    // 策略3: DNS解析后的IP查询
    if (p._resolvedIP && REGEX.IPV4.test(p._resolvedIP)) {
      const ipLong = utils.ipToLong(p._resolvedIP);
      const staticCountry = this.ipTree.search(ipLong);
      if (staticCountry) {
        result = { tag: staticCountry, confidence: 85, source: "dns-resolved-static" };
        utils.cache.set(cacheKey, result);
        return result;
      }
      
      if (this.opt.enableRemoteGeo && utils.geoApiCallCount < this.opt.MAX_GEO_API_CALLS) {
        if (timeoutController && timeoutController.remaining() < 1000) {
          result = { tag: "未知地点", confidence: 0, source: "timeout-skip" };
          utils.cache.set(cacheKey, result);
          return result;
        }
        
        try {
          utils.geoApiCallCount++;
          const remoteGeo = await this.fetchRemoteGeo(p._resolvedIP, timeoutController);
          if (remoteGeo && remoteGeo.country) {
            result = { tag: remoteGeo.country, confidence: 90, source: "dns-resolved-api", isp: remoteGeo.isp };
            utils.cache.set(cacheKey, result);
            return result;
          }
        } catch (e) {
          // 静默失败
        }
      }
    }

    // 策略4: SNI/Host headers TLD
    let sniHost = p.sni || p.servername || 
      (p["ws-opts"] && p["ws-opts"].headers && (p["ws-opts"].headers.Host || p["ws-opts"].headers.host));
    
    if (sniHost && sniHost !== server) {
      const sniTld = String(sniHost).toLowerCase().split('.').pop();
      if (this.countryMap[sniTld]) {
        result = { tag: this.countryMap[sniTld], confidence: 70, source: "sni-tld" };
        utils.cache.set(cacheKey, result);
        return result;
      }
    }

    // 策略5: 节点名提取（最后兜底）
    if (p.name && typeof p.name === 'string') {
      const nameGeo = this._extractGeoFromName(p.name);
      if (nameGeo && nameGeo.tag !== "未知地点") {
        result = { tag: nameGeo.tag, confidence: 30, source: "name-fallback" };
        utils.cache.set(cacheKey, result);
        return result;
      }
    }

    utils.cache.set(cacheKey, result);
    return result;
  }
  
  _extractGeoFromName(name) {
    if (!name || typeof name !== 'string') return null;
    
    // Emoji国旗
    const flagMatch = name.match(/([\u{1F1E6}-\u{1F1FF}]{2})/u);
    if (flagMatch) {
      const flagCode = flagMatch[1];
      try {
        const code1 = String.fromCodePoint(flagCode.codePointAt(0) - 127397);
        const code2 = String.fromCodePoint(flagCode.codePointAt(2) - 127397);
        const isoCode = code1 + code2;
        if (this.countryMap[isoCode]) {
          return { tag: this.countryMap[isoCode], source: "name-emoji" };
        }
      } catch (e) {}
    }
    
    // 中文国家名（完整列表，按长度降序以匹配最长）
    const chineseCountries = [
      // 4字国家名
      "中国香港", "中国台湾", "中国澳门", "沙特阿拉伯", "阿拉伯联合酋长国",
      // 3字国家名  
      "阿联酋", "阿根廷", "澳大利亚", "巴基斯坦", "菲律宾", "哈萨克斯坦",
      "柬埔寨", "马来西亚", "孟加拉", "摩洛哥", "墨西哥", "南非", "尼日利亚",
      "斯里兰卡", "土耳其", "新西兰", "以色列", "印尼", "印度",
      // 2字国家名
      "阿曼", "埃及", "奥地利", "巴林", "巴西", "比利时", "波兰", "丹麦",
      "德国", "俄罗斯", "法国", "芬兰", "韩国", "荷兰", "加拿大", "捷克",
      "卡塔尔", "科威特", "黎巴嫩", "罗马尼亚", "秘鲁", "葡萄牙", "日本",
      "瑞典", "瑞士", "塞尔维亚", "西班牙", "希腊", "新加坡", "新西兰",
      "匈牙利", "伊朗", "意大利", "印度", "印尼", "英国", "越南", "智利",
      "中国", "香港", "台湾", "澳门", "泰国", "挪威", "爱尔兰", "乌克兰",
      "保加利亚", "克罗地亚", "拉脱维亚", "立陶宛", "卢森堡", "斯洛伐克", "斯洛文尼亚"
    ];
    
    // 标准化映射表
    const countryNormalize = {
      "香港": "中国香港", "台湾": "中国台湾", "澳门": "中国澳门",
      "印度": "印度", "印尼": "印尼"
    };
    
    // 按长度降序排列，确保匹配最长国家名
    const sortedCountries = [...chineseCountries].sort((a, b) => b.length - a.length);
    
    for (const country of sortedCountries) {
      if (name.includes(country)) {
        // 标准化国家名
        const normalizedCountry = countryNormalize[country] || country;
        return { tag: normalizedCountry, source: "name-chinese" };
      }
    }
    
    // ISO代码
    const isoMatch = name.match(/\b([A-Z]{2})\b/);
    if (isoMatch && this.countryMap[isoMatch[1]]) {
      return { tag: this.countryMap[isoMatch[1]], source: "name-iso" };
    }
    
    return null;
  }

  // ===== 优化的远程API查询 =====
  async fetchRemoteGeo(ip, timeoutController = null) {
    const cacheKey = `remote_geo:${ip}`;
    if (utils.cache.has(cacheKey)) return utils.cache.get(cacheKey);

    // 计算剩余超时时间
    const remainingTime = timeoutController ? Math.min(timeoutController.remaining() - 500, this.opt.GEO_API_TIMEOUT) : this.opt.GEO_API_TIMEOUT;
    if (remainingTime < 1000) return null;  // 时间不足，直接返回

    const shuffledAPIs = [...this.opt.GEO_APIS].sort(() => Math.random() - 0.5);
    
    const promises = shuffledAPIs.slice(0, 2).map((api) => {  // 只尝试前2个API
      return (async () => {
        try {
          const url = api.replace("{ip}", ip);
          const res = await utils.fetch(url, { timeout: Math.min(remainingTime, 3000), retry: 0 });
          
          if (res && res.ok) {
            const data = res.json();
            if (!data || typeof data !== 'object') return null;
            
            const country = data.country || data.country_name || data.countryName;
            const countryCode = (data.countryCode || data.country_code || "").toUpperCase();
            const success = data.status === "success" || data.success === true || !data.status;
            
            if (success && (country || countryCode)) {
              const finalCountry = this.countryMap[country] || this.countryMap[countryCode] || country;
              if (finalCountry) {
                return {
                  country: finalCountry,
                  countryCode: countryCode || "XX",
                  city: data.city || "",
                  isp: data.isp || data.org || ""
                };
              }
            }
          }
        } catch (e) {
          // 静默失败
        }
        return null;
      })();
    });

    try {
      const geoData = await utils.race(promises, remainingTime);
      if (geoData && geoData.country) {
        utils.cache.set(cacheKey, geoData);
        return geoData;
      }
    } catch (e) {
      // 静默失败
    }
    
    return null;
  }
  
  // ===== 优化的DNS解析 =====
  async resolveIP(host, timeoutController = null) {
    if (!this.opt.enableDNSResolve) return null;
    if (REGEX.IPV4.test(host) || REGEX.IPV6.test(host)) return host;
    
    const cacheKey = `dns:${host}`;
    if (this.opt.DNS_RESOLVE.cacheEnabled && utils.cache.has(cacheKey)) {
      return utils.cache.get(cacheKey);
    }
    
    // 检查剩余时间
    const remainingTime = timeoutController ? Math.min(timeoutController.remaining() - 500, this.opt.DNS_TIMEOUT) : this.opt.DNS_TIMEOUT;
    if (remainingTime < 500) return null;
    
    const providers = this.opt.DNS_RESOLVE.dohProviders.slice(0, 2).map(url => url.replace("{host}", host));
    
    try {
      const ip = await utils.race(providers.map(async url => {
        try {
          const res = await utils.fetch(url, { 
            headers: { "accept": "application/dns-json" }, 
            timeout: remainingTime
          });
          const json = res.json();
          
          if (json.Answer && Array.isArray(json.Answer)) {
            const aRecord = json.Answer.find(a => a.type === 1);
            return aRecord ? aRecord.data : null;
          } else if (json.data && Array.isArray(json.data)) {
            return json.data[0] || null;
          }
          return null;
        } catch (e) { return null; }
      }), remainingTime);
      
      if (ip) {
        if (this.opt.DNS_RESOLVE.cacheEnabled) utils.cache.set(cacheKey, ip);
        return ip;
      }
    } catch (e) {}
    return null;
  }

  applyConsensus(nodes) {
    const hostGroups = {}, subnetGroups = {};

    nodes.forEach(n => {
      let host = String(n.server || "").toLowerCase();
      if (n.sni) host = String(n.sni).toLowerCase();
      else if (n["ws-opts"] && n["ws-opts"].headers && n["ws-opts"].headers.Host) host = String(n["ws-opts"].headers.Host).toLowerCase();
      else if (n.servername) host = String(n.servername).toLowerCase();

      const mainDomain = utils.getMainDomain(host);
      const subnet = utils.getSubnet(n._ip || n.server);
      
      if (!hostGroups[mainDomain]) hostGroups[mainDomain] = [];
      if (!subnetGroups[subnet]) subnetGroups[subnet] = [];
      
      hostGroups[mainDomain].push(n);
      subnetGroups[subnet].push(n);
    });

    const processGroups = (groups) => {
      for (const key in groups) {
        const group = groups[key];
        if (group.length < 2) continue;

        const votes = {};
        group.forEach(n => {
          if (n._geo && n._geo.confidence >= 60) {
            votes[n._geo.tag] = (votes[n._geo.tag] || 0) + 1;
          }
        });

        let winner = null, maxVotes = 0;
        for (const tag in votes) {
          if (votes[tag] > maxVotes) {
            maxVotes = votes[tag];
            winner = tag;
          }
        }

        if (winner && (maxVotes / group.length) >= 0.5) {
          group.forEach(n => {
            if (!n._geo || n._geo.confidence < 60) {
              n._geo = { tag: winner, confidence: 40, source: "consensus" };
            }
          });
        }
      }
    };

    processGroups(hostGroups);
    processGroups(subnetGroups);
  }

  getNodeFingerprint(p) {
    try {
      if (!p || typeof p !== "object") return "invalid";
      const s = String(p.server || "").toLowerCase().trim();
      const t = String(p.type || "").toLowerCase();
      const port = String(p.port || "");
      if (!s || !t || !port) return "invalid";
      
      const k = [t, s, port];
      if (["vmess", "vless"].includes(t)) {
        if (p.uuid) k.push(String(p.uuid));
        if (p.tls) k.push("tls");
        if (p.network) k.push(String(p.network));
      } else if (["ss", "ssr"].includes(t)) {
        if (p.cipher) k.push(String(p.cipher));
        if (p.password) k.push(String(p.password));
      } else if (["trojan", "hysteria", "hysteria2", "tuic"].includes(t)) {
        if (p.password) k.push(String(p.password));
        if (p.sni) k.push(String(p.sni));
      }
      return k.filter(Boolean).join(":");
    } catch {
      return "invalid";
    }
  }
}

// ==================== 主过滤函数 ====================
async function filter(proxies, options = {}) {
  const v = new Validator(options);
  const start = Date.now();
  const total = proxies.length;
  
  // 创建全局超时控制器
  const timeoutController = new TimeoutController(v.opt.GLOBAL_TIMEOUT);
  
  console.log(`[SubStore 超时修复版] 开始处理 ${total} 个节点 (超时限制: ${v.opt.GLOBAL_TIMEOUT}ms)`);
  
  // 阶段1: 基础验证 (同步，快速)
  const validNodes = proxies.filter(p => {
    try {
      return v.isValidBasic(p);
    } catch (e) {
      return false;
    }
  });
  
  console.log(`[SubStore 超时修复版] 验证完成: ${validNodes.length}/${total} 个节点通过`);
  
  if (validNodes.length === 0) {
    console.log(`[SubStore 超时修复版] 警告: 没有节点通过验证`);
    return [];
  }
  
  // 检查超时
  if (!timeoutController.check()) {
    console.log(`[SubStore 超时修复版] 超时，跳过后续处理`);
    return validNodes;
  }
  
  // 阶段2: DNS解析（可选，带超时控制）
  if (v.opt.enableDNSResolve && v.opt.DNS_RESOLVE.enabled) {
    const dnsTasks = validNodes
      .filter(p => !REGEX.IPV4.test(p.server) && !REGEX.IPV6.test(p.server))
      .map(p => async () => {
        try {
          const ip = await v.resolveIP(p.server, timeoutController);
          if (ip) p._resolvedIP = ip;
        } catch (e) {}
        return p;
      });
    
    if (dnsTasks.length > 0) {
      await utils.limit(dnsTasks, CONFIG.CONCURRENCY, timeoutController);
      console.log(`[SubStore 超时修复版] DNS解析完成, 剩余时间: ${timeoutController.remaining()}ms`);
    }
  }
  
  // 检查超时
  if (!timeoutController.check()) {
    console.log(`[SubStore 超时修复版] 超时，跳过地理位置识别`);
  } else {
    // 阶段3: 地理位置识别（带超时控制）
    const geoTasks = validNodes.map(p => async () => {
      try {
        p._geo = await v.getGeoTag(p, timeoutController);
        if (p._resolvedIP) p._ip = p._resolvedIP;
        else if (REGEX.IPV4.test(p.server) || REGEX.IPV6.test(p.server)) p._ip = p.server;
        return p;
      } catch (e) {
        p._geo = { tag: "未知地点", confidence: 0 };
        return p;
      }
    });
    
    await utils.limit(geoTasks, CONFIG.CONCURRENCY, timeoutController);
    console.log(`[SubStore 超时修复版] 地理位置识别完成, API调用: ${utils.geoApiCallCount}次`);
  }
  
  // 阶段4: 集群共识
  v.applyConsensus(validNodes);
  
  // 阶段5: 去重
  const seen = new Map();
  for (const p of validNodes) {
    const fingerprint = v.getNodeFingerprint(p);
    if (fingerprint === "invalid") continue;
    const score = p._qualityScore || v.getQualityScore(p);
    if (!seen.has(fingerprint) || score > seen.get(fingerprint).score) {
      seen.set(fingerprint, { proxy: p, score });
    }
  }
  
  const uniqueNodes = Array.from(seen.values()).map(item => item.proxy);
  
  // 阶段6: 重命名
  const countryCounts = new Map();
  const results = uniqueNodes.map(p => {
    const geo = p._geo || { tag: "未知地点", confidence: 0 };
    let countryTag = geo.tag || "未知地点";
    
    // 确保国家名有效（至少包含中文或英文字母，不能是纯数字）
    if (!countryTag || countryTag === "未知地点" || /^\d+$/.test(countryTag)) {
      countryTag = "未知地点";
    }
    
    // 非中文国家名转换为中文
    if (countryTag !== "未知地点" && !/[\u4e00-\u9fa5]/.test(countryTag)) {
      countryTag = v.countryMap[countryTag] || v.countryMap[countryTag.toUpperCase()] || "未知地点";
    }
    
    const count = (countryCounts.get(countryTag) || 0) + 1;
    countryCounts.set(countryTag, count);
    
    const flag = v.getFlagEmoji(countryTag);
    p.name = flag ? `${flag} ${countryTag} ${count}`.trim() : `${countryTag} ${count}`.trim();
    
    // 清理临时字段
    delete p._geo; delete p._ip; delete p._isCDN; delete p._cdnProvider;
    delete p._perfMetrics; delete p._resolvedIP; delete p._qualityScore;
    
    return p;
  });
  
  // 完成统计
  const duration = ((Date.now() - start) / 1000).toFixed(2);
  console.log(`[SubStore 超时修复版] 完成! 耗时 ${duration}s, 保留 ${results.length} 个节点`);
  
  return results;
}

// ==================== 环境兼容 ====================
if (typeof module !== "undefined" && module.exports) {
  module.exports = { Validator, filter, CONFIG, REGEX, utils, IntervalTree, TimeoutController };
}

if (typeof window !== "undefined") {
  window.SubStoreFilter = { Validator, filter, CONFIG, REGEX, utils, IntervalTree, TimeoutController };
}

// ===== operator函数 - 带超时保护 =====
async function operator(proxies = []) {
  try {
    // 重置API计数器
    utils.geoApiCallCount = 0;
    
    const result = await filter(proxies);
    return result;
  } catch (e) {
    console.log(`[SubStore 超时修复版] 错误: ${e.message}`);
    // 发生错误时返回原始节点（保底策略）
    return proxies;
  }
}
