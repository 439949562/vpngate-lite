# vpngate-lite

不依赖 gate 仓库、不依赖任何 Cloudflare Worker：一个纯标准库 Python 脚本，
抓取 VPN Gate 节点 → 本地完成 SSTP 握手 + PPP 建链 → 隧道内查出口 IP / 判定住宅机房 →
隧道内下载 1MB 测速 → 输出 edgetunnel 链式格式。

## 文件

| 文件 | 说明 |
|---|---|
| `vpngate_lite.py` | 主脚本（唯一必需），零第三方依赖 |
| `.github/workflows/probe.yml` | GitHub Actions 定时探测（每小时 2 次） |
| `out/nodes.txt` | 产物：edgetunnel「自定义优选IP」直接粘贴 |
| `out/report.csv` | 全部节点的检测结果（含失败原因） |
| `out/summary.json` | 统计摘要 |

## 本机运行

国内直连 opengw.net 不通，必须走本机代理（检测视角 = 代理出口）：

```bash
python vpngate_lite.py --proxy http://127.0.0.1:7897
```

## GitHub Actions 运行

1. 把本目录推到你自己的 GitHub 仓库（公开）。
2. Settings → Actions → General → Workflow permissions 选 **Read and write**。
3. 手动 Run workflow 跑一次，确认 `out/nodes.txt` 被提交。
4. edgetunnel 后台「自定义优选IP」填：

```
https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/out/nodes.txt
```

## 常用参数

```
--proxy URL           本机跑必填；Actions 上不用
--edge "域名:443,..."  入口域名池（默认内置 6 个，建议换成你自己的 CF 域名）
--country JP,KR       只要指定国家
--max N               最多探测 N 个（按 ping 排序取前 N，默认 120）
--concurrency N       并发（默认 6；Actions 建议 6，本机可 4）
--no-speed            跳过测速（快一倍）
--include-official    包含官方机房节点（默认排除 public-vpn-*）
```

## 检测原理（与 gate 的区别）

gate 用 Cloudflare Worker 里的 `sstpConnect` 做检测；本脚本把同一套协议流程
（SSTP HTTP 握手 → LCP → PAP(vpn/vpn) → IPCP）用纯 Python 实现在本地，
不经过任何第三方检测服务。测速是隧道内 TLS 下载 Cloudflare `__down` 1MB，
测的是**节点侧带宽**（节点从互联网拉数据的速度），用于相对排序和筛死节点，
不等于你到节点的端到端速度。

## 已知边界

- 只支持 PAP 认证（VPN Gate 全站账号固定 vpn/vpn），MS-CHAPv2 节点会被跳过。
- 用户态 TCP 不重传不校验序号（与 edgetunnel 的实现同级），极端丢包下测速值偏低。
- GitHub 的 schedule 高峰期会延迟甚至跳过，fork 仓库尤甚；可在
  cron-job.org 配一个 30 分钟的 workflow_dispatch 触发兜底（需要 PAT，Actions: write）。
- VPN Gate 节点 30 分钟级轮换，`nodes.txt` 时效约 1~3 小时，死了重跑即可。
