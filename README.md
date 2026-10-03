# GCOY-LOGWARD

蓝队日志体检工具。读 auth.log / secure 与 nginx access.log，输出 8 类检测、
评分、终端中文报告、单文件 HTML 报告与 IOC 清单。零依赖，单文件，Python 3.10+。

纯本地离线分析，只读日志文件，不发包、不扫描、不上网。

## 安装

```bash
git clone https://github.com/8-14ban/GCOY-LOGWARD.git
```

## 快速开始

```bash
# 没有现成日志？先生成一套带完整攻击链的演示日志
python3 gcoy_logward.py demo --outdir /tmp/demo

# 体检
python3 gcoy_logward.py analyze \
  --auth /tmp/demo/demo_auth.log \
  --access /tmp/demo/demo_access.log \
  --html report.html --ioc ioc.json --csv ioc.csv

# 生产环境（白名单豁免运维出口 IP）
python3 gcoy_logward.py analyze \
  --auth /var/log/auth.log \
  --access /var/log/nginx/access.log \
  --whitelist 203.0.113.9,192.0.2.10 \
  --html report.html --ioc ioc.json
```

## 检测项（8 类）

| 检测项 | 级别 | 触发条件 |
| --- | --- | --- |
| SSH 爆破 | 高/中 | 单 IP 失败 >=20 次（>=5 次为低烈度） |
| 爆破后成功登录 | 严重 | 同 IP 先多次失败后 Accepted |
| 可疑时段登录 | 中 | 凌晨 0-6 时成功登录 |
| 提权痕迹 | 高 | sudo 认证失败 / 新增 sudo-wheel 组成员 |
| Webshell 落地访问 | 严重 | POST 到可执行路径返回 200 |
| 敏感路径探测 | 低 | .env / .git / .sql / phpmyadmin 等被探测 |
| 扫描器特征 | 高 | sqlmap/nikto/gobuster 等 15 种工具 UA |
| 目录枚举 | 中 | 单 IP 404 >= 30 次 |

评分制：满分 100，按检测项严重度扣分。90+ 正常 / 70+ 需关注 / 40+ 告警 / 其余危险。

## 输出

- 终端报告：扣分明细 + 每项证据样例 + IOC 汇总
- `--html report.html`：单文件战报，可挂 GitHub Pages
- `--ioc ioc.json`：恶意 IP + 标签（bruteforce / compromise / scanner / webshell-access ...）+ 证据计数，可直接喂防火墙或情报平台
- `--csv ioc.csv`：表格版 IOC

## 设计原则

- 纯本地离线，只读不写日志原文件
- 零第三方依赖，单文件可拷进任意隔离环境
- 白名单机制：已知运维出口 IP 全检测豁免，避免误报

## 自检

```bash
python3 gcoy_logward.py selftest
```
