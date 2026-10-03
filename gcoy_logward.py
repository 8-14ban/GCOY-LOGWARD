#!/usr/bin/env python3
"""GCOY-LOGWARD: 蓝队日志体检工具。auth.log/secure + nginx access.log -> 8 类检测 -> 评分 / 终端报告 / HTML / IOC。零依赖，Python 3.10+。"""

import argparse
import csv
import json
import os
import re
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path

RE_SSH_FAIL = re.compile(r"Failed \S+ for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
RE_SSH_OK = re.compile(r"Accepted \S+ for (\S+) from (\d+\.\d+\.\d+\.\d+)")
RE_SYSLOG_T = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})")
RE_SUDO_FAIL = re.compile(r"sudo:.{0,80}(incorrect password|authentication failure)")
RE_GROUP_ADD = re.compile(r"(usermod|useradd|gpasswd)\[\d+\]:.*(sudo|wheel|admin)", re.I)
RE_ACCESS = re.compile(
    r'^(\d+\.\d+\.\d+\.\d+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+)[^"]*" (\d{3}) (\S+) "([^"]*)" "([^"]*)"'
)
RE_ACC_T = re.compile(r"%d/%b/%Y:%H:%M:%S")

SCANNER_UA = [
    "sqlmap", "nikto", "nmap", "masscan", "gobuster", "dirsearch", "hydra",
    "wfuzz", "acunetix", "nessus", "burp", "wpscan", "dirb", "ffuf", "feroxbuster",
]
SENSITIVE_PATH = [
    ".env", ".git", "wp-login", "phpmyadmin", "phpmy", "/backup", ".sql", ".bak",
    ".conf", "actuator", "/admin/config", "id_rsa", ".htaccess", "web.config",
]
WEB_SHELL = re.compile(r"(\.php($|\?)|/upload|shell|cmd=|exec|eval)", re.I)
ENUM_404 = 30

SUSPECT_HOUR = range(0, 6)


def parse_auth(lines, wl):
    fails = defaultdict(lambda: {"n": 0, "users": set(), "ev": [], "last": None})
    oks = defaultdict(int)
    ok_events = []
    after_bf = []
    odd_hour = []
    sudo_fail, sudo_ev = 0, []
    group_add, group_ev = 0, []
    total = 0
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        total += 1
        hm = RE_SYSLOG_T.match(line)
        hour = int(hm.group(3)) if hm else None
        m = RE_SSH_FAIL.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            if ip in wl:
                continue
            fails[ip]["n"] += 1
            fails[ip]["users"].add(user)
            fails[ip]["last"] = (user, ip)
            if len(fails[ip]["ev"]) < 5:
                fails[ip]["ev"].append(line)
            continue
        m = RE_SSH_OK.search(line)
        if m:
            user, ip = m.group(1), m.group(2)
            if ip in wl:
                continue
            oks[ip] += 1
            ok_events.append((user, ip, hour, line))
            if ip in fails and fails[ip]["n"] >= 5:
                after_bf.append((user, ip, fails[ip]["n"], line))
            if hour is not None and hour in SUSPECT_HOUR:
                odd_hour.append((user, ip, hour, line))
            continue
        if RE_SUDO_FAIL.search(line):
            sudo_fail += 1
            if len(sudo_ev) < 5:
                sudo_ev.append(line)
            continue
        if RE_GROUP_ADD.search(line):
            group_add += 1
            if len(group_ev) < 5:
                group_ev.append(line)
    return {
        "total": total, "fails": fails, "oks": oks, "ok_events": ok_events,
        "after_bf": after_bf, "odd_hour": odd_hour,
        "sudo_fail": sudo_fail, "sudo_ev": sudo_ev,
        "group_add": group_add, "group_ev": group_ev,
    }


def parse_access(lines, wl):
    by_ip = defaultdict(lambda: {"n": 0, "e404": 0, "paths": set(), "ua": set()})
    scanners = defaultdict(set)
    sensitive = defaultdict(lambda: {"paths": set(), "n": 0})
    webshell = []
    total = 0
    for raw in lines:
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        m = RE_ACCESS.match(line)
        if not m:
            continue
        total += 1
        ip, t, method, path, status, size, ref, ua = m.groups()
        if ip in wl:
            continue
        d = by_ip[ip]
        d["n"] += 1
        d["paths"].add(path)
        if ua:
            d["ua"].add(ua)
        if status == "404":
            d["e404"] += 1
        low = ua.lower()
        for tool in SCANNER_UA:
            if tool in low:
                scanners[ip].add(tool)
        if status in ("404", "403") and any(s in path.lower() for s in SENSITIVE_PATH):
            sensitive[ip]["n"] += 1
            sensitive[ip]["paths"].add(path)
        if method == "POST" and WEB_SHELL.search(path) and status == "200":
            webshell.append((ip, path, status, line))
    return {
        "total": total, "by_ip": by_ip, "scanners": scanners,
        "sensitive": sensitive, "webshell": webshell,
    }


def build_findings(auth, acc):
    findings = []

    def add(name, sev, cost, count, evid, note):
        if cost:
            findings.append(
                {"name": name, "sev": sev, "cost": cost, "count": count,
                 "evid": evid[:12], "note": note}
            )

    max_fail_ip, max_fail_n = None, 0
    for ip, d in auth["fails"].items():
        if d["n"] > max_fail_n:
            max_fail_ip, max_fail_n = ip, d["n"]
    if max_fail_n >= 20:
        add("SSH 爆破", "高", 20, max_fail_n,
            [e for d in auth["fails"].values() for e in d["ev"]],
            f"单 IP {max_fail_ip} 失败 {max_fail_n} 次")
    elif max_fail_n >= 5:
        add("SSH 爆破（低烈度）", "中", 10, max_fail_n,
            [e for d in auth["fails"].values() for e in d["ev"]],
            f"单 IP {max_fail_ip} 失败 {max_fail_n} 次")

    if auth["after_bf"]:
        add("爆破后成功登录", "严重", 25, len(auth["after_bf"]),
            [e for _, _, _, e in auth["after_bf"]],
            "疑似口令已被猜中，立即核查账号")

    if auth["odd_hour"]:
        add("可疑时段登录", "中", min(20, 10 * len(auth["odd_hour"])),
            len(auth["odd_hour"]), [e for _, _, _, e in auth["odd_hour"]],
            "凌晨 0-6 时的成功登录，结合业务确认")

    sudo_cost = (10 if auth["sudo_fail"] else 0) + (15 if auth["group_add"] else 0)
    if sudo_cost:
        add("提权痕迹", "高", sudo_cost, auth["sudo_fail"] + auth["group_add"],
            auth["sudo_ev"] + auth["group_ev"],
            "sudo 认证失败或新增特权组成员")

    if acc["webshell"]:
        add("Webshell 落地访问", "严重", 30, len(acc["webshell"]),
            [e for _, _, _, e in acc["webshell"]],
            "POST 写入/访问可执行路径返回 200")

    sens_paths = set()
    for ip, d in acc["sensitive"].items():
        sens_paths |= d["paths"]
    if sens_paths:
        add("敏感路径探测", "低", min(15, 5 * len(sens_paths)),
            sum(d["n"] for d in acc["sensitive"].values()),
            [f"{ip} -> {sorted(d['paths'])[0]}" for ip, d in acc["sensitive"].items()],
            f"命中 {len(sens_paths)} 个敏感路径")

    tools = set()
    for ip, ts in acc["scanners"].items():
        tools |= ts
    if tools:
        add("扫描器特征", "高", min(20, 10 * len(tools)),
            sum(1 for ip in acc["scanners"] for _ in acc["scanners"][ip]),
            [f"{ip} UA 命中 {sorted(ts)}" for ip, ts in acc["scanners"].items()],
            f"识别工具：{', '.join(sorted(tools))}")

    enum_ips = [(ip, d["e404"]) for ip, d in acc["by_ip"].items() if d["e404"] >= ENUM_404]
    if enum_ips:
        add("目录枚举", "中", 10, sum(n for _, n in enum_ips),
            [f"{ip} 404 x{n}" for ip, n in enum_ips],
            "单 IP 404 密度异常")

    findings.sort(key=lambda f: -f["cost"])
    score = max(0, 100 - sum(f["cost"] for f in findings))
    return findings, score


def build_ioc(auth, acc):
    ioc = defaultdict(lambda: {"tags": set(), "ev": 0})

    def tag(ip, t, n):
        ioc[ip]["tags"].add(t)
        ioc[ip]["ev"] += n

    for ip, d in auth["fails"].items():
        if d["n"] >= 5:
            tag(ip, "bruteforce", d["n"])
    for _, ip, _, _ in auth["after_bf"]:
        tag(ip, "compromise", 1)
    for _, ip, _, _ in auth["odd_hour"]:
        tag(ip, "odd-hour-login", 1)
    for ip in acc["scanners"]:
        tag(ip, "scanner", acc["by_ip"][ip]["n"] if ip in acc["by_ip"] else 1)
    for ip, d in acc["sensitive"].items():
        tag(ip, "probe", d["n"])
    for ip, d in acc["by_ip"].items():
        if d["e404"] >= ENUM_404:
            tag(ip, "enum", d["e404"])
    for ip, _, _, _ in acc["webshell"]:
        tag(ip, "webshell-access", 1)
    return {ip: {"tags": sorted(v["tags"]), "evidence": v["ev"]} for ip, v in ioc.items()}


def band(score):
    if score >= 90:
        return "正常"
    if score >= 70:
        return "需关注"
    if score >= 40:
        return "告警"
    return "危险"


def print_report(meta, findings, score, ioc):
    print("GCOY-LOGWARD 日志体检报告")
    print("=" * 56)
    print(
        f"auth 事件 {meta['auth_total']} | access 请求 {meta['acc_total']} | "
        f"白名单 {meta['wl_n']} 个 IP"
    )
    print(f"总体评分: {score}/100 [{band(score)}]")
    print("-" * 56)
    if not findings:
        print("未发现异常。继续保持日志留存与定期体检。")
    else:
        print(f"{'级别':<6}{'扣分':<6}{'检测项':<20}证据数")
        for f in findings:
            print(f"{f['sev']:<6}-{f['cost']:<5}{f['name']:<20}{f['count']}")
        print("-" * 56)
        for f in findings:
            print(f"[{f['sev']}] {f['name']} ({f['note']})")
            for e in f["evid"][:3]:
                print(f"    | {e[:100]}")
    print("-" * 56)
    if ioc:
        print(f"IOC 恶意 IP {len(ioc)} 个:")
        for ip, v in sorted(ioc.items(), key=lambda kv: -kv[1]["evidence"]):
            print(f"  {ip:<18}{v['evidence']:<8}{','.join(v['tags'])}")
    else:
        print("IOC: 无")


STYLE = (
    "body{font-family:system-ui,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;"
    "color:#16222e;line-height:1.55}h1{border-bottom:3px solid #246}table{border-collapse:collapse;"
    "width:100%;margin:10px 0}th,td{border:1px solid #ccd;padding:5px 10px;text-align:left}"
    "th{background:#eef3f8}pre{background:#0f1720;color:#d7e3ee;padding:10px;overflow-x:auto;"
    "border-radius:6px;font-size:13px}.score{font-size:42px;font-weight:800}.sev-严重{color:#c0392b;font-weight:700}"
    ".sev-高{color:#d35400;font-weight:700}.sev-中{color:#b7950b}.sev-低{color:#2471a3}"
)


def render_html(meta, findings, score, ioc, ioc_path=None):
    b = band(score)
    color = {"正常": "#1e8449", "需关注": "#b7950b", "告警": "#d35400", "危险": "#c0392b"}[b]
    h = [
        "<!doctype html><meta charset='utf-8'><title>GCOY-LOGWARD 体检报告</title>",
        f"<style>{STYLE}</style><h1>GCOY-LOGWARD 日志体检报告</h1>",
        f"<p>auth 事件 {meta['auth_total']} | access 请求 {meta['acc_total']} | 白名单 {meta['wl_n']} 个 IP</p>",
        f"<div class='score' style='color:{color}'>{score}<span style='font-size:18px'>/100 {b}</span></div>",
        "<table><tr><th>级别</th><th>扣分</th><th>检测项</th><th>说明</th><th>证据数</th></tr>",
    ]
    for f in findings:
        h.append(
            f"<tr><td class='sev-{f['sev']}'>{f['sev']}</td><td>-{f['cost']}</td>"
            f"<td>{f['name']}</td><td>{f['note']}</td><td>{f['count']}</td></tr>"
        )
    h.append("</table>")
    for f in findings:
        h.append(f"<h3>[{f['sev']}] {f['name']}</h3><pre>" + "\n".join(f["evid"]).replace("<", "&lt;") + "</pre>")
    h.append("<h2>IOC 恶意 IP</h2><table><tr><th>IP</th><th>证据数</th><th>标签</th></tr>")
    for ip, v in sorted(ioc.items(), key=lambda kv: -kv[1]["evidence"]):
        h.append(f"<tr><td>{ip}</td><td>{v['evidence']}</td><td>{','.join(v['tags'])}</td></tr>")
    h.append("</table>")
    if ioc_path:
        h.append(f"<p>IOC 明细已导出：{ioc_path}</p>")
    return "\n".join(h)


def run(analyze_args):
    wl = set(x.strip() for x in (analyze_args.whitelist or "").split(",") if x.strip())
    auth_lines = Path(analyze_args.auth).read_text(encoding="utf-8", errors="replace").splitlines() if analyze_args.auth else []
    acc_lines = Path(analyze_args.access).read_text(encoding="utf-8", errors="replace").splitlines() if analyze_args.access else []
    if not auth_lines and not acc_lines:
        sys.exit("至少提供 --auth 或 --access 之一")
    auth = parse_auth(auth_lines, wl)
    acc = parse_access(acc_lines, wl)
    findings, score = build_findings(auth, acc)
    ioc = build_ioc(auth, acc)
    meta = {"auth_total": auth["total"], "acc_total": acc["total"], "wl_n": len(wl)}
    print_report(meta, findings, score, ioc)
    if analyze_args.ioc:
        Path(analyze_args.ioc).write_text(
            json.dumps({"meta": meta, "score": score, "iocs": ioc}, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(f"[+] IOC JSON -> {Path(analyze_args.ioc).resolve()}")
        if analyze_args.csv:
            with open(analyze_args.csv, "w", newline="", encoding="utf-8") as fp:
                w = csv.writer(fp)
                w.writerow(["ip", "tags", "evidence"])
                for ip, v in ioc.items():
                    w.writerow([ip, ";".join(v["tags"]), v["evidence"]])
            print(f"[+] IOC CSV -> {Path(analyze_args.csv).resolve()}")
    if analyze_args.html:
        Path(analyze_args.html).write_text(
            render_html(meta, findings, score, ioc, analyze_args.ioc), encoding="utf-8"
        )
        print(f"[+] HTML 报告 -> {Path(analyze_args.html).resolve()}")
    return score, ioc, findings


DEMO_USERS = ["root", "admin", "oracle", "ubuntu", "test"]


def gen_demo(outdir):
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    A, B, C = "203.0.113.9", "198.51.100.7", "192.0.2.44"
    auth = []
    auth.append("Oct  1 08:12:33 web1 sshd[1201]: Accepted password for deploy from %s port 51222 ssh2" % A)
    auth.append("Oct  1 09:01:11 web1 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/apt update")
    n = 1201
    for i in range(28):
        n += 1
        u = DEMO_USERS[i % len(DEMO_USERS)]
        auth.append("Oct  1 23:%02d:%02d web1 sshd[%d]: Failed password for %s from %s port %d ssh2"
                    % (40 + i % 20, i % 60, n, u, B, 40000 + i))
    n += 1
    auth.append("Oct  2 00:15:44 web1 sshd[%d]: Accepted password for root from %s port 40122 ssh2" % (n, B))
    n += 1
    auth.append("Oct  2 03:22:10 web1 sshd[%d]: Accepted password for deploy from %s port 55110 ssh2" % (n, C))
    auth.append("Oct  2 03:25:01 web1 sudo:   deploy : 3 incorrect password attempts ; TTY=pts/1")
    auth.append("Oct  2 04:02:19 web1 useradd[2101]: new user: name='svc_backup', UID=1002, GID=1002, home=/home/svc_backup")
    auth.append("Oct  2 04:02:20 web1 usermod[2102]: add 'svc_backup' to group 'sudo'")
    for i in range(12):
        auth.append("Oct  2 10:%02d:00 web1 sshd[%d]: Accepted publickey for deploy from %s port %d ssh2: RSA SHA256:abc"
                    % (20 + i, 3000 + i, A, 51000 + i))
    (outdir / "demo_auth.log").write_text("\n".join(auth) + "\n", encoding="utf-8")

    acc = []
    ua_ok = "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"
    t = "02/Oct/2026:09:%02d:%02d +0000"
    for i in range(20):
        acc.append('%s - - [%s] "GET /index.html HTTP/1.1" 200 5120 "-" "%s"' % (A, t % (i % 60, i * 2 % 60), ua_ok))
    for i in range(8):
        acc.append('%s - - [%s] "GET /index.php?id=1%%27 HTTP/1.1" 200 %d "-" "sqlmap/1.8#stable (https://sqlmap.org)"'
                   % (B, t % (10 + i, i), 2048 + i))
    for i in range(35):
        acc.append('%s - - [%s] "GET /wp-content/plugins/%d HTTP/1.1" 404 153 "-" "sqlmap/1.8#stable"' % (B, t % (20, i), i))
    for p in ["/.env", "/.git/config", "/backup.sql", "/phpmyadmin/", "/.bak"]:
        acc.append('%s - - [%s] "GET %s HTTP/1.1" 404 153 "-" "python-requests/2.31"' % (B, t % (25, 0), p))
    acc.append('%s - - [%s] "POST /upload/avatar.php HTTP/1.1" 200 320 "-" "Mozilla/5.0"' % (B, t % (30, 0)))
    acc.append('%s - - [%s] "POST /cmd.php HTTP/1.1" 200 88 "-" "Mozilla/5.0"' % (B, t % (31, 0)))
    for i in range(6):
        acc.append('%s - - [%s] "GET /static/app.%d.js HTTP/1.1" 200 99000 "-" "%s"' % (A, t % (40, i), i, ua_ok))
    (outdir / "demo_access.log").write_text("\n".join(acc) + "\n", encoding="utf-8")
    print(f"[+] 演示日志已生成 {outdir}/demo_auth.log, {outdir}/demo_access.log")
    return outdir / "demo_auth.log", outdir / "demo_access.log"


def main(argv=None):
    p = argparse.ArgumentParser(prog="gcoy-logward", description="蓝队日志体检：auth.log + nginx access.log -> 8 类检测 -> 评分/HTML/IOC")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("analyze", help="分析日志")
    s.add_argument("--auth", default=None, help="auth.log / secure 路径")
    s.add_argument("--access", default=None, help="nginx access.log 路径")
    s.add_argument("--whitelist", default="", help="逗号分隔 IP，全部检测豁免")
    s.add_argument("--html", default=None, help="导出 HTML 报告路径")
    s.add_argument("--ioc", default=None, help="导出 IOC JSON 路径")
    s.add_argument("--csv", default=None, help="导出 IOC CSV 路径（需 --ioc）")
    s.set_defaults(fn=run)
    s = sub.add_parser("demo", help="生成演示日志")
    s.add_argument("--outdir", default=".")
    def _demo(a):
        fa, fc = gen_demo(a.outdir)
        print(f"下一步: gcoy_logward.py analyze --auth {fa} --access {fc} --html report.html --ioc ioc.json")
    s.set_defaults(fn=_demo)
    def _selftest(a):
        tmp = tempfile.mkdtemp(prefix="gcoy-logward-")
        fa, fc = gen_demo(tmp)
        ns = argparse.Namespace(auth=str(fa), access=str(fc), whitelist="", html=os.path.join(tmp, "r.html"), ioc=os.path.join(tmp, "i.json"), csv=os.path.join(tmp, "i.csv"))
        score, ioc, findings = run(ns)
        assert score < 100, "演示日志应产生扣分"
        assert "198.51.100.7" in ioc, "演示日志应识别恶意 IP"
        names = {f["name"] for f in findings}
        assert "Webshell 落地访问" in names and "爆破后成功登录" in names, names
        html = Path(tmp, "r.html").read_text(encoding="utf-8")
        assert "198.51.100.7" in html
        js = json.loads(Path(tmp, "i.json").read_text(encoding="utf-8"))
        assert js["iocs"]["198.51.100.7"]["tags"]
        print("[selftest] OK ->", tmp)
    s = sub.add_parser("selftest", help="自检")
    s.set_defaults(fn=_selftest)
    args = p.parse_args(argv)
    args.fn(args)


if __name__ == "__main__":
    main()
