#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
authkeylens — authorized_keys 门禁审计。回答两个问题：
这台服务端允许谁进门、这些授权现在还健不健康。

零依赖单文件 CLI（Python 3.8+ 纯 stdlib）。SSH wire format 全部用 struct 手写解析
（ssh-ed25519 / ssh-rsa / ssh-dss / ecdsa-sha2-nistp256/384/521），
指纹输出格式与 `ssh-keygen -lf` 一致：SHA256: + base64(nopad)。

子命令：
    audit（默认）  全量审计，分级发现（CRIT/HIGH/MED/LOW/INFO/OK）+ SUMMARY
                   退出码：0=无 CRIT/HIGH，1=有 CRIT/HIGH，2=用法错误
    list           键位清单：文件 / 类型 / 位数 / SHA256 指纹 / 选项 / 注释
    accept         当前状态写入基线 JSON（--baseline PATH 必填）
    diff           与基线比对，按文件报 ADDED / REMOVED 指纹
                   退出码：2=有漂移，0=一致，用法错误=3（避免与漂移的 2 冲突）

扫描范围（三选一，多给算用法错误；都不给默认 --scan-home）：
    --file PATH     只看这一个 authorized_keys
    --scan-home     当前用户：~/.ssh/authorized_keys + 家目录/.ssh 权限链
    --scan-system   /etc/ssh + /root/.ssh + /home/*/.ssh 中存在且可读的（只读）

只读承诺：audit / list / diff 绝不写任何被扫描文件；
唯一写盘动作 = accept 写入你用 --baseline 显式指定的文件。
"""

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import struct
import sys
from pathlib import Path

VERSION = "1.0.0"
TOOL = "authkeylens"

# ------------------------------------------------------------ 常量 --

KEY_TYPES = (
    "ssh-ed25519", "ssh-rsa", "ssh-dss",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
)
CERT_TYPES = (
    "ssh-rsa-cert-v01@openssh.com", "ssh-dss-cert-v01@openssh.com",
    "ssh-ed25519-cert-v01@openssh.com",
    "ecdsa-sha2-nistp256-cert-v01@openssh.com",
    "sk-ssh-ed25519-cert-v01@openssh.com",
    "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
)
SK_TYPES = ("sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com")
KNOWN_TYPES = set(KEY_TYPES) | set(CERT_TYPES) | set(SK_TYPES)
ECDSA_BITS = {"nistp256": 256, "nistp384": 384, "nistp521": 521}

FLAG_OPTIONS = {
    "no-agent-forwarding", "no-port-forwarding", "no-pty",
    "no-X11-forwarding", "no-user-rc", "restrict", "cert-authority",
}
VALUED_OPTIONS = {
    "command", "from", "expiry-time", "permitopen", "permitlisten",
    "environment", "principals", "tunnel",
}

LEVELS = ("CRIT", "HIGH", "MED", "LOW", "INFO", "OK")
ICON = {"CRIT": "[CRIT]", "HIGH": "[HIGH]", "MED": "[MED] ", "LOW": "[LOW] ",
        "INFO": "[INFO]", "OK": "[OK]  "}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


# ------------------------------------------------------------ SSH wire format --

class WireError(ValueError):
    """SSH wire format 解析失败。"""


def _rd_str(data, off):
    """RFC 4251 string：4 字节大端长度 + 内容。"""
    if off + 4 > len(data):
        raise WireError("blob 截断：读不到 string 长度头")
    (n,) = struct.unpack(">I", data[off:off + 4])
    off += 4
    if off + n > len(data):
        raise WireError("blob 截断：string 声明 %d 字节，只剩 %d" % (n, len(data) - off))
    return data[off:off + n], off + n


def _mpint_bits(raw):
    """按规格：位数 = n 去前导零字节数 * 8。"""
    return len(raw.lstrip(b"\x00")) * 8


def parse_key_blob(keytype, blob):
    """手写解析公钥 blob。返回 {"bits": int|None, "error": str|None}。
    ssh-ed25519: string+string(32B)；ssh-rsa: mpint e + mpint n；
    ssh-dss: mpint p,q,g,y；ecdsa-sha2-nistpXXX: string curve + string Q。"""
    try:
        inner, off = _rd_str(blob, 0)
        inner_name = inner.decode("ascii", "replace")
        if inner_name != keytype:
            return {"bits": None,
                    "error": "blob 内部类型 %r 与行声明 %r 不一致" % (inner_name, keytype)}
        bits = None
        if keytype == "ssh-ed25519":
            pk, off = _rd_str(blob, off)
            if len(pk) != 32:
                return {"bits": None, "error": "ed25519 公钥应为 32 字节，实际 %d" % len(pk)}
            bits = 256
        elif keytype == "ssh-rsa":
            _e, off = _rd_str(blob, off)
            n, off = _rd_str(blob, off)
            bits = _mpint_bits(n)
        elif keytype == "ssh-dss":
            p, off = _rd_str(blob, off)
            _q, off = _rd_str(blob, off)
            _g, off = _rd_str(blob, off)
            _y, off = _rd_str(blob, off)
            bits = _mpint_bits(p)
        elif keytype.startswith("ecdsa-sha2-nistp"):
            curve, off = _rd_str(blob, off)
            point, off = _rd_str(blob, off)
            curve_name = curve.decode("ascii", "replace")
            want = keytype.rsplit("-", 1)[-1]
            if curve_name != want:
                return {"bits": None, "error": "曲线 %r 与类型 %r 不一致" % (curve_name, keytype)}
            bits = ECDSA_BITS.get(want)
            if not point or point[0] != 4:
                return {"bits": None, "error": "ECDSA 公钥点缺未压缩标志(0x04)"}
            if bits and len(point) != 1 + 2 * bits // 8:
                return {"bits": None, "error": "ECDSA 公钥点长度 %d 与曲线 %s 不符" % (len(point), want)}
        elif keytype in CERT_TYPES:
            return {"bits": None, "error": None}  # 证书 blob：取指纹，不深解析
        else:
            return {"bits": None, "error": "不支持的密钥类型 %r" % keytype}
        if off != len(blob):
            return {"bits": None, "error": "blob 尾部多出 %d 字节" % (len(blob) - off)}
        return {"bits": bits, "error": None}
    except WireError as e:
        return {"bits": None, "error": str(e)}
    except Exception as e:  # struct.error 等意外也不许炸
        return {"bits": None, "error": "blob 解析异常: %s" % e}


def fingerprint(blob):
    """SHA256(base64 nopad)，格式与 ssh-keygen -lf 一致。"""
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def short_fp(fp):
    return fp if len(fp) <= 28 else fp[:25] + "…"


# ------------------------------------------------------------ options 解析 --

def parse_options(text):
    """解析 authorized_keys 前置选项串。返回 ([(name, value|None)], error|None)。
    语法：逗号分隔；带值选项 name="value"，引号内支持 \\ 转义与逗号。"""
    opts = []
    i, n = 0, len(text)
    while i < n:
        start = i
        while i < n and text[i] not in "=,":
            i += 1
        name = text[start:i].strip()
        value = None
        if i < n and text[i] == "=":
            i += 1
            if i >= n or text[i] != '"':
                return opts, "选项 %r 的值必须用双引号" % name
            i += 1
            buf = []
            closed = False
            while i < n:
                c = text[i]
                if c == "\\" and i + 1 < n:
                    buf.append(text[i + 1])
                    i += 2
                    continue
                if c == '"':
                    closed = True
                    i += 1
                    break
                buf.append(c)
                i += 1
            if not closed:
                return opts, "选项 %r 的引号未闭合" % name
            value = "".join(buf)
        if i < n and text[i] == ",":
            i += 1
            if i >= n:
                return opts, "选项串以逗号结尾"
        if not name:
            return opts, "出现空选项名"
        opts.append((name, value))
    return opts, None


def validate_option_names(opts):
    """未知/错用选项 = sshd 会整行拒绝。返回错误字符串或 None。"""
    for name, value in opts:
        if name in FLAG_OPTIONS:
            if value is not None:
                return "flag 选项 %r 不应带值" % name
        elif name in VALUED_OPTIONS:
            if value is None:
                return "选项 %r 缺少值" % name
        else:
            return "未知选项 %r（sshd 会整行拒绝）" % name
    return None


def _junk(lineno, raw, reason):
    return ("junk", {"line": lineno, "reason": reason, "text": raw.strip()[:64]})


def parse_authorized_line(raw, lineno):
    """解析一行 authorized_keys。
    返回 None（空行/注释）/ ("key", keydict) / ("junk", junkdict)。"""
    line = raw.strip()
    if not line or line.startswith("#"):
        return None
    # 找第一个引号外空白 → 第一段
    i, n, inq, first_end = 0, len(line), False, None
    while i < n:
        c = line[i]
        if c == '"':
            inq = not inq
        elif c in " \t" and not inq:
            first_end = i
            break
        i += 1
    if first_end is None:
        if line in KNOWN_TYPES:
            return _junk(lineno, raw, "只有密钥类型，缺少 key blob")
        opts, err = parse_options(line)
        return _junk(lineno, raw, err or "缺少 key blob")
    first = line[:first_end]
    rest = line[first_end + 1:]
    opts = []
    if first in KNOWN_TYPES:
        keytype = first
        toks = rest.split(None, 2)  # [b64, comment...]
        if not toks:
            return _junk(lineno, raw, "缺少 key blob")
        b64 = toks[0]
        comment = toks[1] if len(toks) > 1 else ""
    elif first[:4] in ("ssh-", "ecds") or first.startswith("sk-"):
        return _junk(lineno, raw, "未知密钥类型 %r" % first)
    else:
        opts, err = parse_options(first)
        if err:
            return _junk(lineno, raw, "选项解析失败: %s" % err)
        err = validate_option_names(opts)
        if err:
            return _junk(lineno, raw, err)
        toks = rest.split(None, 2)  # [keytype, b64, comment...]
        if len(toks) < 2:
            return _junk(lineno, raw, "选项后面缺少密钥类型或 key blob")
        keytype = toks[0]
        if keytype not in KNOWN_TYPES:
            return _junk(lineno, raw, "未知密钥类型 %r" % keytype)
        b64 = toks[1]
        comment = toks[2] if len(toks) == 3 else ""
    try:
        blob = base64.b64decode(b64, validate=True)
    except Exception:
        return _junk(lineno, raw, "key blob 不是合法 base64")
    pr = parse_key_blob(keytype, blob)
    if pr["error"]:
        return _junk(lineno, raw, "%s blob 解析失败: %s" % (keytype, pr["error"]))
    values = {}
    for nm, v in opts:
        values.setdefault(nm, [])
        if v is not None:
            values[nm].append(v)
    kd = {
        "line": lineno,
        "keytype": keytype,
        "bits": pr["bits"],
        "cert": keytype in CERT_TYPES,
        "fingerprint": fingerprint(blob),
        "options_text": (first if opts else None),
        "opts": [(nm, v) for nm, v in opts],
        "flags": sorted(nm for nm, v in opts if v is None),
        "command": (values.get("command") or [None])[0],
        "from": (values.get("from") or [None])[0],
        "expiry": (values.get("expiry-time") or [None])[0],
        "permitopen": values.get("permitopen", []),
        "comment": comment.strip(),
    }
    return ("key", kd)


def parse_authorized_keys(path):
    """整个文件 → {"keys": [keydict], "junk": [junkdict], "error": str|None}"""
    p = Path(os.path.expanduser(str(path)))
    try:
        text = p.read_text(encoding="utf-8", errors="replace")
    except (OSError, PermissionError) as e:
        return {"keys": [], "junk": [], "error": "读不了: %s" % e}
    keys, junk = [], []
    for lineno, raw in enumerate(text.splitlines(), 1):
        r = parse_authorized_line(raw, lineno)
        if r is None:
            continue
        kind, obj = r
        (keys if kind == "key" else junk).append(obj)
    return {"keys": keys, "junk": junk, "error": None}


# ------------------------------------------------------------ 扫描目标 --

def target_from_file(path):
    p = Path(os.path.abspath(os.path.expanduser(str(path))))
    ssh_dir = home = None
    label = p.parent.name
    if p.parent.name == ".ssh" and p.parent.parent != p.parent:
        ssh_dir = p.parent
        home = p.parent.parent
        label = home.name
    return {"label": label, "file": str(p), "ssh_dir": (str(ssh_dir) if ssh_dir else None),
            "home": (str(home) if home else None), "kind": "file"}


def targets_scan_home():
    home = Path.home()
    return [{"label": home.name, "file": str(home / ".ssh" / "authorized_keys"),
             "ssh_dir": str(home / ".ssh"), "home": str(home), "kind": "home"}]


def targets_scan_system():
    out = []
    roots = [Path("/etc/ssh"), Path("/root/.ssh"),
             Path("/var/root/.ssh")]  # macOS root 家目录
    h = Path("/home")
    if h.is_dir():
        roots.extend(sorted(x / ".ssh" for x in h.iterdir() if x.is_dir()))
    for d in roots:
        f = d / "authorized_keys"
        if f.is_file() and os.access(str(f), os.R_OK):
            out.append({"label": str(d), "file": str(f), "ssh_dir": str(d),
                        "home": (str(d.parent) if d.name == ".ssh" else None),
                        "kind": "system"})
    return out


def resolve_targets(args):
    """三选一 → (targets, usage_error_msg|None)。"""
    given = [bool(args.file), args.scan_home, args.scan_system]
    if sum(given) > 1:
        return None, "--file / --scan-home / --scan-system 三选一，不要同时给"
    if args.file:
        p = Path(os.path.expanduser(args.file))
        if not p.is_file():
            return None, "文件不存在: %s" % p
        return [target_from_file(p)], None
    if args.scan_system:
        ts = targets_scan_system()
        return ts, None
    return targets_scan_home(), None


# ------------------------------------------------------------ 检查项 --

def mode_bits(path):
    try:
        return stat.S_IMODE(os.stat(str(path)).st_mode)
    except OSError:
        return None


def owner_ids(path):
    try:
        st = os.stat(str(path))
        return (st.st_uid, st.st_gid)
    except OSError:
        return None


def check_permission_chain(tg, findings):
    """EN-01/02/03/04：文件权限 / .ssh 目录权限 / 家目录可写 / 属主一致性。"""
    f = tg["file"]
    fm = mode_bits(f)
    if fm is None:
        findings.append(mk("EN-01", "CRIT", "authorized_keys 不存在或不可读: %s" % f))
        return
    if fm & 0o077:
        findings.append(mk("EN-01", "CRIT",
                           "%s 权限 %o 过宽（组/其他可读写）→ chmod 600 %s" % (os.path.basename(f), fm, f)))
    elif fm != 0o600:
        findings.append(mk("EN-01", "LOW",
                           "%s 权限 %o 偏松（建议 600）→ chmod 600 %s" % (os.path.basename(f), fm, f)))
    sd = tg.get("ssh_dir")
    if sd:
        dm = mode_bits(sd)
        if dm is not None and dm & 0o077:
            findings.append(mk("EN-02", "CRIT",
                               "%s 目录权限 %o 过宽 → chmod 700 %s" % (sd, dm, sd)))
    hd = tg.get("home")
    if hd:
        hm = mode_bits(hd)
        if hm is not None and hm & 0o022:
            findings.append(mk("EN-03", "HIGH",
                               "家目录 %s 组/其他可写（权限 %o）→ chmod go-w %s" % (hd, hm, hd)))
    fo, do = owner_ids(f), owner_ids(sd) if sd else None
    if fo and do and fo != do:
        findings.append(mk("EN-04", "MED",
                           "%s 属主 uid=%d 与 %s 属主 uid=%d 不一致（确认是否被人动过）"
                           % (os.path.basename(f), fo[0], sd, do[0])))


def check_keys(tg, parsed, findings):
    """EN-05 ~ EN-17：单文件内容类检查。"""
    label = tg["label"]
    keys, junk = parsed["keys"], parsed["junk"]
    path = tg["file"]
    for j in junk:
        findings.append(mk("EN-07", "HIGH", "第 %d 行无法解析（%s）: %s"
                           % (j["line"], j["reason"], j["text"])))
    for k in keys:
        fp = short_fp(k["fingerprint"])
        if k["keytype"] == "ssh-dss":
            findings.append(mk("EN-05", "CRIT", "%s 第 %d 行 ssh-dss 密钥（DSA，早已废弃）%s"
                               % (label, k["line"], fp)))
        if k["keytype"] == "ssh-rsa" and k["bits"] is not None and k["bits"] < 2048:
            findings.append(mk("EN-06", "CRIT", "%s 第 %d 行 RSA 仅 %d 位（<2048）%s"
                               % (label, k["line"], k["bits"], fp)))
        opts = {nm for nm, _ in k["opts"]}
        if "restrict" in opts and k["command"]:
            findings.append(mk("EN-17", "OK", "%s 第 %d 行 restrict+command= 受限键（好实践）%s"
                               % (label, k["line"], fp)))
        if not k["opts"] and not k["cert"]:
            findings.append(mk("EN-10", "MED", "%s 第 %d 行裸键无任何 options %s %s（等于全权钥匙）"
                               % (label, k["line"], k["keytype"], fp)))
        else:
            has_af = "no-agent-forwarding" not in opts and "restrict" not in opts
            if has_af and not k["command"]:
                findings.append(mk("EN-11", "MED", "%s 第 %d 行允许 agent-forwarding 且无 command= 限制 %s"
                                   % (label, k["line"], fp)))
            has_pf = "no-port-forwarding" not in opts and "restrict" not in opts
            if has_pf and not k["permitopen"]:
                findings.append(mk("EN-12", "MED", "%s 第 %d 行允许 port-forwarding 且无 permitopen= 限制 %s"
                                   % (label, k["line"], fp)))
        if not k["expiry"]:
            findings.append(mk("EN-13", "LOW", "%s 第 %d 行无 expiry-time 长期授权 %s %s"
                               % (label, k["line"], k["keytype"], fp)))
        if not k["from"]:
            findings.append(mk("EN-14", "LOW", "%s 第 %d 行无 from= 来源限制 %s"
                               % (label, k["line"], fp)))
        m = EMAIL_RE.search(k["comment"])
        if m:
            findings.append(mk("EN-15", "INFO", "%s 第 %d 行注释含邮箱 %s"
                               % (label, k["line"], m.group(0))))
    seen = {}
    for k in keys:
        sig = (k["keytype"], k["fingerprint"], k["options_text"], k["comment"])
        seen.setdefault(sig, []).append(k["line"])
    for sig, lines in seen.items():
        if len(lines) > 1:
            findings.append(mk("EN-08", "HIGH", "%s 完全重复条目 %d 份（行 %s）%s"
                               % (label, len(lines), ",".join(map(str, lines)), short_fp(sig[1]))))
    if not keys and not junk:
        findings.append(mk("EN-16", "LOW", "%s 的 authorized_keys 是空的（0 个有效键，确认是否遗留）" % label))


def cross_user_check(all_parsed, findings):
    """EN-09：同一指纹出现在多个用户文件。"""
    by_fp = {}
    for tg, parsed in all_parsed:
        for k in parsed["keys"]:
            by_fp.setdefault(k["fingerprint"], []).append((tg["label"], tg["file"], k["line"], k["keytype"]))
    for fp, hits in sorted(by_fp.items()):
        files = {h[1] for h in hits}
        if len(files) > 1:
            owners = sorted({h[0] for h in hits})
            findings.append(mk("EN-09", "HIGH", "同一指纹 %s 出现在 %d 个文件（%s）——共用密钥"
                               % (short_fp(fp), len(files), ", ".join(owners))))


def mk(code, level, msg):
    return {"code": code, "level": level, "msg": msg}


# ------------------------------------------------------------ audit 引擎 --

def collect(args):
    """→ (all_parsed, usage_error|None)。all_parsed: [(target, parsed)]"""
    targets, err = resolve_targets(args)
    if err:
        return None, err
    allp = []
    for tg in targets:
        allp.append((tg, parse_authorized_keys(tg["file"])))
    return allp, None


def run_audit(allp):
    findings = []
    for tg, parsed in allp:
        check_permission_chain(tg, findings)
        check_keys(tg, parsed, findings)
    cross_user_check(allp, findings)
    order = {lv: i for i, lv in enumerate(LEVELS)}
    findings.sort(key=lambda f: (order[f["level"]], f["code"], f["msg"]))
    blocking = any(f["level"] in ("CRIT", "HIGH") for f in findings)
    return findings, (1 if blocking else 0)


def summarize(findings):
    counts = {lv: 0 for lv in LEVELS}
    for f in findings:
        counts[f["level"]] += 1
    return counts


def print_audit(allp, findings, as_json):
    counts = summarize(findings)
    if as_json:
        print(json.dumps({
            "tool": TOOL, "version": VERSION, "files_scanned": len(allp),
            "findings": findings, "counts": counts,
            "exit": (1 if any(f["level"] in ("CRIT", "HIGH") for f in findings) else 0),
        }, ensure_ascii=False, indent=2))
        return
    if not findings:
        print("authkeylens audit — 干净")
        for tg, parsed in allp:
            print("  %s : %d 个有效键" % (tg["label"], len(parsed["keys"])))
        print("SUMMARY: 0 条发现，authorized_keys 门禁健康。")
        return
    for f in findings:
        print("%s %s %s" % (ICON[f["level"]], f["code"], f["msg"]))
    parts = " / ".join("%s %d" % (lv, counts[lv]) for lv in LEVELS if counts[lv])
    print("SUMMARY: 共 %d 条发现（%s）" % (len(findings), parts))
    print("退出码 %d%s" % (1, "（有 CRIT/HIGH，需处理）" if counts["CRIT"] or counts["HIGH"]
                            else "（无 CRIT/HIGH）" if findings else ""))


# ------------------------------------------------------------ list --

def run_list(allp, as_json):
    rows = []
    for tg, parsed in allp:
        for k in parsed["keys"]:
            rows.append({"file": tg["file"], "label": tg["label"], "line": k["line"],
                         "keytype": k["keytype"], "bits": k["bits"],
                         "fingerprint": k["fingerprint"],
                         "options": k["options_text"] or "", "comment": k["comment"]})
    if as_json:
        print(json.dumps({"tool": TOOL, "version": VERSION, "keys": rows},
                         ensure_ascii=False, indent=2))
        return
    if not rows:
        print("authkeylens list：没有解析到任何有效公钥。")
        return
    print("authkeylens list — %d 个有效公钥：" % len(rows))
    for r in rows:
        bits = ("%-5d" % r["bits"]) if r["bits"] else "  ?  "
        print("  %s L%-3d %-22s %s %s" % (r["label"], r["line"], r["keytype"],
                                          bits, r["fingerprint"]))
        if r["options"]:
            print("        options: %s" % r["options"])
        if r["comment"]:
            print("        comment: %s" % r["comment"])


# ------------------------------------------------------------ baseline --

def make_snapshot(allp):
    files = {}
    for tg, parsed in allp:
        files[tg["file"]] = {
            "label": tg["label"],
            "fingerprints": sorted({k["fingerprint"] for k in parsed["keys"]}),
            "junk_lines": len(parsed["junk"]),
        }
    return {"tool": TOOL, "version": VERSION, "files": files}


def run_accept(allp, baseline, as_json):
    snap = make_snapshot(allp)
    bp = Path(os.path.expanduser(baseline))
    bp.write_text(json.dumps(snap, ensure_ascii=False, indent=1), encoding="utf-8")
    n = sum(len(v["fingerprints"]) for v in snap["files"].values())
    if as_json:
        print(json.dumps({"baseline": str(bp), "files": len(snap["files"]),
                          "fingerprints": n}, ensure_ascii=False))
    else:
        print("基线已写入 %s（%d 个文件 / %d 个指纹）" % (bp, len(snap["files"]), n))


def run_diff(allp, baseline, as_json):
    """退出码：0 一致 / 2 有漂移 / 3 用法错误。"""
    bp = Path(os.path.expanduser(baseline))
    if not bp.is_file():
        return 3, None, "基线文件不存在: %s（先跑 accept --baseline）" % str(bp)
    try:
        old = json.loads(bp.read_text(encoding="utf-8"))
    except Exception as e:
        return 3, None, "基线 JSON 解析失败: %s" % e
    if not isinstance(old, dict) or "files" not in old:
        return 3, None, "基线 JSON 结构不对（缺 files 字段）"
    snap = make_snapshot(allp)
    changes = []  # (kind, file, fp)
    for f in sorted(set(snap["files"]) | set(old["files"])):
        new_fps = set(snap["files"].get(f, {}).get("fingerprints", []))
        old_fps = set(old["files"].get(f, {}).get("fingerprints", []))
        for fp in sorted(new_fps - old_fps):
            changes.append(("ADDED", f, fp))
        for fp in sorted(old_fps - new_fps):
            changes.append(("REMOVED", f, fp))
    if as_json:
        print(json.dumps({"tool": TOOL, "version": VERSION,
                          "drift": bool(changes),
                          "changes": [{"kind": k, "file": f, "fingerprint": fp}
                                      for k, f, fp in changes]}, ensure_ascii=False, indent=2))
    else:
        if not changes:
            print("authkeylens diff：与基线一致，没有漂移。")
        else:
            print("authkeylens diff — 与基线相比 %d 处漂移：" % len(changes))
            for kind, f, fp in changes:
                tag = "ADDED" if kind == "ADDED" else "REMOVED"
                print("  %s %s %s %s" % (tag, short_fp(fp), f,
                                         "（新指纹出现）" if kind == "ADDED" else "（指纹消失）"))
    return (2 if changes else 0), changes, None


# ------------------------------------------------------------ selftest --

def selftest():
    """41 条不变量（EN-01 ~ EN-17 + wire/边界），fixture 全合成。"""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from selftest_authkeylens import run_all
    return run_all(verbose=True)


# ------------------------------------------------------------ CLI --

def build_parser():
    ap = argparse.ArgumentParser(
        prog=TOOL, description="authorized_keys 门禁审计（谁被允许进门、授权是否还健康）")
    ap.add_argument("--version", action="version", version="%s %s" % (TOOL, VERSION))
    sub = ap.add_subparsers(dest="cmd")

    def sub_add(name, **kw):
        p = sub.add_parser(name, **kw)
        # 公共参数在每个子命令上独立声明（argparse 子命令不继承主 parser）
        p.add_argument("--json", action="store_true", help="机器可读输出")
        p.add_argument("--file", default=None, help="只看这一个 authorized_keys")
        p.add_argument("--scan-home", action="store_true", help="扫当前用户 ~/.ssh/authorized_keys")
        p.add_argument("--scan-system", action="store_true",
                       help="扫 /etc/ssh + /root/.ssh + /home/*/.ssh（只读）")
        return p

    sub_add("audit", help="全量审计（默认子命令）")
    sub_add("list", help="键位清单")
    sp_ac = sub_add("accept", help="当前状态写入基线 JSON")
    sp_ac.add_argument("--baseline", required=True, help="基线 JSON 路径")
    sp_df = sub_add("diff", help="与基线比对（exit 2=有漂移，用法错误=3）")
    sp_df.add_argument("--baseline", required=True, help="基线 JSON 路径")
    sub.add_parser("selftest", help="不变量自测")
    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    J = args.json
    cmd = args.cmd or "audit"

    if cmd == "selftest":
        sys.exit(selftest())

    allp, err = collect(args)
    if err:
        print("用法错误: %s" % err, file=sys.stderr)
        sys.exit(2)
    if not allp:
        print("没有找到任何可读的 authorized_keys（试 --file 或 --scan-home）。", file=sys.stderr)
        sys.exit(2)

    if cmd == "audit":
        findings, code = run_audit(allp)
        print_audit(allp, findings, J)
        sys.exit(code)
    if cmd == "list":
        run_list(allp, J)
        sys.exit(0)
    if cmd == "accept":
        run_accept(allp, args.baseline, J)
        sys.exit(0)
    if cmd == "diff":
        code, _, _ = run_diff(allp, args.baseline, J)
        sys.exit(code)
    ap.print_help()
    sys.exit(2)


if __name__ == "__main__":
    main()
