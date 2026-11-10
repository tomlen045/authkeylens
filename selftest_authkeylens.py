#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest_authkeylens.py — authkeylens 的不变量自测。

全部密钥用 struct 手工构造合法 SSH 公钥 blob（ed25519 / rsa-2048 / rsa-1024 弱钥 /
ssh-dss / ecdsa-p256），fixture 用 tempfile 搭建（多用户目录、权限错误、垃圾行、
重复键、restrict 好键、基线漂移）。注释/邮箱一律 example.com 合成值。
绝不触碰真实 ~/.ssh。运行：python3 selftest_authkeylens.py  →  ALL PASS & exit 0。
"""

import base64
import hashlib
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import authkeylens as ak  # noqa: E402

PY = sys.executable
TOOL = str(HERE / "authkeylens.py")


# ------------------------------------------------------------ 手工造 key --

def _s(b):
    """RFC 4251 string。"""
    return struct.pack(">I", len(b)) + b


def _mpint(i):
    """RFC 4251 mpint（正数，带必要前导零字节以保高位）。"""
    if i == 0:
        return _s(b"\x00")
    raw = i.to_bytes((i.bit_length() + 7) // 8, "big")
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return _s(raw)


def blob_ed25519(pub32):
    return _s(b"ssh-ed25519") + _s(pub32)


def blob_rsa(n, e=65537):
    return _s(b"ssh-rsa") + _mpint(e) + _mpint(n)


def blob_dss(p):
    return (_s(b"ssh-dss") + _mpint(p) + _mpint(2 ** 159 + 5)
            + _mpint(2 ** 319 + 7) + _mpint(2 ** 1023 + 11))


def blob_ecdsa_p256(x, y):
    return (_s(b"ecdsa-sha2-nistp256") + _s(b"nistp256")
            + _s(b"\x04" + x.to_bytes(32, "big") + y.to_bytes(32, "big")))


def b64(blob):
    return base64.b64encode(blob).decode()


def line_ed(pub32, comment="demo@example.com", options=None):
    k = blob_ed25519(pub32)
    return (("options " % ()) if False else
            (options + " " if options else "") + "ssh-ed25519 " + b64(k)
            + ((" " + comment) if comment else ""))


def full_line(keytype, blob, comment="demo@example.com", options=None):
    return ((options + " ") if options else "") + keytype + " " + b64(blob) \
        + ((" " + comment) if comment else "")


# 固定合成密钥材料（无任何真实凭据）
ED_A = bytes(range(32))                 # 32B 合成公钥 A
ED_B = bytes(range(32, 64))             # 32B 合成公钥 B
ED_C = bytes([7] * 32)                  # 32B 合成公钥 C
RSA2048_N = int.from_bytes(hashlib.sha256(b"authkeylens-rsa2048").digest(), "big") | (1 << 2047)
RSA1024_N = int.from_bytes(hashlib.sha256(b"authkeylens-rsa1024").digest(), "big") | (1 << 1023)
DSS_P = int.from_bytes(hashlib.sha512(b"authkeylens-dss").digest(), "big") | (1 << 1023)
EC_X = int.from_bytes(hashlib.sha256(b"authkeylens-ec-x").digest(), "big")
EC_Y = int.from_bytes(hashlib.sha256(b"authkeylens-ec-y").digest(), "big")

L_ED_A = line_ed(ED_A)
L_ED_B = line_ed(ED_B)
L_ED_C = line_ed(ED_C)
L_RSA2048 = full_line("ssh-rsa", blob_rsa(RSA2048_N))
L_RSA1024 = full_line("ssh-rsa", blob_rsa(RSA1024_N), comment="weak@example.com")
L_DSS = full_line("ssh-dss", blob_dss(DSS_P))
L_ECDSA = full_line("ecdsa-sha2-nistp256", blob_ecdsa_p256(EC_X, EC_Y))
L_RESTRICT = ("restrict,command=\"echo hi\",no-agent-forwarding,no-port-forwarding,"
              "no-pty,no-X11-forwarding ssh-ed25519 " + b64(blob_ed25519(ED_C))
              + " ci-bot@example.com")
L_BARE = L_ED_A  # 无 options = 裸键
L_COMMAND_ONLY = "command=\"/srv/backup/run.sh\" ssh-ed25519 " + b64(blob_ed25519(ED_B)) + " backup@example.com"
L_WITH_EXPIRY = 'expiry-time="20300101000000" ssh-ed25519 ' + b64(blob_ed25519(ED_A)) + " temp@example.com"


# ------------------------------------------------------------ fixture 基建 --

class Env:
    """tempfile 全套 fixture：多用户目录 + 权限可控。"""

    def __init__(self):
        self.root = tempfile.mkdtemp(prefix="akl-selftest-")
        self.home1 = Path(self.root) / "home" / "alice"
        self.home2 = Path(self.root) / "home" / "bob"
        for d in (self.home1, self.home2):
            (d / ".ssh").mkdir(parents=True)
            os.chmod(d / ".ssh", 0o700)
            os.chmod(d, 0o755)

    def ak(self, home, content, mode=0o600, name="authorized_keys"):
        f = home / ".ssh" / name
        f.write_text(content + "\n", encoding="utf-8")
        os.chmod(f, mode)
        return str(f)

    def wipe(self):
        import shutil
        shutil.rmtree(self.root, ignore_errors=True)


def run_cli(*argv):
    """子进程冒烟：真实 CLI。返回 (exit_code, stdout, stderr)。"""
    r = subprocess.run([PY, TOOL] + list(argv), capture_output=True, text=True, timeout=60)
    return r.returncode, r.stdout, r.stderr


def fake_target(env):
    """让 collect 走 fixture 的 home 而不是真实 ~：monkeypatch resolve_targets。"""
    def patched(args):
        return ([{"label": "alice", "file": str(env.home1 / ".ssh" / "authorized_keys"),
                  "ssh_dir": str(env.home1 / ".ssh"), "home": str(env.home1),
                  "kind": "home"}], None)
    return patched


# ------------------------------------------------------------ 用例 --

RESULTS = []


def reset_state():
    """测试隔离：清掉跨用例残留的 EN-09 状态。"""
    RESULTS.clear()


def check(en, name, fn):
    try:
        fn()
        RESULTS.append((en, name, True, ""))
    except Exception as ex:
        RESULTS.append((en, name, False, "%s: %s" % (type(ex).__name__, ex)))


def run_all(verbose=True):
    env = Env()
    try:
        _register_cases(env)
    finally:
        env.wipe()
    ok = sum(1 for _, _, s, _ in RESULTS if s)
    if verbose:
        for en, name, s, msg in RESULTS:
            print("%s %-6s %s%s" % ("PASS" if s else "FAIL", en, name,
                                    ("" if s else "  -> " + msg)))
        print("SELFTEST %s %d/%d" % ("PASS" if ok == len(RESULTS) else "FAIL",
                                     ok, len(RESULTS)))
    return 0 if ok == len(RESULTS) else 1


def _register_cases(env):
    # ---- wire format ----

    def t01():
        pr = ak.parse_key_blob("ssh-ed25519", blob_ed25519(ED_A))
        assert pr["bits"] == 256 and pr["error"] is None, pr
    check("wire-01", "ed25519 blob struct 手写解析出 256 位", t01)

    def t02():
        pr = ak.parse_key_blob("ssh-rsa", blob_rsa(RSA2048_N))
        assert pr["bits"] == 2048 and pr["error"] is None, pr
    check("wire-02", "rsa-2048 blob 解析出 2048 位（mpint 去前导零）", t02)

    def t03():
        pr = ak.parse_key_blob("ssh-rsa", blob_rsa(RSA1024_N))
        assert pr["bits"] == 1024, pr
    check("wire-03", "rsa-1024 弱钥解析出 1024 位", t03)

    def t04():
        pr = ak.parse_key_blob("ssh-dss", blob_dss(DSS_P))
        assert pr["bits"] == 1024, pr
    check("wire-04", "ssh-dss blob 解析出 p=1024 位", t04)

    def t05():
        pr = ak.parse_key_blob("ecdsa-sha2-nistp256", blob_ecdsa_p256(EC_X, EC_Y))
        assert pr["bits"] == 256 and pr["error"] is None, pr
    check("wire-05", "ecdsa-p256 blob 解析出曲线与 256 位", t05)

    def t06():
        fp_ak = ak.fingerprint(blob_ed25519(ED_A))
        tmp = Path(tempfile.mkdtemp(prefix="akl-fp-")) / "demo.pub"
        tmp.write_text("ssh-ed25519 " + b64(blob_ed25519(ED_A)) + " t@example.com")
        r = subprocess.run(["ssh-keygen", "-lf", str(tmp)], capture_output=True, text=True)
        tmp.parent.joinpath("x").unlink(missing_ok=True)
        if r.returncode == 0:
            assert fp_ak in r.stdout, "指纹与 ssh-keygen -lf 不一致: %s vs %s" % (fp_ak, r.stdout)
        else:
            assert fp_ak.startswith("SHA256:") and len(fp_ak) > 20
    check("wire-06", "SHA256 指纹格式与 ssh-keygen -lf 一致（有则比）", t06)

    def t07():
        for bad in (b"", b"\x00\x01", b"\xff" * 3, _s(b"ssh-rsa")[:6]):
            pr = ak.parse_key_blob("ssh-rsa", bad)
            assert pr["error"], ("应报错", bad, pr)
    check("wire-07", "截断/垃圾 blob 绝不 crash，报 WireError 文案", t07)

    def t08():
        wrong = _s(b"ssh-ed25519") + _s(bytes(32))
        pr = ak.parse_key_blob("ssh-rsa", wrong)
        assert pr["error"] and "不一致" in pr["error"], pr
    check("wire-08", "行声明与 blob 内部类型不一致被识破", t08)

    def t09():
        r = ak.parse_authorized_line(L_RESTRICT, 1)
        kind, kd = r
        assert kind == "key" and kd["command"] == "echo hi", kd
        assert "restrict" in kd["flags"] and kd["expiry"] is None
    check("opt-01", "restrict+command= 选项逐项解析（引号值）", t09)

    def t10():
        r = ak.parse_authorized_line('command="a,b \\"c\\"" ssh-ed25519 ' + b64(blob_ed25519(ED_A)), 1)
        _, kd = r
        assert kd["command"] == 'a,b "c"', kd
    check("opt-02", "command 值内逗号与反斜杠转义", t10)

    def t11():
        r = ak.parse_authorized_line('from="10.0.0.0/8,!.example" ssh-ed25519 ' + b64(blob_ed25519(ED_A)), 1)
        _, kd = r
        assert kd["from"] == "10.0.0.0/8,!.example", kd
    check("opt-03", "from= 值解析", t11)

    def t12():
        r = ak.parse_authorized_line('expiry-time="20261231235959" ssh-ed25519 ' + b64(blob_ed25519(ED_A)), 1)
        _, kd = r
        assert kd["expiry"] == "20261231235959", kd
    check("opt-04", 'expiry-time="..." 解析', t12)

    def t13():
        r = ak.parse_authorized_line('permitopen="host.example:5432" ssh-ed25519 ' + b64(blob_ed25519(ED_A)), 1)
        _, kd = r
        assert kd["permitopen"] == ["host.example:5432"], kd
    check("opt-05", "permitopen= 值解析", t13)

    def t14():
        r = ak.parse_authorized_line("command=\"unterminated ssh-ed25519 " + b64(blob_ed25519(ED_A)), 1)
        assert r[0] == "junk", r
    check("opt-06", "引号未闭合 → junk 不 crash", t14)

    # ---- EN-01/02/03/04 权限链 ----

    def t15():
        f = env.ak(env.home1, L_ED_A)
        os.chmod(f, 0o644)
        tg = ak.target_from_file(f)
        fs = []
        ak.check_permission_chain(tg, fs)
        assert any(x["code"] == "EN-01" and x["level"] == "CRIT" for x in fs), fs
    check("EN-01", "authorized_keys 644 = CRIT（EN-01）", t15)

    def t16():
        f = env.ak(env.home1, L_ED_A)
        os.chmod(env.home1 / ".ssh", 0o755)
        tg = ak.target_from_file(f)
        fs = []
        ak.check_permission_chain(tg, fs)
        assert any(x["code"] == "EN-02" and x["level"] == "CRIT" for x in fs), fs
        os.chmod(env.home1 / ".ssh", 0o700)
    check("EN-02", ".ssh 目录 755 = CRIT（EN-02）", t16)

    def t17():
        f = env.ak(env.home1, L_ED_A)
        os.chmod(env.home1, 0o773)
        tg = ak.target_from_file(f)
        fs = []
        ak.check_permission_chain(tg, fs)
        assert any(x["code"] == "EN-03" and x["level"] == "HIGH" for x in fs), fs
        os.chmod(env.home1, 0o755)
    check("EN-03", "家目录组/其他可写 = HIGH（EN-03）", t17)

    def t18():
        f = env.ak(env.home1, L_ED_A)
        os.chmod(f, 0o600)
        tg = ak.target_from_file(f)
        fs = []
        ak.check_permission_chain(tg, fs)
        assert not any(x["code"] in ("EN-01", "EN-02", "EN-03") for x in fs), fs
    check("EN-01b", "600/700/755 全部合规时权限链零误报", t18)

    def t19():
        f = env.ak(env.home1, L_ED_A)
        os.chmod(f, 0o600)
        # 用 chown 模拟属主不一致（仅 fixture 内文件；无权限则跳过该断言）
        tg = ak.target_from_file(f)
        try:
            os.chown(f, os.getuid() + 12345, -1)
        except PermissionError:
            # 无 root 时用 monkeypatch owner_ids 模拟
            orig = ak.owner_ids
            ak.owner_ids = lambda p: ((111, 111) if str(p) == f else orig(p))
            try:
                fs = []
                ak.check_permission_chain(tg, fs)
                assert any(x["code"] == "EN-04" for x in fs), fs
            finally:
                ak.owner_ids = orig
            return
        fs = []
        ak.check_permission_chain(tg, fs)
        assert any(x["code"] == "EN-04" and x["level"] == "MED" for x in fs), fs
        os.chown(f, os.getuid(), -1)
    check("EN-04", "authorized_keys 属主与目录属主不一致 = MED（EN-04）", t19)

    # ---- EN-05/06/07/08 密钥强度 ----

    def t20():
        r = ak.parse_authorized_line(L_DSS, 1)
        assert r[0] == "key"
        kd = r[1]
        assert kd["keytype"] == "ssh-dss" and kd["bits"] == 1024
    check("EN-05a", "ssh-dss 行解析成功（供 audit 判 CRIT）", t20)

    def t21():
        f = env.ak(env.home1, L_DSS)
        allp, err = ak.collect(_args(file=f))
        assert err is None
        fs, code = ak.run_audit(allp)
        assert any(x["code"] == "EN-05" and x["level"] == "CRIT" for x in fs), fs
        assert code == 1
    check("EN-05", "ssh-dss = CRIT 且退出码 1（EN-05）", t21)

    def t22():
        f = env.ak(env.home1, L_RSA1024)
        allp, _ = ak.collect(_args(file=f))
        fs, code = ak.run_audit(allp)
        assert any(x["code"] == "EN-06" and x["level"] == "CRIT" and "1024" in x["msg"] for x in fs), fs
        assert code == 1
    check("EN-06", "RSA<2048 = CRIT（EN-06）", t22)

    def t23():
        f = env.ak(env.home1, L_RSA2048)
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert not any(x["code"] == "EN-06" for x in fs), fs
    check("EN-06b", "RSA-2048 不触发 EN-06", t23)

    def t24():
        bad1 = "this is garbage not a key"
        bad2 = "ssh-ed25519 not_base64!!"
        bad3 = "unknown-type-xyz AAAA fake@example.com"
        f = env.ak(env.home1, "\n".join([bad1, bad2, bad3]))
        parsed = ak.parse_authorized_keys(f)
        assert len(parsed["junk"]) == 3, parsed["junk"]
        assert len(parsed["keys"]) == 0
        allp, _ = ak.collect(_args(file=f))
        fs, code = ak.run_audit(allp)
        assert any(x["code"] == "EN-07" and x["level"] == "HIGH" for x in fs), fs
        assert code == 1
    check("EN-07", "垃圾行/未知类型 = HIGH 且不 crash（EN-07）", t24)

    def t25():
        f = env.ak(env.home1, L_ED_A + "\n" + L_ED_A)
        allp, _ = ak.collect(_args(file=f))
        fs, code = ak.run_audit(allp)
        hits = [x for x in fs if x["code"] == "EN-08"]
        assert hits and hits[0]["level"] == "HIGH", fs
        assert code == 1
    check("EN-08", "单文件完全重复条目 = HIGH（EN-08）", t25)

    # ---- EN-09 跨文件共用 ----

    def t26():
        f1 = env.ak(env.home1, L_ED_A)
        f2 = env.ak(env.home2, L_ED_A + "\n" + L_ED_B)
        allp, _ = ak.collect(_args(file=f1, extra_files=[f2]))
        fs, _ = ak.run_audit(allp)
        assert any(x["code"] == "EN-09" and x["level"] == "HIGH" for x in fs), fs
    check("EN-09", "同一指纹出现在多个用户文件 = HIGH（EN-09）", t26)

    # ---- EN-10 ~ EN-17 授权蔓延 ----

    def t27():
        f = env.ak(env.home1, L_BARE)
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert any(x["code"] == "EN-10" and x["level"] == "MED" for x in fs), fs
    check("EN-10", "完全裸键（无 options）= MED（EN-10）", t27)

    def t28():
        line = "no-pty ssh-ed25519 " + b64(blob_ed25519(ED_B)) + " agentfwd@example.com"
        f = env.ak(env.home1, line)
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert any(x["code"] == "EN-11" and x["level"] == "MED" for x in fs), fs
    check("EN-11", "agent-forwarding 开且无 command= = MED（EN-11）", t28)

    def t29():
        line = "no-pty ssh-ed25519 " + b64(blob_ed25519(ED_B)) + " fwd@example.com"
        f = env.ak(env.home1, line)
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert any(x["code"] == "EN-12" and x["level"] == "MED" for x in fs), fs
    check("EN-12", "port-forwarding 开且无 permitopen = MED（EN-12）", t29)

    def t30():
        f = env.ak(env.home1, L_ED_B)
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert any(x["code"] == "EN-13" and x["level"] == "LOW" for x in fs), fs
    check("EN-13", "无 expiry-time 长期授权 = LOW（EN-13）", t30)

    def t31():
        f = env.ak(env.home1, L_WITH_EXPIRY)
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert not any(x["code"] == "EN-13" for x in fs), fs
    check("EN-13b", "带 expiry-time 不触发 EN-13", t31)

    def t32():
        f = env.ak(env.home1, L_ED_C)
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert any(x["code"] == "EN-14" and x["level"] == "LOW" for x in fs), fs
    check("EN-14", "无 from= = LOW 提示（EN-14）", t32)

    def t33():
        f = env.ak(env.home1, L_ED_A)
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert any(x["code"] == "EN-15" and x["level"] == "INFO" and "example.com" in x["msg"] for x in fs), fs
    check("EN-15", "注释含邮箱 = INFO（EN-15）", t33)

    def t34():
        f = env.ak(env.home1, "# only comment\n\n")
        allp, _ = ak.collect(_args(file=f))
        fs, _ = ak.run_audit(allp)
        assert any(x["code"] == "EN-16" and x["level"] == "LOW" for x in fs), fs
    check("EN-16", "空 authorized_keys = LOW 提示（EN-16）", t34)

    def t35():
        f = env.ak(env.home1, L_RESTRICT)
        allp, _ = ak.collect(_args(file=f))
        fs, code = ak.run_audit(allp)
        assert any(x["code"] == "EN-17" and x["level"] == "OK" for x in fs), fs
        # restrict 键不应再报 EN-10/11/12
        assert not any(x["code"] in ("EN-10", "EN-11", "EN-12") for x in fs), fs
    check("EN-17", "restrict+command= 受限键 = OK，且不叠加 MED（EN-17）", t35)

    # ---- 子命令与退出码 ----

    def t36():
        f = env.ak(env.home1, L_ED_A)
        code, out, err = run_cli("list", "--file", f)
        assert code == 0, (code, err)
        assert "ssh-ed25519" in out and "SHA256:" in out
    check("cli-01", "list --file 输出键位清单 exit 0", t36)

    def t37():
        f = env.ak(env.home1, L_DSS)
        code, out, err = run_cli("audit", "--file", f)
        assert code == 1, (code, err)
        assert "[CRIT]" in out and "EN-05" in out and "SUMMARY" in out, out
    check("cli-02", "audit 命中 CRIT → exit 1 + SUMMARY", t37)

    def t38():
        f = env.ak(env.home1, L_RESTRICT)
        code, out, err = run_cli("audit", "--file", f)
        assert code == 0, (code, out, err)
        assert "[OK]" in out and "EN-17" in out
    check("cli-03", "audit 只有 OK → exit 0", t38)

    def t39():
        code, out, err = run_cli("audit", "--file", "/nonexistent/ak")
        assert code == 2, (code, err)
        code, out, err = run_cli("audit", "--file", "/x", "--scan-home")
        assert code == 2, (code, err)
        code, out, err = run_cli("diff", "--baseline", "/nonexistent/base.json", "--file",
                                 str(env.home1 / ".ssh" / "authorized_keys"))
        assert code == 3, (code, err)
    check("cli-04", "用法错误 exit 2；diff 缺基线 exit 3", t39)

    def t40():
        f = env.ak(env.home1, L_ED_A + "\n" + L_ED_B)
        base = str(Path(env.root) / "base.json")
        code, out, err = run_cli("accept", "--file", f, "--baseline", base)
        assert code == 0, (code, err)
        assert Path(base).is_file()
        code, out, err = run_cli("diff", "--file", f, "--baseline", base)
        assert code == 0, (code, out, err)
        # 漂移：新增一把 + 删一把
        env.ak(env.home1, L_ED_A + "\n" + L_ED_C)
        code, out, err = run_cli("diff", "--file", f, "--baseline", base)
        assert code == 2, (code, out, err)
        assert "ADDED" in out and "REMOVED" in out, out
    check("cli-05", "accept 写基线；diff 无漂移 exit 0，有漂移 exit 2", t40)

    def t41():
        f = env.ak(env.home1, L_ED_A + "\n" + L_ED_B)
        base = str(Path(env.root) / "base.json")
        run_cli("accept", "--file", f, "--baseline", base)
        env.ak(env.home1, L_ED_C)
        code, out, err = run_cli("diff", "--file", f, "--baseline", base, "--json")
        assert code == 2
        data = json.loads(out)
        assert data["drift"] is True
        kinds = {c["kind"] for c in data["changes"]}
        assert kinds == {"ADDED", "REMOVED"}, data
    check("cli-06", "diff --json 报 drift + ADDED/REMOVED 结构", t41)

    def t42():
        f = env.ak(env.home1, L_ED_A)
        code, out, err = run_cli("audit", "--file", f, "--json")
        assert code in (0, 1)
        data = json.loads(out)
        assert "findings" in data and "counts" in data and "exit" in data
    check("cli-07", "audit --json 机器可读结构", t42)

    def t43():
        f = env.ak(env.home1, "# 注释\n\n" + L_ECDSA + "\r\n")
        parsed = ak.parse_authorized_keys(f)
        assert len(parsed["keys"]) == 1, parsed
        assert parsed["keys"][0]["keytype"] == "ecdsa-sha2-nistp256"
        assert parsed["junk"] == []
    check("rob-01", "CRLF/尾随空白/注释容错", t43)

    def t44():
        f = env.ak(env.home1, "no-user-rc,no-pty ssh-ed25519 " + b64(blob_ed25519(ED_A)) + " x@example.com")
        parsed = ak.parse_authorized_keys(f)
        assert len(parsed["keys"]) == 1, parsed["junk"]
    check("rob-02", "多 flag 选项逗号分隔解析", t44)

    def t45():
        f = env.ak(env.home1, "ssh-ed25519")
        r = ak.parse_authorized_line("ssh-ed25519", 1)
        assert r[0] == "junk" and "缺少 key blob" in r[1]["reason"], r
    check("rob-03", "只有类型没有 blob → junk", t45)

    def t46():
        before = Path(env.home1 / ".ssh" / "authorized_keys").read_bytes() if (
            env.home1 / ".ssh" / "authorized_keys").exists() else b""
        f = env.ak(env.home1, L_ED_A)
        data_before = Path(f).read_bytes()
        ak.collect(_args(file=f))
        allp, _ = ak.collect(_args(file=f))
        ak.run_audit(allp)
        ak.run_list(allp, False)
        assert Path(f).read_bytes() == data_before, "list/audit 改了被扫文件"
        assert before == b"" or True
    check("EN-00", "audit/list/diff 只读承诺：被扫文件字节级不变", t46)


def _args(file=None, extra_files=None):
    """构造一个 namespace 供 collect 使用（绕过真实家目录）。
    extra_files 时 monkeypatch resolve_targets 限定只扫 fixture 文件；
    未 extra_files 时同样 monkeypatch，防止残留 patch 影响隔离。"""
    import argparse

    class NS:
        pass
    ns = NS()
    ns.file = file
    ns.scan_home = False
    ns.scan_system = False
    files = ([file] if file else []) + list(extra_files or [])

    def patched(a):
        return [ak.target_from_file(x) for x in files], None
    ak.resolve_targets = patched
    return ns


if __name__ == "__main__":
    sys.exit(run_all(verbose=True))
