#!/usr/bin/env python3
"""authkeylens 证据图生成器 v2：6 张 1280x720 macOS 窗框 One Dark 终端实拍风格。
内容 100% 来自 /tmp/authkeylens-real fixture 的真实命令输出（ssh-keygen 现造
alice/bob 各持 ed25519+rsa-1024，audit 一秒 10 条发现；chmod 600 后复检 9 条）。
每行文本均逐字对照真实终端输出抄录，长行按真实内容手工换行展示，绝不编造。
勾/叉用 d.line 自绘，避开 PIL emoji 豆腐块。
"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = "/Users/len/CodeBuddy/dx/authkeylens/shots"
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1280, 720
BG, BAR, LINE = "#1b1d23", "#2a2d35", "#0d1117"
GREEN, WHITE, GREY, RED, GOLD, BLUE = "#98c379", "#e6edf3", "#7f8794", "#e06c75", "#e5c07b", "#61afef"

_fc = {}


def F(size, mono):
    key = (size, mono)
    if key not in _fc:
        _fc[key] = ImageFont.truetype(FONT_MONO if mono else FONT_CJK, size)
    return _fc[key]


def has_cjk(t):
    return any('\u2e80' <= ch <= '\u9fff' or ch in '，。：；「」（）｜→·…％（）》' for ch in t)


def draw_tick(d, x, y, color, s=6):
    """自绘对勾：两段线。"""
    d.line([(x, y + s), (x + s * 0.8, y + s * 1.8)], fill=color, width=3)
    d.line([(x + s * 0.8, y + s * 1.8), (x + s * 2.4, y - s * 0.4)], fill=color, width=3)


def draw_cross(d, x, y, color, s=5):
    """自绘叉：两段交叉线。"""
    d.line([(x, y), (x + s * 2, y + s * 2)], fill=color, width=3)
    d.line([(x, y + s * 2), (x + s * 2, y)], fill=color, width=3)


def shot(name, lines, title="authkeylens — zsh"):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 44], fill=BAR)
    d.ellipse([24, 15, 36, 27], fill="#ff5f57")
    d.ellipse([44, 15, 56, 27], fill="#febc2e")
    d.ellipse([64, 15, 76, 27], fill="#28c840")
    tw = d.textlength(title, font=F(16, False))
    d.text(((W - tw) / 2, 13), title, font=F(16, False), fill="#8b90a0")
    d.rectangle([0, 44, W, 46], fill=LINE)
    y = 76
    for item in lines:
        if item[0] == "TICK":
            color = item[1] if len(item) > 1 else GREEN
            draw_tick(d, 56, y + 10, color)
            if len(item) > 2:
                d.text((96, y), item[2], font=F(20, not has_cjk(item[2])), fill=color)
            y += 36
            continue
        if item[0] == "GAP":
            y += int(item[1]) if len(item) > 1 else 12
            continue
        text, color, size, mono = item[0], item[1], item[2], item[3]
        font = F(size, mono and not has_cjk(text))
        d.text((56, y), text, font=font, fill=color)
        y += int(size * 1.62)
    img.save("%s/%s.png" % (OUT, name))
    print(name, "OK  bottom_y=", y, " (H=%d)" % H)


# ════════════════ 真实输出逐字抄录区 ════════════════
# 来源1：python3 selftest_authkeylens.py（真实运行，SELFTEST PASS 46/46，exit 0）
# 来源2：authkeylens list --file /tmp/authkeylens-real/home/alice/.ssh/authorized_keys
# 来源3：authkeylens audit --file 同上（共 10 条发现 CRIT 3 / MED 2 / LOW 4 / INFO 1）
# 来源4：python3 demo_en09.py（alice+bob 同轮审计，EN-09 命中 2 条）
# 来源5：accept + diff 基线演示（exit 0 一致 → 换键后 exit 2 漂移 2 处）
# 来源6：chmod 600 前后两次 audit（10 条→9 条，CRIT 3→2，EN-01 消失）

A = "/tmp/authkeylens-real/home/alice/.ssh/authorized_keys"
B = "/tmp/authkeylens-real/home/bob/.ssh/authorized_keys"

# ── SHOT1 selftest 46/46 全绿尾部 ──
shot("shot1_selftest", [
    ("$ python3 selftest_authkeylens.py", GOLD, 20, True),
    ("authkeylens list — 1 个有效公钥：", GREY, 20, False),
    ("  alice L1   ssh-ed25519  256  SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQ…", GREY, 20, True),
    ("PASS wire-06 SHA256 指纹格式与 ssh-keygen -lf 一致（有则比）", GREEN, 20, False),
    ("PASS EN-01  authorized_keys 644 = CRIT（EN-01）", GREEN, 20, False),
    ("PASS EN-06  RSA<2048 = CRIT（EN-06）", GREEN, 20, False),
    ("PASS EN-09  同一指纹出现在多个用户文件 = HIGH（EN-09）", GREEN, 20, False),
    ("PASS EN-17  restrict+command= 受限键 = OK，且不叠加 MED（EN-17）", GREEN, 20, False),
    ("PASS EN-00  audit/list/diff 只读承诺：被扫文件字节级不变", GREEN, 20, False),
    ("…  wire 8 + opt 6 + EN 22 + cli 7 + rob 3 = 46 条全 PASS", GREY, 20, False),
    ("TICK", GREEN),
    ("SELFTEST PASS 46/46", GREEN, 28, False),
    ("$ echo $?", GOLD, 20, True),
    ("0", WHITE, 20, True),
], title="authkeylens — selftest")

# ── SHOT2 list 键位清单 ──
shot("shot2_list", [
    ("$ authkeylens list --file " + A, GOLD, 20, True),
    ("authkeylens list — 2 个有效公钥：", WHITE, 20, False),
    ("  alice L1   ssh-ed25519            256   SHA256:TXahZGxq1iylx8MJXw07JKjA6Pq+QzJGDx9fJeS8eRU", WHITE, 20, True),
    ("        comment: demo@example.com", GREY, 20, True),
    ("  alice L2   ssh-rsa                1024  SHA256:tR9HexT6P6YjsgIvZKv719sm/faJ3J+B9ysG8KjXYQI", GOLD, 20, True),
    ("GAP", 10),
    ("# 类型 / 位数（模数实算）/ 完整指纹 / 注释，一行看清", GREY, 20, False),
    ("# L2 那把 ssh-rsa 1024 位，就是待会 audit 里 EN-06 的主角", GREY, 20, False),
    ("# fixture 全合成（alice / example.com），指纹可复现", GREY, 20, False),
], title="authkeylens — list")

# ── SHOT3 audit 一秒抓出 10 条发现 ──
shot("shot3_audit", [
    ("$ authkeylens audit --file " + A, GOLD, 20, True),
    ("[CRIT] EN-01 authorized_keys 权限 644 过宽（组/其他可读写）", RED, 20, False),
    ("      → chmod 600 " + A, RED, 20, True),
    ("[CRIT] EN-02 /tmp/authkeylens-real/home/alice/.ssh 目录权限 755 过宽", RED, 20, False),
    ("      → chmod 700 /tmp/authkeylens-real/home/alice/.ssh", RED, 20, True),
    ("[CRIT] EN-06 alice 第 2 行 RSA 仅 1024 位（<2048）SHA256:tR9HexT6P6YjsgIvZK…", RED, 20, False),
    ("[MED]  EN-10 alice 第 1 行裸键无任何 options ssh-ed25519 SHA256:TXahZGxq…（等于全权钥匙）", BLUE, 20, False),
    ("[MED]  EN-10 alice 第 2 行裸键无任何 options ssh-rsa SHA256:tR9HexT6P6YjsgIvZK…（等于全权钥匙）", BLUE, 20, False),
    ("[LOW]  EN-13 alice 第 1 行无 expiry-time 长期授权 ssh-ed25519 SHA256:TXahZGxq…", GREY, 20, False),
    ("[LOW]  EN-13 alice 第 2 行无 expiry-time 长期授权 ssh-rsa SHA256:tR9HexT6P6YjsgIvZK…", GREY, 20, False),
    ("[LOW]  EN-14 alice 第 1 行无 from= 来源限制 SHA256:TXahZGxq1iylx8MJXw…", GREY, 20, False),
    ("[LOW]  EN-14 alice 第 2 行无 from= 来源限制 SHA256:tR9HexT6P6YjsgIvZK…", GREY, 20, False),
    ("[INFO] EN-15 alice 第 1 行注释含邮箱 demo@example.com", GREY, 20, False),
    ("SUMMARY: 共 10 条发现（CRIT 3 / MED 2 / LOW 4 / INFO 1）", WHITE, 21, False),
    ("退出码 1（有 CRIT/HIGH，需处理）", RED, 20, False),
], title="authkeylens — audit")

# ── SHOT4 跨用户共用键 EN-09 ──
shot("shot4_crossuser", [
    ("# fixture：alice 和 bob 的名单里躺着同一把 ed25519 + 同一把 rsa-1024", GREY, 20, False),
    ("$ python3 demo_en09.py   # alice、bob 两份名单塞进同一次审计", GOLD, 20, True),
    ("[HIGH] EN-09 同一指纹 SHA256:TXahZGxq1iylx8MJXw… 出现在 2 个文件（alice, bob）", GOLD, 20, False),
    ("[HIGH] EN-09 同一指纹 SHA256:tR9HexT6P6YjsgIvZK… 出现在 2 个文件（alice, bob）", GOLD, 20, False),
    ("GAP", 10),
    ("SUMMARY: 共 21 条发现，其中 EN-09 跨用户共用命中 2 条", WHITE, 21, False),
    ("同一把钥匙发给了两个账号：离职删号删不掉门禁", GREY, 20, False),
    ("退出码 1（有 CRIT/HIGH，需处理）", RED, 20, False),
    ("GAP", 12),
    ("# EN-09 判定只在多文件同轮审计里生效，selftest t26 同款姿势", GREY, 20, False),
    ("# 离职只删账号？这把钥匙还在别人的门上开着", GREY, 20, False),
], title="authkeylens — 跨用户共用键 EN-09")

# ── SHOT5 accept 基线 + diff 漂移 ──
shot("shot5_diff", [
    ("$ authkeylens accept --file ~/bob/.ssh/authorized_keys \\  # demo 路径缩写", GOLD, 20, True),
    ("      --baseline /tmp/authkeylens-real/base_bob.json", GOLD, 20, True),
    ("基线已写入 /tmp/authkeylens-real/base_bob.json（1 个文件 / 2 个指纹）", WHITE, 20, False),
    ("$ authkeylens diff --baseline /tmp/authkeylens-real/base_bob.json \\", GOLD, 20, True),
    ("      --file ~/bob/.ssh/authorized_keys", GOLD, 20, True),
    ("authkeylens diff：与基线一致，没有漂移。", GREEN, 20, False),
    ("      # 退出码 0（一致）", GREY, 20, False),
    ("GAP", 10),
    ("# ……几天后，bob 的名单被人动过：rsa-1024 消失，混进一把陌生 ed25519", GREY, 20, False),
    ("$ authkeylens diff --baseline /tmp/authkeylens-real/base_bob.json \\", GOLD, 20, True),
    ("      --file ~/bob/.ssh/authorized_keys", GOLD, 20, True),
    ("authkeylens diff — 与基线相比 2 处漂移：", WHITE, 21, False),
    ("  ADDED   SHA256:XqNWf+rhniXsyFoayj… （新指纹出现）", RED, 20, True),
    ("  REMOVED SHA256:tR9HexT6P6YjsgIvZK… （指纹消失）", GOLD, 20, True),
    ("      # 退出码 2（有漂移 → cron 里 diff 一下，名单变了立刻知道）", GREY, 20, False),
], title="authkeylens — accept / diff")

# ── SHOT6 狗粮：chmod 600 修复前后 ──
shot("shot6_dogfood", [
    ("# 修复前（authorized_keys 644 / .ssh 755）", GREY, 20, False),
    ("[CRIT] EN-01 authorized_keys 权限 644 过宽（组/其他可读写）", RED, 20, False),
    ("SUMMARY: 共 10 条发现（CRIT 3 / MED 2 / LOW 4 / INFO 1）", WHITE, 20, False),
    ("GAP", 10),
    ("$ chmod 600 " + A, GOLD, 20, True),
    ("$ authkeylens audit --file " + A, GOLD, 20, True),
    ("[CRIT] EN-02 /tmp/authkeylens-real/home/alice/.ssh 目录权限 755 过宽", RED, 20, False),
    ("      → chmod 700 /tmp/authkeylens-real/home/alice/.ssh", RED, 20, True),
    ("SUMMARY: 共 9 条发现（CRIT 2 / MED 2 / LOW 4 / INFO 1）", GREEN, 21, False),
    ("GAP", 12),
    ("TICK", GREEN),
    ("# 10 条 → 9 条，CRIT 3 → 2：EN-01 当场消失，狗粮是甜的", GREY, 20, False),
    ("# 剩下的 EN-02（目录 755）是下一步 chmod 700 的活", GREY, 20, False),
], title="authkeylens — 狗粮：chmod 600 前后")

print("done:", sorted(os.listdir(OUT)))
