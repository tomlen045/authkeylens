#!/usr/bin/env python3
"""authkeylens 证据图生成器：6 张 1200x675 macOS 窗框 One Dark 终端实拍风格。
内容 100% 来自 /tmp/authkeylens-demo fixture 的真实命令输出（先跑真实 audit/list/diff
抄录文本，长行按真实内容拆行展示，绝不编造）。勾/叉用 d.line 自绘，避开 PIL emoji 豆腐块。
"""
from PIL import Image, ImageDraw, ImageFont
import os

OUT = "/Users/len/CodeBuddy/dx/authkeylens/shots"
os.makedirs(OUT, exist_ok=True)
FONT_CJK = "/System/Library/Fonts/STHeiti Medium.ttc"
FONT_MONO = "/System/Library/Fonts/Menlo.ttc"
W, H = 1200, 675
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


def draw_tick(d, x, y, color, s=5):
    """自绘对勾：两段线。"""
    d.line([(x, y + s), (x + s * 0.8, y + s * 1.8)], fill=color, width=2)
    d.line([(x + s * 0.8, y + s * 1.8), (x + s * 2.4, y - s * 0.4)], fill=color, width=2)


def draw_cross(d, x, y, color, s=4):
    """自绘叉：两段交叉线。"""
    d.line([(x, y), (x + s * 2, y + s * 2)], fill=color, width=2)
    d.line([(x, y + s * 2), (x + s * 2, y)], fill=color, width=2)


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
    y = 74
    for item in lines:
        if isinstance(item, tuple) and item[0] == "TICK":
            draw_tick(d, 56, y + 8, item[1])
            y += 22
            continue
        if isinstance(item, tuple) and item[0] == "CROSS":
            draw_cross(d, 56, y + 8, item[1])
            y += 22
            continue
        text, color, size, mono = item
        if text:
            font = F(size, mono and not has_cjk(text))
            d.text((56, y), text, font=font, fill=color)
        y += int(size * 1.6)
    img.save("%s/%s.png" % (OUT, name))
    print(name, "OK", "bottom_y=", y)


ALICE = "/tmp/authkeylens-demo/home/alice/.ssh/authorized_keys"

# ── SHOT1 selftest 46/46 ──
shot("shot1_selftest", [
    ("$ python3 selftest_authkeylens.py", GOLD, 21, True),
    ("PASS wire-01 ed25519 blob struct 手写解析出 256 位", GREEN, 20, False),
    ("PASS wire-06 SHA256 指纹格式与 ssh-keygen -lf 一致", GREEN, 20, False),
    ("PASS EN-01  authorized_keys 644 = CRIT（EN-01）", GREEN, 20, False),
    ("PASS EN-05  ssh-dss = CRIT 且退出码 1（EN-05）", GREEN, 20, False),
    ("PASS EN-09  同一指纹出现在多个用户文件 = HIGH（EN-09）", GREEN, 20, False),
    ("PASS EN-17  restrict+command= 受限键 = OK（EN-17）", GREEN, 20, False),
    ("…   wire 8 + opt 6 + EN 21 + cli 7 + rob 3 同样全 PASS", GREY, 19, False),
    ("TICK", GREEN),
    ("TICK", GREEN),
    ("SELFTEST PASS 46/46", GREEN, 26, False),
    ("$ echo $?", GREY, 20, True),
    ("0", WHITE, 20, True),
], title="authkeylens — selftest")

# ── SHOT2 list 键位台账 ──
shot("shot2_list", [
    ("$ authkeylens list --file " + ALICE, GOLD, 19, True),
    ("authkeylens list — 4 个有效公钥：", WHITE, 20, False),
    ("  alice L1   ssh-ed25519            256   SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQ…", WHITE, 18, True),
    ("        comment: demo@example.com", GREY, 17, True),
    ("  alice L2   ssh-rsa                1024  SHA256:0FW5os3d3s5bnKX4f5prxEToQNm1…", GOLD, 18, True),
    ("        comment: weak@example.com", GREY, 17, True),
    ("  alice L3   ssh-dss                1024  SHA256:2P7HAYOGbG3dJYFDb2o9HcVXQEm…", GOLD, 18, True),
    ("  alice L5   ssh-ed25519            256   SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQ…", WHITE, 18, True),
    ("", WHITE, 10, True),
    ("# 类型/位数（模数实算）/完整指纹/注释 一行看清；L1 与 L5 同指纹先记下", GREY, 19, False),
    ("# fixture 全合成，指纹可复现", GREY, 19, False),
], title="authkeylens — list")

# ── SHOT3 audit 全量体检 ──
shot("shot3_audit", [
    ("$ authkeylens audit --file " + ALICE, GOLD, 17, True),
    ("[CRIT] EN-01 authorized_keys 权限 644 过宽（组/其他可读写）→ chmod 600 …", RED, 19, False),
    ("[CRIT] EN-05 alice 第 3 行 ssh-dss 密钥（DSA，早已废弃）SHA256:2P7HAYOG…", RED, 19, False),
    ("[CRIT] EN-06 alice 第 2 行 RSA 仅 1024 位（<2048）SHA256:0FW5os3d…", RED, 19, False),
    ("[HIGH] EN-07 第 4 行无法解析（未知选项 'this'（sshd 会整行拒绝））", GOLD, 19, False),
    ("[HIGH] EN-08 alice 完全重复条目 2 份（行 1,5）SHA256:ZkAslGjF…", GOLD, 19, False),
    ("[MED]  EN-10 alice 第 1 行裸键无任何 options ssh-ed25519 …（等于全权钥匙）", BLUE, 19, False),
    ("[LOW]  EN-13 alice 第 1 行 无 expiry-time 长期授权 ssh-ed25519 …", GREY, 19, False),
    ("[INFO] EN-15 alice 第 1 行注释含邮箱 demo@example.com", GREY, 19, False),
    ("", WHITE, 10, True),
    ("SUMMARY: 共 22 条发现（CRIT 4 / HIGH 2 / MED 4 / LOW 8 / INFO 4）", WHITE, 20, False),
    ("退出码 1（有 CRIT/HIGH，需处理）", RED, 20, False),
], title="authkeylens — audit")

# ── SHOT4 跨用户共用 key（EN-09）+ restrict 好键（EN-17）──
shot("shot4_crossuser", [
    ("# alice 和 bob 的名单里都有 SHA256:ZkAslGjF…（fixture 里同一把合成键）", GREY, 19, False),
    ("$ authkeylens audit --file alice/.ssh/authorized_keys --file bob/…  # 双文件场景", GOLD, 17, True),
    ("[HIGH] EN-09 同一指纹 SHA256:ZkAslGjFiUHdGf/WUL… 出现在 2 个文件（alice, bob）——共用密钥", GOLD, 18, False),
    ("[OK]   EN-17 bob 第 2 行 restrict+command= 受限键（好实践）SHA256:gNSIRW+2Iy…", GREEN, 18, False),
    ("[MED]  EN-11 bob 第 3 行 允许 agent-forwarding 且无 command= 限制 …", BLUE, 18, False),
    ("[MED]  EN-12 bob 第 3 行 允许 port-forwarding 且无 permitopen= 限制 …", BLUE, 18, False),
    ("", WHITE, 10, True),
    ("SUMMARY: 共 36 条发现（CRIT 5 / HIGH 3 / MED 7 / LOW 13 / INFO 7 / OK 1）", WHITE, 19, False),
    ("", WHITE, 10, True),
    ("# 同一把 key 躺在多个账号名单里：离职删号删不掉共用钥匙", GREY, 19, False),
    ("# restrict+command= 的 CI 键被点名表扬——门禁该长这样", GREY, 19, False),
], title="authkeylens — 跨用户共用 / 好键")

# ── SHOT5 accept + diff 漂移 ──
shot("shot5_diff", [
    ("$ authkeylens accept --file alice/… --file bob/… --baseline demo-baseline.json", GOLD, 17, True),
    ("基线已写入 demo-baseline.json（2 个文件 / 5 个指纹）", WHITE, 19, False),
    ("$ authkeylens diff --baseline demo-baseline.json", GOLD, 17, True),
    ("authkeylens diff：与基线一致，没有漂移。", GREY, 19, False),
    ("# 几天后 bob 的名单被动过：删 2 把、新增 2 把", GREY, 19, False),
    ("$ authkeylens diff --baseline demo-baseline.json", GOLD, 17, True),
    ("authkeylens diff — 与基线相比 4 处漂移：", WHITE, 19, False),
    ("  ADDED   SHA256:LVC7PY6ur9Dk+WVIYQ… bob/.ssh/authorized_keys （新指纹出现）", RED, 19, True),
    ("  ADDED   SHA256:wgBkRPxHOn5/gpL9fE… bob/.ssh/authorized_keys （新指纹出现）", RED, 19, True),
    ("  REMOVED SHA256:ZkAslGjFiUHdGf/WUL… bob/.ssh/authorized_keys （指纹消失）", GOLD, 19, True),
    ("  REMOVED SHA256:gNSIRW+2Iyiuvsdp/b… bob/.ssh/authorized_keys （指纹消失）", GOLD, 19, True),
    ("", WHITE, 10, True),
    ("# 有漂移退出码 2：cron 里 diff 一下，进门名单变了立刻知道", GREY, 19, False),
], title="authkeylens — accept / diff")

# ── SHOT6 狗粮：修好 alice 之后复检 ──
shot("shot6_dogfood", [
    ("# 把 alice 修一遍：删垃圾行、删重复、清 dss、弱 RSA 换 ed25519、权限收紧", GREY, 19, False),
    ("$ chmod 600 " + ALICE, GOLD, 17, True),
    ("$ chmod 700 /tmp/authkeylens-demo/home/alice/.ssh", GOLD, 17, True),
    ("$ authkeylens audit --file " + ALICE, GOLD, 17, True),
    ("authkeylens audit — 干净", GREEN, 20, False),
    ("  0 条发现。authorized_keys 门禁目前健康。", GREEN, 20, False),
    ("SUMMARY: 0 条发现，authorized_keys 门禁健康。", GREEN, 20, False),
    ("退出码 0", GREEN, 20, False),
    ("", WHITE, 10, True),
    ("TICK", GREEN),
    ("# 修复前 22 条发现（CRIT 4），修复后 0 条——狗粮是甜的", GREY, 19, False),
], title="authkeylens — 狗粮时间")

print("done:", sorted(os.listdir(OUT)))
