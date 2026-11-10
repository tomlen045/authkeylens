# authkeylens — authorized_keys 门禁审计

回答两个问题：**这台服务端允许谁进门、这些授权还健不健康。**

零依赖单文件 Python CLI（Python 3.8+ 纯 stdlib）。SSH wire format 全部用
`struct` 手写解析（不 import cryptography / nacl），指纹输出格式与
`ssh-keygen -lf` 一致：`SHA256:xxxx`（base64 no padding）。

authkeylens 是 SSH 套件里管「进门名单」的那一件：

> **keyvaultdog**（管我的私钥）→ **authkeylens**（管服务端谁被允许进门）
> → **hostlens**（管我出去时记下的指纹）→ **authguard**（管登录日志里的行为）

私钥再稳，服务端的 `authorized_keys` 被塞了一把别人的钥匙，一切白搭。
这四件拼起来，SSH 从「我的钥匙」到「别人的手」再到「谁进过门」全程闭环。

## 为什么需要它

`authorized_keys` 是服务器门禁的名单。它烂起来是无声的：

- 权限 644 躺了三年——同机任何用户都能改你的进门名单
- 一把裸键没有任何 options——等于把 root 同等权力发给了任何拿到私钥的人
- `ssh-dss`、RSA-1024 这种古董 key 还在有效期
- 同一把 key 躺在 5 个账号的名单里——离职账号删了，key 还在别的门上
- 注释里写着 `zhangsan@company.com`——哪天名单截图外流，PII 一起外流
- 上周有个指纹消失了，谁也说不清是哪天、被谁删的

`cat authorized_keys` 解决不了上面任何一条。authkeylens 把体检变成一条命令，
把漂移变成一份按文件分组的报告。

## 安装

```bash
git clone https://github.com/tomlen045/authkeylens.git
cd authkeylens
# 可选：加个 alias
alias authkeylens='python3 /path/to/authkeylens/authkeylens.py'
authkeylens --version
```

零依赖，Python 3.8+ 自带 stdlib 就够。不需要 pip，不需要 venv。

装完先跑自检：

```bash
python3 selftest_authkeylens.py   # 期望 SELFTEST PASS 46/46，exit 0
```

## 子命令

| 命令 | 作用 | 退出码 |
|---|---|---|
| `audit`（默认） | 全量审计，分级发现 + SUMMARY | 0=无 CRIT/HIGH，1=有 CRIT/HIGH，2=用法错误 |
| `list` | 键位清单：文件/类型/位数/SHA256 指纹/选项/注释 | 0 |
| `accept` | 当前状态写入基线 JSON | 0 / 2=用法错误 |
| `diff` | 与基线比对，按文件报 ADDED/REMOVED 指纹 | 0=一致，**2=有漂移**，3=用法错误（避开漂移的 2） |

扫描范围三选一（多给算用法错误，都不给默认 `--scan-home`）：

```bash
authkeylens audit --file /path/to/authorized_keys   # 只看这一个
authkeylens audit --scan-home                       # 当前用户 ~/.ssh + 权限链
authkeylens audit --scan-system                     # /etc/ssh + /root/.ssh + /home/*/.ssh（只读）
```

`--json` 放在任何子命令后面拿机器可读输出，接 cron / CI 都是现成的。

### audit：全量体检

```bash
$ authkeylens audit --file /tmp/authkeylens-demo/home/alice/.ssh/authorized_keys
[CRIT] EN-01 authorized_keys 权限 644 过宽（组/其他可读写）→ chmod 600 …
[CRIT] EN-05 alice 第 3 行 ssh-dss 密钥（DSA，早已废弃）SHA256:2P7HAYOG…
[CRIT] EN-06 alice 第 2 行 RSA 仅 1024 位（<2048）SHA256:0FW5os3d…
[HIGH] EN-07 第 4 行无法解析（未知选项 'this'（sshd 会整行拒绝））…
[HIGH] EN-08 alice 完全重复条目 2 份（行 1,5）SHA256:ZkAslGjF…
[MED]  EN-10 alice 第 1 行裸键无任何 options ssh-ed25519 …（等于全权钥匙）
[LOW]  EN-13 alice 第 1 行无 expiry-time 长期授权 …
[INFO] EN-15 alice 第 1 行注释含邮箱 demo@example.com
SUMMARY: 共 22 条发现（CRIT 4 / HIGH 2 / MED 4 / LOW 8 / INFO 4）
退出码 1（有 CRIT/HIGH，需处理）
```

有 CRIT/HIGH 退出码就是 1，直接接 cron：

```bash
authkeylens audit --scan-system || echo "authorized_keys 门禁有红色警报"
```

### list：进门名单台账

```bash
$ authkeylens list --file ~/.ssh/authorized_keys
authkeylens list — 3 个有效公钥：
  alice L1   ssh-ed25519            256   SHA256:ZkAslGjFiUHdGf/WUL8rQvkib4PTvQatUV0OUQSncCA
        options: restrict,command="echo hi"
        comment: ci-bot@example.com
```

类型、位数（RSA/DSA/ECDSA 按模数与曲线实算）、完整指纹、选项、注释一行看清。

### accept + diff：给进门名单拍快照，漂移说人话

```bash
$ authkeylens accept --scan-home --baseline ~/.authkeylens-baseline.json
基线已写入 /Users/you/.authkeylens-baseline.json（1 个文件 / 3 个指纹）
$ authkeylens diff --scan-home --baseline ~/.authkeylens-baseline.json
authkeylens diff：与基线一致，没有漂移。        # exit 0
# 某天有人动过名单之后：
$ authkeylens diff --scan-home --baseline ~/.authkeylens-baseline.json
authkeylens diff — 与基线相比 2 处漂移：
  ADDED SHA256:LVC7PY6ur9Dk+WVIYQ… /Users/bob/.ssh/authorized_keys （新指纹出现）
  REMOVED SHA256:gNSIRW+2Iyiuvsdp… /Users/bob/.ssh/authorized_keys （指纹消失）  # exit 2
```

crontab 里每周 `accept` 一次，diff 就是你的授权变更时间轴。

## 17 条不变量（EN-01 起，selftest 46/46 全绿）

| 编号 | 级别 | 不变量 |
|---|---|---|
| EN-01 | CRIT | authorized_keys 文件权限 >600（组/其他可读写） |
| EN-02 | CRIT | .ssh 目录权限 >700 |
| EN-03 | HIGH | 家目录组/其他可写 |
| EN-04 | MED | authorized_keys 属主与所在目录属主不一致 |
| EN-05 | CRIT | ssh-dss 密钥（DSA 早已废弃） |
| EN-06 | CRIT | RSA < 2048 位 |
| EN-07 | HIGH | 未知/无法解析的密钥类型或垃圾行（sshd 会整行拒绝的行） |
| EN-08 | HIGH | 单文件内完全重复条目 |
| EN-09 | HIGH | 同一指纹出现在多个用户文件（共用密钥） |
| EN-10 | MED | 完全裸键（无任何 options，等于发了一把全权钥匙） |
| EN-11 | MED | 开了 agent-forwarding 且无 command= 限制 |
| EN-12 | MED | 开了 port-forwarding 且无 permitopen= 限制 |
| EN-13 | LOW | 无 expiry-time 的长期授权 |
| EN-14 | LOW | 无 from= 来源限制（仅提示） |
| EN-15 | INFO | 注释里含邮箱等 PII |
| EN-16 | LOW | 空的 authorized_keys（0 个有效键，提示确认是否遗留） |
| EN-17 | OK | restrict + command= 受限键（好实践，统计并表扬） |

基线类：diff 模式报 ADDED/REMOVED 指纹（按文件分组），exit 2。

### 自测覆盖

`selftest_authkeylens.py` 用 `struct` 手工构造合法公钥 blob
（ed25519 / rsa-2048 / rsa-1024 弱钥 / ssh-dss / ecdsa-p256）+ tempfile 全套
fixture（多用户目录、权限错误 chmod、垃圾行、重复键、restrict 好键、基线漂移），
覆盖每条不变量至少 1 个断言 + wire format 8 条 + options 解析 6 条 + CLI
子进程冒烟（exit code 断言）7 条。fixture 注释/邮箱一律 example.com 合成值，
绝不触碰真实 `~/.ssh`。

## 诚实边界

- authkeylens 解析行并算指纹，**不验证密钥的数学结构**（RSA 模数是否真素数
  之类）——那是 `ssh-keygen -l -f` / ssh-keygen -yf 的活。
- `expiry-time` 只看「有没有写」，不判断是否已过期——过期键 sshd 自己会拒，
  名单里躺不躺过期键是纪律问题，audit 只提示无 expiry 的长期授权。
- `--scan-system` 是快照不是监控：跨用户共用（EN-09）只在同一轮扫描内判定。
  要时间轴，用 accept + diff。
- 它读不了 root 不让你读的文件——权限不足的文件会跳过并在 JSON 里可见。

## 套件兄弟

| 工具 | 回答的问题 |
|---|---|
| keyvaultdog | 我的私钥资产还健康吗 |
| **authkeylens** | **服务端允许谁进门、授权还健不健康** |
| hostlens | 我出去时记下的主机指纹还可信吗 |
| authguard | 登录日志里谁在试图进门 |

## License

MIT
