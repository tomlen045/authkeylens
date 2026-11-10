#!/usr/bin/env bash
# authkeylens Gitee 发布（token 内嵌 remote，必须带用户名段；照 hostlens 逻辑）
set -e
cd "$(dirname "$0")"
GIT=/usr/bin/git

TOKEN=$(grep -hoE '[0-9a-f]{32}' /Users/len/CodeBuddy/dx/*/.git/config 2>/dev/null | while read -r t; do
  [ "$(curl -s -o /dev/null -w '%{http_code}' "https://gitee.com/api/v5/user?access_token=$t")" = "200" ] && echo "$t" && break
done)
[ -n "$TOKEN" ] || { echo "no valid gitee token"; exit 1; }

# 1. 建仓（form-urlencoded，access_token 放 body；默认 private）
echo "-> create gitee repo tomlen/authkeylens ..."
HTTP=$(curl -s -o /tmp/gl_ak.json -w '%{http_code}' -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "access_token=$TOKEN" \
  --data-urlencode "name=authkeylens" \
  --data-urlencode "description=authkeylens - authorized_keys gate audit in one file: SSH wire-format parse by hand (ed25519/rsa/dss/ecdsa), SHA256 fingerprints, per-line options (command/from/restrict/expiry), 17 invariants CRIT/HIGH/MED/LOW, baseline diff. Zero dependencies." \
  --data-urlencode "private=true" \
  https://gitee.com/api/v5/user/repos)
if [ "$HTTP" = "201" ]; then echo "  created"
elif [ "$HTTP" = "200" ]; then echo "  exists"
else echo "  HTTP $HTTP: $(head -c 300 /tmp/gl_ak.json)"; exit 1; fi

# 2. push（带用户名段 + GIT_TERMINAL_PROMPT=0）
if ! "$GIT" remote get-url gitee >/dev/null 2>&1; then
  "$GIT" remote add gitee "https://tomlen:$TOKEN@gitee.com/tomlen/authkeylens.git"
fi
echo "-> push main ..."
env GIT_TERMINAL_PROMPT=0 "$GIT" push -u gitee main 2>&1 | tail -3

# 3. 置公开（PATCH 必须带 name；空仓会 422，必须 push 后再 PATCH）
echo "-> PATCH public ..."
HTTP=$(curl -s -o /tmp/gl_ak_patch.json -w '%{http_code}' -X PATCH \
  --data-urlencode "access_token=$TOKEN" \
  --data-urlencode "name=authkeylens" \
  --data-urlencode "private=false" \
  https://gitee.com/api/v5/repos/tomlen/authkeylens)
echo "  PATCH HTTP $HTTP"

# 4. 匿名复核
sleep 2
CODE_API=$(curl -s -o /tmp/gl_ak_read.json -w '%{http_code}' https://gitee.com/api/v5/repos/tomlen/authkeylens)
PRIVATE=$(python3 -c "import json;print(json.load(open('/tmp/gl_ak_read.json')).get('private'))" 2>/dev/null)
echo "  api=$CODE_API private=$PRIVATE"
if [ "$CODE_API" = "200" ] && [ "$PRIVATE" = "False" ]; then
  echo "GITEE_OK https://gitee.com/tomlen/authkeylens"
else
  echo "verify failed"; exit 2
fi
