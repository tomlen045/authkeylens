#!/usr/bin/env bash
# authkeylens GitHub 镜像发布（token 从钥匙串读 generic password，不回显）
set -e
cd "$(dirname "$0")"
GIT=/usr/bin/git

GH_TOKEN=$(security find-generic-password -s GH_TOKEN -a tomlen045 -w 2>/dev/null)
[ -n "$GH_TOKEN" ] || { echo "no GH_TOKEN in keychain"; exit 1; }

DESC="authkeylens - authorized_keys gate audit in one file: SSH wire-format parse by hand (ed25519/rsa/dss/ecdsa), SHA256 fingerprints, per-line options (command/from/restrict/expiry), 17 invariants CRIT/HIGH/MED/LOW, baseline diff. Zero dependencies."

# 1. 建仓（幂等）
echo "-> create github repo tomlen045/authkeylens ..."
HTTP=$(curl -s -o /tmp/gh_ak.json -w '%{http_code}' \
  -H "Authorization: token $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  https://api.github.com/user/repos \
  -d "{\"name\":\"authkeylens\",\"description\":\"$DESC\",\"has_wiki\":false,\"private\":false}")
if [ "$HTTP" = "201" ]; then echo "  created"
elif [ "$HTTP" = "422" ]; then echo "  exists, skip"
else echo "  HTTP $HTTP: $(head -c 200 /tmp/gh_ak.json)"; exit 1; fi

# 2. 推送
if ! "$GIT" remote get-url github >/dev/null 2>&1; then
  "$GIT" remote add github "https://tomlen045:$GH_TOKEN@github.com/tomlen045/authkeylens.git"
fi
echo "-> push main ..."
env GIT_TERMINAL_PROMPT=0 "$GIT" push -u github main 2>&1 | tail -3

# 3. About 描述
curl -s -o /dev/null -X PATCH \
  -H "Authorization: token $GH_TOKEN" -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/tomlen045/authkeylens \
  -d "{\"description\":\"$DESC\"}"

# 4. 匿名验证
sleep 3
CODE_API=$(curl -s -o /tmp/gh_ak_read.json -w '%{http_code}' https://api.github.com/repos/tomlen045/authkeylens)
CODE_RAW=$(curl -s -o /dev/null -w '%{http_code}' https://raw.githubusercontent.com/tomlen045/authkeylens/main/README.md)
echo "  API=$CODE_API | raw README=$CODE_RAW"
if [ "$CODE_API" = "200" ] && [ "$CODE_RAW" = "200" ]; then
  echo "GITHUB_OK https://github.com/tomlen045/authkeylens"
else
  echo "verify failed"; exit 2
fi
