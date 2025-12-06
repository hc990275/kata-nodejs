#!/bin/bash
set -e

# ================== 端口设置（你可以改） ==================
export TUIC_PORT=0
export HY2_PORT=
export REALITY_PORT=

# ================== 节点固定名称 ==================
HY2_NAME="hy2法国卡塔"
REALITY_NAME="vless法国卡塔"

# ================== 强制切换到脚本所在目录 ==================
cd "$(dirname "$0")"

# ================== 环境变量 & 目录 ==================
export FILE_PATH="${PWD}/.npm"
mkdir -p "$FILE_PATH"

# ================== UUID 固定保存 ==================
UUID_FILE="${FILE_PATH}/uuid.txt"
if [ -f "$UUID_FILE" ]; then
  UUID=$(cat "$UUID_FILE")
else
  UUID=$(cat /proc/sys/kernel/random/uuid)
  echo "$UUID" > "$UUID_FILE"
  chmod 600 "$UUID_FILE"
fi

# ================== 架构检测与下载 ==================
ARCH=$(uname -m)
if [[ "$ARCH" == "arm"* ]] || [[ "$ARCH" == "aarch64" ]]; then
  BASE_URL="https://arm64.ssss.nyc.mn"
elif [[ "$ARCH" == "amd64"* ]] || [[ "$ARCH" == "x86_64" ]]; then
  BASE_URL="https://amd64.ssss.nyc.mn"
elif [[ "$ARCH" == "s390x" ]]; then
  BASE_URL="https://s390x.ssss.nyc.mn"
else
  echo "不支持的架构: $ARCH"
  exit 1
fi

download_file() {
  local URL=$1
  local FILENAME=$2
  if command -v curl >/dev/null 2>&1; then
    curl -L -sS -o "$FILENAME" "$URL"
  else
    wget -q -O "$FILENAME" "$URL"
  fi
}

BIN_FILE="${FILE_PATH}/$(head /dev/urandom | tr -dc a-z0-9 | head -c6)"
download_file "${BASE_URL}/sb" "$BIN_FILE"
chmod +x "$BIN_FILE"

# ================== 固定 Reality 密钥 ==================
KEY_FILE="${FILE_PATH}/key.txt"
if [ -f "$KEY_FILE" ]; then
  private_key=$(grep "PrivateKey:" "$KEY_FILE" | awk '{print $2}')
  public_key=$(grep "PublicKey:" "$KEY_FILE" | awk '{print $2}')
else
  output=$("$BIN_FILE" generate reality-keypair)
  echo "$output" > "$KEY_FILE"
  chmod 600 "$KEY_FILE"
  private_key=$(echo "$output" | awk '/PrivateKey:/ {print $2}')
  public_key=$(echo "$output" | awk '/PublicKey:/ {print $2}')
fi

# ================== 证书生成 ==================
openssl ecparam -genkey -name prime256v1 -out "${FILE_PATH}/private.key" 2>/dev/null
openssl req -new -x509 -days 3650 -key "${FILE_PATH}/private.key" -out "${FILE_PATH}/cert.pem" -subj "/CN=bing.com" 2>/dev/null

# ================== 动态 JSON 拼接（无尾逗号） ==================
INBOUNDS=""

append() {
  if [ -z "$INBOUNDS" ]; then
    INBOUNDS="$1"
  else
    INBOUNDS="${INBOUNDS},$1"
  fi
}

# HY2
if [[ "$HY2_PORT" != "" && "$HY2_PORT" != "0" ]]; then
append "{
  \"type\": \"hysteria2\",
  \"listen\": \"::\",
  \"listen_port\": $HY2_PORT,
  \"users\": [{\"password\": \"$UUID\"}],
  \"masquerade\": \"https://bing.com\",
  \"tls\": {\"enabled\": true, \"alpn\": [\"h3\"], \"certificate_path\": \"${FILE_PATH}/cert.pem\", \"key_path\": \"${FILE_PATH}/private.key\"}
}"
fi

# Reality VLESS
if [[ "$REALITY_PORT" != "" && "$REALITY_PORT" != "0" ]]; then
append "{
  \"type\": \"vless\",
  \"listen\": \"::\",
  \"listen_port\": $REALITY_PORT,
  \"users\": [{\"uuid\": \"$UUID\", \"flow\": \"xtls-rprx-vision\"}],
  \"tls\": {
    \"enabled\": true,
    \"server_name\": \"www.nazhumi.com\",
    \"reality\": {
      \"enabled\": true,
      \"handshake\": {\"server\": \"www.nazhumi.com\", \"server_port\": 443},
      \"private_key\": \"$private_key\",
      \"short_id\": [\"\"]
    }
  }
}"
fi

cat > "${FILE_PATH}/config.json" <<EOF
{
  "log": { "disabled": true },
  "inbounds": [$INBOUNDS],
  "outbounds": [{ "type": "direct" }]
}
EOF

# ================== 启动 Sing-box ==================
$BIN_FILE run -c "${FILE_PATH}/config.json" &
SINGBOX_PID=$!

# ================== 获取 IP ==================
if command -v curl >/dev/null 2>&1; then
  IP=$(curl -s --max-time 2 ipv4.ip.sb || echo "")
else
  IP=$(wget -qO- ipv4.ip.sb || echo "")
fi

if [ -z "$IP" ]; then
  echo "获取 IP 失败"
  exit 1
fi

# ================== 生成订阅 ==================
> "${FILE_PATH}/list.txt"

# HY2 节点
if [[ "$HY2_PORT" != "" && "$HY2_PORT" != "0" ]]; then
echo "hysteria2://${UUID}@${IP}:${HY2_PORT}/?sni=www.bing.com&insecure=1#${HY2_NAME}" >> "${FILE_PATH}/list.txt"
fi

# Reality 节点
if [[ "$REALITY_PORT" != "" && "$REALITY_PORT" != "0" ]]; then
echo "vless://${UUID}@${IP}:${REALITY_PORT}?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.nazhumi.com&fp=firefox&pbk=${public_key}&type=tcp#${REALITY_NAME}" >> "${FILE_PATH}/list.txt"
fi

base64 "${FILE_PATH}/list.txt" | tr -d '\n' > "${FILE_PATH}/sub.txt"
cat "${FILE_PATH}/list.txt"
echo
echo "订阅文件已生成: ${FILE_PATH}/sub.txt"

# ================== 定时重启 ==================
while true; do
  now=$(date +%H%M --date="+8 hour")
  if [[ "$now" == "0003" ]]; then
    kill $SINGBOX_PID 2>/dev/null || true
    sleep 3
    $BIN_FILE run -c "${FILE_PATH}/config.json" &
    SINGBOX_PID=$!
    sleep 70
  fi
  sleep 1
done
