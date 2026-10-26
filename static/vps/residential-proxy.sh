#!/usr/bin/env bash
# ============================================================
# KUI 住宅代理组件安装器（FRP 融合版）
#
# 住宅引擎（Free-Residential-IP-Proxy-Controller-Sec）已融合进
# KUI Worker 本身：本脚本只做一件事——用本机 agent_token 向 KUI
# 索取安装脚本 (GET /api/proxy/installer)，校验后执行。
# 安装脚本由 KUI 服务端生成：c2 地址就是 KUI 本身，c2.json 里
# 的 web_user/web_pass 是 KUI 面板管理员凭据（与 FRP 原版模型
# 一致），引擎脚本再由安装脚本凭 Basic 鉴权从 KUI 拉取。
#
# 前置要求（FRP 引擎安装的硬性要求）：root + systemd + apt 系。
# 不满足时仅告警跳过（exit 0），不拖垮 KUI 主部署。
#
# 用法（由 kui.sh 自动调用，参数保持兼容）：
#   residential-proxy.sh --domain <KUI地址> --ip <本机IP> \
#       --token <agent_token> [--controller <兼容参数，已忽略>]
#   --token 也可经环境变量 KUI_AGENT_TOKEN 传入。
# ============================================================
set -uo pipefail

DOMAIN=""; VPS_IP=""; TOKEN=""; CONTROLLER=""
while [ $# -gt 0 ]; do
  case "$1" in
    --domain)     [ $# -ge 2 ] || { echo "❌ --domain 缺少参数" >&2; exit 2; }; DOMAIN="$2"; shift 2 ;;
    --controller) [ $# -ge 2 ] || { echo "❌ --controller 缺少参数" >&2; exit 2; }; CONTROLLER="$2"; shift 2 ;;
    --ip)         [ $# -ge 2 ] || { echo "❌ --ip 缺少参数" >&2; exit 2; }; VPS_IP="$2"; shift 2 ;;
    --token)      [ $# -ge 2 ] || { echo "❌ --token 缺少参数" >&2; exit 2; }; TOKEN="$2"; shift 2 ;;
    *) echo "❌ 未知参数: $1" >&2; exit 2 ;;
  esac
done
[ -n "$TOKEN" ] || TOKEN="${KUI_AGENT_TOKEN:-}"
if [ -z "$DOMAIN" ] || [ -z "$VPS_IP" ] || [ -z "$TOKEN" ]; then
  echo "❌ 用法: $0 --domain <KUI地址> --ip <本机IP> --token <agent_token>" >&2
  exit 2
fi
DOMAIN="${DOMAIN%/}"
if ! printf '%s' "$VPS_IP" | grep -Eq '^[0-9A-Fa-f:.]+$'; then echo "❌ VPS IP 格式无效" >&2; exit 2; fi
case "$DOMAIN" in https://*) ;; *) echo "❌ --domain 必须使用 HTTPS" >&2; exit 2 ;; esac

skip() { echo "⚠️ 住宅组件跳过：$1"; echo "   （KUI 核心功能不受影响；处理后可重跑本脚本补装）"; exit 0; }

[ "$(id -u)" = "0" ] || skip "需要 root 身份"
command -v systemctl >/dev/null 2>&1 || skip "住宅引擎需要 systemd，本机不支持"
command -v curl >/dev/null 2>&1 || skip "缺少 curl"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

echo "[1/3] 向 KUI 索取住宅引擎安装脚本..."
if ! curl -fsSL --retry 3 --retry-delay 2 \
      -H "Authorization: $TOKEN" \
      "$DOMAIN/api/proxy/installer?ip=$VPS_IP" \
      -o "$WORKDIR/installer.sh"; then
  skip "获取安装脚本失败（KUI 侧未设置 FRP_AGENT_PASSWORD/ADMIN_PASSWORD、PROXY_USER、PROXY_PASS，或 agent token 无效）"
fi
# 完整性标记校验：正牌安装脚本必然写入 c2.json 并创建 proxy-lite 服务
if ! grep -q "c2\.json" "$WORKDIR/installer.sh" || ! grep -q "proxy-lite" "$WORKDIR/installer.sh"; then
  skip "安装脚本内容异常（缺少 c2.json / proxy-lite 标记），已中止执行"
fi
bash -n "$WORKDIR/installer.sh" || skip "安装脚本语法校验失败"

echo "[2/3] 执行安装脚本（写入 c2.json、拉取引擎、注册 systemd 服务）..."
systemctl stop proxy-lite.service 2>/dev/null || true
if ! bash "$WORKDIR/installer.sh"; then
  skip "安装脚本执行失败（详见上方输出）"
fi

echo "[3/3] 校验住宅服务..."
sleep 2
if systemctl is-active --quiet proxy-lite.service && [ -f /opt/proxy_lite/c2.json ]; then
  echo "✅ 住宅引擎部署成功（控制器即 KUI 本身: $DOMAIN）"
  echo "   节点状态与国家/端口策略请在 KUI 面板「住宅代理」页查看。"
else
  echo "⚠️ proxy-lite 服务未正常运行，请查看: journalctl -u proxy-lite.service -n 50" >&2
  exit 0
fi
