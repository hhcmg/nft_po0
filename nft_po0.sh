#!/usr/bin/env bash
# PO0 nftables relay manager v3
# IPv4 TCP/UDP DNAT + per-destination SNAT, with takeover/coexist firewall modes.

set -Eeuo pipefail

VERSION="3.0.0"

STATE_DIR="/etc/po0-relay"
STATE_FILE="${STATE_DIR}/rules.db"
LOCAL_STATE_FILE="${STATE_DIR}/local-ports.db"
MODE_FILE="${STATE_DIR}/mode"
OWN_CONF="${STATE_DIR}/po0-relay.nft"
SYSCTL_CONF="/etc/sysctl.d/99-po0-relay.conf"

LOADER_FILE="/usr/local/sbin/po0-relay-loader"
SERVICE_FILE="/etc/systemd/system/po0-relay.service"
SERVICE_NAME="po0-relay.service"

LEGACY_NFT_CONF="/etc/nftables.conf"
BACKUP_DIR="/root/po0-relay-backups"
LOCK_FILE="/run/lock/po0-relay-manager.lock"

TABLE_NAT_FAMILY="ip"
TABLE_NAT_NAME="po0_relay_nat"
TABLE_FILTER_FAMILY="inet"
TABLE_FILTER_NAME="po0_relay_filter"
TABLE_MANGLE_FAMILY="ip"
TABLE_MANGLE_NAME="po0_relay_mangle"

declare -a RULE_NAMES=()
declare -a RULE_PROTOCOLS=()
declare -a IN_IFS=()
declare -a RELAY_PORTS=()
declare -a DEST_IPS=()
declare -a DEST_PORTS=()
declare -a SOURCE_CIDRS=()
declare -a MSS_VALUES=()
declare -a OUT_IFS=()
declare -a SNAT_IPS=()
declare -a ROUTE_LINES=()

declare -a LOCAL_NAMES=()
declare -a LOCAL_PROTOCOLS=()
declare -a LOCAL_PORTS=()

MODE=""
DEFAULT_WAN_IF=""
DEFAULT_SOURCE_IP=""
SSH_PORTS_CSV=""
STATE_NEEDS_MIGRATION=0
LEGACY_V2_ACTIVE=0
UFW_WAS_ACTIVE=0
FIREWALLD_WAS_ACTIVE=0

ROUTE_IF=""
ROUTE_SRC=""
ROUTE_LINE=""

info() { printf '\033[1;34m[INFO]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[ OK ]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[FAIL]\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<EOF
PO0 nftables 中转与本机端口管理器 v${VERSION}

用法：
  sudo bash $0                  进入交互管理菜单
  sudo bash $0 --status         查看规则、逐线路路由及计数器
  sudo bash $0 --rollback       从历史备份恢复
  sudo bash $0 --install-deps   单独安装运行依赖
  bash $0 --help                查看帮助

v3 核心变化：
  - 每条转发按“下一跳 IP”执行 ip route get，独立检测出口接口和 SNAT 源地址
  - forward 与 postrouting 均使用 ct status dnat，避免误匹配普通流量
  - 中转端口只经过 prerouting/forward，不再错误加入 input
  - 本机服务端口只在“安全接管模式”中由 input 链放行
  - 提供安全接管模式与 NAT 共存模式
  - 只维护 po0_relay_* 独立表，不执行 flush ruleset
  - 由独立 po0-relay.service 持久化，不依赖或改写 /etc/nftables.conf
  - 支持每条线路的来源 IPv4/CIDR 白名单和可选 PMTU/固定 TCP MSS
  - 应用前备份、语法检查，并提供限时自动回滚保护

模式说明：
  takeover  安全接管：input/forward 默认 drop，自动放行 SSH 与登记的本机端口。
  coexist   NAT 共存：只管理 DNAT/SNAT（及可选 MSS），不修改 input/forward。
            若 UFW/firewalld/其他规则阻止 FORWARD，需由原防火墙额外放行。
EOF
}

require_root() {
  [[ ${EUID} -eq 0 ]] || die "请使用 root 运行：sudo bash $0"
}

acquire_lock() {
  command -v flock >/dev/null 2>&1 || die "缺少 flock（通常由 util-linux 提供）"
  install -d -m 755 "$(dirname "$LOCK_FILE")"
  exec 9>"$LOCK_FILE"
  flock -n 9 || die "已有另一个管理器实例正在运行"
}

missing_commands() {
  local cmd missing=()
  for cmd in nft ip ss systemctl sysctl awk sed grep flock mktemp install; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  ((${#missing[@]} == 0)) || printf '%s\n' "${missing[*]}"
}

ensure_dependencies() {
  local missing
  missing=$(missing_commands || true)
  [[ -z "$missing" ]] || die "缺少命令：${missing}。请先运行：sudo bash $0 --install-deps"
}

install_dependencies() {
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y nftables iproute2 util-linux
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nftables iproute util-linux
  elif command -v yum >/dev/null 2>&1; then
    yum install -y nftables iproute util-linux
  else
    die "未识别包管理器；请手动安装 nftables、iproute2/iproute 和 util-linux"
  fi
  ensure_dependencies
  ok "依赖安装完成"
}

detect_default_network() {
  local route
  route=$(ip -4 route get 1.1.1.1 2>/dev/null | head -n1 || true)
  DEFAULT_WAN_IF=$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<<"$route")
  DEFAULT_SOURCE_IP=$(awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' <<<"$route")

  if [[ -z "$DEFAULT_WAN_IF" ]]; then
    DEFAULT_WAN_IF=$(ip -4 route show default | awk 'NR==1 {print $5}')
  fi
  if [[ -z "$DEFAULT_WAN_IF" ]]; then
    DEFAULT_WAN_IF=$(ip -4 -o addr show scope global | awk 'NR==1 {print $2}')
  fi
  [[ -n "$DEFAULT_WAN_IF" ]] || die "无法检测默认 IPv4 网卡"

  if [[ -z "$DEFAULT_SOURCE_IP" ]]; then
    DEFAULT_SOURCE_IP=$(ip -4 -o addr show dev "$DEFAULT_WAN_IF" scope global |
      awk 'NR==1 {split($4,a,"/"); print a[1]}')
  fi
  [[ -n "$DEFAULT_SOURCE_IP" ]] || DEFAULT_SOURCE_IP="unknown"
}

detect_ssh_ports() {
  local ports session_port
  ports=$(sshd -T 2>/dev/null |
    awk '$1=="port" && $2 ~ /^[0-9]+$/ {print $2}' || true)

  if [[ -n ${SSH_CONNECTION:-} ]]; then
    session_port=$(awk '{print $4}' <<<"$SSH_CONNECTION")
    [[ ${session_port:-} =~ ^[0-9]+$ ]] && ports+=$'\n'"$session_port"
  fi

  ports=$(awk '/^[0-9]+$/ && $1>=1 && $1<=65535 {print $1}' <<<"${ports:-22}" | sort -nu)
  [[ -n "$ports" ]] || ports="22"
  SSH_PORTS_CSV=$(paste -sd, <<<"$ports")
}

is_valid_ipv4() {
  local ip=${1:-} a b c d octet
  [[ $ip =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  IFS=. read -r a b c d <<<"$ip"
  for octet in "$a" "$b" "$c" "$d"; do
    ((10#$octet >= 0 && 10#$octet <= 255)) || return 1
  done
}

is_valid_port() {
  [[ ${1:-} =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 65535))
}

is_valid_protocol() {
  [[ ${1:-} == tcp || ${1:-} == udp || ${1:-} == both ]]
}

is_safe_ifname() {
  local ifname=${1:-}
  [[ $ifname =~ ^[[:alnum:]_.:-]{1,15}$ ]]
}

is_valid_ifname() {
  local ifname=${1:-}
  is_safe_ifname "$ifname" || return 1
  ip link show dev "$ifname" >/dev/null 2>&1
}

is_valid_mss() {
  [[ ${1:-} == off || ${1:-} == auto ]] || \
    { [[ ${1:-} =~ ^[0-9]+$ ]] && ((10#$1 >= 536 && 10#$1 <= 65535)); }
}

trim_spaces() {
  local value=$1
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

normalize_source_cidrs() {
  local raw=${1:-*} item ip prefix normalized=""
  local -a parts=()
  raw=$(trim_spaces "$raw")
  [[ -z "$raw" || "$raw" == "*" || "$raw" == "any" ]] && { printf '*'; return 0; }

  IFS=, read -ra parts <<<"$raw"
  ((${#parts[@]} > 0)) || return 1
  for item in "${parts[@]}"; do
    item=$(trim_spaces "$item")
    [[ $item =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]] || return 1
    ip=${item%%/*}
    is_valid_ipv4 "$ip" || return 1
    if [[ $item == */* ]]; then
      prefix=${item##*/}
      ((10#$prefix >= 0 && 10#$prefix <= 32)) || return 1
    fi
    [[ -z "$normalized" ]] || normalized+=","
    normalized+="$item"
  done
  [[ "$normalized" == "0.0.0.0/0" ]] && normalized="*"
  printf '%s' "$normalized"
}

sanitize_name() {
  local name=$1
  name=${name//$'\t'/ }
  name=${name//$'\r'/ }
  name=${name//$'\n'/ }
  name=${name//|/-}
  name=${name//#/-}
  name=$(trim_spaces "$name")
  printf '%s' "${name:0:40}"
}

detect_destination_route() {
  local dest_ip=$1 route
  ROUTE_IF=""
  ROUTE_SRC=""
  ROUTE_LINE=""

  route=$(ip -4 route get "$dest_ip" 2>/dev/null | head -n1 || true)
  [[ -n "$route" ]] || return 1
  [[ $route != unreachable* && $route != blackhole* && $route != prohibit* ]] || return 1

  ROUTE_IF=$(awk '{for(i=1;i<=NF;i++) if($i=="dev") {print $(i+1); exit}}' <<<"$route")
  ROUTE_SRC=$(awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' <<<"$route")
  [[ -n "$ROUTE_IF" ]] || return 1

  if [[ -z "$ROUTE_SRC" ]]; then
    ROUTE_SRC=$(ip -4 -o addr show dev "$ROUTE_IF" scope global |
      awk 'NR==1 {split($4,a,"/"); print a[1]}')
  fi
  [[ -n "$ROUTE_SRC" ]] || return 1
  is_valid_ipv4 "$ROUTE_SRC" || return 1
  [[ "$ROUTE_IF" != lo ]] || return 1

  ROUTE_LINE=$route
}

refresh_rule_routes() {
  local strict=${1:-0} i failed=0
  OUT_IFS=()
  SNAT_IPS=()
  ROUTE_LINES=()

  for ((i=0; i<${#RULE_NAMES[@]}; i++)); do
    if detect_destination_route "${DEST_IPS[i]}"; then
      OUT_IFS+=("$ROUTE_IF")
      SNAT_IPS+=("$ROUTE_SRC")
      ROUTE_LINES+=("$ROUTE_LINE")
    else
      OUT_IFS+=("unknown")
      SNAT_IPS+=("unknown")
      ROUTE_LINES+=("unavailable")
      warn "无法检测 [${RULE_NAMES[i]}] 到 ${DEST_IPS[i]} 的出口接口或源地址"
      failed=1
    fi
  done

  if ((strict && failed)); then
    return 1
  fi
}

load_mode() {
  MODE=""
  if [[ -f "$MODE_FILE" ]]; then
    MODE=$(awk 'NR==1 {print $1}' "$MODE_FILE")
    if [[ "$MODE" != takeover && "$MODE" != coexist ]]; then
      warn "忽略无效模式文件：$MODE_FILE"
      MODE=""
    fi
  fi

  if [[ -z "$MODE" ]] && is_legacy_v2_config; then
    MODE="takeover"
    STATE_NEEDS_MIGRATION=1
  fi
}

load_state() {
  RULE_NAMES=()
  RULE_PROTOCOLS=()
  IN_IFS=()
  RELAY_PORTS=()
  DEST_IPS=()
  DEST_PORTS=()
  SOURCE_CIDRS=()
  MSS_VALUES=()
  LOCAL_NAMES=()
  LOCAL_PROTOCOLS=()
  LOCAL_PORTS=()
  STATE_NEEDS_MIGRATION=0

  local name protocol f3 f4 f5 f6 f7 f8 extra
  local in_if relay_port dest_ip dest_port sources mss normalized

  if [[ -f "$STATE_FILE" ]]; then
    while IFS='|' read -r name protocol f3 f4 f5 f6 f7 f8 extra; do
      [[ -z ${name:-} || ${name:0:1} == "#" ]] && continue

      if [[ -z ${f6:-} ]] && is_valid_port "${f3:-}" && is_valid_ipv4 "${f4:-}"; then
        in_if=$DEFAULT_WAN_IF
        relay_port=$f3
        dest_ip=$f4
        dest_port=$f5
        sources="*"
        mss="off"
        STATE_NEEDS_MIGRATION=1
      else
        in_if=$f3
        relay_port=$f4
        dest_ip=$f5
        dest_port=$f6
        sources=${f7:-*}
        mss=${f8:-off}
      fi

      normalized=$(normalize_source_cidrs "$sources" 2>/dev/null || true)
      if ! is_valid_protocol "$protocol" || ! is_safe_ifname "$in_if" || \
         ! is_valid_port "$relay_port" || ! is_valid_ipv4 "$dest_ip" || \
         ! is_valid_port "$dest_port" || [[ -z "$normalized" ]] || ! is_valid_mss "$mss"; then
        warn "忽略状态文件中的无效转发规则：${name:-unnamed}"
        continue
      fi
      if [[ "$protocol" == udp && "$mss" != off ]]; then
        warn "规则 ${name} 是 UDP，已忽略其 TCP MSS 设置"
        mss="off"
      fi

      RULE_NAMES+=("$(sanitize_name "$name")")
      RULE_PROTOCOLS+=("$protocol")
      IN_IFS+=("$in_if")
      RELAY_PORTS+=("$relay_port")
      DEST_IPS+=("$dest_ip")
      DEST_PORTS+=("$dest_port")
      SOURCE_CIDRS+=("$normalized")
      MSS_VALUES+=("$mss")
    done <"$STATE_FILE"
  fi

  if [[ -f "$LOCAL_STATE_FILE" ]]; then
    while IFS='|' read -r name protocol f3 extra; do
      [[ -z ${name:-} || ${name:0:1} == "#" ]] && continue
      if ! is_valid_protocol "$protocol" || ! is_valid_port "${f3:-}"; then
        warn "忽略本机端口状态文件中的无效规则：${name:-unnamed}"
        continue
      fi
      LOCAL_NAMES+=("$(sanitize_name "$name")")
      LOCAL_PROTOCOLS+=("$protocol")
      LOCAL_PORTS+=("$f3")
    done <"$LOCAL_STATE_FILE"
  fi

  load_mode
}

validate_rule_interfaces() {
  local i failed=0
  for ((i=0; i<${#IN_IFS[@]}; i++)); do
    if ! is_valid_ifname "${IN_IFS[i]}"; then
      warn "规则 [${RULE_NAMES[i]}] 的入口网卡不存在：${IN_IFS[i]}"
      failed=1
    fi
  done
  ((failed == 0))
}

save_state_to() {
  local target=$1 i
  {
    echo "# v3: name|protocol|ingress_if|relay_port|destination_ip|destination_port|source_cidrs|tcp_mss"
    for ((i=0; i<${#RULE_NAMES[@]}; i++)); do
      printf '%s|%s|%s|%s|%s|%s|%s|%s\n' \
        "${RULE_NAMES[i]}" "${RULE_PROTOCOLS[i]}" "${IN_IFS[i]}" \
        "${RELAY_PORTS[i]}" "${DEST_IPS[i]}" "${DEST_PORTS[i]}" \
        "${SOURCE_CIDRS[i]}" "${MSS_VALUES[i]}"
    done
  } >"$target"
}

save_local_state_to() {
  local target=$1 i
  {
    echo "# name|protocol|local_port"
    for ((i=0; i<${#LOCAL_NAMES[@]}; i++)); do
      printf '%s|%s|%s\n' "${LOCAL_NAMES[i]}" "${LOCAL_PROTOCOLS[i]}" "${LOCAL_PORTS[i]}"
    done
  } >"$target"
}

save_mode_to() {
  local target=$1
  printf '%s\n' "$MODE" >"$target"
}

mode_label() {
  case "${MODE:-}" in
    takeover) printf '安全接管' ;;
    coexist)  printf 'NAT 共存' ;;
    *)        printf '尚未选择' ;;
  esac
}

show_local_ports() {
  local i
  printf '\n%-4s %-24s %-10s %s\n' "序号" "本机服务名称" "协议" "端口"
  printf '%s\n' "------------------------------------------------------------"
  if ((${#LOCAL_NAMES[@]} == 0)); then
    echo "（尚未登记本机服务端口；安全接管模式始终自动放行 SSH）"
  else
    for ((i=0; i<${#LOCAL_NAMES[@]}; i++)); do
      printf '%-4s %-24s %-10s %s\n' \
        "$((i+1))" "${LOCAL_NAMES[i]}" "${LOCAL_PROTOCOLS[i]}" "${LOCAL_PORTS[i]}"
    done
  fi
  if [[ "$MODE" == coexist ]]; then
    warn "NAT 共存模式不会把上述本机端口写入 input；它们仅被保留供以后切回安全接管模式。"
  fi
}

show_rules() {
  local i route_status
  refresh_rule_routes 0 || true
  printf '\n当前模式：%s (%s)\n' "$(mode_label)" "${MODE:-unset}"
  printf '%-4s %-16s %-6s %-15s %-22s %-15s %-15s\n' \
    "序号" "名称" "协议" "入口" "下一跳" "出口/源地址" "来源限制"
  printf '%s\n' "----------------------------------------------------------------------------------------------------------------"
  if ((${#RULE_NAMES[@]} == 0)); then
    echo "（暂无转发规则）"
  else
    for ((i=0; i<${#RULE_NAMES[@]}; i++)); do
      route_status="${OUT_IFS[i]}/${SNAT_IPS[i]}"
      printf '%-4s %-16s %-6s %-15s %-22s %-15s %-15s\n' \
        "$((i+1))" "${RULE_NAMES[i]:0:16}" "${RULE_PROTOCOLS[i]}" \
        "${IN_IFS[i]}:${RELAY_PORTS[i]}" "${DEST_IPS[i]}:${DEST_PORTS[i]}" \
        "${route_status:0:15}" "${SOURCE_CIDRS[i]:0:15}"
      printf '     MSS=%s  route: %s\n' "${MSS_VALUES[i]}" "${ROUTE_LINES[i]}"
    done
  fi
  show_local_ports
  echo
}

protocols_overlap() {
  local first=$1 second=$2
  [[ $first == both || $second == both || $first == "$second" ]]
}

relay_rule_conflicts() {
  local in_if=$1 port=$2 protocol=$3 skip=${4:--1} i
  for ((i=0; i<${#RELAY_PORTS[@]}; i++)); do
    ((i == skip)) && continue
    if [[ ${IN_IFS[i]} == "$in_if" && ${RELAY_PORTS[i]} == "$port" ]] && \
       protocols_overlap "${RULE_PROTOCOLS[i]}" "$protocol"; then
      return 0
    fi
  done
  return 1
}

local_port_conflicts() {
  local candidate=$1 protocol=$2 i
  for ((i=0; i<${#LOCAL_PORTS[@]}; i++)); do
    if [[ ${LOCAL_PORTS[i]} == "$candidate" ]] && \
       protocols_overlap "${LOCAL_PROTOCOLS[i]}" "$protocol"; then
      return 0
    fi
  done
  return 1
}

ssh_port_conflicts() {
  local candidate=$1 protocol=$2 port
  [[ "$protocol" != udp ]] || return 1
  local -a ssh_ports=()
  IFS=, read -ra ssh_ports <<<"$SSH_PORTS_CSV"
  for port in "${ssh_ports[@]}"; do
    [[ $port == "$candidate" ]] && return 0
  done
  return 1
}

local_port_is_listening() {
  local protocol=$1 port=$2
  case "$protocol" in
    tcp)  ss -H -lnt "sport = :$port" 2>/dev/null | grep -q . ;;
    udp)  ss -H -lnu "sport = :$port" 2>/dev/null | grep -q . ;;
    both) ss -H -lntu "sport = :$port" 2>/dev/null | grep -q . ;;
  esac
}

choose_mode() {
  local choice previous=$MODE
  echo
  echo "1) 安全接管模式：管理 input + forward + NAT；默认拒绝未登记端口"
  echo "2) NAT 共存模式：只管理 NAT/MSS；现有防火墙继续负责 input + forward"
  read -rp "请选择 [${MODE:-未设置}]：" choice
  case "$choice" in
    1) MODE="takeover" ;;
    2) MODE="coexist" ;;
    "") [[ -n "$MODE" ]] || { warn "首次使用必须选择模式"; return; } ;;
    *) warn "请输入 1 或 2"; return ;;
  esac

  if [[ "$previous" != "$MODE" ]]; then
    ok "待应用模式已改为：$(mode_label)"
    [[ "$MODE" == coexist ]] && \
      warn "切换到共存模式后，本脚本将删除自己的默认 drop 过滤表；现有防火墙承担过滤责任。"
    info "选择“应用并保存”后才会真正生效"
  fi
}

ensure_mode_selected() {
  if [[ -z "$MODE" ]]; then
    info "首次使用 v3，请先选择防火墙工作模式"
    while [[ -z "$MODE" ]]; do choose_mode; done
  fi
}

add_rule() {
  local name protocol_choice protocol in_if relay_port dest_ip dest_port default_port
  local sources_input sources mss_input mss
  echo
  read -rp "线路名称 [relay-$(( ${#RULE_NAMES[@]} + 1 ))]: " name
  name=$(sanitize_name "${name:-relay-$(( ${#RULE_NAMES[@]} + 1 ))}")
  [[ -n "$name" ]] || name="relay-$(( ${#RULE_NAMES[@]} + 1 ))"

  while true; do
    read -rp "协议：1=TCP+UDP（默认），2=TCP，3=UDP [1]: " protocol_choice
    case "${protocol_choice:-1}" in
      1) protocol=both; break ;;
      2) protocol=tcp; break ;;
      3) protocol=udp; break ;;
      *) warn "请输入 1、2 或 3" ;;
    esac
  done

  while true; do
    read -rp "入口网卡 [${DEFAULT_WAN_IF}]: " in_if
    in_if=${in_if:-$DEFAULT_WAN_IF}
    is_valid_ifname "$in_if" && break
    warn "网卡不存在或名称无效；可用 ip -brief link 查看"
  done

  while true; do
    read -rp "下一跳/落地机 IPv4：" dest_ip
    is_valid_ipv4 "$dest_ip" || { warn "IPv4 格式无效"; continue; }
    if ! detect_destination_route "$dest_ip"; then
      warn "当前没有可用路由，或无法确定出口源地址"
      continue
    fi
    printf '  内核路由：%s\n' "$ROUTE_LINE"
    printf '  将使用：出口=%s，SNAT源地址=%s\n' "$ROUTE_IF" "$ROUTE_SRC"
    break
  done

  while true; do
    read -rp "下一跳/落地机端口：" dest_port
    is_valid_port "$dest_port" && break
    warn "端口必须在 1-65535 之间"
  done

  default_port=$dest_port
  while true; do
    read -rp "中转入口端口 [${default_port}]: " relay_port
    relay_port=${relay_port:-$default_port}
    is_valid_port "$relay_port" || { warn "端口必须在 1-65535 之间"; continue; }
    ssh_port_conflicts "$relay_port" "$protocol" && { warn "不能占用 SSH TCP 端口 ${relay_port}"; continue; }
    relay_rule_conflicts "$in_if" "$relay_port" "$protocol" && {
      warn "${in_if} 上的 ${protocol}/${relay_port} 已被重叠协议的转发规则使用"
      continue
    }
    local_port_conflicts "$relay_port" "$protocol" && {
      warn "${protocol}/${relay_port} 已登记为本机服务端口，不能同时用于转发"
      continue
    }
    if local_port_is_listening "$protocol" "$relay_port"; then
      warn "本机已有进程监听 ${protocol}/${relay_port}，请换一个中转端口"
      continue
    fi
    break
  done

  while true; do
    read -rp "允许的来源 IPv4/CIDR，多个用逗号分隔；* 表示任意 [*]: " sources_input
    sources=$(normalize_source_cidrs "${sources_input:-*}" 2>/dev/null || true)
    [[ -n "$sources" ]] && break
    warn "来源格式无效，例如：1.2.3.4,10.0.0.0/8 或 *"
  done

  mss="off"
  if [[ "$protocol" != udp ]]; then
    while true; do
      read -rp "TCP MSS：off=关闭（默认），auto=按路由MTU钳制，或输入固定值 [off]: " mss_input
      mss=${mss_input:-off}
      is_valid_mss "$mss" && break
      warn "请输入 off、auto 或 536-65535 的整数；通常无需设置"
    done
  fi

  RULE_NAMES+=("$name")
  RULE_PROTOCOLS+=("$protocol")
  IN_IFS+=("$in_if")
  RELAY_PORTS+=("$relay_port")
  DEST_IPS+=("$dest_ip")
  DEST_PORTS+=("$dest_port")
  SOURCE_CIDRS+=("$sources")
  MSS_VALUES+=("$mss")
  OUT_IFS+=("$ROUTE_IF")
  SNAT_IPS+=("$ROUTE_SRC")
  ROUTE_LINES+=("$ROUTE_LINE")

  ok "已加入待应用列表：${name} ${protocol} ${in_if}:${relay_port} -> ${dest_ip}:${dest_port}"
  info "出口=${ROUTE_IF}，逐规则 SNAT=${ROUTE_SRC}，来源=${sources}，MSS=${mss}"
}

delete_rule() {
  local selection idx confirm array_name
  ((${#RULE_NAMES[@]} > 0)) || { warn "没有可删除的转发规则"; return; }
  show_rules
  read -rp "删除转发序号（0 取消）：" selection
  [[ $selection =~ ^[0-9]+$ ]] || { warn "请输入数字"; return; }
  ((selection != 0)) || return
  ((selection >= 1 && selection <= ${#RULE_NAMES[@]})) || { warn "序号超出范围"; return; }
  idx=$((selection-1))
  read -rp "确认删除 [${RULE_NAMES[idx]}]？输入 YES：" confirm
  [[ ${confirm:-} == YES ]] || { info "已取消"; return; }

  for array_name in RULE_NAMES RULE_PROTOCOLS IN_IFS RELAY_PORTS DEST_IPS DEST_PORTS \
                    SOURCE_CIDRS MSS_VALUES OUT_IFS SNAT_IPS ROUTE_LINES; do
    unset "${array_name}[idx]"
    eval "${array_name}=(\"\${${array_name}[@]}\")"
  done
  ok "转发规则已从待应用列表删除"
}

clear_rules() {
  local confirm
  read -rp "这会移除所有转发；本机端口列表不变。输入 CLEAR 确认：" confirm
  [[ ${confirm:-} == CLEAR ]] || { info "已取消"; return; }
  RULE_NAMES=(); RULE_PROTOCOLS=(); IN_IFS=(); RELAY_PORTS=()
  DEST_IPS=(); DEST_PORTS=(); SOURCE_CIDRS=(); MSS_VALUES=()
  OUT_IFS=(); SNAT_IPS=(); ROUTE_LINES=()
  ok "待应用转发列表已清空"
}

add_local_port() {
  local name protocol_choice protocol port
  echo
  [[ "$MODE" == coexist ]] && \
    warn "当前为 NAT 共存模式：本条目会保存，但不会写入 input；请用现有防火墙放行。"
  read -rp "本机服务名称 [local-$(( ${#LOCAL_NAMES[@]} + 1 ))]: " name
  name=$(sanitize_name "${name:-local-$(( ${#LOCAL_NAMES[@]} + 1 ))}")
  [[ -n "$name" ]] || name="local-$(( ${#LOCAL_NAMES[@]} + 1 ))"

  while true; do
    read -rp "放行协议：1=TCP+UDP（默认），2=TCP，3=UDP [1]: " protocol_choice
    case "${protocol_choice:-1}" in
      1) protocol=both; break ;;
      2) protocol=tcp; break ;;
      3) protocol=udp; break ;;
      *) warn "请输入 1、2 或 3" ;;
    esac
  done

  while true; do
    read -rp "本机需要放行的端口：" port
    is_valid_port "$port" || { warn "端口必须在 1-65535 之间"; continue; }
    if ssh_port_conflicts "$port" "$protocol"; then
      warn "SSH 的 TCP/${port} 已自动放行，无需重复添加"
      continue
    fi
    if local_port_conflicts "$port" "$protocol"; then
      warn "${protocol}/${port} 已存在于本机端口列表"
      continue
    fi
    if relay_port_used_any_interface "$port" "$protocol"; then
      warn "${protocol}/${port} 已用于中转，不能同时登记为本机服务"
      continue
    fi
    break
  done

  LOCAL_NAMES+=("$name")
  LOCAL_PROTOCOLS+=("$protocol")
  LOCAL_PORTS+=("$port")

  if local_port_is_listening "$protocol" "$port"; then
    ok "检测到本机已有服务监听该端口"
  else
    warn "目前未发现对应监听服务；可以先登记，稍后再启动节点"
  fi
  ok "已加入待应用本机端口列表：${name} ${protocol}/${port}"
}

relay_port_used_any_interface() {
  local port=$1 protocol=$2 i
  for ((i=0; i<${#RELAY_PORTS[@]}; i++)); do
    if [[ ${RELAY_PORTS[i]} == "$port" ]] && protocols_overlap "${RULE_PROTOCOLS[i]}" "$protocol"; then
      return 0
    fi
  done
  return 1
}

delete_local_port() {
  local selection idx confirm
  ((${#LOCAL_NAMES[@]} > 0)) || { warn "没有可删除的本机端口"; return; }
  show_local_ports
  read -rp "删除本机端口序号（0 取消）：" selection
  [[ $selection =~ ^[0-9]+$ ]] || { warn "请输入数字"; return; }
  ((selection != 0)) || return
  ((selection >= 1 && selection <= ${#LOCAL_NAMES[@]})) || { warn "序号超出范围"; return; }
  idx=$((selection-1))
  read -rp "确认删除 [${LOCAL_NAMES[idx]} ${LOCAL_PROTOCOLS[idx]}/${LOCAL_PORTS[idx]}]？输入 YES：" confirm
  [[ ${confirm:-} == YES ]] || { info "已取消"; return; }
  unset 'LOCAL_NAMES[idx]' 'LOCAL_PROTOCOLS[idx]' 'LOCAL_PORTS[idx]'
  LOCAL_NAMES=("${LOCAL_NAMES[@]}")
  LOCAL_PROTOCOLS=("${LOCAL_PROTOCOLS[@]}")
  LOCAL_PORTS=("${LOCAL_PORTS[@]}")
  ok "本机端口已从待应用列表删除"
}

show_listening_ports() {
  echo
  info "本机当前监听的 TCP/UDP 端口："
  ss -lntup || true
  echo
  info "中转端口不应有本机进程监听；本机服务端口则应有对应监听进程。"
}

protocol_expr() {
  local protocol=$1 port_expr=$2
  case "$protocol" in
    tcp)  printf 'tcp dport %s' "$port_expr" ;;
    udp)  printf 'udp dport %s' "$port_expr" ;;
    both) printf 'meta l4proto { tcp, udp } th dport %s' "$port_expr" ;;
  esac
}

source_expr() {
  local sources=$1 set_value
  if [[ "$sources" == "*" ]]; then
    printf ''
  else
    set_value=${sources//,/, }
    printf 'ip saddr { %s } ' "$set_value"
  fi
}

generate_config() {
  local target=$1 i proto_in proto_out proto_local src_expr
  local have_mss=0 mss_target
  for ((i=0; i<${#MSS_VALUES[@]}; i++)); do
    [[ ${MSS_VALUES[i]} != off ]] && have_mss=1
  done

  {
    cat <<EOF
#!/usr/sbin/nft -f
# Generated by po0-relay-manager v${VERSION} on $(date '+%F %T %Z')
# Mode: ${MODE}; every SNAT source was resolved against its own destination.

table ip ${TABLE_NAT_NAME} {
    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;
EOF
    for ((i=0; i<${#RULE_NAMES[@]}; i++)); do
      proto_in=$(protocol_expr "${RULE_PROTOCOLS[i]}" "${RELAY_PORTS[i]}")
      src_expr=$(source_expr "${SOURCE_CIDRS[i]}")
      printf '        # Relay [%s]\n' "${RULE_NAMES[i]}"
      printf '        iifname "%s" %s%s counter dnat to %s:%s\n' \
        "${IN_IFS[i]}" "$src_expr" "$proto_in" "${DEST_IPS[i]}" "${DEST_PORTS[i]}"
    done
    cat <<'EOF'
    }

    chain postrouting {
        type nat hook postrouting priority srcnat; policy accept;
EOF
    for ((i=0; i<${#RULE_NAMES[@]}; i++)); do
      proto_out=$(protocol_expr "${RULE_PROTOCOLS[i]}" "${DEST_PORTS[i]}")
      src_expr=$(source_expr "${SOURCE_CIDRS[i]}")
      printf '        # Relay [%s] - only connections that were actually DNATed\n' "${RULE_NAMES[i]}"
      printf '        ct status dnat oifname "%s" %sip daddr %s %s counter snat to %s\n' \
        "${OUT_IFS[i]}" "$src_expr" "${DEST_IPS[i]}" "$proto_out" "${SNAT_IPS[i]}"
    done
    cat <<'EOF'
    }
}
EOF

    if [[ "$MODE" == takeover ]]; then
      cat <<EOF

table inet ${TABLE_FILTER_NAME} {
    chain input {
        type filter hook input priority filter; policy drop;
        ct state invalid counter drop
        ct state established,related counter accept
        iifname "lo" counter accept
        meta l4proto icmp counter accept
        meta l4proto ipv6-icmp counter accept
        iifname "${DEFAULT_WAN_IF}" meta nfproto ipv4 udp sport 67 udp dport 68 counter accept
        iifname "${DEFAULT_WAN_IF}" meta nfproto ipv6 udp sport 547 udp dport 546 counter accept
        tcp dport { ${SSH_PORTS_CSV} } ct state new counter accept
EOF
      for ((i=0; i<${#LOCAL_NAMES[@]}; i++)); do
        proto_local=$(protocol_expr "${LOCAL_PROTOCOLS[i]}" "${LOCAL_PORTS[i]}")
        printf '        # Local service [%s]\n' "${LOCAL_NAMES[i]}"
        printf '        iifname "%s" %s ct state new counter accept\n' \
          "$DEFAULT_WAN_IF" "$proto_local"
      done
      cat <<'EOF'
    }

    chain forward {
        type filter hook forward priority filter; policy drop;
        ct state invalid counter drop
        ct state established,related counter accept
EOF
      for ((i=0; i<${#RULE_NAMES[@]}; i++)); do
        proto_out=$(protocol_expr "${RULE_PROTOCOLS[i]}" "${DEST_PORTS[i]}")
        src_expr=$(source_expr "${SOURCE_CIDRS[i]}")
        printf '        # Relay [%s] - new flow must carry conntrack DNAT status\n' "${RULE_NAMES[i]}"
        printf '        ct state new ct status dnat iifname "%s" oifname "%s" %sip daddr %s %s counter accept\n' \
          "${IN_IFS[i]}" "${OUT_IFS[i]}" "$src_expr" "${DEST_IPS[i]}" "$proto_out"
      done
      cat <<'EOF'
    }

    chain output {
        type filter hook output priority filter; policy accept;
    }
}
EOF
    fi

    if ((have_mss)); then
      cat <<EOF

table ip ${TABLE_MANGLE_NAME} {
    chain forward {
        type filter hook forward priority mangle; policy accept;
EOF
      for ((i=0; i<${#RULE_NAMES[@]}; i++)); do
        [[ ${MSS_VALUES[i]} != off ]] || continue
        src_expr=$(source_expr "${SOURCE_CIDRS[i]}")
        mss_target=${MSS_VALUES[i]}
        [[ "$mss_target" == auto ]] && mss_target="rt mtu"
        printf '        # TCP MSS clamp for [%s]\n' "${RULE_NAMES[i]}"
        printf '        ct status dnat iifname "%s" oifname "%s" %sip daddr %s tcp dport %s tcp flags & (syn | rst) == syn tcp option maxseg size set %s counter\n' \
          "${IN_IFS[i]}" "${OUT_IFS[i]}" "$src_expr" "${DEST_IPS[i]}" \
          "${DEST_PORTS[i]}" "$mss_target"
      done
      cat <<'EOF'
    }
}
EOF
    fi
  } >"$target"
}

table_exists() {
  nft list table "$1" "$2" >/dev/null 2>&1
}

generate_live_batch() {
  local target=$1 config=$2
  {
    echo "#!/usr/sbin/nft -f"
    table_exists "$TABLE_MANGLE_FAMILY" "$TABLE_MANGLE_NAME" && \
      echo "delete table ${TABLE_MANGLE_FAMILY} ${TABLE_MANGLE_NAME}"
    table_exists "$TABLE_FILTER_FAMILY" "$TABLE_FILTER_NAME" && \
      echo "delete table ${TABLE_FILTER_FAMILY} ${TABLE_FILTER_NAME}"
    table_exists "$TABLE_NAT_FAMILY" "$TABLE_NAT_NAME" && \
      echo "delete table ${TABLE_NAT_FAMILY} ${TABLE_NAT_NAME}"
    sed '1{/^#!\/usr\/sbin\/nft -f$/d;}' "$config"
  } >"$target"
}

write_loader_to() {
  local target=$1
  cat >"$target" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

CONF="/etc/po0-relay/po0-relay.nft"
ACTION="${1:-load}"
TMP=$(mktemp /run/po0-relay-loader.XXXXXX)
trap 'rm -f "$TMP"' EXIT

emit_deletes() {
  nft list table ip po0_relay_mangle >/dev/null 2>&1 && echo "delete table ip po0_relay_mangle"
  nft list table inet po0_relay_filter >/dev/null 2>&1 && echo "delete table inet po0_relay_filter"
  nft list table ip po0_relay_nat >/dev/null 2>&1 && echo "delete table ip po0_relay_nat"
  return 0
}

{
  echo "#!/usr/sbin/nft -f"
  emit_deletes
  if [[ "$ACTION" != stop ]]; then
    [[ -r "$CONF" ]] || { echo "Missing $CONF" >&2; exit 1; }
    sed '1{/^#!\/usr\/sbin\/nft -f$/d;}' "$CONF"
  fi
} >"$TMP"

if [[ "$ACTION" == stop ]] && [[ $(wc -l <"$TMP") -eq 1 ]]; then
  exit 0
fi

nft -f "$TMP"
EOF
  chmod 755 "$target"
}

write_service_to() {
  local target=$1
  cat >"$target" <<EOF
[Unit]
Description=PO0 relay nftables rules
Documentation=file://${STATE_DIR}/po0-relay.nft
DefaultDependencies=no
Wants=network-pre.target
Before=network-pre.target
After=local-fs.target nftables.service ufw.service firewalld.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${LOADER_FILE} load
ExecReload=${LOADER_FILE} load
ExecStop=${LOADER_FILE} stop

[Install]
WantedBy=multi-user.target
EOF
}

is_legacy_v2_config() {
  [[ -f "$LEGACY_NFT_CONF" ]] && \
    grep -qE 'Generated by po0-relay-manager v2([.]| )' "$LEGACY_NFT_CONF"
}

is_ufw_active() {
  command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'
}

is_firewalld_active() {
  systemctl is-active --quiet firewalld 2>/dev/null
}

preflight_mode() {
  LEGACY_V2_ACTIVE=0
  UFW_WAS_ACTIVE=0
  FIREWALLD_WAS_ACTIVE=0
  is_legacy_v2_config && LEGACY_V2_ACTIVE=1
  is_ufw_active && UFW_WAS_ACTIVE=1
  is_firewalld_active && FIREWALLD_WAS_ACTIVE=1

  if [[ "$MODE" == takeover ]]; then
    if systemctl is-active --quiet docker 2>/dev/null || \
       systemctl is-active --quiet containerd 2>/dev/null; then
      die "安全接管模式会用默认 drop 的 forward 链影响容器流量。请停止容器服务，或改用 NAT 共存模式。"
    fi
    ((UFW_WAS_ACTIVE)) && die "检测到 UFW active。请先执行 ufw disable，或改用 NAT 共存模式。"
    ((FIREWALLD_WAS_ACTIVE)) && die "检测到 firewalld active。请先停用它，或改用 NAT 共存模式。"
  else
    ((UFW_WAS_ACTIVE)) && warn "UFW 正在运行：DNAT 可加载，但 UFW 可能仍会丢弃 FORWARD。应用后请按提示添加 ufw route allow。"
    ((FIREWALLD_WAS_ACTIVE)) && warn "firewalld 正在运行：DNAT 可加载，但仍需在 firewalld policy/zone 中放行转发。"
  fi

  if ((LEGACY_V2_ACTIVE)); then
    warn "检测到 v2 生成的 /etc/nftables.conf。应用 v3 时将停用旧 nftables.service，避免 v2 与 v3 重复生效。"
    warn "停用旧服务时，其 ExecStop 可能清空一次活动 ruleset；随后会立即恢复现有防火墙并加载 v3。"
    warn "原配置和活动 ruleset 会先完整备份；v3 不删除 /etc/nftables.conf。"
  fi
}

remove_legacy_v2_tables() {
  local tmp have_rules=0
  tmp=$(mktemp /tmp/po0-v2-remove.XXXXXX)
  {
    echo "#!/usr/sbin/nft -f"
    if table_exists inet filter; then
      echo "delete table inet filter"
      have_rules=1
    fi
    if table_exists ip nat; then
      echo "delete table ip nat"
      have_rules=1
    fi
  } >"$tmp"
  if ((have_rules)); then
    nft -f "$tmp"
  fi
  rm -f -- "$tmp"
}

backup_one() {
  local source=$1 label=$2 backup=$3
  if [[ -e "$source" || -L "$source" ]]; then
    cp -a "$source" "$backup/$label"
  else
    : >"$backup/${label}.absent"
  fi
}

make_backup() {
  local stamp backup
  stamp=$(date '+%Y%m%d-%H%M%S-%N')
  backup="${BACKUP_DIR}/${stamp}"
  install -d -m 700 "$backup"
  printf '3\n' >"$backup/backup-format"

  backup_one "$LEGACY_NFT_CONF" "nftables.conf" "$backup"
  backup_one "$OWN_CONF" "po0-relay.nft" "$backup"
  backup_one "$STATE_FILE" "rules.db" "$backup"
  backup_one "$LOCAL_STATE_FILE" "local-ports.db" "$backup"
  backup_one "$MODE_FILE" "mode" "$backup"
  backup_one "$SYSCTL_CONF" "99-po0-relay.conf" "$backup"
  backup_one "$LOADER_FILE" "po0-relay-loader" "$backup"
  backup_one "$SERVICE_FILE" "po0-relay.service" "$backup"

  {
    echo "flush ruleset"
    nft list ruleset 2>/dev/null || true
  } >"$backup/live-ruleset.nft"
  sysctl -n net.ipv4.ip_forward 2>/dev/null >"$backup/ip-forward.value" || echo 0 >"$backup/ip-forward.value"

  if systemctl is-enabled --quiet nftables.service 2>/dev/null; then
    echo yes >"$backup/nftables.enabled"
  else
    echo no >"$backup/nftables.enabled"
  fi
  if systemctl is-active --quiet nftables.service 2>/dev/null; then
    echo yes >"$backup/nftables.active"
  else
    echo no >"$backup/nftables.active"
  fi
  if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo yes >"$backup/po0.enabled"
  else
    echo no >"$backup/po0.enabled"
  fi
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    echo yes >"$backup/po0.active"
  else
    echo no >"$backup/po0.active"
  fi

  printf '%s\n' "$backup"
}

restore_one() {
  local backup=$1 label=$2 target=$3 mode=${4:-600}
  if [[ -e "$backup/$label" || -L "$backup/$label" ]]; then
    install -D -m "$mode" "$backup/$label" "$target"
  elif [[ -f "$backup/${label}.absent" ]]; then
    rm -f -- "$target"
  fi
}

restore_v3_backup() {
  local backup=$1
  [[ -f "$backup/backup-format" ]] || return 1
  [[ -f "$backup/live-ruleset.nft" ]] || return 1

  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true

  restore_one "$backup" "nftables.conf" "$LEGACY_NFT_CONF" 644
  restore_one "$backup" "po0-relay.nft" "$OWN_CONF" 600
  restore_one "$backup" "rules.db" "$STATE_FILE" 600
  restore_one "$backup" "local-ports.db" "$LOCAL_STATE_FILE" 600
  restore_one "$backup" "mode" "$MODE_FILE" 600
  restore_one "$backup" "99-po0-relay.conf" "$SYSCTL_CONF" 644
  restore_one "$backup" "po0-relay-loader" "$LOADER_FILE" 755
  restore_one "$backup" "po0-relay.service" "$SERVICE_FILE" 644
  systemctl daemon-reload || true

  if [[ $(cat "$backup/nftables.enabled" 2>/dev/null || echo no) == yes ]]; then
    systemctl enable nftables.service >/dev/null 2>&1 || true
  else
    systemctl disable nftables.service >/dev/null 2>&1 || true
  fi
  if [[ $(cat "$backup/nftables.active" 2>/dev/null || echo no) == yes ]]; then
    systemctl start nftables.service >/dev/null 2>&1 || true
  fi

  if [[ $(cat "$backup/po0.enabled" 2>/dev/null || echo no) == yes ]]; then
    systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi
  if [[ $(cat "$backup/po0.active" 2>/dev/null || echo no) == yes ]]; then
    systemctl start "$SERVICE_NAME" >/dev/null 2>&1 || true
  fi

  # Service starts may rewrite nftables. Restore the exact captured live snapshot last.
  nft -f "$backup/live-ruleset.nft" || return 1
  sysctl -w "net.ipv4.ip_forward=$(cat "$backup/ip-forward.value")" >/dev/null 2>&1 || true
  return 0
}

write_watchdog_script() {
  local target=$1 backup=$2
  local q_backup q_service q_nft q_own q_state q_local q_mode q_sysctl q_loader q_unit
  printf -v q_backup '%q' "$backup"
  printf -v q_service '%q' "$SERVICE_NAME"
  printf -v q_nft '%q' "$LEGACY_NFT_CONF"
  printf -v q_own '%q' "$OWN_CONF"
  printf -v q_state '%q' "$STATE_FILE"
  printf -v q_local '%q' "$LOCAL_STATE_FILE"
  printf -v q_mode '%q' "$MODE_FILE"
  printf -v q_sysctl '%q' "$SYSCTL_CONF"
  printf -v q_loader '%q' "$LOADER_FILE"
  printf -v q_unit '%q' "$SERVICE_FILE"

  cat >"$target" <<EOF
#!/usr/bin/env bash
set +e
backup=${q_backup}
systemctl disable --now ${q_service} >/dev/null 2>&1
restore_one() {
  local label=\$1 target=\$2 mode=\$3
  if [[ -e "\$backup/\$label" || -L "\$backup/\$label" ]]; then
    install -D -m "\$mode" "\$backup/\$label" "\$target"
  elif [[ -f "\$backup/\${label}.absent" ]]; then
    rm -f -- "\$target"
  fi
}
restore_one nftables.conf ${q_nft} 644
restore_one po0-relay.nft ${q_own} 600
restore_one rules.db ${q_state} 600
restore_one local-ports.db ${q_local} 600
restore_one mode ${q_mode} 600
restore_one 99-po0-relay.conf ${q_sysctl} 644
restore_one po0-relay-loader ${q_loader} 755
restore_one po0-relay.service ${q_unit} 644
systemctl daemon-reload
[[ \$(cat "\$backup/nftables.enabled" 2>/dev/null) == yes ]] && systemctl enable nftables.service >/dev/null 2>&1
[[ \$(cat "\$backup/nftables.active" 2>/dev/null) == yes ]] && systemctl start nftables.service >/dev/null 2>&1
[[ \$(cat "\$backup/po0.enabled" 2>/dev/null) == yes ]] && systemctl enable ${q_service} >/dev/null 2>&1
[[ \$(cat "\$backup/po0.active" 2>/dev/null) == yes ]] && systemctl start ${q_service} >/dev/null 2>&1
nft -f "\$backup/live-ruleset.nft"
sysctl -w "net.ipv4.ip_forward=\$(cat "\$backup/ip-forward.value")" >/dev/null 2>&1
logger -t po0-relay "Automatic rollback restored \$backup"
EOF
  chmod 700 "$target"
}

start_watchdog() {
  local backup=$1 unit_base=$2 script=$3
  command -v systemd-run >/dev/null 2>&1 || return 1
  write_watchdog_script "$script" "$backup"
  systemd-run --quiet --unit="$unit_base" --on-active=120s "$script" >/dev/null 2>&1
}

cancel_watchdog() {
  local unit_base=$1 script=$2
  systemctl stop "${unit_base}.timer" >/dev/null 2>&1 || true
  systemctl stop "${unit_base}.service" >/dev/null 2>&1 || true
  systemctl reset-failed "${unit_base}.service" >/dev/null 2>&1 || true
  rm -f -- "$script"
}

show_coexist_guidance() {
  local i proto source_prefix
  [[ "$MODE" == coexist ]] || return 0
  if is_ufw_active; then
    echo
    warn "UFW 的 input allow 不能替代 DNAT 所需的 FORWARD 放行。可按规则执行："
    for ((i=0; i<${#RULE_NAMES[@]}; i++)); do
      for proto in tcp udp; do
        [[ ${RULE_PROTOCOLS[i]} == both || ${RULE_PROTOCOLS[i]} == "$proto" ]] || continue
        source_prefix=""
        [[ ${SOURCE_CIDRS[i]} == "*" ]] || source_prefix="from ${SOURCE_CIDRS[i]%%,*} "
        printf '  ufw route allow in on %q out on %q proto %s %sto %s port %s\n' \
          "${IN_IFS[i]}" "${OUT_IFS[i]}" "$proto" "$source_prefix" \
          "${DEST_IPS[i]}" "${DEST_PORTS[i]}"
      done
    done
    warn "若一条规则有多个来源 CIDR，请为每个来源分别添加；删除转发时也要同步删除对应 UFW 规则。"
  else
    info "NAT 共存模式未修改 input/forward；请确认现有防火墙允许上述 DNAT 后的转发流量。"
  fi
}

apply_configuration() {
  local tmp_conf tmp_state tmp_local tmp_mode tmp_loader tmp_service tmp_batch
  local backup confirm watchdog_base watchdog_script keep_reply

  ensure_mode_selected
  validate_rule_interfaces || die "至少一条规则的入口网卡不存在，已拒绝应用"
  refresh_rule_routes 1 || die "至少一条线路无法确定逐规则出口/SNAT 源地址，已拒绝应用"
  preflight_mode

  tmp_conf=$(mktemp /tmp/po0-v3-conf.XXXXXX)
  tmp_state=$(mktemp /tmp/po0-v3-state.XXXXXX)
  tmp_local=$(mktemp /tmp/po0-v3-local.XXXXXX)
  tmp_mode=$(mktemp /tmp/po0-v3-mode.XXXXXX)
  tmp_loader=$(mktemp /tmp/po0-v3-loader.XXXXXX)
  tmp_service=$(mktemp /tmp/po0-v3-service.XXXXXX)
  tmp_batch=$(mktemp /tmp/po0-v3-batch.XXXXXX)
  trap 'rm -f "${tmp_conf:-}" "${tmp_state:-}" "${tmp_local:-}" "${tmp_mode:-}" "${tmp_loader:-}" "${tmp_service:-}" "${tmp_batch:-}"; trap - RETURN' RETURN

  generate_config "$tmp_conf"
  save_state_to "$tmp_state"
  save_local_state_to "$tmp_local"
  save_mode_to "$tmp_mode"
  write_loader_to "$tmp_loader"
  write_service_to "$tmp_service"
  generate_live_batch "$tmp_batch" "$tmp_conf"

  info "执行 nftables 事务语法检查"
  nft -c -f "$tmp_batch" || die "语法检查失败，现有规则没有改变"
  ok "语法检查通过"

  show_rules
  if [[ "$MODE" == takeover ]]; then
    warn "安全接管模式：本脚本自己的 input/forward 链 policy drop。"
    warn "SSH TCP 端口 ${SSH_PORTS_CSV} 及上表本机端口会保留；中转端口不会写入 input。"
  else
    warn "NAT 共存模式：本脚本不改变 input/forward，也不能覆盖其他防火墙的 drop。"
  fi
  warn "本次只替换 ${TABLE_NAT_NAME}/${TABLE_FILTER_NAME}/${TABLE_MANGLE_NAME}；不会 flush ruleset。"
  read -rp "保持当前 SSH 会话，并输入 APPLY 确认：" confirm
  [[ ${confirm:-} == APPLY ]] || { info "已取消，未修改配置"; return; }

  backup=$(make_backup)
  info "备份已创建：${backup}"

  install -d -m 700 "$STATE_DIR"
  install -m 600 "$tmp_conf" "$OWN_CONF"
  install -m 600 "$tmp_state" "$STATE_FILE"
  install -m 600 "$tmp_local" "$LOCAL_STATE_FILE"
  install -m 600 "$tmp_mode" "$MODE_FILE"
  install -m 755 "$tmp_loader" "$LOADER_FILE"
  install -m 644 "$tmp_service" "$SERVICE_FILE"
  printf 'net.ipv4.ip_forward=1\n' >"$SYSCTL_CONF"
  chmod 644 "$SYSCTL_CONF"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null

  if ((LEGACY_V2_ACTIVE)); then
    systemctl disable --now nftables.service >/dev/null 2>&1 || \
      warn "无法完整停用旧 nftables.service；请在应用后检查服务状态"
    remove_legacy_v2_tables || {
      warn "无法删除 v2 的通用 filter/nat 表，正在回滚"
      restore_v3_backup "$backup" || true
      die "v2 迁移失败"
    }
    if ((UFW_WAS_ACTIVE)); then
      ufw --force reload >/dev/null || {
        restore_v3_backup "$backup" || true
        die "v2 迁移后无法恢复 UFW，已尝试回滚"
      }
    fi
    if ((FIREWALLD_WAS_ACTIVE)); then
      firewall-cmd --reload >/dev/null || {
        restore_v3_backup "$backup" || true
        die "v2 迁移后无法恢复 firewalld，已尝试回滚"
      }
    fi
  fi

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME" >/dev/null

  watchdog_base="po0-relay-auto-rollback-$(date +%s)-$$"
  watchdog_script="/run/${watchdog_base}.sh"
  if start_watchdog "$backup" "$watchdog_base" "$watchdog_script"; then
    info "已启动 120 秒自动回滚保护"
  else
    watchdog_base=""
    watchdog_script=""
    warn "无法启动 systemd 自动回滚定时器；若应用失败将立即恢复，但请保持当前 SSH 会话"
  fi

  if ! systemctl restart "$SERVICE_NAME"; then
    [[ -n "$watchdog_base" ]] && cancel_watchdog "$watchdog_base" "$watchdog_script"
    warn "v3 服务加载失败，正在恢复应用前状态"
    restore_v3_backup "$backup" || warn "自动恢复不完整，请使用：$0 --rollback"
    die "应用失败；备份位于 ${backup}"
  fi

  ok "v3 规则已经加载"
  if read -r -t 105 -p "请立即测试新的 SSH/转发连接；确认正常后输入 KEEP 保留，否则将回滚：" keep_reply && \
     [[ ${keep_reply:-} == KEEP ]]; then
    [[ -n "$watchdog_base" ]] && cancel_watchdog "$watchdog_base" "$watchdog_script"
    ok "已确认保留，新配置设置为开机加载"
  else
    [[ -n "$watchdog_base" ]] && cancel_watchdog "$watchdog_base" "$watchdog_script"
    warn "未收到 KEEP，正在恢复应用前状态"
    restore_v3_backup "$backup" || die "回滚失败，请从控制台运行：$0 --rollback"
    die "已回滚；未保留本次修改"
  fi

  STATE_NEEDS_MIGRATION=0
  show_coexist_guidance
}

owned_rules_report() {
  echo "当前 v3 自有规则与计数器："
  if table_exists "$TABLE_NAT_FAMILY" "$TABLE_NAT_NAME"; then
    nft list table "$TABLE_NAT_FAMILY" "$TABLE_NAT_NAME"
  else
    echo "  （${TABLE_NAT_NAME} 未加载）"
  fi
  if table_exists "$TABLE_FILTER_FAMILY" "$TABLE_FILTER_NAME"; then
    nft list table "$TABLE_FILTER_FAMILY" "$TABLE_FILTER_NAME"
  else
    echo "  （${TABLE_FILTER_NAME} 未加载；共存模式下这是正常现象）"
  fi
  if table_exists "$TABLE_MANGLE_FAMILY" "$TABLE_MANGLE_NAME"; then
    nft list table "$TABLE_MANGLE_FAMILY" "$TABLE_MANGLE_NAME"
  else
    echo "  （${TABLE_MANGLE_NAME} 未加载；未设置 MSS 时这是正常现象）"
  fi
}

status_report() {
  detect_default_network
  detect_ssh_ports
  load_state
  echo "PO0 relay manager v${VERSION}"
  echo "模式：$(mode_label) (${MODE:-unset})"
  echo "默认入口网卡：${DEFAULT_WAN_IF}"
  echo "默认路由源地址：${DEFAULT_SOURCE_IP}（仅供显示；SNAT 按每条目的地单独检测）"
  echo "SSH 端口：${SSH_PORTS_CSV}"
  echo "IPv4 forwarding：$(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo unknown)"
  echo "po0-relay.service：$(systemctl is-active "$SERVICE_NAME" 2>/dev/null || true) / $(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || true)"
  if is_legacy_v2_config; then
    warn "仍检测到 v2 的 /etc/nftables.conf；只要旧 nftables.service 已停用，它不会与 v3 同时加载。"
  fi
  ((STATE_NEEDS_MIGRATION)) && warn "当前状态仍为 v2/未保存模式格式；下次应用时会迁移为 v3。"
  show_rules
  owned_rules_report
  show_coexist_guidance
}

legacy_rollback() {
  local backup=$1
  [[ -f "$backup/nftables.conf" ]] || die "旧备份不包含 nftables.conf"
  nft -c -f "$backup/nftables.conf" || die "旧备份配置语法检查失败"
  install -m 644 "$backup/nftables.conf" "$LEGACY_NFT_CONF"
  [[ -f "$backup/rules.db" ]] && install -D -m 600 "$backup/rules.db" "$STATE_FILE"
  [[ -f "$backup/local-ports.db" ]] && install -D -m 600 "$backup/local-ports.db" "$LOCAL_STATE_FILE"
  [[ -f "$backup/99-po0-relay.conf" ]] && install -m 644 "$backup/99-po0-relay.conf" "$SYSCTL_CONF"
  systemctl disable --now "$SERVICE_NAME" >/dev/null 2>&1 || true
  nft -f "$backup/nftables.conf"
  systemctl enable nftables.service >/dev/null 2>&1 || true
  systemctl restart nftables.service >/dev/null 2>&1 || true
}

rollback_menu() {
  local backups=() item selection backup confirm
  [[ -d "$BACKUP_DIR" ]] || die "没有找到备份目录"
  while IFS= read -r item; do backups+=("$item"); done < <(
    find "$BACKUP_DIR" -mindepth 1 -maxdepth 1 -type d -printf '%f\n' | sort -r
  )
  ((${#backups[@]} > 0)) || die "没有可用备份"

  echo "可用备份："
  local i kind
  for ((i=0; i<${#backups[@]}; i++)); do
    kind="legacy"
    [[ -f "$BACKUP_DIR/${backups[i]}/backup-format" ]] && kind="v3"
    printf '  %d) %s [%s]\n' "$((i+1))" "${backups[i]}" "$kind"
  done
  read -rp "选择序号（0 取消）：" selection
  [[ $selection =~ ^[0-9]+$ ]] || die "无效序号"
  ((selection != 0)) || return
  ((selection >= 1 && selection <= ${#backups[@]})) || die "序号超出范围"
  backup="${BACKUP_DIR}/${backups[selection-1]}"

  read -rp "输入 ROLLBACK 确认恢复 ${backups[selection-1]}：" confirm
  [[ ${confirm:-} == ROLLBACK ]] || { info "已取消"; return; }

  if [[ -f "$backup/backup-format" ]]; then
    restore_v3_backup "$backup" || die "恢复失败；请通过服务器控制台检查 ${backup}"
  else
    legacy_rollback "$backup"
  fi
  ok "已恢复：${backups[selection-1]}"
}

interactive_menu() {
  detect_default_network
  detect_ssh_ports
  load_state
  ensure_mode_selected

  while true; do
    echo
    echo "=========================================================================="
    echo " PO0 nftables 中转管理器 v${VERSION}"
    echo " 模式=$(mode_label)  默认网卡=${DEFAULT_WAN_IF}  默认源=${DEFAULT_SOURCE_IP}  SSH=${SSH_PORTS_CSV}"
    echo "=========================================================================="
    echo "  1) 查看规则、逐线路路由和本机端口"
    echo "  2) 添加转发规则"
    echo "  3) 删除转发规则"
    echo "  4) 清空转发规则"
    echo "  5) 应用并保存"
    echo "  6) 查看运行状态和计数器"
    echo "  7) 从备份回滚"
    echo "  8) 添加本机服务端口"
    echo "  9) 删除本机服务端口"
    echo " 10) 查看本机当前监听端口"
    echo " 11) 切换安全接管/NAT共存模式"
    echo "  0) 不应用并退出"
    read -rp "请选择：" choice
    case "${choice:-}" in
      1) show_rules ;;
      2) add_rule ;;
      3) delete_rule ;;
      4) clear_rules ;;
      5) apply_configuration; load_state ;;
      6) status_report ;;
      7) rollback_menu; load_state ;;
      8) add_local_port ;;
      9) delete_local_port ;;
      10) show_listening_ports ;;
      11) choose_mode ;;
      0) exit 0 ;;
      *) warn "无效选择" ;;
    esac
  done
}

main() {
  case "${1:-}" in
    -h|--help) usage; exit 0 ;;
  esac

  require_root
  if [[ ${1:-} == --install-deps ]]; then
    install_dependencies
    exit 0
  fi

  ensure_dependencies
  acquire_lock

  case "${1:-}" in
    "") interactive_menu ;;
    --status) status_report ;;
    --rollback) rollback_menu ;;
    *) usage; die "未知参数：$1" ;;
  esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
  main "$@"
fi
