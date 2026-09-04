#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=../nft_po0.sh
source "${PROJECT_DIR}/nft_po0.sh"

show_rules() { :; }
is_valid_ifname() { return 0; }
ssh_port_conflicts() { return 1; }
relay_rule_conflicts() { return 1; }
local_port_conflicts() { return 1; }
local_port_is_listening() { return 1; }
detect_destination_route() {
  ROUTE_IF="eth1"
  ROUTE_SRC="192.0.2.10"
  ROUTE_LINE="${1} dev eth1 src 192.0.2.10"
}

RULE_NAMES=("existing-relay")
RULE_PROTOCOLS=("tcp")
IN_IFS=("eth0")
RELAY_PORTS=("8443")
DEST_IPS=("198.51.100.20")
DEST_PORTS=("443")
SOURCE_CIDRS=("*")
MSS_VALUES=("off")
OUT_IFS=("eth1")
SNAT_IPS=("192.0.2.10")
ROUTE_LINES=("old mock route")
LOCAL_NAMES=()
LOCAL_PROTOCOLS=()
LOCAL_PORTS=()
SSH_PORTS_CSV="22"

# Select rule 1, keep the first seven editable fields, change only MSS, then save.
edit_rule < <(printf '%s\n' 1 '' '' '' '' '' '' '' auto SAVE)

[[ ${RULE_NAMES[0]} == "existing-relay" ]]
[[ ${RULE_PROTOCOLS[0]} == "tcp" ]]
[[ ${IN_IFS[0]} == "eth0" ]]
[[ ${RELAY_PORTS[0]} == "8443" ]]
[[ ${DEST_IPS[0]} == "198.51.100.20" ]]
[[ ${DEST_PORTS[0]} == "443" ]]
[[ ${SOURCE_CIDRS[0]} == "*" ]]
[[ ${MSS_VALUES[0]} == "auto" ]]

# The edited value must reach the generated nftables rule.
GENERATED_CONFIG=$(mktemp)
trap 'rm -f "$GENERATED_CONFIG"' EXIT
MODE="coexist"
generate_config "$GENERATED_CONFIG"
grep -Fq 'tcp option maxseg size set rt mtu counter' "$GENERATED_CONFIG"

# A cancelled edit must not alter the pending rule.
edit_rule < <(printf '%s\n' 1 '' '' '' '' '' '' '' 1380 CANCEL)
[[ ${MSS_VALUES[0]} == "auto" ]]

printf 'test_edit_rule: PASS\n'
