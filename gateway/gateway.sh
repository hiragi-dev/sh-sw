#!/bin/sh
# shsw ゲートウェイ: LAN 側インターフェースから来た通信を shsw-proxy の透過入口へ回す。
#
# - TCP 80/443 (グローバル宛て) → REDIRECT で shsw-proxy の透過ポートへ
# - UDP 443 (QUIC / HTTP3) は拒否して TCP に落とさせる (GATEWAY_BLOCK_QUIC=false で無効)
# - LAN → WAN を NAT (masquerade) し、Docker が既定で拒否する転送を DOCKER-USER で許可
# - 透過ポートへの直接接続 (REDIRECT されていないもの) は拒否
#
# ホストの network namespace で動かす (network_mode: host, NET_ADMIN)。
# 停止時 (SIGTERM) にすべてのルールを取り除く。
set -eu

LAN_IFACES="${GATEWAY_LAN_IFACES:?GATEWAY_LAN_IFACES (例: ap0 または eth1,ap0) を指定してください}"
WAN_IFACE="${GATEWAY_WAN_IFACE:-}"
PORT="${GATEWAY_TRANSPARENT_PORT:-8443}"
BLOCK_QUIC="${GATEWAY_BLOCK_QUIC:-true}"
TABLE=shsw_gw

if [ -z "$WAN_IFACE" ]; then
  WAN_IFACE="$(ip -4 route show default | awk '{for (i=1;i<NF;i++) if ($i=="dev") {print $(i+1); exit}}')"
fi
[ -n "$WAN_IFACE" ] || { echo "gateway: WAN interface not found (set GATEWAY_WAN_IFACE)" >&2; exit 1; }

# "eth1,ap0" -> { "eth1", "ap0" }
LAN_SET="{ \"$(echo "$LAN_IFACES" | sed 's/ //g; s/,/", "/g')\" }"
LAN_LIST="$(echo "$LAN_IFACES" | tr ',' ' ')"

log() { echo "gateway: $*"; }

apply_nft() {
  check="${1:-}"
  quic_rule=""
  if [ "$BLOCK_QUIC" = "true" ]; then
    quic_rule="iifname $LAN_SET udp dport 443 counter reject"
  fi
  nft $check -f - <<NFT
table ip $TABLE
delete table ip $TABLE
table ip $TABLE {
  set private_dst {
    type ipv4_addr
    flags interval
    elements = { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16,
                 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
  }
  chain prerouting {
    type nat hook prerouting priority dstnat - 10; policy accept;
    iifname $LAN_SET ip daddr != @private_dst tcp dport { 80, 443 } counter redirect to :$PORT
  }
  chain postrouting {
    type nat hook postrouting priority srcnat; policy accept;
    iifname $LAN_SET oifname "$WAN_IFACE" counter masquerade
  }
  chain forward {
    type filter hook forward priority filter - 10; policy accept;
    $quic_rule
  }
  chain input {
    type filter hook input priority filter - 10; policy accept;
    tcp dport $PORT ct status & dnat == 0 counter drop
  }
}
NFT
}

ipt_rule() { # 冪等に DOCKER-USER へ追加 / 削除
  action="$1"; shift
  if iptables -C DOCKER-USER "$@" 2>/dev/null; then
    [ "$action" = "del" ] && iptables -D DOCKER-USER "$@"
  else
    [ "$action" = "add" ] && iptables -I DOCKER-USER "$@"
  fi
  return 0
}

docker_user_rules() {
  for lan in $LAN_LIST; do
    ipt_rule "$1" -i "$lan" -o "$WAN_IFACE" -j ACCEPT
    ipt_rule "$1" -i "$WAN_IFACE" -o "$lan" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  done
}

cleanup() {
  log "removing rules"
  nft delete table ip "$TABLE" 2>/dev/null || true
  iptables -L DOCKER-USER -n >/dev/null 2>&1 && docker_user_rules del
  exit 0
}
trap cleanup TERM INT

if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
  log "WARNING: net.ipv4.ip_forward is 0; forwarding will not work (Docker normally enables it)"
fi
for lan in $LAN_LIST; do
  ip link show "$lan" >/dev/null 2>&1 || log "WARNING: LAN interface $lan does not exist (yet); rules apply once it appears"
done

# GATEWAY_CHECK=1 なら構文チェックだけして終了
if [ "${GATEWAY_CHECK:-}" = "1" ]; then
  apply_nft -c && log "nft ruleset OK (lan=[$LAN_IFACES] wan=$WAN_IFACE)"
  exit 0
fi

apply_nft
iptables -L DOCKER-USER -n >/dev/null 2>&1 || iptables -N DOCKER-USER
docker_user_rules add
log "applied: lan=[$LAN_IFACES] wan=$WAN_IFACE transparent_port=$PORT block_quic=$BLOCK_QUIC"

# ファイアウォールの再読み込み等でルールが消えていたら張り直す
while :; do
  sleep 30 &
  wait $! || true
  if ! nft list table ip "$TABLE" >/dev/null 2>&1; then
    log "nft table missing; re-applying"
    apply_nft
  fi
  docker_user_rules add
done
