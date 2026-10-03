FROM debian:bookworm-slim
# ホスト (Raspberry Pi OS / Debian) と同じ nft バックエンドの iptables を使う
RUN apt-get update && apt-get install -y --no-install-recommends nftables iptables iproute2 \
 && rm -rf /var/lib/apt/lists/*
COPY gateway.sh /usr/local/bin/gateway.sh
RUN chmod +x /usr/local/bin/gateway.sh
ENTRYPOINT ["/usr/local/bin/gateway.sh"]
