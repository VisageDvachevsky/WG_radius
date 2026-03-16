#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 3 ]]; then
    echo "usage: $0 <wg_native_smoke-bin> <wg_radiusd-bin> <source-dir>" >&2
    exit 2
fi

WG_NATIVE_SMOKE_BIN=$1
WG_RADIUSD_BIN=$2
SOURCE_DIR=$3

if [[ -z "${WG_RADIUS_IT_SUDO_PASSWORD:-}" ]]; then
    echo "WG_RADIUS_IT_SUDO_PASSWORD is not set; skipping integration test" >&2
    exit 77
fi

for required in ip wg mktemp grep; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "missing required command: $required" >&2
        exit 77
    fi
done

sudo_pw() {
    printf '%s\n' "$WG_RADIUS_IT_SUDO_PASSWORD" | sudo -S "$@"
}

if ! sudo_pw true >/dev/null 2>&1; then
    echo "sudo authentication failed; skipping integration test" >&2
    exit 77
fi

ns_name="wg-radius-it-$$"
tmp_dir=$(mktemp -d)
iface_name="wg-it0"

cleanup() {
    set +e
    sudo_pw ip netns del "$ns_name" >/dev/null 2>&1 || true
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

server_private_key=$(wg genkey)
server_public_key=$(printf '%s' "$server_private_key" | wg pubkey)
peer_private_key=$(wg genkey)
peer_public_key=$(printf '%s' "$peer_private_key" | wg pubkey)

server_key_file="$tmp_dir/server.key"
printf '%s\n' "$server_private_key" >"$server_key_file"
chmod 600 "$server_key_file"

cat >"$tmp_dir/wg_radiusd.conf" <<EOF
[profile wg-it]
interface = $iface_name
auth_host = 127.0.0.1
auth_port = 1812
acct_host = 127.0.0.1
acct_port = 1813
secret = integration-secret
nas_identifier = wg-it
authorization_trigger = peer-appearance
reject_handling = remove-peer
EOF

sudo_pw ip netns add "$ns_name"
sudo_pw ip -n "$ns_name" link add "$iface_name" type wireguard
sudo_pw ip -n "$ns_name" addr add 10.20.0.1/24 dev "$iface_name"
sudo_pw ip netns exec "$ns_name" wg set "$iface_name" private-key "$server_key_file" listen-port 51820
sudo_pw ip netns exec "$ns_name" wg set "$iface_name" peer "$peer_public_key" allowed-ips 10.20.0.2/32
sudo_pw ip -n "$ns_name" link set "$iface_name" up

snapshot_output=$(sudo_pw ip netns exec "$ns_name" "$WG_NATIVE_SMOKE_BIN" snapshot "$iface_name")
echo "$snapshot_output"

grep -q "interface: $iface_name" <<<"$snapshot_output"
grep -q "peers: 1" <<<"$snapshot_output"
grep -q -- "- peer: $peer_public_key" <<<"$snapshot_output"
grep -q "allowed_ips: 10.20.0.2/32" <<<"$snapshot_output"

daemon_output=$(sudo_pw ip netns exec "$ns_name" "$WG_RADIUSD_BIN" "$tmp_dir/wg_radiusd.conf" --once)
echo "$daemon_output"

grep -q "profile wg-it interface=$iface_name" <<<"$daemon_output"
grep -q "auth_submitted=0" <<<"$daemon_output"

remove_output=$(sudo_pw ip netns exec "$ns_name" "$WG_NATIVE_SMOKE_BIN" exec-remove-peer "$iface_name" "$peer_public_key")
echo "$remove_output"

grep -q "peer removed via executor" <<<"$remove_output"

remaining_peers=$(sudo_pw ip netns exec "$ns_name" wg show "$iface_name" peers)
if [[ -n "$remaining_peers" ]]; then
    echo "expected peer list to be empty after removal, got: $remaining_peers" >&2
    exit 1
fi

echo "phase1 real WireGuard integration smoke passed"
