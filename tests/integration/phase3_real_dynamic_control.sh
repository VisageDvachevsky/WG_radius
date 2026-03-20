#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "usage: $0 <wg_radiusd-bin> <source-dir>" >&2
    exit 2
fi

WG_RADIUSD_BIN=$1
SOURCE_DIR=$2

if [[ -z "${WG_RADIUS_IT_SUDO_PASSWORD:-}" ]]; then
    echo "WG_RADIUS_IT_SUDO_PASSWORD is not set; skipping integration test" >&2
    exit 77
fi

for required in ip wg docker mktemp stdbuf grep timeout ping awk bash python3; do
    if ! command -v "$required" >/dev/null 2>&1; then
        echo "missing required command: $required" >&2
        exit 77
    fi
done

sudo_pw() {
    printf '%s\n' "$WG_RADIUS_IT_SUDO_PASSWORD" | sudo -S "$@"
}

dump_diagnostics() {
    set +e
    echo "==== radius log file ====" >&2
    [[ -f "$radius_log" ]] && cat "$radius_log" >&2 || true
    echo "==== wg_radiusd log ====" >&2
    [[ -f "$daemon_log" ]] && cat "$daemon_log" >&2 || true
    echo "==== freeradius docker logs ====" >&2
    docker logs "$radius_container" 2>&1 >&2 || true
    echo "==== server wg show ====" >&2
    sudo_pw wg show "$iface_name" >&2 || true
    echo "==== client wg show ====" >&2
    sudo_pw ip netns exec "$client_ns" wg show "$client_iface" >&2 || true
}

wait_for_condition() {
    local command=$1
    local attempts=${2:-120}
    local delay=${3:-0.1}

    for _ in $(seq 1 "$attempts"); do
        if eval "$command"; then
            return 0
        fi
        sleep "$delay"
    done

    echo "condition failed: $command" >&2
    dump_diagnostics
    return 1
}

wait_for_count() {
    local pattern=$1
    local file=$2
    local expected=$3
    local attempts=${4:-120}
    local delay=${5:-0.1}

    wait_for_condition "[[ -f '$file' ]] && [[ \$(grep -c -- \"$pattern\" '$file') -ge $expected ]]" "$attempts" "$delay"
}

send_radius_packet() {
    local request_type=$1
    local secret=$2
    local peer_public_key=$3
    shift 3

    python3 - "$request_type" "127.0.0.1" "$coa_port" "$secret" "$peer_public_key" "$@" <<'PY'
import hashlib
import hmac
import socket
import struct
import sys

request_type = sys.argv[1]
host = sys.argv[2]
port = int(sys.argv[3])
secret = sys.argv[4].encode()
peer_public_key = sys.argv[5]
attrs = sys.argv[6:]

def attr_string(attr_type, value):
    data = value.encode()
    return bytes([attr_type, len(data) + 2]) + data

def attr_uint32(attr_type, value):
    return bytes([attr_type, 6]) + struct.pack("!I", value)

def attr_vendor_uint32(vendor_id, vendor_type, value):
    return bytes([26, 12]) + struct.pack("!IBBI", vendor_id, vendor_type, 6, value)

code = 40 if request_type == "disconnect" else 43
identifier = 9 if request_type == "disconnect" else 10
packet = bytearray(20)
packet[0] = code
packet[1] = identifier
packet.extend(attr_string(1, peer_public_key))

if request_type == "coa":
    for item in attrs:
        key, value = item.split("=", 1)
        parsed = int(value)
        if key == "session_timeout":
            packet.extend(attr_uint32(27, parsed))
        elif key == "ingress_bps":
            packet.extend(attr_vendor_uint32(10055, 2, parsed))
        elif key == "egress_bps":
            packet.extend(attr_vendor_uint32(10055, 1, parsed))
        else:
            raise SystemExit(f"unsupported attr: {key}")

packet[2:4] = struct.pack("!H", len(packet) + 18)
message_auth_offset = len(packet)
packet.extend(bytes([80, 18]))
packet.extend(b"\x00" * 16)

request_auth = hashlib.md5(bytes(packet) + secret).digest()
packet[4:20] = request_auth

hmac_input = bytearray(packet)
hmac_input[message_auth_offset + 2:message_auth_offset + 18] = b"\x00" * 16
message_auth = hmac.new(secret, bytes(hmac_input), hashlib.md5).digest()
packet[message_auth_offset + 2:message_auth_offset + 18] = message_auth

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(packet, (host, port))
sock.close()
PY
}

if ! sudo_pw true >/dev/null 2>&1; then
    echo "sudo authentication failed; skipping integration test" >&2
    exit 77
fi

tmp_dir=$(mktemp -d)
iface_name="wg-phase3-$RANDOM"
client_ns="wg-radius-phase3-$RANDOM"
client_iface="wg-client0"
host_veth="veth-host-$RANDOM"
client_veth="veth-ns-$RANDOM"
radius_container="wg-radius-fr-phase3-$RANDOM"
radius_image="freeradius/freeradius-server:latest"
radius_auth_port=18180
radius_acct_port=18190
coa_port=37991
radius_secret="integration-secret"
radius_log="$tmp_dir/log/phase3.log"
daemon_log="$tmp_dir/wg_radiusd.log"
daemon_pid_file="$tmp_dir/wg_radiusd.pid"
server_transport_ip="192.0.2.1/24"
client_transport_ip="192.0.2.2/24"
server_wg_ip="10.50.0.1/24"
client_wg_ip="10.50.0.2/32"
daemon_pid=""

stop_daemon() {
    set +e
    if [[ -f "$daemon_pid_file" ]]; then
        local daemon_root_pid
        daemon_root_pid=$(cat "$daemon_pid_file")
        if [[ -n "$daemon_root_pid" ]]; then
            sudo_pw kill "$daemon_root_pid" >/dev/null 2>&1 || true
            for _ in $(seq 1 50); do
                if ! sudo_pw kill -0 "$daemon_root_pid" >/dev/null 2>&1; then
                    break
                fi
                sleep 0.1
            done
        fi
        : >"$daemon_pid_file"
    fi
    if [[ -n "$daemon_pid" ]]; then
        kill "$daemon_pid" >/dev/null 2>&1 || true
        wait "$daemon_pid" >/dev/null 2>&1 || true
        daemon_pid=""
    fi
}

start_daemon() {
    sudo_pw bash -lc "echo \$\$ > '$daemon_pid_file'; exec stdbuf -oL -eL '$WG_RADIUSD_BIN' '$tmp_dir/wg_radiusd.conf' > '$daemon_log' 2>&1" &
    daemon_pid=$!
    wait_for_condition "[[ -s '$daemon_pid_file' ]]" 40 0.1
    sleep 0.4
}

cleanup() {
    set +e
    stop_daemon
    docker rm -f "$radius_container" >/dev/null 2>&1 || true
    sudo_pw ip netns del "$client_ns" >/dev/null 2>&1 || true
    sudo_pw ip link del "$host_veth" >/dev/null 2>&1 || true
    sudo_pw ip link del "$iface_name" >/dev/null 2>&1 || true
    rm -rf "$tmp_dir"
}
trap cleanup EXIT

mkdir -p "$tmp_dir/log"

accept_private_key=$(wg genkey)
accept_public_key=$(printf '%s' "$accept_private_key" | wg pubkey)
server_private_key=$(wg genkey)
server_public_key=$(printf '%s' "$server_private_key" | wg pubkey)
server_key_file="$tmp_dir/server.key"
client_key_file="$tmp_dir/client.key"
printf '%s\n' "$server_private_key" >"$server_key_file"
printf '%s\n' "$accept_private_key" >"$client_key_file"
chmod 600 "$server_key_file" "$client_key_file"

docker run --rm --entrypoint /bin/sh "$radius_image" -lc 'tar -C /etc -cf - freeradius' | tar -C "$tmp_dir" -xf -

rm -f "$tmp_dir/freeradius/mods-enabled"/*
ln -s ../mods-available/always "$tmp_dir/freeradius/mods-enabled/always"
ln -s ../mods-available/files "$tmp_dir/freeradius/mods-enabled/files"

rm -f "$tmp_dir/freeradius/sites-enabled"/*

cat >"$tmp_dir/freeradius/clients.conf" <<EOF
client localhost {
    ipaddr = 127.0.0.1
    secret = $radius_secret
}
EOF

cat >>"$tmp_dir/freeradius/dictionary" <<'EOF'
VENDOR Roaring-Penguin 10055
ATTRIBUTE RP-Upstream-Speed-Limit 1 integer Roaring-Penguin
ATTRIBUTE RP-Downstream-Speed-Limit 2 integer Roaring-Penguin
EOF

cat >"$tmp_dir/freeradius/mods-config/files/authorize" <<EOF
$accept_public_key Auth-Type := Accept
    Session-Timeout := 3600,
    RP-Upstream-Speed-Limit := 10000,
    RP-Downstream-Speed-Limit := 20000
EOF

cat >"$tmp_dir/freeradius/mods-enabled/wg_phase3_auth_request" <<EOF
linelog wg_phase3_auth_request {
    filename = /var/log/freeradius/phase3.log
    permissions = 0644
    format = "auth-request user=%{%{User-Name}:-<none>}"
}
EOF

cat >"$tmp_dir/freeradius/mods-enabled/wg_phase3_access_accept" <<EOF
linelog wg_phase3_access_accept {
    filename = /var/log/freeradius/phase3.log
    permissions = 0644
    format = "access-accept user=%{%{User-Name}:-<none>}"
}
EOF

cat >"$tmp_dir/freeradius/mods-enabled/wg_phase3_accounting" <<EOF
linelog wg_phase3_accounting {
    filename = /var/log/freeradius/phase3.log
    permissions = 0644
    format = "accounting user=%{%{User-Name}:-<none>} status=%{%{Acct-Status-Type}:-<none>} term_cause=%{%{Acct-Terminate-Cause}:-<none>} connect_info=%{%{Connect-Info}:-<none>}"
}
EOF

cat >"$tmp_dir/freeradius/sites-enabled/default" <<EOF
server default {
    listen {
        type = auth
        ipaddr = 127.0.0.1
        port = $radius_auth_port
    }

    listen {
        type = acct
        ipaddr = 127.0.0.1
        port = $radius_acct_port
    }

    authorize {
        wg_phase3_auth_request
        files
    }

    authenticate {
        Auth-Type Accept {
            ok
        }
    }

    post-auth {
        wg_phase3_access_accept
    }

    accounting {
        wg_phase3_accounting
        ok
    }
}
EOF

chmod -R a+rX "$tmp_dir/freeradius"
chmod -R a+rwX "$tmp_dir/log"

docker rm -f "$radius_container" >/dev/null 2>&1 || true
docker run -d \
    --name "$radius_container" \
    --network host \
    -v "$tmp_dir/freeradius:/etc/freeradius" \
    -v "$tmp_dir/log:/var/log/freeradius" \
    "$radius_image" \
    freeradius -f -X -d /etc/freeradius >/dev/null

wait_for_condition "docker logs '$radius_container' 2>&1 | grep -q 'Ready to process requests'" 60 0.1

cat >"$tmp_dir/wg_radiusd.conf" <<EOF
[profile wg-it]
interface = $iface_name
auth_host = 127.0.0.1
auth_port = $radius_auth_port
acct_host = 127.0.0.1
acct_port = $radius_acct_port
coa_host = 127.0.0.1
coa_port = $coa_port
secret = $radius_secret
nas_identifier = wg-it
nas_ip_address = 127.0.0.1
authorization_trigger = first-handshake
reject_handling = block-peer
poll_interval_ms = 100
timeout_ms = 1000
retries = 1
acct_interim_interval = 2
inactive_timeout = 30
inactivity_strategy = handshake-and-traffic
EOF

sudo_pw ip netns add "$client_ns"
sudo_pw ip link add "$host_veth" type veth peer name "$client_veth"
sudo_pw ip addr add "$server_transport_ip" dev "$host_veth"
sudo_pw ip link set "$host_veth" up
sudo_pw ip link set "$client_veth" netns "$client_ns"
sudo_pw ip -n "$client_ns" addr add "$client_transport_ip" dev "$client_veth"
sudo_pw ip -n "$client_ns" link set lo up
sudo_pw ip -n "$client_ns" link set "$client_veth" up

sudo_pw ip link add "$iface_name" type wireguard
sudo_pw ip addr add "$server_wg_ip" dev "$iface_name"
sudo_pw wg set "$iface_name" private-key "$server_key_file" listen-port 51821
sudo_pw wg set "$iface_name" peer "$accept_public_key" allowed-ips "$client_wg_ip"
sudo_pw ip link set "$iface_name" up

sudo_pw ip netns exec "$client_ns" ip link add "$client_iface" type wireguard
sudo_pw ip netns exec "$client_ns" ip addr add "$client_wg_ip" dev "$client_iface"
sudo_pw ip netns exec "$client_ns" wg set "$client_iface" private-key "$client_key_file"
sudo_pw ip netns exec "$client_ns" wg set \
    "$client_iface" \
    peer "$server_public_key" \
    endpoint 192.0.2.1:51821 \
    allowed-ips 10.50.0.1/32
sudo_pw ip netns exec "$client_ns" ip link set "$client_iface" up

start_daemon

wait_for_count "auth-request user=$accept_public_key" "$radius_log" 1 120 0.1
wait_for_count "access-accept user=$accept_public_key" "$radius_log" 1 120 0.1
wait_for_count "accounting user=$accept_public_key status=Start" "$radius_log" 1 120 0.1

sudo_pw ip netns exec "$client_ns" ping -c 1 -W 2 10.50.0.1 >/dev/null
wait_for_condition "sudo_pw wg show '$iface_name' latest-handshakes | grep '$accept_public_key' | awk '{print \$2}' | grep -qv '^0$'" 80 0.1

send_radius_packet disconnect "wrong-secret" "$accept_public_key"
sleep 1
wait_for_condition "sudo_pw wg show '$iface_name' peers | grep -q '$accept_public_key'" 20 0.1
if [[ -f "$daemon_log" ]] && grep -q "executed_command type=BlockPeer peer=$accept_public_key" "$daemon_log"; then
    echo "disconnect with invalid secret unexpectedly triggered block path" >&2
    dump_diagnostics
    exit 1
fi

send_radius_packet coa "$radius_secret" "$accept_public_key" ingress_bps=55000
wait_for_count "executed_command type=ApplySessionPolicy peer=$accept_public_key status=Executed" "$daemon_log" 2 120 0.1
wait_for_condition "sudo_pw wg show '$iface_name' peers | grep -q '$accept_public_key'" 20 0.1

send_radius_packet disconnect "$radius_secret" "$accept_public_key"
wait_for_count "executed_command type=BlockPeer peer=$accept_public_key status=Executed" "$daemon_log" 1 120 0.1
wait_for_count "executed_command type=StopAccounting peer=$accept_public_key status=Executed" "$daemon_log" 1 120 0.1
wait_for_count "accounting user=$accept_public_key status=Stop" "$radius_log" 1 120 0.1
wait_for_condition "grep 'accounting user=$accept_public_key status=Stop' '$radius_log' | tail -n 1 | grep 'term_cause=Admin-Reset' | grep 'connect_info=.*wg-stop-reason=disconnect-request' >/dev/null" 120 0.1

for _ in $(seq 1 60); do
    if ! sudo_pw wg show "$iface_name" peers | grep -q "$accept_public_key"; then
        break
    fi
    sleep 0.1
done

if sudo_pw wg show "$iface_name" peers | grep -q "$accept_public_key"; then
    echo "peer still present after Disconnect handling" >&2
    dump_diagnostics
    exit 1
fi

echo "phase3 real dynamic control integration passed"
