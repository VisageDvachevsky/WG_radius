#include "wg_radius/wireguard/netlink_wireguard_client.hpp"

#include <arpa/inet.h>
#include <linux/time_types.h>
#include <linux/wireguard.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include <netlink/attr.h>
#include <netlink/genl/ctrl.h>
#include <netlink/genl/genl.h>
#include <netlink/msg.h>
#include <netlink/netlink.h>
#include <netlink/socket.h>

namespace wg_radius::wireguard {

namespace {

constexpr std::string_view kBase64Alphabet =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

using DeviceAttrTable = std::array<nlattr*, WGDEVICE_A_MAX + 1>;
using PeerAttrTable = std::array<nlattr*, WGPEER_A_MAX + 1>;
using AllowedIpAttrTable = std::array<nlattr*, WGALLOWEDIP_A_MAX + 1>;

std::string encode_base64(const std::uint8_t* data, std::size_t size) {
    std::string encoded;
    encoded.reserve(((size + 2) / 3) * 4);

    for (std::size_t offset = 0; offset < size; offset += 3) {
        const std::uint32_t octet_a = data[offset];
        const std::uint32_t octet_b = offset + 1 < size ? data[offset + 1] : 0;
        const std::uint32_t octet_c = offset + 2 < size ? data[offset + 2] : 0;
        const std::uint32_t chunk = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded.push_back(kBase64Alphabet[(chunk >> 18) & 0x3f]);
        encoded.push_back(kBase64Alphabet[(chunk >> 12) & 0x3f]);
        encoded.push_back(offset + 1 < size ? kBase64Alphabet[(chunk >> 6) & 0x3f] : '=');
        encoded.push_back(offset + 2 < size ? kBase64Alphabet[chunk & 0x3f] : '=');
    }

    return encoded;
}

std::optional<std::string> parse_endpoint(const nlattr* endpoint_attr) {
    if (endpoint_attr == nullptr) {
        return std::nullopt;
    }

    const auto* sockaddr = static_cast<const struct sockaddr*>(nla_data(endpoint_attr));
    const socklen_t sockaddr_len = nla_len(endpoint_attr);
    char host[NI_MAXHOST] = {};
    char service[NI_MAXSERV] = {};
    if (getnameinfo(
            sockaddr,
            sockaddr_len,
            host,
            sizeof(host),
            service,
            sizeof(service),
            NI_NUMERICHOST | NI_NUMERICSERV) != 0) {
        return std::nullopt;
    }

    if (sockaddr->sa_family == AF_INET6) {
        return std::string{"["} + host + "]:" + service;
    }

    return std::string{host} + ":" + service;
}

std::optional<std::string> parse_allowed_ip(const nlattr* allowed_ip_attr) {
    static nla_policy allowed_ip_policy[WGALLOWEDIP_A_MAX + 1] = {};
    AllowedIpAttrTable attrs{};

    if (nla_parse_nested(
            attrs.data(),
            WGALLOWEDIP_A_MAX,
            const_cast<nlattr*>(allowed_ip_attr),
            allowed_ip_policy) < 0) {
        return std::nullopt;
    }

    if (attrs[WGALLOWEDIP_A_FAMILY] == nullptr || attrs[WGALLOWEDIP_A_IPADDR] == nullptr ||
        attrs[WGALLOWEDIP_A_CIDR_MASK] == nullptr) {
        return std::nullopt;
    }

    const auto family = static_cast<int>(nla_get_u16(attrs[WGALLOWEDIP_A_FAMILY]));
    const auto cidr = static_cast<unsigned>(nla_get_u8(attrs[WGALLOWEDIP_A_CIDR_MASK]));
    char address[INET6_ADDRSTRLEN] = {};

    if (family == AF_INET) {
        if (nla_len(attrs[WGALLOWEDIP_A_IPADDR]) < static_cast<int>(sizeof(in_addr))) {
            return std::nullopt;
        }
        if (inet_ntop(family, nla_data(attrs[WGALLOWEDIP_A_IPADDR]), address, sizeof(address)) ==
            nullptr) {
            return std::nullopt;
        }
    } else if (family == AF_INET6) {
        if (nla_len(attrs[WGALLOWEDIP_A_IPADDR]) < static_cast<int>(sizeof(in6_addr))) {
            return std::nullopt;
        }
        if (inet_ntop(family, nla_data(attrs[WGALLOWEDIP_A_IPADDR]), address, sizeof(address)) ==
            nullptr) {
            return std::nullopt;
        }
    } else {
        return std::nullopt;
    }

    std::ostringstream stream;
    stream << address << '/' << cidr;
    return stream.str();
}

std::optional<std::uint64_t> parse_handshake_epoch_sec(const nlattr* handshake_attr) {
    if (handshake_attr == nullptr ||
        nla_len(handshake_attr) < static_cast<int>(sizeof(__kernel_timespec))) {
        return std::nullopt;
    }

    const auto* timespec = static_cast<const __kernel_timespec*>(nla_data(handshake_attr));
    return static_cast<std::uint64_t>(timespec->tv_sec);
}

struct ParseContext {
    InterfaceSnapshot snapshot;
};

int handle_device_message(nl_msg* message, void* arg) {
    static nla_policy device_policy[WGDEVICE_A_MAX + 1] = {};
    static nla_policy peer_policy[WGPEER_A_MAX + 1] = {};

    auto* context = static_cast<ParseContext*>(arg);
    auto* header = static_cast<genlmsghdr*>(nlmsg_data(nlmsg_hdr(message)));
    DeviceAttrTable device_attrs{};
    if (nla_parse(
            device_attrs.data(),
            WGDEVICE_A_MAX,
            genlmsg_attrdata(header, 0),
            genlmsg_attrlen(header, 0),
            device_policy) < 0) {
        return NL_SKIP;
    }

    if (device_attrs[WGDEVICE_A_IFNAME] != nullptr) {
        context->snapshot.interface_name = nla_get_string(device_attrs[WGDEVICE_A_IFNAME]);
    }

    if (device_attrs[WGDEVICE_A_PEERS] == nullptr) {
        return NL_OK;
    }

    nlattr* peer_entry = nullptr;
    int peer_remaining = 0;
    nla_for_each_nested(peer_entry, device_attrs[WGDEVICE_A_PEERS], peer_remaining) {
        PeerAttrTable peer_attrs{};
        if (nla_parse_nested(peer_attrs.data(), WGPEER_A_MAX, peer_entry, peer_policy) < 0) {
            continue;
        }

        if (peer_attrs[WGPEER_A_PUBLIC_KEY] == nullptr ||
            nla_len(peer_attrs[WGPEER_A_PUBLIC_KEY]) != WG_KEY_LEN) {
            continue;
        }

        const auto public_key = encode_base64(
            static_cast<const std::uint8_t*>(nla_data(peer_attrs[WGPEER_A_PUBLIC_KEY])),
            WG_KEY_LEN);

        auto& peer = context->snapshot.peers[public_key];
        peer.public_key = public_key;

        if (const auto endpoint = parse_endpoint(peer_attrs[WGPEER_A_ENDPOINT]); endpoint.has_value()) {
            peer.endpoint = std::move(*endpoint);
        }
        if (const auto handshake = parse_handshake_epoch_sec(peer_attrs[WGPEER_A_LAST_HANDSHAKE_TIME]);
            handshake.has_value()) {
            peer.latest_handshake_epoch_sec = *handshake;
        }
        if (peer_attrs[WGPEER_A_RX_BYTES] != nullptr) {
            peer.transfer_rx_bytes = nla_get_u64(peer_attrs[WGPEER_A_RX_BYTES]);
        }
        if (peer_attrs[WGPEER_A_TX_BYTES] != nullptr) {
            peer.transfer_tx_bytes = nla_get_u64(peer_attrs[WGPEER_A_TX_BYTES]);
        }

        if (peer_attrs[WGPEER_A_ALLOWEDIPS] != nullptr) {
            nlattr* allowed_ip_entry = nullptr;
            int allowed_ip_remaining = 0;
            nla_for_each_nested(
                allowed_ip_entry, peer_attrs[WGPEER_A_ALLOWEDIPS], allowed_ip_remaining) {
                const auto allowed_ip = parse_allowed_ip(allowed_ip_entry);
                if (!allowed_ip.has_value()) {
                    continue;
                }
                peer.allowed_ips.push_back(*allowed_ip);
            }
        }
    }

    return NL_OK;
}

}  // namespace

NetlinkWireGuardClient::NetlinkWireGuardClient() {
    socket_.reset(nl_socket_alloc());
    if (!socket_) {
        return;
    }

    if (genl_connect(socket_.get()) < 0) {
        socket_.reset();
        return;
    }

    family_id_ = genl_ctrl_resolve(socket_.get(), WG_GENL_NAME);
    if (family_id_ < 0) {
        socket_.reset();
    }
}

NetlinkWireGuardClient::~NetlinkWireGuardClient() = default;

NetlinkWireGuardClient::NetlinkWireGuardClient(NetlinkWireGuardClient&&) noexcept = default;

NetlinkWireGuardClient& NetlinkWireGuardClient::operator=(NetlinkWireGuardClient&&) noexcept = default;

std::optional<InterfaceSnapshot> NetlinkWireGuardClient::fetch_interface_snapshot(
    const std::string& interface_name) {
    if (!socket_ || family_id_ < 0 || interface_name.empty() || interface_name.size() >= IFNAMSIZ) {
        return std::nullopt;
    }

    ParseContext context{.snapshot = InterfaceSnapshot{.interface_name = interface_name, .peers = {}}};
    nl_socket_modify_cb(socket_.get(), NL_CB_VALID, NL_CB_CUSTOM, handle_device_message, &context);

    std::unique_ptr<nl_msg, decltype(&nlmsg_free)> message{nlmsg_alloc(), &nlmsg_free};
    if (!message) {
        return std::nullopt;
    }

    if (genlmsg_put(
            message.get(),
            NL_AUTO_PORT,
            NL_AUTO_SEQ,
            family_id_,
            0,
            NLM_F_REQUEST | NLM_F_DUMP,
            WG_CMD_GET_DEVICE,
            WG_GENL_VERSION) == nullptr) {
        return std::nullopt;
    }

    if (nla_put_string(message.get(), WGDEVICE_A_IFNAME, interface_name.c_str()) < 0) {
        return std::nullopt;
    }

    if (nl_send_auto(socket_.get(), message.get()) < 0) {
        return std::nullopt;
    }

    if (nl_recvmsgs_default(socket_.get()) < 0) {
        return std::nullopt;
    }

    return context.snapshot;
}

void NetlinkWireGuardClient::Deleter::operator()(nl_sock* socket) const noexcept {
    if (socket != nullptr) {
        nl_socket_free(socket);
    }
}

}  // namespace wg_radius::wireguard
