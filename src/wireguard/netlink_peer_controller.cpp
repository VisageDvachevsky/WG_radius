#include "wg_radius/wireguard/netlink_peer_controller.hpp"

#include <linux/wireguard.h>
#include <net/if.h>

#include <array>
#include <cstdint>
#include <memory>
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

int decode_base64_char(char character) {
    const auto position = kBase64Alphabet.find(character);
    if (position == std::string_view::npos) {
        return -1;
    }

    return static_cast<int>(position);
}

bool decode_base64_key(const std::string& encoded, std::array<std::uint8_t, WG_KEY_LEN>& decoded) {
    if (encoded.size() != 44 || encoded[43] != '=') {
        return false;
    }

    std::size_t out_index = 0;
    for (std::size_t index = 0; index < encoded.size(); index += 4) {
        const int a = decode_base64_char(encoded[index]);
        const int b = decode_base64_char(encoded[index + 1]);
        const int c = encoded[index + 2] == '=' ? 0 : decode_base64_char(encoded[index + 2]);
        const int d = encoded[index + 3] == '=' ? 0 : decode_base64_char(encoded[index + 3]);
        if (a < 0 || b < 0 || (encoded[index + 2] != '=' && c < 0) ||
            (encoded[index + 3] != '=' && d < 0)) {
            return false;
        }

        const std::uint32_t chunk =
            (static_cast<std::uint32_t>(a) << 18) |
            (static_cast<std::uint32_t>(b) << 12) |
            (static_cast<std::uint32_t>(c) << 6) |
            static_cast<std::uint32_t>(d);

        if (out_index < decoded.size()) {
            decoded[out_index++] = static_cast<std::uint8_t>((chunk >> 16) & 0xff);
        }
        if (encoded[index + 2] != '=' && out_index < decoded.size()) {
            decoded[out_index++] = static_cast<std::uint8_t>((chunk >> 8) & 0xff);
        }
        if (encoded[index + 3] != '=' && out_index < decoded.size()) {
            decoded[out_index++] = static_cast<std::uint8_t>(chunk & 0xff);
        }
    }

    return out_index == decoded.size();
}

}  // namespace

NetlinkPeerController::NetlinkPeerController() {
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

NetlinkPeerController::~NetlinkPeerController() = default;

NetlinkPeerController::NetlinkPeerController(NetlinkPeerController&&) noexcept = default;

NetlinkPeerController& NetlinkPeerController::operator=(NetlinkPeerController&&) noexcept = default;

bool NetlinkPeerController::remove_peer(
    const std::string& interface_name,
    const std::string& peer_public_key) {
    if (!socket_ || family_id_ < 0 || interface_name.empty() || interface_name.size() >= IFNAMSIZ) {
        return false;
    }

    std::array<std::uint8_t, WG_KEY_LEN> decoded_key{};
    if (!decode_base64_key(peer_public_key, decoded_key)) {
        return false;
    }

    std::unique_ptr<nl_msg, decltype(&nlmsg_free)> message{nlmsg_alloc(), &nlmsg_free};
    if (!message) {
        return false;
    }

    if (genlmsg_put(
            message.get(),
            NL_AUTO_PORT,
            NL_AUTO_SEQ,
            family_id_,
            0,
            NLM_F_REQUEST,
            WG_CMD_SET_DEVICE,
            WG_GENL_VERSION) == nullptr) {
        return false;
    }

    if (nla_put_string(message.get(), WGDEVICE_A_IFNAME, interface_name.c_str()) < 0) {
        return false;
    }

    auto* peers = nla_nest_start(message.get(), WGDEVICE_A_PEERS);
    if (peers == nullptr) {
        return false;
    }

    auto* peer = nla_nest_start(message.get(), 1);
    if (peer == nullptr) {
        return false;
    }

    if (nla_put(message.get(), WGPEER_A_PUBLIC_KEY, WG_KEY_LEN, decoded_key.data()) < 0 ||
        nla_put_u32(message.get(), WGPEER_A_FLAGS, WGPEER_F_REMOVE_ME) < 0) {
        return false;
    }

    nla_nest_end(message.get(), peer);
    nla_nest_end(message.get(), peers);

    if (nl_send_auto(socket_.get(), message.get()) < 0) {
        return false;
    }

    return nl_wait_for_ack(socket_.get()) >= 0;
}

void NetlinkPeerController::Deleter::operator()(nl_sock* socket) const noexcept {
    if (socket != nullptr) {
        nl_socket_free(socket);
    }
}

}  // namespace wg_radius::wireguard
