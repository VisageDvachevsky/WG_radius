#pragma once

#include "wg_radius/wireguard/peer_controller.hpp"

#include <memory>

struct nl_sock;

namespace wg_radius::wireguard {

class NetlinkPeerController final : public PeerController {
public:
    NetlinkPeerController();
    ~NetlinkPeerController() override;

    NetlinkPeerController(const NetlinkPeerController&) = delete;
    NetlinkPeerController& operator=(const NetlinkPeerController&) = delete;

    NetlinkPeerController(NetlinkPeerController&&) noexcept;
    NetlinkPeerController& operator=(NetlinkPeerController&&) noexcept;

    [[nodiscard]] bool remove_peer(
        const std::string& interface_name,
        const std::string& peer_public_key) override;

private:
    struct Deleter {
        void operator()(nl_sock* socket) const noexcept;
    };

    std::unique_ptr<nl_sock, Deleter> socket_;
    int family_id_{-1};
};

}  // namespace wg_radius::wireguard
