#pragma once

#include <string>

namespace wg_radius::wireguard {

class PeerController {
public:
    virtual ~PeerController() = default;

    [[nodiscard]] virtual bool remove_peer(
        const std::string& interface_name,
        const std::string& peer_public_key) = 0;
};

}  // namespace wg_radius::wireguard
