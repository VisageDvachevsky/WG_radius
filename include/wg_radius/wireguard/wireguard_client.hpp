#pragma once

#include "wg_radius/wireguard/wg_snapshot.hpp"

#include <optional>
#include <string>

namespace wg_radius::wireguard {

class WireGuardClient {
public:
    virtual ~WireGuardClient() = default;

    [[nodiscard]] virtual std::optional<InterfaceSnapshot> fetch_interface_snapshot(
        const std::string& interface_name) = 0;
};

}  // namespace wg_radius::wireguard
