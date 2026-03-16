#pragma once

#include "wg_radius/domain/peer_session.hpp"

#include <string>

namespace wg_radius::shaping {

class TrafficShaper {
public:
    virtual ~TrafficShaper() = default;

    [[nodiscard]] virtual bool apply_policy(
        const std::string& interface_name,
        const std::string& peer_public_key,
        const domain::SessionPolicy& policy) = 0;
};

}  // namespace wg_radius::shaping
