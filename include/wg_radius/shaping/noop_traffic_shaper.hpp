#pragma once

#include "wg_radius/shaping/traffic_shaper.hpp"

namespace wg_radius::shaping {

class NoopTrafficShaper final : public TrafficShaper {
public:
    [[nodiscard]] bool apply_policy(
        const std::string& interface_name,
        const std::string& peer_public_key,
        const domain::SessionPolicy& policy) override;
};

}  // namespace wg_radius::shaping
