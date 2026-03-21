#pragma once

#include "wg_radius/shaping/traffic_shaper.hpp"

namespace wg_radius::shaping {

class NoopTrafficShaper final : public TrafficShaper {
public:
    [[nodiscard]] bool apply_policy(
        const std::string& interface_name,
        const std::string& peer_public_key,
        const std::vector<std::string>& allowed_ips,
        const domain::SessionPolicy& policy) override;
    [[nodiscard]] bool remove_policy(
        const std::string& interface_name,
        const std::string& peer_public_key) override;
};

}  // namespace wg_radius::shaping
