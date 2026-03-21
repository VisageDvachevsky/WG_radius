#include "wg_radius/shaping/noop_traffic_shaper.hpp"

namespace wg_radius::shaping {

bool NoopTrafficShaper::apply_policy(
    const std::string& interface_name,
    const std::string& peer_public_key,
    const std::vector<std::string>& allowed_ips,
    const domain::SessionPolicy& policy) {
    (void)interface_name;
    (void)peer_public_key;
    (void)allowed_ips;
    (void)policy;
    return true;
}

bool NoopTrafficShaper::remove_policy(
    const std::string& interface_name,
    const std::string& peer_public_key) {
    (void)interface_name;
    (void)peer_public_key;
    return true;
}

}  // namespace wg_radius::shaping
