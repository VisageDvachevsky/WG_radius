#include "wg_radius/shaping/noop_traffic_shaper.hpp"

namespace wg_radius::shaping {

bool NoopTrafficShaper::apply_policy(
    const std::string& interface_name,
    const std::string& peer_public_key,
    const domain::SessionPolicy& policy) {
    (void)interface_name;
    (void)peer_public_key;
    (void)policy;
    return true;
}

}  // namespace wg_radius::shaping
