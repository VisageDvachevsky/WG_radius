#pragma once

#include "wg_radius/domain/peer_session.hpp"
#include "wg_radius/radius/radius_profile.hpp"

#include <string>
#include <vector>

namespace wg_radius::config {

struct InterfaceProfile {
    std::string name;
    std::string interface_name;
    radius::RadiusProfile radius_profile;
    int poll_interval_ms{1000};
    domain::AuthorizationTrigger authorization_trigger{
        domain::AuthorizationTrigger::OnPeerAppearance};
    domain::RejectMode reject_mode{domain::RejectMode::RemovePeer};
};

struct DaemonConfig {
    std::vector<InterfaceProfile> profiles;
};

}  // namespace wg_radius::config
