#pragma once

#include "wg_radius/domain/peer_session.hpp"
#include "wg_radius/radius/radius_profile.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace wg_radius::config {

enum class InactivityStrategy {
    HandshakeOnly,
    TrafficOnly,
    HandshakeAndTraffic,
};

struct InterfaceProfile {
    std::string name;
    std::string interface_name;
    radius::RadiusProfile radius_profile;
    std::optional<radius::RadiusEndpoint> coa_server;
    int poll_interval_ms{1000};
    std::optional<std::chrono::seconds> acct_interim_interval;
    std::optional<std::chrono::seconds> inactive_timeout;
    InactivityStrategy inactivity_strategy{InactivityStrategy::HandshakeOnly};
    domain::AuthorizationTrigger authorization_trigger{
        domain::AuthorizationTrigger::OnPeerAppearance};
    domain::RejectMode reject_mode{domain::RejectMode::RemovePeer};
};

struct DaemonConfig {
    std::vector<InterfaceProfile> profiles;
};

}  // namespace wg_radius::config
