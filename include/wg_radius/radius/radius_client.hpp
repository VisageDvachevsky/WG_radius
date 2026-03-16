#pragma once

#include "wg_radius/domain/peer_session.hpp"

#include <optional>
#include <string>

namespace wg_radius::radius {

struct AuthorizationRequest {
    std::string interface_name;
    std::string peer_public_key;
};

enum class AuthorizationDecision {
    Accept,
    Reject,
    Error,
};

struct AuthorizationResponse {
    AuthorizationDecision decision;
    std::optional<domain::SessionPolicy> policy;
};

class RadiusClient {
public:
    virtual ~RadiusClient() = default;

    [[nodiscard]] virtual AuthorizationResponse authorize(
        const AuthorizationRequest& request) = 0;
};

}  // namespace wg_radius::radius
