#pragma once

#include "wg_radius/domain/session_manager.hpp"
#include "wg_radius/wireguard/wg_snapshot.hpp"

#include <vector>

namespace wg_radius::application {

class WgEventRouter {
public:
    explicit WgEventRouter(domain::SessionManager& session_manager);

    [[nodiscard]] std::vector<domain::Command> seed(
        const wireguard::InterfaceSnapshot& snapshot,
        domain::SessionManager::TimePoint now = domain::SessionManager::TimePoint{});
    [[nodiscard]] std::vector<domain::Command> handle(
        const wireguard::Event& event,
        domain::SessionManager::TimePoint now = domain::SessionManager::TimePoint{});

private:
    domain::SessionManager& session_manager_;
};

}  // namespace wg_radius::application
