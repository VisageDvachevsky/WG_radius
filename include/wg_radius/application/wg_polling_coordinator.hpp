#pragma once

#include "wg_radius/application/wg_event_router.hpp"
#include "wg_radius/wireguard/wireguard_client.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace wg_radius::application {

enum class PollStatus {
    Seeded,
    NoChanges,
    CommandsProduced,
    SnapshotUnavailable,
    InterfaceMismatch,
};

struct PollResult {
    PollStatus status;
    std::vector<domain::Command> commands;
};

class WgPollingCoordinator {
public:
    WgPollingCoordinator(
        std::string interface_name,
        wireguard::WireGuardClient& wireguard_client,
        WgEventRouter& event_router);

    [[nodiscard]] PollResult poll();
    [[nodiscard]] PollResult poll_at(domain::SessionManager::TimePoint now);

private:
    std::string interface_name_;
    wireguard::WireGuardClient& wireguard_client_;
    WgEventRouter& event_router_;
    std::optional<wireguard::InterfaceSnapshot> previous_snapshot_;
};

}  // namespace wg_radius::application
