#include "wg_radius/application/wg_polling_coordinator.hpp"

namespace wg_radius::application {

WgPollingCoordinator::WgPollingCoordinator(
    std::string interface_name,
    wireguard::WireGuardClient& wireguard_client,
    WgEventRouter& event_router)
    : interface_name_(std::move(interface_name)),
      wireguard_client_(wireguard_client),
      event_router_(event_router) {}

PollResult WgPollingCoordinator::poll() {
    return poll_at(std::chrono::steady_clock::now());
}

PollResult WgPollingCoordinator::poll_at(domain::SessionManager::TimePoint now) {
    const auto current_snapshot = wireguard_client_.fetch_interface_snapshot(interface_name_);
    if (!current_snapshot.has_value()) {
        return {.status = PollStatus::SnapshotUnavailable, .commands = {}};
    }

    if (current_snapshot->interface_name != interface_name_) {
        return {.status = PollStatus::InterfaceMismatch, .commands = {}};
    }

    if (!previous_snapshot_.has_value()) {
        auto commands = event_router_.seed(*current_snapshot, now);
        previous_snapshot_ = current_snapshot;
        return {.status = PollStatus::Seeded, .commands = std::move(commands)};
    }

    std::vector<domain::Command> commands;
    const auto events = wireguard::SnapshotDiffer::diff(previous_snapshot_, *current_snapshot);
    for (const auto& event : events) {
        auto event_commands = event_router_.handle(event, now);
        commands.insert(commands.end(), event_commands.begin(), event_commands.end());
    }

    previous_snapshot_ = current_snapshot;
    return {
        .status = commands.empty() ? PollStatus::NoChanges : PollStatus::CommandsProduced,
        .commands = std::move(commands)};
}

}  // namespace wg_radius::application
