#include "wg_radius/application/command_executor.hpp"

namespace wg_radius::application {

CommandExecutor::CommandExecutor(
    std::string interface_name,
    wireguard::PeerController& peer_controller,
    shaping::TrafficShaper& traffic_shaper)
    : interface_name_(std::move(interface_name)),
      peer_controller_(peer_controller),
      traffic_shaper_(traffic_shaper) {}

CommandExecutionResult CommandExecutor::execute(const domain::Command& command) {
    switch (command.type) {
        case domain::CommandType::RemovePeer: {
            const bool ok = peer_controller_.remove_peer(interface_name_, command.peer_public_key);
            return {.command = command, .status = ok ? CommandExecutionStatus::Executed
                                                     : CommandExecutionStatus::Failed};
        }
        case domain::CommandType::ApplySessionPolicy: {
            if (!command.policy.has_value()) {
                return {.command = command, .status = CommandExecutionStatus::Failed};
            }
            const bool ok =
                traffic_shaper_.apply_policy(interface_name_, command.peer_public_key, *command.policy);
            return {.command = command, .status = ok ? CommandExecutionStatus::Executed
                                                     : CommandExecutionStatus::Failed};
        }
        case domain::CommandType::SendAccessRequest:
        case domain::CommandType::StartAccounting:
        case domain::CommandType::StopAccounting:
        case domain::CommandType::BlockPeer:
            return {.command = command, .status = CommandExecutionStatus::Ignored};
    }

    return {.command = command, .status = CommandExecutionStatus::Failed};
}

std::vector<CommandExecutionResult> CommandExecutor::execute_all(
    const std::vector<domain::Command>& commands) {
    std::vector<CommandExecutionResult> results;
    results.reserve(commands.size());

    for (const auto& command : commands) {
        results.push_back(execute(command));
    }

    return results;
}

}  // namespace wg_radius::application
