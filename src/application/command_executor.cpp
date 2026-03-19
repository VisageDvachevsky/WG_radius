#include "wg_radius/application/command_executor.hpp"

namespace wg_radius::application {

CommandExecutor::CommandExecutor(
    std::string interface_name,
    radius::RadiusClient& radius_client,
    wireguard::PeerController& peer_controller,
    shaping::TrafficShaper& traffic_shaper)
    : interface_name_(std::move(interface_name)),
      radius_client_(radius_client),
      peer_controller_(peer_controller),
      traffic_shaper_(traffic_shaper) {}

CommandExecutionResult CommandExecutor::execute(const domain::Command& command) {
    switch (command.type) {
        case domain::CommandType::RemovePeer: {
            const bool ok = peer_controller_.remove_peer(interface_name_, command.peer_public_key);
            return {.command = command, .status = ok ? CommandExecutionStatus::Executed
                                                     : CommandExecutionStatus::Failed};
        }
        case domain::CommandType::BlockPeer: {
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
        case domain::CommandType::StartAccounting:
        case domain::CommandType::InterimAccounting:
        case domain::CommandType::StopAccounting: {
            if (!command.accounting_session_id.has_value()) {
                return {.command = command, .status = CommandExecutionStatus::Failed};
            }

            const domain::AccountingContext empty_context{};
            const auto& accounting_context = command.accounting_context.has_value()
                ? *command.accounting_context
                : empty_context;

            std::optional<std::string> framed_ip_address;
            if (!accounting_context.allowed_ips.empty()) {
                const auto& first_allowed_ip = accounting_context.allowed_ips.front();
                const auto slash = first_allowed_ip.find('/');
                framed_ip_address = first_allowed_ip.substr(0, slash);
            }

            const bool ok = radius_client_.account({
                .event_type =
                    command.type == domain::CommandType::StartAccounting
                    ? radius::AccountingEventType::Start
                    : command.type == domain::CommandType::InterimAccounting
                    ? radius::AccountingEventType::InterimUpdate
                    : radius::AccountingEventType::Stop,
                .interface_name = interface_name_,
                .peer_public_key = command.peer_public_key,
                .accounting_session_id = *command.accounting_session_id,
                .endpoint = accounting_context.endpoint,
                .framed_ip_address = framed_ip_address,
                .session_duration = accounting_context.session_duration,
                .transfer_rx_bytes = accounting_context.transfer_rx_bytes,
                .transfer_tx_bytes = accounting_context.transfer_tx_bytes,
                .stop_reason = accounting_context.stop_reason,
            });
            return {.command = command, .status = ok ? CommandExecutionStatus::Executed
                                                     : CommandExecutionStatus::Failed};
        }
        case domain::CommandType::SendAccessRequest:
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
