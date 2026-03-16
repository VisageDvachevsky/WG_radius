#include "wg_radius/application/auth_command_processor.hpp"

namespace wg_radius::application {

AuthCommandProcessor::AuthCommandProcessor(
    std::string interface_name,
    const radius::RadiusProfile& radius_profile,
    domain::SessionManager& session_manager,
    radius::RadiusClient& radius_client)
    : interface_name_(std::move(interface_name)),
      radius_profile_(radius_profile),
      session_manager_(session_manager),
      radius_client_(radius_client) {}

AuthProcessingResult AuthCommandProcessor::process(const domain::Command& command) {
    if (command.type != domain::CommandType::SendAccessRequest) {
        return {.command = command, .status = AuthProcessingStatus::Ignored, .follow_up_commands = {}};
    }

    const auto response = radius_client_.authorize({
        .interface_name = interface_name_,
        .peer_public_key = command.peer_public_key,
        .endpoint = command.authorization_context.has_value()
            ? command.authorization_context->endpoint
            : std::nullopt,
        .allowed_ips = command.authorization_context.has_value()
            ? command.authorization_context->allowed_ips
            : std::vector<std::string>{},
        .nas_identifier = radius_profile_.nas_identifier,
        .nas_ip_address = radius_profile_.nas_ip_address,
        .calling_station_id = command.peer_public_key,
        .user_name = command.peer_public_key,
    });

    switch (response.decision) {
        case radius::AuthorizationDecision::Accept:
            if (!response.policy.has_value()) {
                return {.command = command, .status = AuthProcessingStatus::Failed, .follow_up_commands = {}};
            }
            return {
                .command = command,
                .status = AuthProcessingStatus::Processed,
                .follow_up_commands =
                    session_manager_.on_access_accept(command.peer_public_key, *response.policy),
            };
        case radius::AuthorizationDecision::Reject:
            return {
                .command = command,
                .status = AuthProcessingStatus::Processed,
                .follow_up_commands = session_manager_.on_access_reject(command.peer_public_key),
            };
        case radius::AuthorizationDecision::Error:
            return {.command = command, .status = AuthProcessingStatus::Failed, .follow_up_commands = {}};
    }

    return {.command = command, .status = AuthProcessingStatus::Failed, .follow_up_commands = {}};
}

}  // namespace wg_radius::application
