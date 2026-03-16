#pragma once

#include "wg_radius/domain/session_manager.hpp"
#include "wg_radius/radius/radius_client.hpp"

#include <string>
#include <vector>

namespace wg_radius::application {

enum class AuthProcessingStatus {
    Processed,
    Ignored,
    Failed,
};

struct AuthProcessingResult {
    domain::Command command;
    AuthProcessingStatus status;
    std::vector<domain::Command> follow_up_commands;
};

class AuthCommandProcessor {
public:
    AuthCommandProcessor(
        std::string interface_name,
        domain::SessionManager& session_manager,
        radius::RadiusClient& radius_client);

    [[nodiscard]] AuthProcessingResult process(const domain::Command& command);

private:
    std::string interface_name_;
    domain::SessionManager& session_manager_;
    radius::RadiusClient& radius_client_;
};

}  // namespace wg_radius::application
