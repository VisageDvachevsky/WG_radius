#pragma once

#include "wg_radius/domain/session_manager.hpp"
#include "wg_radius/shaping/traffic_shaper.hpp"
#include "wg_radius/wireguard/peer_controller.hpp"

#include <string>
#include <vector>

namespace wg_radius::application {

enum class CommandExecutionStatus {
    Executed,
    Ignored,
    Failed,
};

struct CommandExecutionResult {
    domain::Command command;
    CommandExecutionStatus status;
};

class CommandExecutor {
public:
    CommandExecutor(
        std::string interface_name,
        wireguard::PeerController& peer_controller,
        shaping::TrafficShaper& traffic_shaper);

    [[nodiscard]] CommandExecutionResult execute(const domain::Command& command);
    [[nodiscard]] std::vector<CommandExecutionResult> execute_all(
        const std::vector<domain::Command>& commands);

private:
    std::string interface_name_;
    wireguard::PeerController& peer_controller_;
    shaping::TrafficShaper& traffic_shaper_;
};

}  // namespace wg_radius::application
