#pragma once

#include "wg_radius/application/auth_command_queue.hpp"
#include "wg_radius/application/command_executor.hpp"
#include "wg_radius/application/wg_polling_coordinator.hpp"

#include <vector>

namespace wg_radius::application {

struct RuntimeStepResult {
    PollStatus poll_status;
    std::size_t auth_commands_submitted;
    std::vector<CommandExecutionResult> executed_commands;
    std::size_t auth_results_processed;
};

class ProfileRuntime {
public:
    ProfileRuntime(
        WgPollingCoordinator& polling_coordinator,
        AuthCommandQueue& auth_command_queue,
        CommandExecutor& command_executor);

    [[nodiscard]] RuntimeStepResult step();

private:
    std::size_t dispatch_commands(
        const std::vector<domain::Command>& commands,
        std::vector<CommandExecutionResult>& executed_commands);

    WgPollingCoordinator& polling_coordinator_;
    AuthCommandQueue& auth_command_queue_;
    CommandExecutor& command_executor_;
};

}  // namespace wg_radius::application
