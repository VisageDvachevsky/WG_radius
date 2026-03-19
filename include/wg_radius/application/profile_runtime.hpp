#pragma once

#include "wg_radius/application/auth_command_queue.hpp"
#include "wg_radius/application/command_executor.hpp"
#include "wg_radius/coa/request_source.hpp"
#include "wg_radius/application/wg_polling_coordinator.hpp"
#include "wg_radius/domain/session_manager.hpp"

#include <chrono>
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
        domain::SessionManager& session_manager,
        CommandExecutor& command_executor,
        coa::RequestSource* coa_request_source = nullptr);

    [[nodiscard]] RuntimeStepResult step();
    [[nodiscard]] RuntimeStepResult step_at(domain::SessionManager::TimePoint now);

private:
    std::size_t dispatch_commands(
        const std::vector<domain::Command>& commands,
        std::vector<CommandExecutionResult>& executed_commands,
        domain::SessionManager::TimePoint now);
    std::vector<domain::Command> on_command_executed(
        const CommandExecutionResult& execution_result,
        domain::SessionManager::TimePoint now);

    WgPollingCoordinator& polling_coordinator_;
    AuthCommandQueue& auth_command_queue_;
    domain::SessionManager& session_manager_;
    CommandExecutor& command_executor_;
    coa::RequestSource* coa_request_source_;
};

}  // namespace wg_radius::application
