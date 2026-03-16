#include "wg_radius/application/profile_runtime.hpp"

namespace wg_radius::application {

ProfileRuntime::ProfileRuntime(
    WgPollingCoordinator& polling_coordinator,
    AuthCommandQueue& auth_command_queue,
    CommandExecutor& command_executor)
    : polling_coordinator_(polling_coordinator),
      auth_command_queue_(auth_command_queue),
      command_executor_(command_executor) {}

RuntimeStepResult ProfileRuntime::step() {
    auto poll_result = polling_coordinator_.poll();
    std::vector<CommandExecutionResult> executed_commands;
    std::size_t auth_commands_submitted = dispatch_commands(poll_result.commands, executed_commands);

    std::size_t auth_results_processed = 0;
    while (true) {
        auto auth_result = auth_command_queue_.try_pop_result();
        if (!auth_result.has_value()) {
            break;
        }
        ++auth_results_processed;
        auth_commands_submitted += dispatch_commands(auth_result->follow_up_commands, executed_commands);
    }

    return {
        .poll_status = poll_result.status,
        .auth_commands_submitted = auth_commands_submitted,
        .executed_commands = std::move(executed_commands),
        .auth_results_processed = auth_results_processed,
    };
}

std::size_t ProfileRuntime::dispatch_commands(
    const std::vector<domain::Command>& commands,
    std::vector<CommandExecutionResult>& executed_commands) {
    std::size_t auth_commands_submitted = 0;

    for (const auto& command : commands) {
        if (command.type == domain::CommandType::SendAccessRequest) {
            auth_command_queue_.submit(command);
            ++auth_commands_submitted;
            continue;
        }

        executed_commands.push_back(command_executor_.execute(command));
    }

    return auth_commands_submitted;
}

}  // namespace wg_radius::application
