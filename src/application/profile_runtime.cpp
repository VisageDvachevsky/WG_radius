#include "wg_radius/application/profile_runtime.hpp"

namespace wg_radius::application {

ProfileRuntime::ProfileRuntime(
    WgPollingCoordinator& polling_coordinator,
    AuthCommandQueue& auth_command_queue,
    domain::SessionManager& session_manager,
    CommandExecutor& command_executor)
    : polling_coordinator_(polling_coordinator),
      auth_command_queue_(auth_command_queue),
      session_manager_(session_manager),
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
    std::vector<domain::Command> pending_commands = commands;

    while (!pending_commands.empty()) {
        auto command = std::move(pending_commands.front());
        pending_commands.erase(pending_commands.begin());

        if (command.type == domain::CommandType::SendAccessRequest) {
            auth_command_queue_.submit(command);
            ++auth_commands_submitted;
            continue;
        }

        auto execution_result = command_executor_.execute(command);
        auto follow_up_commands = on_command_executed(execution_result);
        executed_commands.push_back(std::move(execution_result));
        pending_commands.insert(
            pending_commands.end(),
            std::make_move_iterator(follow_up_commands.begin()),
            std::make_move_iterator(follow_up_commands.end()));
    }

    return auth_commands_submitted;
}

std::vector<domain::Command> ProfileRuntime::on_command_executed(
    const CommandExecutionResult& execution_result) {
    if (execution_result.status != CommandExecutionStatus::Executed) {
        return {};
    }

    switch (execution_result.command.type) {
        case domain::CommandType::StartAccounting:
            return session_manager_.on_accounting_started(execution_result.command.peer_public_key);
        case domain::CommandType::StopAccounting:
            return session_manager_.on_accounting_stopped(execution_result.command.peer_public_key);
        case domain::CommandType::BlockPeer:
            return session_manager_.on_peer_blocked(execution_result.command.peer_public_key);
        case domain::CommandType::SendAccessRequest:
        case domain::CommandType::ApplySessionPolicy:
        case domain::CommandType::RemovePeer:
            return {};
    }

    return {};
}

}  // namespace wg_radius::application
