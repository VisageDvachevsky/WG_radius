#include "wg_radius/application/profile_runtime.hpp"

#include <algorithm>

namespace wg_radius::application {

ProfileRuntime::ProfileRuntime(
    WgPollingCoordinator& polling_coordinator,
    AuthCommandQueue& auth_command_queue,
    domain::SessionManager& session_manager,
    CommandExecutor& command_executor,
    coa::RequestSource* coa_request_source)
    : polling_coordinator_(polling_coordinator),
      auth_command_queue_(auth_command_queue),
      session_manager_(session_manager),
      command_executor_(command_executor),
      coa_request_source_(coa_request_source) {}

RuntimeStepResult ProfileRuntime::step() {
    return step_at(std::chrono::steady_clock::now());
}

RuntimeStepResult ProfileRuntime::step_at(domain::SessionManager::TimePoint now) {
    auto poll_result = polling_coordinator_.poll_at(now);
    std::vector<CommandExecutionResult> executed_commands;
    std::size_t auth_commands_submitted = dispatch_commands(poll_result.commands, executed_commands, now);

    std::size_t auth_results_processed = 0;
    while (true) {
        auto auth_result = auth_command_queue_.try_pop_result();
        if (!auth_result.has_value()) {
            break;
        }
        ++auth_results_processed;
        auth_commands_submitted +=
            dispatch_commands(auth_result->follow_up_commands, executed_commands, now);
    }

    if (coa_request_source_ != nullptr) {
        while (true) {
            auto request = coa_request_source_->try_pop_request();
            if (!request.has_value()) {
                break;
            }
            if (request->type == coa::RequestType::Disconnect) {
                dispatch_commands(
                    session_manager_.on_disconnect_request(request->peer_public_key),
                    executed_commands,
                    now);
                continue;
            }

            if (request->type == coa::RequestType::Coa && request->policy.has_value()) {
                dispatch_commands(
                    session_manager_.on_coa_request(request->peer_public_key, *request->policy),
                    executed_commands,
                    now);
            }
        }
    }

    dispatch_commands(session_manager_.on_timer(now), executed_commands, now);

    return {
        .poll_status = poll_result.status,
        .auth_commands_submitted = auth_commands_submitted,
        .executed_commands = std::move(executed_commands),
        .auth_results_processed = auth_results_processed,
    };
}

std::size_t ProfileRuntime::dispatch_commands(
    const std::vector<domain::Command>& commands,
    std::vector<CommandExecutionResult>& executed_commands,
    domain::SessionManager::TimePoint now) {
    std::size_t auth_commands_submitted = 0;
    std::vector<domain::Command> pending_commands = commands;
    std::size_t next_command_index = 0;

    while (next_command_index < pending_commands.size()) {
        auto command = std::move(pending_commands[next_command_index++]);

        if (command.type == domain::CommandType::SendAccessRequest) {
            auth_command_queue_.submit(command);
            ++auth_commands_submitted;
            continue;
        }

        auto execution_result = command_executor_.execute(command);
        if (execution_result.command.type == domain::CommandType::ApplySessionPolicy &&
            execution_result.status == CommandExecutionStatus::Failed) {
            pending_commands.erase(
                std::remove_if(
                    pending_commands.begin() + static_cast<std::ptrdiff_t>(next_command_index),
                    pending_commands.end(),
                    [&](const domain::Command& pending_command) {
                        return pending_command.type == domain::CommandType::StartAccounting &&
                            pending_command.peer_public_key == execution_result.command.peer_public_key;
                    }),
                pending_commands.end());
        }
        auto follow_up_commands = on_command_executed(execution_result, now);
        executed_commands.push_back(std::move(execution_result));
        pending_commands.insert(
            pending_commands.end(),
            std::make_move_iterator(follow_up_commands.begin()),
            std::make_move_iterator(follow_up_commands.end()));
    }

    return auth_commands_submitted;
}

std::vector<domain::Command> ProfileRuntime::on_command_executed(
    const CommandExecutionResult& execution_result,
    domain::SessionManager::TimePoint now) {
    if (execution_result.status != CommandExecutionStatus::Executed) {
        if (execution_result.command.type == domain::CommandType::ApplySessionPolicy) {
            return session_manager_.on_policy_application_failed(execution_result.command.peer_public_key);
        }
        return {};
    }

    switch (execution_result.command.type) {
        case domain::CommandType::ApplySessionPolicy:
            if (!execution_result.command.policy.has_value()) {
                return {};
            }
            return session_manager_.on_policy_applied(
                execution_result.command.peer_public_key,
                *execution_result.command.policy);
        case domain::CommandType::StartAccounting:
            return session_manager_.on_accounting_started(execution_result.command.peer_public_key, now);
        case domain::CommandType::InterimAccounting:
            return {};
        case domain::CommandType::StopAccounting:
            return session_manager_.on_accounting_stopped(execution_result.command.peer_public_key);
        case domain::CommandType::BlockPeer:
            return session_manager_.on_peer_blocked(execution_result.command.peer_public_key);
        case domain::CommandType::SendAccessRequest:
            return {};
        case domain::CommandType::RemovePeer:
            return session_manager_.on_peer_removed(execution_result.command.peer_public_key, now);
    }

    return {};
}

}  // namespace wg_radius::application
