#include "wg_radius/application/async_auth_command_processor.hpp"

namespace wg_radius::application {

AsyncAuthCommandProcessor::AsyncAuthCommandProcessor(AuthCommandProcessor& processor)
    : processor_(processor), worker_(&AsyncAuthCommandProcessor::worker_loop, this) {}

AsyncAuthCommandProcessor::~AsyncAuthCommandProcessor() {
    {
        std::lock_guard lock(mutex_);
        stopping_ = true;
    }
    cv_.notify_all();
    if (worker_.joinable()) {
        worker_.join();
    }
}

void AsyncAuthCommandProcessor::submit(domain::Command command) {
    {
        std::lock_guard lock(mutex_);
        pending_commands_.push(std::move(command));
    }
    cv_.notify_one();
}

std::optional<AuthProcessingResult> AsyncAuthCommandProcessor::try_pop_result() {
    std::lock_guard lock(mutex_);
    if (completed_results_.empty()) {
        return std::nullopt;
    }

    auto result = std::move(completed_results_.front());
    completed_results_.pop();
    return result;
}

void AsyncAuthCommandProcessor::worker_loop() {
    while (true) {
        std::optional<domain::Command> command;
        {
            std::unique_lock lock(mutex_);
            cv_.wait(lock, [&] { return stopping_ || !pending_commands_.empty(); });
            if (stopping_ && pending_commands_.empty()) {
                return;
            }
            command = std::move(pending_commands_.front());
            pending_commands_.pop();
        }

        auto result = processor_.process(*command);
        {
            std::lock_guard lock(mutex_);
            completed_results_.push(std::move(result));
        }
    }
}

}  // namespace wg_radius::application
