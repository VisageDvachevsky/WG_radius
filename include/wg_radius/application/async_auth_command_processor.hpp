#pragma once

#include "wg_radius/application/auth_command_queue.hpp"
#include "wg_radius/application/auth_command_processor.hpp"

#include <condition_variable>
#include <mutex>
#include <optional>
#include <queue>
#include <thread>

namespace wg_radius::application {

class AsyncAuthCommandProcessor final : public AuthCommandQueue {
public:
    explicit AsyncAuthCommandProcessor(AuthCommandProcessor& processor);
    ~AsyncAuthCommandProcessor();

    AsyncAuthCommandProcessor(const AsyncAuthCommandProcessor&) = delete;
    AsyncAuthCommandProcessor& operator=(const AsyncAuthCommandProcessor&) = delete;

    void submit(domain::Command command) override;
    [[nodiscard]] std::optional<AuthProcessingResult> try_pop_result() override;

private:
    void worker_loop();

    AuthCommandProcessor& processor_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::queue<domain::Command> pending_commands_;
    std::queue<AuthProcessingResult> completed_results_;
    bool stopping_{false};
    std::thread worker_;
};

}  // namespace wg_radius::application
