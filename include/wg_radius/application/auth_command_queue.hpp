#pragma once

#include "wg_radius/application/auth_command_processor.hpp"

#include <optional>

namespace wg_radius::application {

class AuthCommandQueue {
public:
    virtual ~AuthCommandQueue() = default;

    virtual void submit(domain::Command command) = 0;
    [[nodiscard]] virtual std::optional<AuthProcessingResult> try_pop_result() = 0;
};

}  // namespace wg_radius::application
