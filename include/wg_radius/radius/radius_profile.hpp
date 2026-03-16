#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace wg_radius::radius {

struct RadiusEndpoint {
    std::string host;
    std::uint16_t port;
};

struct RadiusProfile {
    RadiusEndpoint auth_server;
    RadiusEndpoint accounting_server;
    std::string shared_secret;
    std::chrono::milliseconds timeout;
    int retries;
    std::string nas_identifier;
    std::optional<std::string> nas_ip_address;
};

}  // namespace wg_radius::radius
