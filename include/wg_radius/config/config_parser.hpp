#pragma once

#include "wg_radius/config/config.hpp"

#include <optional>
#include <string>

namespace wg_radius::config {

class ConfigParser {
public:
    [[nodiscard]] static std::optional<DaemonConfig> parse(const std::string& text);
};

}  // namespace wg_radius::config
