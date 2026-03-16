#include "wg_radius/config/config_parser.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>

namespace wg_radius::config {

namespace {

std::string trim(std::string value) {
    const auto not_space = [](unsigned char ch) { return !std::isspace(ch); };
    value.erase(value.begin(), std::find_if(value.begin(), value.end(), not_space));
    value.erase(std::find_if(value.rbegin(), value.rend(), not_space).base(), value.end());
    return value;
}

std::optional<std::uint16_t> parse_u16(const std::string& value) {
    std::uint16_t parsed = 0;
    const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (ec != std::errc{} || ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<int> parse_int(const std::string& value) {
    int parsed = 0;
    const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (ec != std::errc{} || ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return parsed;
}

std::optional<domain::AuthorizationTrigger> parse_trigger(const std::string& value) {
    if (value == "peer-appearance") {
        return domain::AuthorizationTrigger::OnPeerAppearance;
    }
    if (value == "first-handshake") {
        return domain::AuthorizationTrigger::OnFirstHandshake;
    }
    return std::nullopt;
}

}  // namespace

std::optional<DaemonConfig> ConfigParser::parse(const std::string& text) {
    std::stringstream input(text);
    std::string line;
    std::optional<InterfaceProfile> current_profile;
    DaemonConfig config;
    std::unordered_map<std::string, bool> names_seen;

    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line.starts_with('#')) {
            continue;
        }

        if (line.starts_with("[profile ")) {
            if (!line.ends_with(']')) {
                return std::nullopt;
            }
            if (current_profile.has_value()) {
                if (current_profile->name.empty() || current_profile->interface_name.empty() ||
                    current_profile->radius_profile.auth_server.host.empty() ||
                    current_profile->radius_profile.accounting_server.host.empty() ||
                    current_profile->radius_profile.shared_secret.empty()) {
                    return std::nullopt;
                }
                config.profiles.push_back(*current_profile);
            }

            const auto name = line.substr(9, line.size() - 10);
            if (name.empty() || names_seen.contains(name)) {
                return std::nullopt;
            }
            names_seen[name] = true;
            current_profile = InterfaceProfile{
                .name = name,
                .interface_name = {},
                .radius_profile =
                    radius::RadiusProfile{
                        .auth_server = {},
                        .accounting_server = {},
                        .shared_secret = {},
                        .timeout = std::chrono::seconds{5},
                        .retries = 3,
                        .nas_identifier = {},
                    },
                .poll_interval_ms = 1000,
                .authorization_trigger = domain::AuthorizationTrigger::OnPeerAppearance,
            };
            continue;
        }

        if (!current_profile.has_value()) {
            return std::nullopt;
        }

        const auto separator = line.find('=');
        if (separator == std::string::npos) {
            return std::nullopt;
        }

        const auto key = trim(line.substr(0, separator));
        const auto value = trim(line.substr(separator + 1));
        if (key == "interface") {
            current_profile->interface_name = value;
        } else if (key == "auth_host") {
            current_profile->radius_profile.auth_server.host = value;
        } else if (key == "auth_port") {
            const auto parsed = parse_u16(value);
            if (!parsed.has_value()) {
                return std::nullopt;
            }
            current_profile->radius_profile.auth_server.port = *parsed;
        } else if (key == "acct_host") {
            current_profile->radius_profile.accounting_server.host = value;
        } else if (key == "acct_port") {
            const auto parsed = parse_u16(value);
            if (!parsed.has_value()) {
                return std::nullopt;
            }
            current_profile->radius_profile.accounting_server.port = *parsed;
        } else if (key == "secret") {
            current_profile->radius_profile.shared_secret = value;
        } else if (key == "nas_identifier") {
            current_profile->radius_profile.nas_identifier = value;
        } else if (key == "timeout_ms") {
            const auto parsed = parse_int(value);
            if (!parsed.has_value() || *parsed <= 0) {
                return std::nullopt;
            }
            current_profile->radius_profile.timeout = std::chrono::milliseconds{*parsed};
        } else if (key == "retries") {
            const auto parsed = parse_int(value);
            if (!parsed.has_value() || *parsed < 0) {
                return std::nullopt;
            }
            current_profile->radius_profile.retries = *parsed;
        } else if (key == "poll_interval_ms") {
            const auto parsed = parse_int(value);
            if (!parsed.has_value() || *parsed <= 0) {
                return std::nullopt;
            }
            current_profile->poll_interval_ms = *parsed;
        } else if (key == "authorization_trigger") {
            const auto parsed = parse_trigger(value);
            if (!parsed.has_value()) {
                return std::nullopt;
            }
            current_profile->authorization_trigger = *parsed;
        } else {
            return std::nullopt;
        }
    }

    if (current_profile.has_value()) {
        if (current_profile->name.empty() || current_profile->interface_name.empty() ||
            current_profile->radius_profile.auth_server.host.empty() ||
            current_profile->radius_profile.accounting_server.host.empty() ||
            current_profile->radius_profile.shared_secret.empty()) {
            return std::nullopt;
        }
        config.profiles.push_back(*current_profile);
    }

    if (config.profiles.empty()) {
        return std::nullopt;
    }

    return config;
}

}  // namespace wg_radius::config
