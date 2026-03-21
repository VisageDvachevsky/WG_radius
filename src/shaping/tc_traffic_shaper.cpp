#include "wg_radius/shaping/tc_traffic_shaper.hpp"

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <optional>
#include <utility>

namespace wg_radius::shaping {

namespace {

constexpr auto kRootRate = "1000gbit";

}  // namespace

bool ProcessTcCommandRunner::run(const std::vector<std::string>& argv) {
    if (argv.empty()) {
        return false;
    }

    std::vector<char*> raw_argv;
    raw_argv.reserve(argv.size() + 1);
    for (const auto& arg : argv) {
        raw_argv.push_back(const_cast<char*>(arg.c_str()));
    }
    raw_argv.push_back(nullptr);

    const pid_t pid = fork();
    if (pid < 0) {
        return false;
    }

    if (pid == 0) {
        execvp(raw_argv.front(), raw_argv.data());
        _exit(errno == ENOENT ? 127 : 126);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        return false;
    }

    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

TcTrafficShaper::TcTrafficShaper()
    : runner_(&owned_runner_) {}

TcTrafficShaper::TcTrafficShaper(TcCommandRunner& runner)
    : runner_(&runner) {}

bool TcTrafficShaper::apply_policy(
    const std::string& interface_name,
    const std::string& peer_public_key,
    const std::vector<std::string>& allowed_ips,
    const domain::SessionPolicy& policy) {
    if (!policy_has_shaping(policy)) {
        return remove_policy(interface_name, peer_public_key);
    }
    if (allowed_ips.empty()) {
        return false;
    }
    if (!ensure_interface_ready(interface_name)) {
        return false;
    }

    const auto previous = peers_.find(peer_public_key);
    const bool had_previous = previous != peers_.end();
    std::optional<PeerState> previous_state;
    if (had_previous) {
        previous_state = previous->second;
    }

    const auto target_class_minor = class_minor_for_peer(peer_public_key);
    const auto target_filter_pref = filter_pref_for_peer(peer_public_key);
    cleanup_handle_state(interface_name, target_class_minor, target_filter_pref);

    if (had_previous &&
        (previous_state->class_minor != target_class_minor || previous_state->filter_pref != target_filter_pref)) {
        cleanup_handle_state(interface_name, previous_state->class_minor, previous_state->filter_pref);
    }

    auto next_state = make_peer_state(peer_public_key, interface_name, allowed_ips, policy);

    if (!install_state(interface_name, next_state)) {
        cleanup_handle_state(interface_name, next_state.class_minor, next_state.filter_pref);
        if (previous_state.has_value() && install_state(interface_name, *previous_state)) {
            peers_[peer_public_key] = *previous_state;
        } else if (previous_state.has_value()) {
            peers_.erase(peer_public_key);
        }
        return false;
    }

    peers_[peer_public_key] = std::move(next_state);
    return true;
}

bool TcTrafficShaper::remove_policy(
    const std::string& interface_name,
    const std::string& peer_public_key) {
    cleanup_handle_state(
        interface_name,
        class_minor_for_peer(peer_public_key),
        filter_pref_for_peer(peer_public_key));

    const auto it = peers_.find(peer_public_key);
    if (it != peers_.end() &&
        (it->second.class_minor != class_minor_for_peer(peer_public_key) ||
         it->second.filter_pref != filter_pref_for_peer(peer_public_key))) {
        cleanup_handle_state(interface_name, it->second.class_minor, it->second.filter_pref);
    }
    peers_.erase(peer_public_key);
    return true;
}

bool TcTrafficShaper::ensure_interface_ready(const std::string& interface_name) {
    auto& state = interfaces_[interface_name];
    if (state.initialized) {
        return true;
    }

    if (!runner_->run({"tc", "qdisc", "replace", "dev", interface_name, "root", "handle", "1:", "htb", "default", "1"})) {
        return false;
    }
    if (!runner_->run({"tc", "class", "replace", "dev", interface_name, "parent", "1:", "classid", "1:1", "htb", "rate", kRootRate, "ceil", kRootRate})) {
        return false;
    }
    if (!runner_->run({"tc", "qdisc", "replace", "dev", interface_name, "clsact"})) {
        return false;
    }

    state.initialized = true;
    return true;
}

bool TcTrafficShaper::install_state(
    const std::string& interface_name,
    const PeerState& state) {
    if (state.policy.egress_bps.has_value()) {
        if (!runner_->run(
                {"tc",
                 "class",
                 "replace",
                 "dev",
                 interface_name,
                 "parent",
                 "1:1",
                 "classid",
                 class_id(state.class_minor),
                 "htb",
                 "rate",
                 rate_bit_string(*state.policy.egress_bps),
                 "ceil",
                 rate_bit_string(*state.policy.egress_bps)})) {
            return false;
        }

        for (const auto& allowed_ip : state.allowed_ips) {
            if (!runner_->run(
                    {"tc",
                     "filter",
                     "add",
                     "dev",
                     interface_name,
                     "parent",
                     "1:",
                     "protocol",
                     protocol_for_cidr(allowed_ip),
                     "pref",
                     std::to_string(state.filter_pref),
                     "flower",
                     "dst_ip",
                     allowed_ip,
                     "classid",
                     class_id(state.class_minor)})) {
                return false;
            }
        }
    }

    if (state.policy.ingress_bps.has_value()) {
        for (const auto& allowed_ip : state.allowed_ips) {
            if (!runner_->run(
                    {"tc",
                     "filter",
                     "add",
                     "dev",
                     interface_name,
                     "parent",
                     "ffff:",
                     "protocol",
                     protocol_for_cidr(allowed_ip),
                     "pref",
                     std::to_string(state.filter_pref),
                     "flower",
                     "src_ip",
                     allowed_ip,
                     "action",
                     "police",
                     "rate",
                     rate_bit_string(*state.policy.ingress_bps),
                     "burst",
                     burst_bytes_string(*state.policy.ingress_bps),
                     "conform-exceed",
                     "drop"})) {
                return false;
            }
        }
    }

    return true;
}

void TcTrafficShaper::cleanup_state(const std::string& interface_name, const PeerState& state) {
    cleanup_handle_state(interface_name, state.class_minor, state.filter_pref);
}

TcTrafficShaper::PeerState TcTrafficShaper::make_peer_state(
    const std::string& peer_public_key,
    const std::string& interface_name,
    std::vector<std::string> allowed_ips,
    domain::SessionPolicy policy) {
    return PeerState{
        .interface_name = interface_name,
        .allowed_ips = std::move(allowed_ips),
        .policy = std::move(policy),
        .class_minor = class_minor_for_peer(peer_public_key),
        .filter_pref = filter_pref_for_peer(peer_public_key),
    };
}

void TcTrafficShaper::cleanup_handle_state(
    const std::string& interface_name,
    std::uint16_t class_minor,
    std::uint32_t filter_pref) {
    (void)runner_->run(
        {"tc", "filter", "delete", "dev", interface_name, "parent", "ffff:", "pref", std::to_string(filter_pref)});
    (void)runner_->run(
        {"tc", "filter", "delete", "dev", interface_name, "parent", "1:", "pref", std::to_string(filter_pref)});
    (void)runner_->run(
        {"tc", "class", "delete", "dev", interface_name, "classid", class_id(class_minor)});
}

std::uint32_t TcTrafficShaper::stable_hash(const std::string& value) {
    std::uint32_t hash = 2166136261u;
    for (const unsigned char byte : value) {
        hash ^= byte;
        hash *= 16777619u;
    }
    return hash;
}

std::uint16_t TcTrafficShaper::class_minor_for_peer(const std::string& peer_public_key) {
    return static_cast<std::uint16_t>(10u + (stable_hash(peer_public_key) % 65500u));
}

std::uint32_t TcTrafficShaper::filter_pref_for_peer(const std::string& peer_public_key) {
    return 100u + (stable_hash(peer_public_key) % 60000u);
}

bool TcTrafficShaper::policy_has_shaping(const domain::SessionPolicy& policy) {
    return policy.ingress_bps.has_value() || policy.egress_bps.has_value();
}

std::string TcTrafficShaper::class_id(std::uint16_t class_minor) {
    return "1:" + std::to_string(class_minor);
}

std::string TcTrafficShaper::protocol_for_cidr(const std::string& cidr) {
    return cidr.find(':') == std::string::npos ? "ip" : "ipv6";
}

std::string TcTrafficShaper::rate_bit_string(std::uint64_t bps) {
    return std::to_string(bps) + "bit";
}

std::string TcTrafficShaper::burst_bytes_string(std::uint64_t bps) {
    const auto burst_bytes = std::max<std::uint64_t>(1600, bps / 80);
    return std::to_string(burst_bytes) + "b";
}

}  // namespace wg_radius::shaping
