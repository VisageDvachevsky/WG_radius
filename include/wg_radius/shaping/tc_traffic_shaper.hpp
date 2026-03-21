#pragma once

#include "wg_radius/shaping/traffic_shaper.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace wg_radius::shaping {

class TcCommandRunner {
public:
    virtual ~TcCommandRunner() = default;

    [[nodiscard]] virtual bool run(const std::vector<std::string>& argv) = 0;
};

class ProcessTcCommandRunner final : public TcCommandRunner {
public:
    [[nodiscard]] bool run(const std::vector<std::string>& argv) override;
};

class TcTrafficShaper final : public TrafficShaper {
public:
    TcTrafficShaper();
    explicit TcTrafficShaper(TcCommandRunner& runner);

    [[nodiscard]] bool apply_policy(
        const std::string& interface_name,
        const std::string& peer_public_key,
        const std::vector<std::string>& allowed_ips,
        const domain::SessionPolicy& policy) override;
    [[nodiscard]] bool remove_policy(
        const std::string& interface_name,
        const std::string& peer_public_key) override;

private:
    struct PeerState {
        std::string interface_name;
        std::vector<std::string> allowed_ips;
        domain::SessionPolicy policy;
        std::uint16_t class_minor;
        std::uint32_t filter_pref;
    };

    struct InterfaceState {
        bool initialized{false};
    };

    [[nodiscard]] bool ensure_interface_ready(const std::string& interface_name);
    [[nodiscard]] bool install_state(
        const std::string& interface_name,
        const PeerState& state);
    void cleanup_state(const std::string& interface_name, const PeerState& state);
    void cleanup_handle_state(
        const std::string& interface_name,
        std::uint16_t class_minor,
        std::uint32_t filter_pref);
    [[nodiscard]] PeerState make_peer_state(
        const std::string& peer_public_key,
        const std::string& interface_name,
        std::vector<std::string> allowed_ips,
        domain::SessionPolicy policy);
    [[nodiscard]] static std::uint32_t stable_hash(const std::string& value);
    [[nodiscard]] static std::uint16_t class_minor_for_peer(const std::string& peer_public_key);
    [[nodiscard]] static std::uint32_t filter_pref_for_peer(const std::string& peer_public_key);
    [[nodiscard]] static bool policy_has_shaping(const domain::SessionPolicy& policy);
    [[nodiscard]] static std::string class_id(std::uint16_t class_minor);
    [[nodiscard]] static std::string protocol_for_cidr(const std::string& cidr);
    [[nodiscard]] static std::string rate_bit_string(std::uint64_t bps);
    [[nodiscard]] static std::string burst_bytes_string(std::uint64_t bps);

    ProcessTcCommandRunner owned_runner_;
    TcCommandRunner* runner_;
    std::unordered_map<std::string, InterfaceState> interfaces_;
    std::unordered_map<std::string, PeerState> peers_;
};

}  // namespace wg_radius::shaping
