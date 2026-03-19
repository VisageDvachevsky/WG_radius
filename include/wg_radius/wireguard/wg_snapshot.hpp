#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace wg_radius::wireguard {

struct PeerSnapshot {
    std::string public_key;
    std::optional<std::string> endpoint;
    std::vector<std::string> allowed_ips;
    std::uint64_t latest_handshake_epoch_sec{0};
    std::uint64_t transfer_rx_bytes{0};
    std::uint64_t transfer_tx_bytes{0};
};

struct InterfaceSnapshot {
    std::string interface_name;
    std::unordered_map<std::string, PeerSnapshot> peers;
};

enum class EventType {
    PeerObserved,
    PeerRemoved,
    HandshakeObserved,
    HandshakeRefreshed,
    TrafficUpdated,
};

struct Event {
    EventType type;
    std::string peer_public_key;
    std::optional<std::string> endpoint;
    std::vector<std::string> allowed_ips;
    std::uint64_t latest_handshake_epoch_sec{0};
    std::uint64_t transfer_rx_bytes{0};
    std::uint64_t transfer_tx_bytes{0};
};

class SnapshotParser {
public:
    [[nodiscard]] static std::optional<InterfaceSnapshot> parse_dump(
        const std::string& interface_name,
        const std::string& dump_text);
};

class SnapshotDiffer {
public:
    [[nodiscard]] static std::vector<Event> diff(
        const std::optional<InterfaceSnapshot>& previous,
        const InterfaceSnapshot& current);
};

}  // namespace wg_radius::wireguard
