#include "wg_radius/wireguard/wg_snapshot.hpp"

#include <sstream>
#include <string>
#include <vector>

namespace wg_radius::wireguard {

namespace {

std::vector<std::string> split_tab_line(const std::string& line) {
    std::vector<std::string> fields;
    std::stringstream stream(line);
    std::string field;

    while (std::getline(stream, field, '\t')) {
        fields.push_back(field);
    }

    return fields;
}

std::optional<std::uint64_t> parse_u64(const std::string& value) {
    try {
        return std::stoull(value);
    } catch (...) {
        return std::nullopt;
    }
}

std::optional<std::string> normalize_optional_field(const std::string& value) {
    if (value == "(none)") {
        return std::nullopt;
    }

    return value;
}

std::vector<std::string> parse_allowed_ips(const std::string& value) {
    if (value == "(none)" || value.empty()) {
        return {};
    }

    std::vector<std::string> allowed_ips;
    std::stringstream stream(value);
    std::string item;
    while (std::getline(stream, item, ',')) {
        if (!item.empty()) {
            allowed_ips.push_back(item);
        }
    }

    return allowed_ips;
}

}  // namespace

std::optional<InterfaceSnapshot> SnapshotParser::parse_dump(
    const std::string& interface_name,
    const std::string& dump_text) {
    InterfaceSnapshot snapshot{.interface_name = interface_name, .peers = {}};

    std::stringstream lines(dump_text);
    std::string line;
    bool saw_interface_row = false;

    while (std::getline(lines, line)) {
        if (line.empty()) {
            continue;
        }

        const auto fields = split_tab_line(line);
        if (!saw_interface_row) {
            if (fields.size() != 4 || fields[0].empty() || fields[1].empty()) {
                return std::nullopt;
            }

            saw_interface_row = true;
            continue;
        }

        if (fields.size() < 8) {
            return std::nullopt;
        }

        const auto handshake = parse_u64(fields[4]);
        const auto rx = parse_u64(fields[5]);
        const auto tx = parse_u64(fields[6]);
        if (!handshake.has_value() || !rx.has_value() || !tx.has_value()) {
            return std::nullopt;
        }

        PeerSnapshot peer{
            .public_key = fields[0],
            .endpoint = normalize_optional_field(fields[2]),
            .allowed_ips = parse_allowed_ips(fields[3]),
            .latest_handshake_epoch_sec = *handshake,
            .transfer_rx_bytes = *rx,
            .transfer_tx_bytes = *tx,
        };

        snapshot.peers.emplace(peer.public_key, std::move(peer));
    }

    if (!saw_interface_row) {
        return std::nullopt;
    }

    return snapshot;
}

std::vector<Event> SnapshotDiffer::diff(
    const std::optional<InterfaceSnapshot>& previous,
    const InterfaceSnapshot& current) {
    std::vector<Event> events;

    if (!previous.has_value()) {
        return events;
    }

    for (const auto& [public_key, current_peer] : current.peers) {
        const auto previous_it = previous->peers.find(public_key);
        if (previous_it == previous->peers.end()) {
            events.push_back(Event{
                .type = EventType::PeerObserved,
                .peer_public_key = public_key,
                .endpoint = current_peer.endpoint,
                .allowed_ips = current_peer.allowed_ips,
            });
            if (current_peer.latest_handshake_epoch_sec > 0) {
                events.push_back(Event{
                    .type = EventType::HandshakeObserved,
                    .peer_public_key = public_key,
                    .endpoint = current_peer.endpoint,
                    .allowed_ips = current_peer.allowed_ips,
                });
            }
            continue;
        }

        const auto& previous_peer = previous_it->second;
        if (previous_peer.latest_handshake_epoch_sec == 0 &&
            current_peer.latest_handshake_epoch_sec > 0) {
            events.push_back(Event{
                .type = EventType::HandshakeObserved,
                .peer_public_key = public_key,
                .endpoint = current_peer.endpoint,
                .allowed_ips = current_peer.allowed_ips,
            });
        } else if (
            current_peer.latest_handshake_epoch_sec > previous_peer.latest_handshake_epoch_sec) {
            events.push_back(Event{
                .type = EventType::HandshakeRefreshed,
                .peer_public_key = public_key,
                .endpoint = current_peer.endpoint,
                .allowed_ips = current_peer.allowed_ips,
            });
        }

        if (current_peer.transfer_rx_bytes != previous_peer.transfer_rx_bytes ||
            current_peer.transfer_tx_bytes != previous_peer.transfer_tx_bytes) {
            events.push_back(Event{
                .type = EventType::TrafficUpdated,
                .peer_public_key = public_key,
                .endpoint = current_peer.endpoint,
                .allowed_ips = current_peer.allowed_ips,
            });
        }
    }

    for (const auto& [public_key, previous_peer] : previous->peers) {
        (void)previous_peer;
        if (!current.peers.contains(public_key)) {
            events.push_back(Event{
                .type = EventType::PeerRemoved,
                .peer_public_key = public_key,
                .endpoint = std::nullopt,
                .allowed_ips = {},
            });
        }
    }

    return events;
}

}  // namespace wg_radius::wireguard
