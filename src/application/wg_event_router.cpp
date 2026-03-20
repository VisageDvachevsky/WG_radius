#include "wg_radius/application/wg_event_router.hpp"

namespace wg_radius::application {

WgEventRouter::WgEventRouter(domain::SessionManager& session_manager)
    : session_manager_(session_manager) {}

std::vector<domain::Command> WgEventRouter::seed(
    const wireguard::InterfaceSnapshot& snapshot,
    domain::SessionManager::TimePoint now) {
    std::vector<domain::Command> commands;
    for (const auto& [public_key, peer] : snapshot.peers) {
        auto peer_commands = session_manager_.on_peer_seeded(
            public_key,
            peer.latest_handshake_epoch_sec > 0,
            {.endpoint = peer.endpoint, .allowed_ips = peer.allowed_ips},
            peer.latest_handshake_epoch_sec,
            peer.transfer_rx_bytes,
            peer.transfer_tx_bytes,
            now);
        commands.insert(commands.end(), peer_commands.begin(), peer_commands.end());
    }
    return commands;
}

std::vector<domain::Command> WgEventRouter::handle(
    const wireguard::Event& event,
    domain::SessionManager::TimePoint now) {
    session_manager_.record_snapshot_activity(
        event.peer_public_key,
        event.latest_handshake_epoch_sec,
        event.transfer_rx_bytes,
        event.transfer_tx_bytes,
        now);

    switch (event.type) {
        case wireguard::EventType::PeerObserved:
            return session_manager_.on_peer_observed(
                event.peer_public_key,
                {.endpoint = event.endpoint, .allowed_ips = event.allowed_ips});
        case wireguard::EventType::PeerRemoved:
            return session_manager_.on_peer_removed(event.peer_public_key, now);
        case wireguard::EventType::HandshakeObserved:
            return session_manager_.on_handshake_observed(
                event.peer_public_key,
                {.endpoint = event.endpoint, .allowed_ips = event.allowed_ips});
        case wireguard::EventType::HandshakeRefreshed:
        case wireguard::EventType::TrafficUpdated:
            return {};
    }

    return {};
}

}  // namespace wg_radius::application
