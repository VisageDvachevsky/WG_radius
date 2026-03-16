#include "wg_radius/application/wg_event_router.hpp"

namespace wg_radius::application {

WgEventRouter::WgEventRouter(domain::SessionManager& session_manager)
    : session_manager_(session_manager) {}

void WgEventRouter::seed(const wireguard::InterfaceSnapshot& snapshot) {
    for (const auto& [public_key, peer] : snapshot.peers) {
        session_manager_.on_peer_seeded(public_key, peer.latest_handshake_epoch_sec > 0);
    }
}

std::vector<domain::Command> WgEventRouter::handle(const wireguard::Event& event) {
    switch (event.type) {
        case wireguard::EventType::PeerObserved:
            return session_manager_.on_peer_observed(event.peer_public_key);
        case wireguard::EventType::PeerRemoved:
            return session_manager_.on_peer_removed(event.peer_public_key);
        case wireguard::EventType::HandshakeObserved:
            return session_manager_.on_handshake_observed(event.peer_public_key);
        case wireguard::EventType::TrafficUpdated:
            return {};
    }

    return {};
}

}  // namespace wg_radius::application
