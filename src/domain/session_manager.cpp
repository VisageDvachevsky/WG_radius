#include "wg_radius/domain/session_manager.hpp"

#include <utility>

namespace wg_radius::domain {

SessionManager::SessionManager(AuthorizationTrigger trigger_mode, RejectMode reject_mode)
    : trigger_mode_(trigger_mode), reject_mode_(reject_mode) {}

void SessionManager::on_peer_seeded(const std::string& peer_public_key, bool handshake_seen) {
    auto& session = get_or_create_session(peer_public_key);
    session.seed(handshake_seen);
}

std::vector<Command> SessionManager::on_peer_observed(
    const std::string& peer_public_key,
    AuthorizationContext context) {
    auto& session = get_or_create_session(peer_public_key);
    if (!session.on_peer_observed()) {
        return {};
    }

    return {{.type = CommandType::SendAccessRequest,
             .peer_public_key = peer_public_key,
             .accounting_session_id = std::nullopt,
             .policy = std::nullopt,
             .authorization_context = std::move(context)}};
}

std::vector<Command> SessionManager::on_handshake_observed(
    const std::string& peer_public_key,
    AuthorizationContext context) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    if (!it->second.on_handshake_observed()) {
        return {};
    }

    return {{.type = CommandType::SendAccessRequest,
             .peer_public_key = peer_public_key,
             .accounting_session_id = std::nullopt,
             .policy = std::nullopt,
             .authorization_context = std::move(context)}};
}

std::vector<Command> SessionManager::on_access_accept(
    const std::string& peer_public_key,
    SessionPolicy policy) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    const auto accounting_session_id = generate_accounting_session_id(peer_public_key);
    if (!it->second.accept(policy, accounting_session_id)) {
        return {};
    }

    std::vector<Command> commands;
    commands.push_back(
        {.type = CommandType::ApplySessionPolicy,
         .peer_public_key = peer_public_key,
         .accounting_session_id = accounting_session_id,
         .policy = policy,
         .authorization_context = std::nullopt});
    commands.push_back(
        {.type = CommandType::StartAccounting,
         .peer_public_key = peer_public_key,
         .accounting_session_id = accounting_session_id,
         .policy = std::move(policy),
         .authorization_context = std::nullopt});
    return commands;
}

std::vector<Command> SessionManager::on_access_reject(const std::string& peer_public_key) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    if (reject_mode_ == RejectMode::BlockPeer) {
        if (!it->second.begin_block()) {
            return {};
        }
        return {{.type = CommandType::BlockPeer,
                 .peer_public_key = peer_public_key,
                 .accounting_session_id = std::nullopt,
                 .policy = std::nullopt,
                 .authorization_context = std::nullopt}};
    }

    if (!it->second.begin_removal()) {
        return {};
    }
    return {{.type = CommandType::RemovePeer,
             .peer_public_key = peer_public_key,
             .accounting_session_id = std::nullopt,
             .policy = std::nullopt,
             .authorization_context = std::nullopt}};
}

std::vector<Command> SessionManager::on_accounting_started(const std::string& peer_public_key) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    if (!it->second.mark_accounting_started()) {
        return {};
    }

    return {};
}

std::vector<Command> SessionManager::on_accounting_stopped(const std::string& peer_public_key) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    if (!it->second.mark_accounting_stopped()) {
        return {};
    }

    sessions_.erase(it);
    return {};
}

std::vector<Command> SessionManager::on_peer_blocked(const std::string& peer_public_key) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    if (!it->second.mark_blocked()) {
        return {};
    }

    return {};
}

std::vector<Command> SessionManager::on_peer_removed(const std::string& peer_public_key) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    it->second.observe_peer_removed();

    if (it->second.state() == SessionState::Active) {
        if (!it->second.begin_accounting_stop()) {
            return {};
        }
        return {{.type = CommandType::StopAccounting,
                 .peer_public_key = peer_public_key,
                 .accounting_session_id = it->second.accounting_session_id(),
                 .policy = std::nullopt,
                 .authorization_context = std::nullopt}};
    }

    if (it->second.state() == SessionState::AccountingStopPending) {
        return {};
    }

    sessions_.erase(it);
    return {};
}

const PeerSession* SessionManager::find_session(const std::string& peer_public_key) const {
    const auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return nullptr;
    }

    return &it->second;
}

PeerSession& SessionManager::get_or_create_session(const std::string& peer_public_key) {
    auto [it, inserted] =
        sessions_.emplace(peer_public_key, PeerSession{peer_public_key, trigger_mode_});
    (void)inserted;
    return it->second;
}

std::string SessionManager::generate_accounting_session_id(const std::string& peer_public_key) {
    const auto short_key = peer_public_key.substr(0, std::min<std::size_t>(12, peer_public_key.size()));
    return short_key + "-" + std::to_string(next_session_id_++);
}

}  // namespace wg_radius::domain
