#include "wg_radius/domain/session_manager.hpp"

#include <utility>

namespace wg_radius::domain {

SessionManager::SessionManager(AuthorizationTrigger trigger_mode, RejectMode reject_mode)
    : trigger_mode_(trigger_mode), reject_mode_(reject_mode) {}

std::vector<Command> SessionManager::on_peer_discovered(const std::string& peer_public_key) {
    auto& session = get_or_create_session(peer_public_key);
    if (!session.on_peer_discovered()) {
        return {};
    }

    return {{.type = CommandType::SendAccessRequest, .peer_public_key = peer_public_key, .policy = std::nullopt}};
}

std::vector<Command> SessionManager::on_first_handshake(const std::string& peer_public_key) {
    auto& session = get_or_create_session(peer_public_key);
    if (!session.on_first_handshake()) {
        return {};
    }

    return {{.type = CommandType::SendAccessRequest, .peer_public_key = peer_public_key, .policy = std::nullopt}};
}

std::vector<Command> SessionManager::on_access_accept(
    const std::string& peer_public_key,
    SessionPolicy policy) {
    auto* session = find_session(peer_public_key);
    if (session == nullptr) {
        return {};
    }

    auto& mutable_session = sessions_.at(peer_public_key);
    if (!mutable_session.accept(policy)) {
        return {};
    }

    return {{.type = CommandType::StartAccounting, .peer_public_key = peer_public_key, .policy = std::move(policy)}};
}

std::vector<Command> SessionManager::on_access_reject(const std::string& peer_public_key) {
    auto* session = find_session(peer_public_key);
    if (session == nullptr) {
        return {};
    }

    auto& mutable_session = sessions_.at(peer_public_key);
    if (!mutable_session.reject(reject_mode_)) {
        return {};
    }

    if (reject_mode_ == RejectMode::BlockPeer) {
        return {{.type = CommandType::BlockPeer, .peer_public_key = peer_public_key, .policy = std::nullopt}};
    }

    return {{.type = CommandType::RemovePeer, .peer_public_key = peer_public_key, .policy = std::nullopt}};
}

std::vector<Command> SessionManager::on_accounting_started(const std::string& peer_public_key) {
    auto* session = find_session(peer_public_key);
    if (session == nullptr) {
        return {};
    }

    auto& mutable_session = sessions_.at(peer_public_key);
    if (!mutable_session.mark_accounting_started()) {
        return {};
    }

    return {};
}

std::vector<Command> SessionManager::on_peer_removed(const std::string& peer_public_key) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    const bool had_accounting = it->second.accounting_state() == AccountingState::Started;
    const bool terminated = it->second.terminate();
    (void)terminated;
    if (!had_accounting) {
        if (it->second.state() == SessionState::Terminated) {
            sessions_.erase(it);
        }
        return {};
    }

    auto commands = std::vector<Command>{
        {.type = CommandType::StopAccounting, .peer_public_key = peer_public_key, .policy = std::nullopt}};
    sessions_.erase(it);
    return commands;
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

}  // namespace wg_radius::domain
