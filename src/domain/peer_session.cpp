#include "wg_radius/domain/peer_session.hpp"

namespace wg_radius::domain {

PeerSession::PeerSession(std::string peer_public_key, AuthorizationTrigger trigger_mode)
    : peer_public_key_(std::move(peer_public_key)), trigger_mode_(trigger_mode) {}

const std::string& PeerSession::peer_public_key() const noexcept {
    return peer_public_key_;
}

AuthorizationTrigger PeerSession::trigger_mode() const noexcept {
    return trigger_mode_;
}

SessionState PeerSession::state() const noexcept {
    return state_;
}

AccountingState PeerSession::accounting_state() const noexcept {
    return accounting_state_;
}

bool PeerSession::first_handshake_seen() const noexcept {
    return first_handshake_seen_;
}

const std::optional<SessionPolicy>& PeerSession::applied_policy() const noexcept {
    return applied_policy_;
}

bool PeerSession::on_peer_discovered() {
    if (state_ != SessionState::Discovered) {
        return false;
    }

    if (trigger_mode_ == AuthorizationTrigger::OnPeerAppearance) {
        move_to_pending_auth();
        return true;
    }

    return false;
}

bool PeerSession::on_first_handshake() {
    if (state_ == SessionState::Blocked || state_ == SessionState::Terminated) {
        return false;
    }

    const bool first_event = !first_handshake_seen_;
    first_handshake_seen_ = true;

    if (first_event && trigger_mode_ == AuthorizationTrigger::OnFirstHandshake &&
        state_ == SessionState::Discovered) {
        move_to_pending_auth();
        return true;
    }

    return false;
}

bool PeerSession::accept(SessionPolicy policy) {
    if (state_ != SessionState::PendingAuth) {
        return false;
    }

    applied_policy_ = std::move(policy);
    state_ = SessionState::Authorized;
    accounting_state_ = AccountingState::NotStarted;
    return true;
}

bool PeerSession::mark_accounting_started() {
    if (state_ != SessionState::Authorized || accounting_state_ != AccountingState::NotStarted) {
        return false;
    }

    accounting_state_ = AccountingState::Started;
    return true;
}

bool PeerSession::mark_accounting_stopped() {
    if (accounting_state_ != AccountingState::Started) {
        return false;
    }

    accounting_state_ = AccountingState::Stopped;
    return true;
}

bool PeerSession::reject(RejectMode mode) {
    if (state_ != SessionState::PendingAuth) {
        return false;
    }

    applied_policy_.reset();
    accounting_state_ = AccountingState::NotStarted;
    state_ = mode == RejectMode::BlockPeer ? SessionState::Blocked : SessionState::Terminated;
    return true;
}

bool PeerSession::terminate() {
    if (state_ == SessionState::Terminated) {
        return false;
    }

    state_ = SessionState::Terminated;
    if (accounting_state_ == AccountingState::Started) {
        accounting_state_ = AccountingState::Stopped;
    }
    return true;
}

void PeerSession::move_to_pending_auth() {
    state_ = SessionState::PendingAuth;
}

}  // namespace wg_radius::domain
