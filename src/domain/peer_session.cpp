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

bool PeerSession::first_handshake_seen() const noexcept {
    return first_handshake_seen_;
}

bool PeerSession::peer_present() const noexcept {
    return peer_present_;
}

const std::optional<std::string>& PeerSession::accounting_session_id() const noexcept {
    return accounting_session_id_;
}

const std::optional<SessionPolicy>& PeerSession::applied_policy() const noexcept {
    return applied_policy_;
}

bool PeerSession::on_peer_observed() {
    mark_peer_present();
    if (state_ != SessionState::Discovered) {
        return false;
    }

    if (trigger_mode_ == AuthorizationTrigger::OnPeerAppearance) {
        move_to_auth_pending();
        return true;
    }

    return false;
}

void PeerSession::seed(bool handshake_seen) {
    mark_peer_present();
    first_handshake_seen_ = handshake_seen;
}

bool PeerSession::on_handshake_observed() {
    mark_peer_present();
    if (state_ == SessionState::Blocked || state_ == SessionState::BlockingPending) {
        return false;
    }

    const bool first_event = !first_handshake_seen_;
    first_handshake_seen_ = true;

    if (first_event && trigger_mode_ == AuthorizationTrigger::OnFirstHandshake &&
        state_ == SessionState::Discovered) {
        move_to_auth_pending();
        return true;
    }

    return false;
}

bool PeerSession::accept(SessionPolicy policy, std::string accounting_session_id) {
    if (state_ != SessionState::AuthPending) {
        return false;
    }

    applied_policy_ = std::move(policy);
    accounting_session_id_ = std::move(accounting_session_id);
    state_ = SessionState::AccountingStartPending;
    return true;
}

bool PeerSession::mark_accounting_started() {
    if (state_ != SessionState::AccountingStartPending) {
        return false;
    }

    state_ = SessionState::Active;
    return true;
}

bool PeerSession::begin_accounting_stop() {
    if (state_ != SessionState::Active) {
        return false;
    }

    state_ = SessionState::AccountingStopPending;
    return true;
}

bool PeerSession::mark_accounting_stopped() {
    if (state_ != SessionState::AccountingStopPending) {
        return false;
    }

    return true;
}

bool PeerSession::begin_block() {
    if (state_ != SessionState::AuthPending) {
        return false;
    }

    applied_policy_.reset();
    accounting_session_id_.reset();
    state_ = SessionState::BlockingPending;
    return true;
}

bool PeerSession::mark_blocked() {
    if (state_ != SessionState::BlockingPending) {
        return false;
    }

    state_ = SessionState::Blocked;
    return true;
}

bool PeerSession::begin_removal() {
    if (state_ != SessionState::AuthPending) {
        return false;
    }

    applied_policy_.reset();
    accounting_session_id_.reset();
    state_ = SessionState::Discovered;
    return true;
}

void PeerSession::observe_peer_removed() {
    peer_present_ = false;
}

void PeerSession::move_to_auth_pending() {
    state_ = SessionState::AuthPending;
}

void PeerSession::mark_peer_present() {
    peer_present_ = true;
}

}  // namespace wg_radius::domain
