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

const std::optional<PeerSession::TimePoint>& PeerSession::last_accounting_update_at() const noexcept {
    return last_accounting_update_at_;
}

const std::optional<PeerSession::TimePoint>& PeerSession::last_handshake_activity_at() const noexcept {
    return last_handshake_activity_at_;
}

const std::optional<PeerSession::TimePoint>& PeerSession::last_traffic_activity_at() const noexcept {
    return last_traffic_activity_at_;
}

const std::optional<PeerSession::TimePoint>& PeerSession::session_started_at() const noexcept {
    return session_started_at_;
}

const std::optional<std::string>& PeerSession::endpoint() const noexcept {
    return endpoint_;
}

const std::vector<std::string>& PeerSession::allowed_ips() const noexcept {
    return allowed_ips_;
}

std::uint64_t PeerSession::transfer_rx_bytes() const noexcept {
    return transfer_rx_bytes_;
}

std::uint64_t PeerSession::transfer_tx_bytes() const noexcept {
    return transfer_tx_bytes_;
}

const std::optional<AccountingStopReason>& PeerSession::stop_reason() const noexcept {
    return stop_reason_;
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

void PeerSession::update_authorization_context(
    std::optional<std::string> endpoint,
    std::vector<std::string> allowed_ips) {
    endpoint_ = std::move(endpoint);
    allowed_ips_ = std::move(allowed_ips);
}

void PeerSession::seed(bool handshake_seen) {
    mark_peer_present();
    first_handshake_seen_ = handshake_seen;
}

void PeerSession::record_snapshot_activity(
    std::uint64_t latest_handshake_epoch_sec,
    std::uint64_t transfer_rx_bytes,
    std::uint64_t transfer_tx_bytes,
    TimePoint now) {
    mark_peer_present();

    if (latest_handshake_epoch_sec > latest_handshake_epoch_sec_) {
        latest_handshake_epoch_sec_ = latest_handshake_epoch_sec;
        last_handshake_activity_at_ = now;
    }

    if (transfer_rx_bytes != transfer_rx_bytes_ || transfer_tx_bytes != transfer_tx_bytes_) {
        transfer_rx_bytes_ = transfer_rx_bytes;
        transfer_tx_bytes_ = transfer_tx_bytes;
        last_traffic_activity_at_ = now;
    }
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

bool PeerSession::mark_accounting_started(TimePoint now) {
    if (state_ != SessionState::AccountingStartPending) {
        return false;
    }

    last_accounting_update_at_ = now;
    session_started_at_ = now;
    stop_reason_.reset();
    state_ = SessionState::Active;
    return true;
}

bool PeerSession::mark_interim_accounting(TimePoint now) {
    if (state_ != SessionState::Active) {
        return false;
    }

    last_accounting_update_at_ = now;
    return true;
}

bool PeerSession::update_policy(SessionPolicy policy) {
    if (state_ != SessionState::Active) {
        return false;
    }

    applied_policy_ = std::move(policy);
    return true;
}

bool PeerSession::begin_accounting_stop(AccountingStopReason reason) {
    if (state_ != SessionState::Active) {
        return false;
    }

    stop_reason_ = reason;
    state_ = SessionState::AccountingStopPending;
    return true;
}

bool PeerSession::mark_accounting_stopped() {
    if (state_ != SessionState::AccountingStopPending) {
        return false;
    }

    last_accounting_update_at_.reset();
    session_started_at_.reset();
    stop_reason_.reset();
    return true;
}

bool PeerSession::begin_block() {
    if (state_ != SessionState::AuthPending) {
        return false;
    }

    applied_policy_.reset();
    accounting_session_id_.reset();
    last_accounting_update_at_.reset();
    session_started_at_.reset();
    stop_reason_.reset();
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
    last_accounting_update_at_.reset();
    session_started_at_.reset();
    stop_reason_.reset();
    state_ = SessionState::Discovered;
    return true;
}

void PeerSession::note_stop_reason(AccountingStopReason reason) {
    stop_reason_ = reason;
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
