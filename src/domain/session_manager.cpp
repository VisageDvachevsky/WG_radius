#include "wg_radius/domain/session_manager.hpp"

#include <algorithm>
#include <utility>

namespace wg_radius::domain {

namespace {

bool inactivity_elapsed(
    const std::optional<PeerSession::TimePoint>& activity_at,
    SessionManager::TimePoint now,
    std::chrono::seconds timeout) {
    return activity_at.has_value() && now - *activity_at >= timeout;
}

}  // namespace

SessionManager::SessionManager(AuthorizationTrigger trigger_mode, RejectMode reject_mode)
    : SessionManager(trigger_mode, reject_mode, AccountingPolicy{}) {}

SessionManager::SessionManager(
    AuthorizationTrigger trigger_mode,
    RejectMode reject_mode,
    AccountingPolicy accounting_policy)
    : trigger_mode_(trigger_mode),
      reject_mode_(reject_mode),
      accounting_policy_(std::move(accounting_policy)) {}

std::vector<Command> SessionManager::on_peer_seeded(
    const std::string& peer_public_key,
    bool handshake_seen,
    AuthorizationContext context,
    std::uint64_t latest_handshake_epoch_sec,
    std::uint64_t transfer_rx_bytes,
    std::uint64_t transfer_tx_bytes,
    TimePoint now) {
    auto& session = get_or_create_session(peer_public_key);
    session.update_authorization_context(context.endpoint, context.allowed_ips);
    session.record_snapshot_activity(
        latest_handshake_epoch_sec,
        transfer_rx_bytes,
        transfer_tx_bytes,
        now);

    bool should_authorize = false;
    if (trigger_mode_ == AuthorizationTrigger::OnPeerAppearance) {
        session.seed(handshake_seen);
        should_authorize = session.on_peer_observed();
    } else if (handshake_seen) {
        should_authorize = session.on_handshake_observed();
    } else {
        session.seed(false);
    }

    if (!should_authorize) {
        return {};
    }

    return {{.type = CommandType::SendAccessRequest,
             .peer_public_key = peer_public_key,
             .accounting_session_id = std::nullopt,
             .policy = std::nullopt,
             .authorization_context = std::move(context)}};
}

void SessionManager::record_snapshot_activity(
    const std::string& peer_public_key,
    std::uint64_t latest_handshake_epoch_sec,
    std::uint64_t transfer_rx_bytes,
    std::uint64_t transfer_tx_bytes,
    TimePoint now) {
    auto& session = get_or_create_session(peer_public_key);
    session.record_snapshot_activity(
        latest_handshake_epoch_sec,
        transfer_rx_bytes,
        transfer_tx_bytes,
        now);
}

std::vector<Command> SessionManager::on_peer_observed(
    const std::string& peer_public_key,
    AuthorizationContext context) {
    auto& session = get_or_create_session(peer_public_key);
    session.update_authorization_context(context.endpoint, context.allowed_ips);
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
    it->second.update_authorization_context(context.endpoint, context.allowed_ips);

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
         .authorization_context = std::nullopt,
         .accounting_context = make_accounting_context(it->second)});
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
                 .authorization_context = std::nullopt,
                 .accounting_context = std::nullopt}};
    }

    if (!it->second.begin_removal()) {
        return {};
    }
    return {{.type = CommandType::RemovePeer,
             .peer_public_key = peer_public_key,
             .accounting_session_id = std::nullopt,
             .policy = std::nullopt,
             .authorization_context = std::nullopt,
             .accounting_context = std::nullopt}};
}

std::vector<Command> SessionManager::on_disconnect_request(const std::string& peer_public_key) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end() || !it->second.peer_present()) {
        return {};
    }

    it->second.note_stop_reason(AccountingStopReason::DisconnectRequest);

    return {{.type = CommandType::RemovePeer,
             .peer_public_key = peer_public_key,
             .accounting_session_id = std::nullopt,
             .policy = std::nullopt,
             .authorization_context = std::nullopt,
             .accounting_context = std::nullopt}};
}

std::vector<Command> SessionManager::on_accounting_started(
    const std::string& peer_public_key,
    TimePoint now) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    if (!it->second.mark_accounting_started(now)) {
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

std::vector<Command> SessionManager::on_peer_removed(const std::string& peer_public_key, TimePoint now) {
    auto it = sessions_.find(peer_public_key);
    if (it == sessions_.end()) {
        return {};
    }

    it->second.observe_peer_removed();

    if (it->second.state() == SessionState::Active) {
        const auto stop_reason = it->second.stop_reason().value_or(AccountingStopReason::PeerRemoved);
        if (!it->second.begin_accounting_stop(stop_reason)) {
            return {};
        }
        return {{.type = CommandType::StopAccounting,
                 .peer_public_key = peer_public_key,
                 .accounting_session_id = it->second.accounting_session_id(),
                 .policy = std::nullopt,
                 .authorization_context = std::nullopt,
                 .accounting_context = make_accounting_context(it->second, now)}};
    }

    if (it->second.state() == SessionState::AccountingStopPending) {
        return {};
    }

    sessions_.erase(it);
    return {};
}

std::vector<Command> SessionManager::on_timer(TimePoint now) {
    std::vector<Command> commands;

    for (auto& [peer_public_key, session] : sessions_) {
        if (session.state() != SessionState::Active || !session.accounting_session_id().has_value()) {
            continue;
        }

        if (accounting_policy_.inactive_timeout.has_value()) {
            const auto timeout = *accounting_policy_.inactive_timeout;
            const bool handshake_inactive =
                inactivity_elapsed(session.last_handshake_activity_at(), now, timeout);
            const bool traffic_inactive =
                inactivity_elapsed(session.last_traffic_activity_at(), now, timeout);

            bool should_stop = false;
            switch (accounting_policy_.inactivity_strategy) {
                case config::InactivityStrategy::HandshakeOnly:
                    should_stop = handshake_inactive;
                    break;
                case config::InactivityStrategy::TrafficOnly:
                    should_stop = traffic_inactive;
                    break;
                case config::InactivityStrategy::HandshakeAndTraffic:
                    should_stop = handshake_inactive && traffic_inactive;
                    break;
            }

            auto stop_reason = AccountingStopReason::InactivityHandshake;
            switch (accounting_policy_.inactivity_strategy) {
                case config::InactivityStrategy::HandshakeOnly:
                    stop_reason = AccountingStopReason::InactivityHandshake;
                    break;
                case config::InactivityStrategy::TrafficOnly:
                    stop_reason = AccountingStopReason::InactivityTraffic;
                    break;
                case config::InactivityStrategy::HandshakeAndTraffic:
                    stop_reason = AccountingStopReason::InactivityHandshakeAndTraffic;
                    break;
            }

            if (should_stop && session.begin_accounting_stop(stop_reason)) {
                commands.push_back(
                    {.type = CommandType::StopAccounting,
                     .peer_public_key = peer_public_key,
                     .accounting_session_id = session.accounting_session_id(),
                     .policy = std::nullopt,
                     .authorization_context = std::nullopt,
                     .accounting_context = make_accounting_context(session, now)});
                continue;
            }
        }

        if (!accounting_policy_.acct_interim_interval.has_value() ||
            !session.last_accounting_update_at().has_value()) {
            continue;
        }

        if (now - *session.last_accounting_update_at() >= *accounting_policy_.acct_interim_interval &&
            session.mark_interim_accounting(now)) {
            commands.push_back(
                {.type = CommandType::InterimAccounting,
                 .peer_public_key = peer_public_key,
                 .accounting_session_id = session.accounting_session_id(),
                 .policy = std::nullopt,
                 .authorization_context = std::nullopt,
                 .accounting_context = make_accounting_context(session, now)});
        }
    }

    return commands;
}

std::optional<AccountingContext> SessionManager::make_accounting_context(
    const PeerSession& session,
    std::optional<TimePoint> now) const {
    std::optional<std::chrono::seconds> session_duration;
    if (now.has_value() && session.session_started_at().has_value()) {
        session_duration = std::chrono::duration_cast<std::chrono::seconds>(*now - *session.session_started_at());
    }

    return AccountingContext{
        .endpoint = session.endpoint(),
        .allowed_ips = session.allowed_ips(),
        .session_started_at = session.session_started_at(),
        .session_duration = session_duration,
        .transfer_rx_bytes = session.transfer_rx_bytes(),
        .transfer_tx_bytes = session.transfer_tx_bytes(),
        .stop_reason = session.stop_reason(),
    };
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
