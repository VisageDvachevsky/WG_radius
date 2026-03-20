#pragma once

#include "wg_radius/config/config.hpp"
#include "wg_radius/domain/peer_session.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace wg_radius::domain {

enum class CommandType {
    SendAccessRequest,
    ApplySessionPolicy,
    StartAccounting,
    InterimAccounting,
    StopAccounting,
    RemovePeer,
    BlockPeer,
};

struct AuthorizationContext {
    std::optional<std::string> endpoint;
    std::vector<std::string> allowed_ips;
};

struct Command {
    CommandType type;
    std::string peer_public_key;
    std::optional<std::string> accounting_session_id;
    std::optional<SessionPolicy> policy;
    std::optional<AuthorizationContext> authorization_context;
    std::optional<AccountingContext> accounting_context;
};

class SessionManager {
public:
    struct AccountingPolicy {
        std::optional<std::chrono::seconds> acct_interim_interval;
        std::optional<std::chrono::seconds> inactive_timeout;
        config::InactivityStrategy inactivity_strategy{config::InactivityStrategy::HandshakeOnly};
    };

    using TimePoint = std::chrono::steady_clock::time_point;

    SessionManager(AuthorizationTrigger trigger_mode, RejectMode reject_mode);
    SessionManager(
        AuthorizationTrigger trigger_mode,
        RejectMode reject_mode,
        AccountingPolicy accounting_policy);

    [[nodiscard]] std::vector<Command> on_peer_seeded(
        const std::string& peer_public_key,
        bool handshake_seen,
        AuthorizationContext context,
        std::uint64_t latest_handshake_epoch_sec,
        std::uint64_t transfer_rx_bytes,
        std::uint64_t transfer_tx_bytes,
        TimePoint now = TimePoint{});
    void record_snapshot_activity(
        const std::string& peer_public_key,
        std::uint64_t latest_handshake_epoch_sec,
        std::uint64_t transfer_rx_bytes,
        std::uint64_t transfer_tx_bytes,
        TimePoint now);
    [[nodiscard]] std::vector<Command> on_peer_observed(
        const std::string& peer_public_key,
        AuthorizationContext context);
    [[nodiscard]] std::vector<Command> on_handshake_observed(
        const std::string& peer_public_key,
        AuthorizationContext context);
    [[nodiscard]] std::vector<Command> on_access_accept(
        const std::string& peer_public_key,
        SessionPolicy policy);
    [[nodiscard]] std::vector<Command> on_access_reject(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_disconnect_request(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_accounting_started(
        const std::string& peer_public_key,
        TimePoint now = TimePoint{});
    [[nodiscard]] std::vector<Command> on_accounting_stopped(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_peer_blocked(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_peer_removed(
        const std::string& peer_public_key,
        TimePoint now = TimePoint{});
    [[nodiscard]] std::vector<Command> on_timer(TimePoint now);

    [[nodiscard]] const PeerSession* find_session(const std::string& peer_public_key) const;

private:
    [[nodiscard]] std::string generate_accounting_session_id(const std::string& peer_public_key);
    [[nodiscard]] std::optional<AccountingContext> make_accounting_context(
        const PeerSession& session,
        std::optional<TimePoint> now = std::nullopt) const;
    [[nodiscard]] PeerSession& get_or_create_session(const std::string& peer_public_key);

    AuthorizationTrigger trigger_mode_;
    RejectMode reject_mode_;
    AccountingPolicy accounting_policy_;
    std::uint64_t next_session_id_{1};
    std::unordered_map<std::string, PeerSession> sessions_;
};

}  // namespace wg_radius::domain
