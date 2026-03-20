#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wg_radius::domain {

using SessionTimePoint = std::chrono::steady_clock::time_point;

enum class AuthorizationTrigger {
    OnPeerAppearance,
    OnFirstHandshake,
};

enum class RejectMode {
    RemovePeer,
    BlockPeer,
};

enum class SessionState {
    Discovered,
    AuthPending,
    AccountingStartPending,
    Active,
    AccountingStopPending,
    BlockingPending,
    Blocked,
};

enum class AccountingStopReason {
    PeerRemoved,
    InactivityHandshake,
    InactivityTraffic,
    InactivityHandshakeAndTraffic,
    DisconnectRequest,
};

struct SessionPolicy {
    std::optional<std::uint64_t> ingress_bps;
    std::optional<std::uint64_t> egress_bps;
    std::optional<std::chrono::seconds> session_timeout;
};

struct AccountingContext {
    std::optional<std::string> endpoint;
    std::vector<std::string> allowed_ips;
    std::optional<SessionTimePoint> session_started_at;
    std::optional<std::chrono::seconds> session_duration;
    std::uint64_t transfer_rx_bytes{0};
    std::uint64_t transfer_tx_bytes{0};
    std::optional<AccountingStopReason> stop_reason;
};

class PeerSession {
public:
    using TimePoint = SessionTimePoint;

    PeerSession(std::string peer_public_key, AuthorizationTrigger trigger_mode);

    [[nodiscard]] const std::string& peer_public_key() const noexcept;
    [[nodiscard]] AuthorizationTrigger trigger_mode() const noexcept;
    [[nodiscard]] SessionState state() const noexcept;
    [[nodiscard]] bool first_handshake_seen() const noexcept;
    [[nodiscard]] bool peer_present() const noexcept;
    [[nodiscard]] const std::optional<std::string>& accounting_session_id() const noexcept;
    [[nodiscard]] const std::optional<SessionPolicy>& applied_policy() const noexcept;
    [[nodiscard]] const std::optional<TimePoint>& last_accounting_update_at() const noexcept;
    [[nodiscard]] const std::optional<TimePoint>& last_handshake_activity_at() const noexcept;
    [[nodiscard]] const std::optional<TimePoint>& last_traffic_activity_at() const noexcept;
    [[nodiscard]] const std::optional<TimePoint>& session_started_at() const noexcept;
    [[nodiscard]] const std::optional<std::string>& endpoint() const noexcept;
    [[nodiscard]] const std::vector<std::string>& allowed_ips() const noexcept;
    [[nodiscard]] std::uint64_t transfer_rx_bytes() const noexcept;
    [[nodiscard]] std::uint64_t transfer_tx_bytes() const noexcept;
    [[nodiscard]] const std::optional<AccountingStopReason>& stop_reason() const noexcept;

    [[nodiscard]] bool on_peer_observed();
    void update_authorization_context(std::optional<std::string> endpoint, std::vector<std::string> allowed_ips);
    void seed(bool handshake_seen);
    void record_snapshot_activity(
        std::uint64_t latest_handshake_epoch_sec,
        std::uint64_t transfer_rx_bytes,
        std::uint64_t transfer_tx_bytes,
        TimePoint now);
    [[nodiscard]] bool on_handshake_observed();
    [[nodiscard]] bool accept(SessionPolicy policy, std::string accounting_session_id);
    [[nodiscard]] bool mark_accounting_started(TimePoint now = TimePoint{});
    [[nodiscard]] bool mark_interim_accounting(TimePoint now);
    [[nodiscard]] bool update_policy(SessionPolicy policy);
    [[nodiscard]] bool begin_accounting_stop(
        AccountingStopReason reason = AccountingStopReason::PeerRemoved);
    [[nodiscard]] bool mark_accounting_stopped();
    [[nodiscard]] bool begin_block();
    [[nodiscard]] bool mark_blocked();
    [[nodiscard]] bool begin_removal();
    void note_stop_reason(AccountingStopReason reason);
    void observe_peer_removed();

private:
    void move_to_auth_pending();
    void mark_peer_present();

    std::string peer_public_key_;
    AuthorizationTrigger trigger_mode_;
    SessionState state_{SessionState::Discovered};
    bool first_handshake_seen_{false};
    bool peer_present_{true};
    std::uint64_t latest_handshake_epoch_sec_{0};
    std::uint64_t transfer_rx_bytes_{0};
    std::uint64_t transfer_tx_bytes_{0};
    std::optional<std::string> endpoint_;
    std::vector<std::string> allowed_ips_;
    std::optional<std::string> accounting_session_id_;
    std::optional<SessionPolicy> applied_policy_;
    std::optional<TimePoint> last_accounting_update_at_;
    std::optional<TimePoint> last_handshake_activity_at_;
    std::optional<TimePoint> last_traffic_activity_at_;
    std::optional<TimePoint> session_started_at_;
    std::optional<AccountingStopReason> stop_reason_;
};

}  // namespace wg_radius::domain
