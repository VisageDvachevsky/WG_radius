#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace wg_radius::domain {

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

struct SessionPolicy {
    std::optional<std::uint64_t> ingress_bps;
    std::optional<std::uint64_t> egress_bps;
    std::optional<std::chrono::seconds> session_timeout;
};

class PeerSession {
public:
    PeerSession(std::string peer_public_key, AuthorizationTrigger trigger_mode);

    [[nodiscard]] const std::string& peer_public_key() const noexcept;
    [[nodiscard]] AuthorizationTrigger trigger_mode() const noexcept;
    [[nodiscard]] SessionState state() const noexcept;
    [[nodiscard]] bool first_handshake_seen() const noexcept;
    [[nodiscard]] bool peer_present() const noexcept;
    [[nodiscard]] const std::optional<std::string>& accounting_session_id() const noexcept;
    [[nodiscard]] const std::optional<SessionPolicy>& applied_policy() const noexcept;

    [[nodiscard]] bool on_peer_observed();
    void seed(bool handshake_seen);
    [[nodiscard]] bool on_handshake_observed();
    [[nodiscard]] bool accept(SessionPolicy policy, std::string accounting_session_id);
    [[nodiscard]] bool mark_accounting_started();
    [[nodiscard]] bool begin_accounting_stop();
    [[nodiscard]] bool mark_accounting_stopped();
    [[nodiscard]] bool begin_block();
    [[nodiscard]] bool mark_blocked();
    [[nodiscard]] bool begin_removal();
    void observe_peer_removed();

private:
    void move_to_auth_pending();
    void mark_peer_present();

    std::string peer_public_key_;
    AuthorizationTrigger trigger_mode_;
    SessionState state_{SessionState::Discovered};
    bool first_handshake_seen_{false};
    bool peer_present_{true};
    std::optional<std::string> accounting_session_id_;
    std::optional<SessionPolicy> applied_policy_;
};

}  // namespace wg_radius::domain
