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
    PendingAuth,
    Authorized,
    Blocked,
    Terminated,
};

enum class AccountingState {
    NotStarted,
    Started,
    Stopped,
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
    [[nodiscard]] AccountingState accounting_state() const noexcept;
    [[nodiscard]] bool first_handshake_seen() const noexcept;
    [[nodiscard]] const std::optional<SessionPolicy>& applied_policy() const noexcept;

    [[nodiscard]] bool on_peer_discovered();
    [[nodiscard]] bool on_first_handshake();
    [[nodiscard]] bool accept(SessionPolicy policy);
    [[nodiscard]] bool mark_accounting_started();
    [[nodiscard]] bool mark_accounting_stopped();
    [[nodiscard]] bool reject(RejectMode mode);
    [[nodiscard]] bool terminate();

private:
    void move_to_pending_auth();

    std::string peer_public_key_;
    AuthorizationTrigger trigger_mode_;
    SessionState state_{SessionState::Discovered};
    AccountingState accounting_state_{AccountingState::NotStarted};
    bool first_handshake_seen_{false};
    std::optional<SessionPolicy> applied_policy_;
};

}  // namespace wg_radius::domain
