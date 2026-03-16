#pragma once

#include "wg_radius/domain/peer_session.hpp"

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace wg_radius::domain {

enum class CommandType {
    SendAccessRequest,
    ApplySessionPolicy,
    StartAccounting,
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
};

class SessionManager {
public:
    SessionManager(AuthorizationTrigger trigger_mode, RejectMode reject_mode);

    void on_peer_seeded(const std::string& peer_public_key, bool handshake_seen);
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
    [[nodiscard]] std::vector<Command> on_accounting_started(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_accounting_stopped(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_peer_blocked(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_peer_removed(const std::string& peer_public_key);

    [[nodiscard]] const PeerSession* find_session(const std::string& peer_public_key) const;

private:
    [[nodiscard]] std::string generate_accounting_session_id(const std::string& peer_public_key);
    [[nodiscard]] PeerSession& get_or_create_session(const std::string& peer_public_key);

    AuthorizationTrigger trigger_mode_;
    RejectMode reject_mode_;
    std::uint64_t next_session_id_{1};
    std::unordered_map<std::string, PeerSession> sessions_;
};

}  // namespace wg_radius::domain
