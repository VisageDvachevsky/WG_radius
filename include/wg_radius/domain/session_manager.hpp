#pragma once

#include "wg_radius/domain/peer_session.hpp"

#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace wg_radius::domain {

enum class CommandType {
    SendAccessRequest,
    StartAccounting,
    StopAccounting,
    RemovePeer,
    BlockPeer,
};

struct Command {
    CommandType type;
    std::string peer_public_key;
    std::optional<SessionPolicy> policy;
};

class SessionManager {
public:
    SessionManager(AuthorizationTrigger trigger_mode, RejectMode reject_mode);

    [[nodiscard]] std::vector<Command> on_peer_discovered(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_first_handshake(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_access_accept(
        const std::string& peer_public_key,
        SessionPolicy policy);
    [[nodiscard]] std::vector<Command> on_access_reject(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_accounting_started(const std::string& peer_public_key);
    [[nodiscard]] std::vector<Command> on_peer_removed(const std::string& peer_public_key);

    [[nodiscard]] const PeerSession* find_session(const std::string& peer_public_key) const;

private:
    [[nodiscard]] PeerSession& get_or_create_session(const std::string& peer_public_key);

    AuthorizationTrigger trigger_mode_;
    RejectMode reject_mode_;
    std::unordered_map<std::string, PeerSession> sessions_;
};

}  // namespace wg_radius::domain
