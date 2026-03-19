#pragma once

#include "wg_radius/domain/peer_session.hpp"

#include <optional>
#include <string>
#include <vector>

namespace wg_radius::radius {

struct AuthorizationRequest {
    std::string interface_name;
    std::string peer_public_key;
    std::optional<std::string> endpoint;
    std::vector<std::string> allowed_ips;
    std::string nas_identifier;
    std::optional<std::string> nas_ip_address;
    std::string calling_station_id;
    std::string user_name;
};

enum class AccountingEventType {
    Start,
    InterimUpdate,
    Stop,
};

struct AccountingRequest {
    AccountingEventType event_type;
    std::string interface_name;
    std::string peer_public_key;
    std::string accounting_session_id;
    std::optional<std::string> endpoint;
    std::optional<std::string> framed_ip_address;
    std::optional<std::chrono::seconds> session_duration;
    std::uint64_t transfer_rx_bytes{0};
    std::uint64_t transfer_tx_bytes{0};
    std::optional<domain::AccountingStopReason> stop_reason;
};

enum class AuthorizationDecision {
    Accept,
    Reject,
    Error,
};

struct AuthorizationResponse {
    AuthorizationDecision decision;
    std::optional<domain::SessionPolicy> policy;
};

class RadiusClient {
public:
    virtual ~RadiusClient() = default;

    [[nodiscard]] virtual AuthorizationResponse authorize(
        const AuthorizationRequest& request) = 0;
    [[nodiscard]] virtual bool account(const AccountingRequest& request) = 0;
};

}  // namespace wg_radius::radius
