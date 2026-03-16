#pragma once

#include "wg_radius/wireguard/wireguard_client.hpp"

#include <memory>

struct nl_sock;

namespace wg_radius::wireguard {

class NetlinkWireGuardClient final : public WireGuardClient {
public:
    NetlinkWireGuardClient();
    ~NetlinkWireGuardClient() override;

    NetlinkWireGuardClient(const NetlinkWireGuardClient&) = delete;
    NetlinkWireGuardClient& operator=(const NetlinkWireGuardClient&) = delete;

    NetlinkWireGuardClient(NetlinkWireGuardClient&&) noexcept;
    NetlinkWireGuardClient& operator=(NetlinkWireGuardClient&&) noexcept;

    [[nodiscard]] std::optional<InterfaceSnapshot> fetch_interface_snapshot(
        const std::string& interface_name) override;

private:
    struct Deleter {
        void operator()(nl_sock* socket) const noexcept;
    };

    std::unique_ptr<nl_sock, Deleter> socket_;
    int family_id_{-1};
};

}  // namespace wg_radius::wireguard
