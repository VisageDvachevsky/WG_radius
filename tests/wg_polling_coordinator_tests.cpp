#include "wg_radius/application/wg_polling_coordinator.hpp"

#include "test_harness.hpp"

#include <deque>
#include <optional>
#include <string>

using namespace wg_radius;

namespace {

class FakeWireGuardClient final : public wireguard::WireGuardClient {
public:
    std::deque<std::optional<wireguard::InterfaceSnapshot>> snapshots;

    std::optional<wireguard::InterfaceSnapshot> fetch_interface_snapshot(
        const std::string& interface_name) override {
        last_interface_name = interface_name;
        if (snapshots.empty()) {
            return std::nullopt;
        }

        auto snapshot = snapshots.front();
        snapshots.pop_front();
        return snapshot;
    }

    std::string last_interface_name;
};

wireguard::InterfaceSnapshot make_snapshot(
    const std::string& interface_name,
    std::initializer_list<wireguard::PeerSnapshot> peers) {
    wireguard::InterfaceSnapshot snapshot{.interface_name = interface_name, .peers = {}};
    for (const auto& peer : peers) {
        snapshot.peers.emplace(peer.public_key, peer);
    }

    return snapshot;
}

}  // namespace

TEST_CASE(polling_coordinator_fetches_requested_interface) {
    FakeWireGuardClient client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", client, router};

    client.snapshots.push_back(make_snapshot("wg0", {}));

    const auto result = coordinator.poll();
    EXPECT_EQ(result.status, application::PollStatus::Seeded);
    EXPECT_TRUE(result.commands.empty());
    EXPECT_EQ(client.last_interface_name, "wg0");
}

TEST_CASE(polling_coordinator_seeds_initial_snapshot_without_commands) {
    FakeWireGuardClient client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", client, router};

    client.snapshots.push_back(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-a",
            .endpoint = std::make_optional<std::string>("198.51.100.10:12345"),
            .allowed_ips = {"10.0.0.2/32"},
            .latest_handshake_epoch_sec = 0,
            .transfer_rx_bytes = 0,
            .transfer_tx_bytes = 0,
        }}));

    const auto result = coordinator.poll();

    EXPECT_EQ(result.status, application::PollStatus::Seeded);
    EXPECT_TRUE(result.commands.empty());
}

TEST_CASE(polling_coordinator_emits_access_request_for_runtime_handshake_after_seed) {
    FakeWireGuardClient client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnFirstHandshake,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", client, router};

    client.snapshots.push_back(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-a",
            .endpoint = std::make_optional<std::string>("198.51.100.10:12345"),
            .allowed_ips = {"10.0.0.2/32"},
            .latest_handshake_epoch_sec = 0,
            .transfer_rx_bytes = 0,
            .transfer_tx_bytes = 0,
        }}));
    EXPECT_EQ(coordinator.poll().status, application::PollStatus::Seeded);

    client.snapshots.push_back(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-a",
            .endpoint = std::make_optional<std::string>("198.51.100.10:12345"),
            .allowed_ips = {"10.0.0.2/32"},
            .latest_handshake_epoch_sec = 1710000000,
            .transfer_rx_bytes = 0,
            .transfer_tx_bytes = 0,
        }}));

    const auto result = coordinator.poll();

    EXPECT_EQ(result.status, application::PollStatus::CommandsProduced);
    EXPECT_EQ(result.commands.size(), 1U);
    EXPECT_EQ(result.commands.front().type, domain::CommandType::SendAccessRequest);
    EXPECT_EQ(result.commands.front().peer_public_key, "peer-a");
}

TEST_CASE(polling_coordinator_reports_snapshot_fetch_failure) {
    FakeWireGuardClient client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", client, router};

    client.snapshots.push_back(std::nullopt);

    const auto result = coordinator.poll();

    EXPECT_EQ(result.status, application::PollStatus::SnapshotUnavailable);
    EXPECT_TRUE(result.commands.empty());
}

TEST_CASE(polling_coordinator_reports_interface_mismatch) {
    FakeWireGuardClient client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", client, router};

    client.snapshots.push_back(make_snapshot("wg999", {}));

    const auto result = coordinator.poll();

    EXPECT_EQ(result.status, application::PollStatus::InterfaceMismatch);
    EXPECT_TRUE(result.commands.empty());
}

TEST_CASE(polling_coordinator_turns_peer_removal_into_stop_accounting_after_activation) {
    FakeWireGuardClient client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", client, router};

    client.snapshots.push_back(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-a",
            .endpoint = std::make_optional<std::string>("198.51.100.10:12345"),
            .allowed_ips = {"10.0.0.2/32"},
            .latest_handshake_epoch_sec = 0,
            .transfer_rx_bytes = 0,
            .transfer_tx_bytes = 0,
        }}));
    EXPECT_EQ(coordinator.poll().status, application::PollStatus::Seeded);
    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", domain::SessionPolicy{}).size(), 2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());

    client.snapshots.push_back(make_snapshot("wg0", {}));

    const auto result = coordinator.poll();

    EXPECT_EQ(result.status, application::PollStatus::CommandsProduced);
    EXPECT_EQ(result.commands.size(), 1U);
    EXPECT_EQ(result.commands.front().type, domain::CommandType::StopAccounting);
    EXPECT_EQ(result.commands.front().peer_public_key, "peer-a");
}
