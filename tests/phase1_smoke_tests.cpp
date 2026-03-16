#include "wg_radius/application/async_auth_command_processor.hpp"
#include "wg_radius/application/auth_command_processor.hpp"
#include "wg_radius/application/command_executor.hpp"
#include "wg_radius/application/profile_runtime.hpp"
#include "wg_radius/application/wg_event_router.hpp"
#include "wg_radius/application/wg_polling_coordinator.hpp"

#include "test_harness.hpp"

#include <chrono>
#include <optional>
#include <queue>
#include <thread>

using namespace wg_radius;

namespace {

const radius::RadiusProfile kRadiusProfile{
    .auth_server = {"127.0.0.1", 1812},
    .accounting_server = {"127.0.0.1", 1813},
    .shared_secret = "secret",
    .timeout = std::chrono::seconds{5},
    .retries = 3,
    .nas_identifier = "wg-smoke",
    .nas_ip_address = std::nullopt,
};

class FakeRadiusClient final : public radius::RadiusClient {
public:
    radius::AuthorizationResponse next_auth_response{
        .decision = radius::AuthorizationDecision::Accept,
        .policy = domain::SessionPolicy{
            .ingress_bps = 10'000,
            .egress_bps = 20'000,
            .session_timeout = std::chrono::seconds{3600},
        },
    };
    std::vector<radius::AuthorizationRequest> auth_requests;
    std::vector<radius::AccountingRequest> accounting_requests;

    radius::AuthorizationResponse authorize(const radius::AuthorizationRequest& request) override {
        auth_requests.push_back(request);
        return next_auth_response;
    }

    bool account(const radius::AccountingRequest& request) override {
        accounting_requests.push_back(request);
        return true;
    }
};

class FakePeerController final : public wireguard::PeerController {
public:
    std::vector<std::string> removed_peers;

    bool remove_peer(const std::string&, const std::string& peer_public_key) override {
        removed_peers.push_back(peer_public_key);
        return true;
    }
};

class FakeTrafficShaper final : public shaping::TrafficShaper {
public:
    std::vector<std::string> shaped_peers;

    bool apply_policy(const std::string&, const std::string& peer_public_key, const domain::SessionPolicy&) override {
        shaped_peers.push_back(peer_public_key);
        return true;
    }
};

class FakeWireGuardClient final : public wireguard::WireGuardClient {
public:
    std::queue<std::optional<wireguard::InterfaceSnapshot>> snapshots;

    std::optional<wireguard::InterfaceSnapshot> fetch_interface_snapshot(const std::string&) override {
        if (snapshots.empty()) {
            return std::nullopt;
        }

        auto snapshot = snapshots.front();
        snapshots.pop();
        return snapshot;
    }
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

template <typename Predicate>
void spin_until(Predicate&& predicate) {
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (predicate()) {
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}

}  // namespace

TEST_CASE(phase1_smoke_accept_path_authorizes_applies_policy_and_starts_accounting) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    application::AuthCommandProcessor auth_processor{"wg0", kRadiusProfile, manager, radius_client};
    application::AsyncAuthCommandProcessor async_processor{auth_processor};
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, async_processor, manager, executor};

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(runtime.step().poll_status, application::PollStatus::Seeded);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-a",
            .endpoint = std::string{"198.51.100.10:12345"},
            .allowed_ips = {"10.0.0.2/32"},
            .latest_handshake_epoch_sec = 1710000001,
            .transfer_rx_bytes = 100,
            .transfer_tx_bytes = 200,
        }}));
    const auto submit_result = runtime.step();

    EXPECT_EQ(submit_result.poll_status, application::PollStatus::CommandsProduced);
    EXPECT_EQ(submit_result.auth_commands_submitted, 1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-a",
                .endpoint = std::string{"198.51.100.10:12345"},
                .allowed_ips = {"10.0.0.2/32"},
                .latest_handshake_epoch_sec = 1710000001,
                .transfer_rx_bytes = 100,
                .transfer_tx_bytes = 200,
            }}));
        const auto result = runtime.step();
        return result.auth_results_processed == 1U;
    });

    EXPECT_EQ(radius_client.auth_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.front().event_type, radius::AccountingEventType::Start);
    EXPECT_EQ(traffic_shaper.shaped_peers.size(), 1U);
    EXPECT_EQ(traffic_shaper.shaped_peers.front(), "peer-a");
    EXPECT_TRUE(manager.find_session("peer-a") != nullptr);
    EXPECT_EQ(manager.find_session("peer-a")->state(), domain::SessionState::Active);
}

TEST_CASE(phase1_smoke_reject_remove_path_removes_peer_without_accounting_start) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    radius_client.next_auth_response = {
        .decision = radius::AuthorizationDecision::Reject,
        .policy = std::nullopt,
    };
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    application::AuthCommandProcessor auth_processor{"wg0", kRadiusProfile, manager, radius_client};
    application::AsyncAuthCommandProcessor async_processor{auth_processor};
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, async_processor, manager, executor};

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(runtime.step().poll_status, application::PollStatus::Seeded);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-b",
            .endpoint = std::nullopt,
            .allowed_ips = {"10.0.0.3/32"},
            .latest_handshake_epoch_sec = 0,
            .transfer_rx_bytes = 0,
            .transfer_tx_bytes = 0,
        }}));
    EXPECT_EQ(runtime.step().auth_commands_submitted, 1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-b",
                .endpoint = std::nullopt,
                .allowed_ips = {"10.0.0.3/32"},
                .latest_handshake_epoch_sec = 0,
                .transfer_rx_bytes = 0,
                .transfer_tx_bytes = 0,
            }}));
        const auto result = runtime.step();
        return !peer_controller.removed_peers.empty() || result.auth_results_processed == 1U;
    });

    EXPECT_EQ(radius_client.auth_requests.size(), 1U);
    EXPECT_TRUE(radius_client.accounting_requests.empty());
    EXPECT_EQ(peer_controller.removed_peers.size(), 1U);
    EXPECT_EQ(peer_controller.removed_peers.front(), "peer-b");
}

TEST_CASE(phase1_smoke_active_peer_removal_sends_accounting_stop) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    application::AuthCommandProcessor auth_processor{"wg0", kRadiusProfile, manager, radius_client};
    application::AsyncAuthCommandProcessor async_processor{auth_processor};
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, async_processor, manager, executor};

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(runtime.step().poll_status, application::PollStatus::Seeded);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-c",
            .endpoint = std::string{"198.51.100.20:54321"},
            .allowed_ips = {"10.0.0.4/32"},
            .latest_handshake_epoch_sec = 1710000001,
            .transfer_rx_bytes = 10,
            .transfer_tx_bytes = 20,
        }}));
    EXPECT_EQ(runtime.step().auth_commands_submitted, 1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-c",
                .endpoint = std::string{"198.51.100.20:54321"},
                .allowed_ips = {"10.0.0.4/32"},
                .latest_handshake_epoch_sec = 1710000001,
                .transfer_rx_bytes = 10,
                .transfer_tx_bytes = 20,
            }}));
        const auto result = runtime.step();
        (void)result;
        return manager.find_session("peer-c") != nullptr &&
            manager.find_session("peer-c")->state() == domain::SessionState::Active;
    });

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    const auto removal_result = runtime.step();

    EXPECT_EQ(removal_result.poll_status, application::PollStatus::CommandsProduced);
    EXPECT_EQ(radius_client.accounting_requests.size(), 2U);
    EXPECT_EQ(radius_client.accounting_requests.back().event_type, radius::AccountingEventType::Stop);
    EXPECT_TRUE(manager.find_session("peer-c") == nullptr);
}
