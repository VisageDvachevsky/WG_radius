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
    EXPECT_EQ(
        radius_client.accounting_requests.front().framed_ip_address,
        std::optional<std::string>{"10.0.0.2"});
    EXPECT_EQ(radius_client.accounting_requests.front().transfer_rx_bytes, 100U);
    EXPECT_EQ(radius_client.accounting_requests.front().transfer_tx_bytes, 200U);
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
    EXPECT_EQ(
        radius_client.accounting_requests.back().stop_reason,
        std::optional{domain::AccountingStopReason::PeerRemoved});
    EXPECT_TRUE(manager.find_session("peer-c") == nullptr);
}

TEST_CASE(phase2_smoke_active_peer_emits_interim_then_stops_on_inactivity) {
    using namespace std::chrono_literals;

    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer,
        {
            .acct_interim_interval = 30s,
            .inactive_timeout = 60s,
            .inactivity_strategy = wg_radius::config::InactivityStrategy::HandshakeAndTraffic,
        }};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    application::AuthCommandProcessor auth_processor{"wg0", kRadiusProfile, manager, radius_client};
    application::AsyncAuthCommandProcessor async_processor{auth_processor};
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, async_processor, manager, executor};

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(
        runtime.step_at(std::chrono::steady_clock::time_point{}).poll_status,
        application::PollStatus::Seeded);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-z",
            .endpoint = std::string{"198.51.100.30:60000"},
            .allowed_ips = {"10.0.0.9/32"},
            .latest_handshake_epoch_sec = 1710000100,
            .transfer_rx_bytes = 500,
            .transfer_tx_bytes = 700,
        }}));
    EXPECT_EQ(
        runtime.step_at(std::chrono::steady_clock::time_point{} + 1s).auth_commands_submitted,
        1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-z",
                .endpoint = std::string{"198.51.100.30:60000"},
                .allowed_ips = {"10.0.0.9/32"},
                .latest_handshake_epoch_sec = 1710000100,
                .transfer_rx_bytes = 500,
                .transfer_tx_bytes = 700,
            }}));
        const auto result = runtime.step_at(std::chrono::steady_clock::time_point{} + 2s);
        return result.auth_results_processed == 1U;
    });

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-z",
            .endpoint = std::string{"198.51.100.30:60000"},
            .allowed_ips = {"10.0.0.9/32"},
            .latest_handshake_epoch_sec = 1710000100,
            .transfer_rx_bytes = 500,
            .transfer_tx_bytes = 700,
        }}));
    EXPECT_EQ(
        runtime.step_at(std::chrono::steady_clock::time_point{} + 33s).executed_commands.size(),
        1U);
    EXPECT_EQ(radius_client.accounting_requests.size(), 2U);
    EXPECT_EQ(
        radius_client.accounting_requests.back().event_type,
        radius::AccountingEventType::InterimUpdate);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-z",
            .endpoint = std::string{"198.51.100.30:60000"},
            .allowed_ips = {"10.0.0.9/32"},
            .latest_handshake_epoch_sec = 1710000100,
            .transfer_rx_bytes = 500,
            .transfer_tx_bytes = 700,
        }}));
    EXPECT_EQ(
        runtime.step_at(std::chrono::steady_clock::time_point{} + 65s).executed_commands.size(),
        1U);
    EXPECT_EQ(radius_client.accounting_requests.size(), 3U);
    EXPECT_EQ(radius_client.accounting_requests.back().event_type, radius::AccountingEventType::Stop);
    EXPECT_EQ(
        radius_client.accounting_requests.back().stop_reason,
        std::optional{domain::AccountingStopReason::InactivityHandshakeAndTraffic});
}

TEST_CASE(phase2_smoke_startup_reconciliation_authorizes_seeded_handshaken_peer) {
    using namespace std::chrono_literals;

    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnFirstHandshake,
        domain::RejectMode::RemovePeer,
        {
            .acct_interim_interval = 30s,
            .inactive_timeout = 60s,
            .inactivity_strategy = wg_radius::config::InactivityStrategy::HandshakeAndTraffic,
        }};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    application::AuthCommandProcessor auth_processor{"wg0", kRadiusProfile, manager, radius_client};
    application::AsyncAuthCommandProcessor async_processor{auth_processor};
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, async_processor, manager, executor};

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-r",
            .endpoint = std::string{"198.51.100.40:61000"},
            .allowed_ips = {"10.0.0.10/32"},
            .latest_handshake_epoch_sec = 1710000200,
            .transfer_rx_bytes = 900,
            .transfer_tx_bytes = 1200,
        }}));
    const auto seed_result = runtime.step_at(std::chrono::steady_clock::time_point{});

    EXPECT_EQ(seed_result.poll_status, application::PollStatus::Seeded);
    EXPECT_EQ(seed_result.auth_commands_submitted, 1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-r",
                .endpoint = std::string{"198.51.100.40:61000"},
                .allowed_ips = {"10.0.0.10/32"},
                .latest_handshake_epoch_sec = 1710000200,
                .transfer_rx_bytes = 900,
                .transfer_tx_bytes = 1200,
            }}));
        return runtime.step_at(std::chrono::steady_clock::time_point{} + 1s).auth_results_processed == 1U;
    });

    EXPECT_EQ(radius_client.auth_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.front().event_type, radius::AccountingEventType::Start);
    EXPECT_EQ(radius_client.accounting_requests.front().transfer_rx_bytes, 900U);
    EXPECT_EQ(radius_client.accounting_requests.front().transfer_tx_bytes, 1200U);
    EXPECT_TRUE(manager.find_session("peer-r") != nullptr);
    EXPECT_EQ(manager.find_session("peer-r")->state(), domain::SessionState::Active);
}

TEST_CASE(phase2_smoke_startup_reconciliation_keeps_inactivity_window_from_seed_snapshot) {
    using namespace std::chrono_literals;

    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnFirstHandshake,
        domain::RejectMode::RemovePeer,
        {
            .acct_interim_interval = std::nullopt,
            .inactive_timeout = 60s,
            .inactivity_strategy = wg_radius::config::InactivityStrategy::HandshakeAndTraffic,
        }};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    application::AuthCommandProcessor auth_processor{"wg0", kRadiusProfile, manager, radius_client};
    application::AsyncAuthCommandProcessor async_processor{auth_processor};
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, async_processor, manager, executor};

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-s",
            .endpoint = std::string{"198.51.100.50:62000"},
            .allowed_ips = {"10.0.0.11/32"},
            .latest_handshake_epoch_sec = 1710000300,
            .transfer_rx_bytes = 1000,
            .transfer_tx_bytes = 1100,
        }}));
    EXPECT_EQ(runtime.step_at(std::chrono::steady_clock::time_point{}).auth_commands_submitted, 1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-s",
                .endpoint = std::string{"198.51.100.50:62000"},
                .allowed_ips = {"10.0.0.11/32"},
                .latest_handshake_epoch_sec = 1710000300,
                .transfer_rx_bytes = 1000,
                .transfer_tx_bytes = 1100,
            }}));
        return runtime.step_at(std::chrono::steady_clock::time_point{} + 1s).auth_results_processed == 1U;
    });

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-s",
            .endpoint = std::string{"198.51.100.50:62000"},
            .allowed_ips = {"10.0.0.11/32"},
            .latest_handshake_epoch_sec = 1710000300,
            .transfer_rx_bytes = 1000,
            .transfer_tx_bytes = 1100,
        }}));
    EXPECT_TRUE(
        runtime.step_at(std::chrono::steady_clock::time_point{} + 30s).executed_commands.empty());

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-s",
            .endpoint = std::string{"198.51.100.50:62000"},
            .allowed_ips = {"10.0.0.11/32"},
            .latest_handshake_epoch_sec = 1710000300,
            .transfer_rx_bytes = 1000,
            .transfer_tx_bytes = 1100,
        }}));
    EXPECT_EQ(
        runtime.step_at(std::chrono::steady_clock::time_point{} + 61s).executed_commands.size(),
        1U);
    EXPECT_EQ(radius_client.accounting_requests.back().event_type, radius::AccountingEventType::Stop);
    EXPECT_EQ(
        radius_client.accounting_requests.back().stop_reason,
        std::optional{domain::AccountingStopReason::InactivityHandshakeAndTraffic});
}

TEST_CASE(phase3_smoke_active_peer_reapplies_policy_from_coa_request) {
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
    class FakeCoaRequestSource final : public coa::RequestSource {
    public:
        std::queue<coa::Request> requests;

        std::optional<coa::Request> try_pop_request() override {
            if (requests.empty()) {
                return std::nullopt;
            }
            auto value = requests.front();
            requests.pop();
            return value;
        }
    } coa_source;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{
        coordinator,
        async_processor,
        manager,
        executor,
        &coa_source};

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(runtime.step().poll_status, application::PollStatus::Seeded);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-coa",
            .endpoint = std::string{"198.51.100.60:63000"},
            .allowed_ips = {"10.0.0.12/32"},
            .latest_handshake_epoch_sec = 1710000400,
            .transfer_rx_bytes = 200,
            .transfer_tx_bytes = 300,
        }}));
    EXPECT_EQ(runtime.step().auth_commands_submitted, 1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-coa",
                .endpoint = std::string{"198.51.100.60:63000"},
                .allowed_ips = {"10.0.0.12/32"},
                .latest_handshake_epoch_sec = 1710000400,
                .transfer_rx_bytes = 200,
                .transfer_tx_bytes = 300,
            }}));
        const auto result = runtime.step();
        return result.auth_results_processed == 1U;
    });

    EXPECT_EQ(traffic_shaper.shaped_peers.size(), 1U);
    EXPECT_TRUE(manager.find_session("peer-coa") != nullptr);

    coa_source.requests.push(
        {
            .type = coa::RequestType::Coa,
            .peer_public_key = "peer-coa",
            .policy =
                domain::SessionPolicy{
                    .ingress_bps = 55'000,
                    .egress_bps = 66'000,
                    .session_timeout = std::chrono::seconds{180},
                },
        });
    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-coa",
            .endpoint = std::string{"198.51.100.60:63000"},
            .allowed_ips = {"10.0.0.12/32"},
            .latest_handshake_epoch_sec = 1710000400,
            .transfer_rx_bytes = 200,
            .transfer_tx_bytes = 300,
        }}));

    const auto coa_result = runtime.step();

    EXPECT_EQ(coa_result.executed_commands.size(), 1U);
    EXPECT_EQ(coa_result.executed_commands.front().command.type, domain::CommandType::ApplySessionPolicy);
    EXPECT_EQ(traffic_shaper.shaped_peers.size(), 2U);
    EXPECT_EQ(traffic_shaper.shaped_peers.back(), "peer-coa");
    EXPECT_EQ(manager.find_session("peer-coa")->applied_policy()->ingress_bps, std::optional<std::uint64_t>{55'000});
    EXPECT_EQ(manager.find_session("peer-coa")->applied_policy()->egress_bps, std::optional<std::uint64_t>{66'000});
    EXPECT_EQ(
        manager.find_session("peer-coa")->applied_policy()->session_timeout,
        std::optional<std::chrono::seconds>{std::chrono::seconds{180}});
}

TEST_CASE(phase3_smoke_disconnect_request_blocks_peer_and_stops_accounting_in_block_mode) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::BlockPeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    application::AuthCommandProcessor auth_processor{"wg0", kRadiusProfile, manager, radius_client};
    application::AsyncAuthCommandProcessor async_processor{auth_processor};
    class FakeCoaRequestSource final : public coa::RequestSource {
    public:
        std::queue<coa::Request> requests;

        std::optional<coa::Request> try_pop_request() override {
            if (requests.empty()) {
                return std::nullopt;
            }
            auto value = requests.front();
            requests.pop();
            return value;
        }
    } coa_source;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{
        coordinator,
        async_processor,
        manager,
        executor,
        &coa_source};

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(runtime.step().poll_status, application::PollStatus::Seeded);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-disc",
            .endpoint = std::string{"198.51.100.61:64000"},
            .allowed_ips = {"10.0.0.13/32"},
            .latest_handshake_epoch_sec = 1710000500,
            .transfer_rx_bytes = 210,
            .transfer_tx_bytes = 310,
        }}));
    EXPECT_EQ(runtime.step().auth_commands_submitted, 1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-disc",
                .endpoint = std::string{"198.51.100.61:64000"},
                .allowed_ips = {"10.0.0.13/32"},
                .latest_handshake_epoch_sec = 1710000500,
                .transfer_rx_bytes = 210,
                .transfer_tx_bytes = 310,
            }}));
        const auto result = runtime.step();
        return result.auth_results_processed == 1U;
    });

    coa_source.requests.push(
        {.type = coa::RequestType::Disconnect, .peer_public_key = "peer-disc", .policy = std::nullopt});
    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-disc",
            .endpoint = std::string{"198.51.100.61:64000"},
            .allowed_ips = {"10.0.0.13/32"},
            .latest_handshake_epoch_sec = 1710000500,
            .transfer_rx_bytes = 210,
            .transfer_tx_bytes = 310,
        }}));

    const auto disconnect_result = runtime.step();

    EXPECT_EQ(disconnect_result.executed_commands.size(), 2U);
    EXPECT_EQ(disconnect_result.executed_commands.front().command.type, domain::CommandType::BlockPeer);
    EXPECT_EQ(disconnect_result.executed_commands.back().command.type, domain::CommandType::StopAccounting);
    EXPECT_EQ(peer_controller.removed_peers.size(), 1U);
    EXPECT_EQ(peer_controller.removed_peers.front(), "peer-disc");
    EXPECT_EQ(radius_client.accounting_requests.size(), 2U);
    EXPECT_EQ(radius_client.accounting_requests.back().event_type, radius::AccountingEventType::Stop);
    EXPECT_EQ(
        radius_client.accounting_requests.back().stop_reason,
        std::optional{domain::AccountingStopReason::DisconnectRequest});
    EXPECT_TRUE(manager.find_session("peer-disc") == nullptr);
}

TEST_CASE(phase3_smoke_partial_coa_preserves_existing_policy_fields) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    radius_client.next_auth_response = {
        .decision = radius::AuthorizationDecision::Accept,
        .policy = domain::SessionPolicy{
            .ingress_bps = 10'000,
            .egress_bps = 20'000,
            .session_timeout = std::chrono::seconds{60},
        },
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
    class FakeCoaRequestSource final : public coa::RequestSource {
    public:
        std::queue<coa::Request> requests;

        std::optional<coa::Request> try_pop_request() override {
            if (requests.empty()) {
                return std::nullopt;
            }
            auto value = requests.front();
            requests.pop();
            return value;
        }
    } coa_source;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{
        coordinator,
        async_processor,
        manager,
        executor,
        &coa_source};

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(runtime.step().poll_status, application::PollStatus::Seeded);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-merge",
            .endpoint = std::string{"198.51.100.62:65000"},
            .allowed_ips = {"10.0.0.14/32"},
            .latest_handshake_epoch_sec = 1710000600,
            .transfer_rx_bytes = 220,
            .transfer_tx_bytes = 320,
        }}));
    EXPECT_EQ(runtime.step().auth_commands_submitted, 1U);

    spin_until([&] {
        wg_client.snapshots.push(make_snapshot(
            "wg0",
            {{
                .public_key = "peer-merge",
                .endpoint = std::string{"198.51.100.62:65000"},
                .allowed_ips = {"10.0.0.14/32"},
                .latest_handshake_epoch_sec = 1710000600,
                .transfer_rx_bytes = 220,
                .transfer_tx_bytes = 320,
            }}));
        const auto result = runtime.step();
        return result.auth_results_processed == 1U;
    });

    coa_source.requests.push(
        {
            .type = coa::RequestType::Coa,
            .peer_public_key = "peer-merge",
            .policy =
                domain::SessionPolicy{
                    .ingress_bps = 55'000,
                    .egress_bps = std::nullopt,
                    .session_timeout = std::nullopt,
                },
        });
    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-merge",
            .endpoint = std::string{"198.51.100.62:65000"},
            .allowed_ips = {"10.0.0.14/32"},
            .latest_handshake_epoch_sec = 1710000600,
            .transfer_rx_bytes = 220,
            .transfer_tx_bytes = 320,
        }}));

    const auto coa_result = runtime.step();

    EXPECT_EQ(coa_result.executed_commands.size(), 1U);
    EXPECT_TRUE(coa_result.executed_commands.front().command.policy.has_value());
    EXPECT_EQ(
        coa_result.executed_commands.front().command.policy->ingress_bps,
        std::optional<std::uint64_t>{55'000});
    EXPECT_EQ(
        coa_result.executed_commands.front().command.policy->egress_bps,
        std::optional<std::uint64_t>{20'000});
    EXPECT_EQ(
        coa_result.executed_commands.front().command.policy->session_timeout,
        std::optional<std::chrono::seconds>{std::chrono::seconds{60}});
}
