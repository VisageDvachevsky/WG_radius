#include "wg_radius/application/profile_runtime.hpp"

#include "test_harness.hpp"

#include <chrono>
#include <queue>

using namespace wg_radius;

namespace {

class FakeRadiusClient final : public radius::RadiusClient {
public:
    radius::AuthorizationResponse authorize(const radius::AuthorizationRequest& request) override {
        (void)request;
        return {
            .decision = radius::AuthorizationDecision::Error,
            .policy = std::nullopt,
        };
    }

    std::vector<radius::AccountingRequest> accounting_requests;
    bool next_account_result{true};

    bool account(const radius::AccountingRequest& request) override {
        accounting_requests.push_back(request);
        return next_account_result;
    }
};

class FakeAuthQueue final : public application::AuthCommandQueue {
public:
    std::vector<domain::Command> submitted;
    std::queue<application::AuthProcessingResult> results;

    void submit(domain::Command command) override {
        submitted.push_back(std::move(command));
    }

    std::optional<application::AuthProcessingResult> try_pop_result() override {
        if (results.empty()) {
            return std::nullopt;
        }

        auto value = std::move(results.front());
        results.pop();
        return value;
    }
};

class FakePeerController final : public wireguard::PeerController {
public:
    int remove_calls{0};

    bool remove_peer(const std::string&, const std::string&) override {
        ++remove_calls;
        return true;
    }
};

class FakeTrafficShaper final : public shaping::TrafficShaper {
public:
    int apply_calls{0};

    bool apply_policy(const std::string&, const std::string&, const domain::SessionPolicy&) override {
        ++apply_calls;
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

TEST_CASE(profile_runtime_submits_auth_commands_from_polling_result) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, manager, executor};

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(runtime.step().poll_status, application::PollStatus::Seeded);

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-a",
            .endpoint = std::nullopt,
            .allowed_ips = {"10.0.0.2/32"},
            .latest_handshake_epoch_sec = 0,
            .transfer_rx_bytes = 0,
            .transfer_tx_bytes = 0,
        }}));

    const auto result = runtime.step();

    EXPECT_EQ(result.poll_status, application::PollStatus::CommandsProduced);
    EXPECT_EQ(result.auth_commands_submitted, 1U);
    EXPECT_EQ(auth_queue.submitted.size(), 1U);
    EXPECT_EQ(auth_queue.submitted.front().type, domain::CommandType::SendAccessRequest);
}

TEST_CASE(profile_runtime_submits_auth_commands_for_seeded_peer_on_startup_reconciliation) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnFirstHandshake,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, manager, executor};

    wg_client.snapshots.push(make_snapshot(
        "wg0",
        {{
            .public_key = "peer-a",
            .endpoint = std::make_optional<std::string>("198.51.100.10:12345"),
            .allowed_ips = {"10.0.0.2/32"},
            .latest_handshake_epoch_sec = 1710000000,
            .transfer_rx_bytes = 10,
            .transfer_tx_bytes = 20,
        }}));

    const auto result = runtime.step();

    EXPECT_EQ(result.poll_status, application::PollStatus::Seeded);
    EXPECT_EQ(result.auth_commands_submitted, 1U);
    EXPECT_EQ(auth_queue.submitted.size(), 1U);
    EXPECT_EQ(auth_queue.submitted.front().type, domain::CommandType::SendAccessRequest);
    EXPECT_TRUE(auth_queue.submitted.front().authorization_context.has_value());
}

TEST_CASE(profile_runtime_executes_follow_up_commands_from_auth_results) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, manager, executor};

    auth_queue.results.push({
        .command = {
            .type = domain::CommandType::SendAccessRequest,
            .peer_public_key = "peer-a",
            .accounting_session_id = std::nullopt,
            .policy = std::nullopt,
        },
        .status = application::AuthProcessingStatus::Processed,
        .follow_up_commands =
            {
                {
                    .type = domain::CommandType::ApplySessionPolicy,
                    .peer_public_key = "peer-a",
                    .accounting_session_id = std::string{"sess-1"},
                    .policy = domain::SessionPolicy{.ingress_bps = 1000, .egress_bps = std::nullopt, .session_timeout = std::nullopt},
                },
                {
                    .type = domain::CommandType::RemovePeer,
                    .peer_public_key = "peer-a",
                    .accounting_session_id = std::nullopt,
                    .policy = std::nullopt,
                },
            },
    });
    wg_client.snapshots.push(make_snapshot("wg0", {}));

    const auto result = runtime.step();

    EXPECT_EQ(result.auth_results_processed, 1U);
    EXPECT_EQ(result.executed_commands.size(), 2U);
    EXPECT_EQ(traffic_shaper.apply_calls, 1);
    EXPECT_EQ(peer_controller.remove_calls, 1);
}

TEST_CASE(profile_runtime_must_continue_with_accounting_commands_after_successful_auth) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, manager, executor};

    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", domain::SessionPolicy{}).size(), 2U);

    auth_queue.results.push({
        .command = {
            .type = domain::CommandType::SendAccessRequest,
            .peer_public_key = "peer-a",
            .accounting_session_id = std::nullopt,
            .policy = std::nullopt,
        },
        .status = application::AuthProcessingStatus::Processed,
        .follow_up_commands =
            {
                {
                    .type = domain::CommandType::StartAccounting,
                    .peer_public_key = "peer-a",
                    .accounting_session_id = std::string{"acct-1"},
                    .policy = domain::SessionPolicy{},
                },
            },
    });
    wg_client.snapshots.push(make_snapshot("wg0", {}));

    const auto result = runtime.step();

    EXPECT_EQ(result.auth_results_processed, 1U);
    EXPECT_EQ(result.executed_commands.size(), 1U);
    EXPECT_EQ(result.executed_commands.front().status, application::CommandExecutionStatus::Executed);
    EXPECT_EQ(radius_client.accounting_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.front().event_type, radius::AccountingEventType::Start);
    EXPECT_EQ(manager.find_session("peer-a")->state(), domain::SessionState::Active);
}

TEST_CASE(profile_runtime_must_surface_accounting_stop_execution_after_peer_removal) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, manager, executor};

    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", domain::SessionPolicy{}).size(), 2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());
    EXPECT_EQ(manager.on_peer_removed("peer-a").size(), 1U);

    auth_queue.results.push({
        .command = {
            .type = domain::CommandType::SendAccessRequest,
            .peer_public_key = "peer-a",
            .accounting_session_id = std::nullopt,
            .policy = std::nullopt,
        },
        .status = application::AuthProcessingStatus::Processed,
        .follow_up_commands =
            {
                {
                    .type = domain::CommandType::StopAccounting,
                    .peer_public_key = "peer-a",
                    .accounting_session_id = std::string{"acct-1"},
                    .policy = std::nullopt,
                },
            },
    });
    wg_client.snapshots.push(make_snapshot("wg0", {}));

    const auto result = runtime.step();

    EXPECT_EQ(result.auth_results_processed, 1U);
    EXPECT_EQ(result.executed_commands.size(), 1U);
    EXPECT_EQ(result.executed_commands.front().status, application::CommandExecutionStatus::Executed);
    EXPECT_EQ(radius_client.accounting_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.front().event_type, radius::AccountingEventType::Stop);
    EXPECT_TRUE(manager.find_session("peer-a") == nullptr);
}

TEST_CASE(profile_runtime_executes_interim_accounting_tick_for_active_session) {
    using namespace std::chrono_literals;

    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer,
        {.acct_interim_interval = 30s, .inactive_timeout = std::nullopt}};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, manager, executor};

    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    manager.record_snapshot_activity("peer-a", 0, 0, 0, std::chrono::steady_clock::time_point{});
    EXPECT_EQ(manager.on_access_accept("peer-a", domain::SessionPolicy{}).size(), 2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a", std::chrono::steady_clock::time_point{}).empty());

    wg_client.snapshots.push(make_snapshot("wg0", {}));
    EXPECT_EQ(runtime.step_at(std::chrono::steady_clock::time_point{} + 31s).executed_commands.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.front().event_type, radius::AccountingEventType::InterimUpdate);
}

TEST_CASE(profile_runtime_processes_disconnect_request_into_remove_and_stop_accounting) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    FakeCoaRequestSource coa_source;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{
        coordinator,
        auth_queue,
        manager,
        executor,
        &coa_source};

    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", domain::SessionPolicy{}).size(), 2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());

    coa_source.requests.push(
        {.type = coa::RequestType::Disconnect, .peer_public_key = "peer-a"});
    wg_client.snapshots.push(make_snapshot("wg0", {}));

    const auto result = runtime.step();

    EXPECT_EQ(result.executed_commands.size(), 2U);
    EXPECT_EQ(result.executed_commands.front().command.type, domain::CommandType::RemovePeer);
    EXPECT_EQ(result.executed_commands.back().command.type, domain::CommandType::StopAccounting);
    EXPECT_EQ(peer_controller.remove_calls, 1);
    EXPECT_EQ(radius_client.accounting_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.front().event_type, radius::AccountingEventType::Stop);
    EXPECT_EQ(
        radius_client.accounting_requests.front().stop_reason,
        std::optional{domain::AccountingStopReason::DisconnectRequest});
}

TEST_CASE(profile_runtime_processes_coa_request_into_live_policy_reapply) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    FakeCoaRequestSource coa_source;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{
        coordinator,
        auth_queue,
        manager,
        executor,
        &coa_source};

    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    EXPECT_EQ(
        manager.on_access_accept(
            "peer-a",
            {.ingress_bps = 10'000, .egress_bps = 20'000, .session_timeout = std::chrono::seconds{60}})
            .size(),
        2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());

    coa_source.requests.push(
        {
            .type = coa::RequestType::Coa,
            .peer_public_key = "peer-a",
            .policy =
                domain::SessionPolicy{
                    .ingress_bps = 30'000,
                    .egress_bps = 40'000,
                    .session_timeout = std::chrono::seconds{120},
                },
        });
    wg_client.snapshots.push(make_snapshot("wg0", {}));

    const auto result = runtime.step();

    EXPECT_EQ(result.executed_commands.size(), 1U);
    EXPECT_EQ(result.executed_commands.front().command.type, domain::CommandType::ApplySessionPolicy);
    EXPECT_EQ(result.executed_commands.front().status, application::CommandExecutionStatus::Executed);
    EXPECT_EQ(traffic_shaper.apply_calls, 1);
    EXPECT_EQ(peer_controller.remove_calls, 0);
    EXPECT_TRUE(manager.find_session("peer-a")->applied_policy().has_value());
    EXPECT_EQ(manager.find_session("peer-a")->applied_policy()->ingress_bps, std::optional<std::uint64_t>{30'000});
    EXPECT_EQ(manager.find_session("peer-a")->applied_policy()->egress_bps, std::optional<std::uint64_t>{40'000});
    EXPECT_EQ(
        manager.find_session("peer-a")->applied_policy()->session_timeout,
        std::optional<std::chrono::seconds>{std::chrono::seconds{120}});
}

TEST_CASE(profile_runtime_processes_disconnect_request_into_block_and_stop_accounting_in_block_mode) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::BlockPeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    FakeCoaRequestSource coa_source;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{
        coordinator,
        auth_queue,
        manager,
        executor,
        &coa_source};

    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", domain::SessionPolicy{}).size(), 2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());

    coa_source.requests.push(
        {.type = coa::RequestType::Disconnect, .peer_public_key = "peer-a", .policy = std::nullopt});
    wg_client.snapshots.push(make_snapshot("wg0", {}));

    const auto result = runtime.step();

    EXPECT_EQ(result.executed_commands.size(), 2U);
    EXPECT_EQ(result.executed_commands.front().command.type, domain::CommandType::BlockPeer);
    EXPECT_EQ(result.executed_commands.back().command.type, domain::CommandType::StopAccounting);
    EXPECT_EQ(peer_controller.remove_calls, 1);
    EXPECT_EQ(radius_client.accounting_requests.size(), 1U);
    EXPECT_EQ(radius_client.accounting_requests.front().event_type, radius::AccountingEventType::Stop);
    EXPECT_EQ(
        radius_client.accounting_requests.front().stop_reason,
        std::optional{domain::AccountingStopReason::DisconnectRequest});
    EXPECT_TRUE(manager.find_session("peer-a") == nullptr);
}

TEST_CASE(profile_runtime_merges_partial_coa_request_into_existing_policy_before_reapply) {
    FakeWireGuardClient wg_client;
    FakeRadiusClient radius_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    FakeCoaRequestSource coa_source;
    application::CommandExecutor executor{"wg0", radius_client, peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{
        coordinator,
        auth_queue,
        manager,
        executor,
        &coa_source};

    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    EXPECT_EQ(
        manager.on_access_accept(
            "peer-a",
            {.ingress_bps = 10'000, .egress_bps = 20'000, .session_timeout = std::chrono::seconds{60}})
            .size(),
        2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());

    coa_source.requests.push(
        {
            .type = coa::RequestType::Coa,
            .peer_public_key = "peer-a",
            .policy =
                domain::SessionPolicy{
                    .ingress_bps = 30'000,
                    .egress_bps = std::nullopt,
                    .session_timeout = std::nullopt,
                },
        });
    wg_client.snapshots.push(make_snapshot("wg0", {}));

    const auto result = runtime.step();

    EXPECT_EQ(result.executed_commands.size(), 1U);
    EXPECT_TRUE(result.executed_commands.front().command.policy.has_value());
    EXPECT_EQ(result.executed_commands.front().command.policy->ingress_bps, std::optional<std::uint64_t>{30'000});
    EXPECT_EQ(result.executed_commands.front().command.policy->egress_bps, std::optional<std::uint64_t>{20'000});
    EXPECT_EQ(
        result.executed_commands.front().command.policy->session_timeout,
        std::optional<std::chrono::seconds>{std::chrono::seconds{60}});
}
