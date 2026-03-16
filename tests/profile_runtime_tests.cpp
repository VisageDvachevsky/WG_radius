#include "wg_radius/application/profile_runtime.hpp"

#include "test_harness.hpp"

#include <queue>

using namespace wg_radius;

namespace {

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
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, executor};

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

TEST_CASE(profile_runtime_executes_follow_up_commands_from_auth_results) {
    FakeWireGuardClient wg_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, executor};

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

// TODO(stage-1/accounting): re-enable after CommandExecutor grows operational
// accounting backends.
#if 0
TEST_CASE(profile_runtime_must_continue_with_accounting_commands_after_successful_auth) {
    FakeWireGuardClient wg_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, executor};

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
}

TEST_CASE(profile_runtime_must_surface_accounting_stop_execution_after_peer_removal) {
    FakeWireGuardClient wg_client;
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};
    application::WgPollingCoordinator coordinator{"wg0", wg_client, router};
    FakeAuthQueue auth_queue;
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};
    application::ProfileRuntime runtime{coordinator, auth_queue, executor};

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
}
#endif
