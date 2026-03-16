#include "wg_radius/application/command_executor.hpp"

#include "test_harness.hpp"

#include <string>
#include <vector>

using namespace wg_radius;

namespace {

class FakePeerController final : public wireguard::PeerController {
public:
    bool next_result{true};
    std::string last_interface_name;
    std::string last_peer_public_key;
    int remove_calls{0};

    bool remove_peer(const std::string& interface_name, const std::string& peer_public_key) override {
        last_interface_name = interface_name;
        last_peer_public_key = peer_public_key;
        ++remove_calls;
        return next_result;
    }
};

class FakeTrafficShaper final : public shaping::TrafficShaper {
public:
    bool next_result{true};
    std::string last_interface_name;
    std::string last_peer_public_key;
    std::optional<domain::SessionPolicy> last_policy;
    int apply_calls{0};

    bool apply_policy(
        const std::string& interface_name,
        const std::string& peer_public_key,
        const domain::SessionPolicy& policy) override {
        last_interface_name = interface_name;
        last_peer_public_key = peer_public_key;
        last_policy = policy;
        ++apply_calls;
        return next_result;
    }
};

}  // namespace

TEST_CASE(command_executor_executes_remove_peer_via_peer_controller) {
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};
    domain::Command command{
        .type = domain::CommandType::RemovePeer,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    };

    const auto result = executor.execute(command);

    EXPECT_EQ(result.status, application::CommandExecutionStatus::Executed);
    EXPECT_EQ(peer_controller.remove_calls, 1);
    EXPECT_EQ(peer_controller.last_interface_name, "wg0");
    EXPECT_EQ(peer_controller.last_peer_public_key, "peer-a");
}

TEST_CASE(command_executor_reports_failed_remove_peer) {
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    peer_controller.next_result = false;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};

    const auto result = executor.execute({
        .type = domain::CommandType::RemovePeer,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    });

    EXPECT_EQ(result.status, application::CommandExecutionStatus::Failed);
}

TEST_CASE(command_executor_executes_apply_session_policy_via_traffic_shaper) {
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};

    const auto result = executor.execute({
        .type = domain::CommandType::ApplySessionPolicy,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::string{"sess-1"},
        .policy = domain::SessionPolicy{.ingress_bps = 1000, .egress_bps = 2000, .session_timeout = std::nullopt},
    });

    EXPECT_EQ(result.status, application::CommandExecutionStatus::Executed);
    EXPECT_EQ(peer_controller.remove_calls, 0);
    EXPECT_EQ(traffic_shaper.apply_calls, 1);
    EXPECT_EQ(traffic_shaper.last_interface_name, "wg0");
    EXPECT_EQ(traffic_shaper.last_peer_public_key, "peer-a");
}

TEST_CASE(command_executor_executes_command_batch_in_order) {
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};
    const std::vector<domain::Command> commands{
        {.type = domain::CommandType::SendAccessRequest, .peer_public_key = "peer-a", .accounting_session_id = std::nullopt, .policy = std::nullopt},
        {.type = domain::CommandType::RemovePeer, .peer_public_key = "peer-b", .accounting_session_id = std::nullopt, .policy = std::nullopt},
    };

    const auto results = executor.execute_all(commands);

    EXPECT_EQ(results.size(), 2U);
    EXPECT_EQ(results.at(0).status, application::CommandExecutionStatus::Ignored);
    EXPECT_EQ(results.at(1).status, application::CommandExecutionStatus::Executed);
    EXPECT_EQ(peer_controller.remove_calls, 1);
    EXPECT_EQ(peer_controller.last_peer_public_key, "peer-b");
}

// TODO(stage-1/accounting, stage-3/blocking): re-enable after CommandExecutor
// gets operational backends for accounting and block-peer side effects.
#if 0
TEST_CASE(command_executor_must_execute_start_accounting_instead_of_ignoring_it) {
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};

    const auto result = executor.execute({
        .type = domain::CommandType::StartAccounting,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::string{"acct-1"},
        .policy = domain::SessionPolicy{},
    });

    EXPECT_EQ(result.status, application::CommandExecutionStatus::Executed);
}

TEST_CASE(command_executor_must_execute_stop_accounting_instead_of_ignoring_it) {
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};

    const auto result = executor.execute({
        .type = domain::CommandType::StopAccounting,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::string{"acct-1"},
        .policy = std::nullopt,
    });

    EXPECT_EQ(result.status, application::CommandExecutionStatus::Executed);
}

TEST_CASE(command_executor_must_execute_block_peer_instead_of_ignoring_it) {
    FakePeerController peer_controller;
    FakeTrafficShaper traffic_shaper;
    application::CommandExecutor executor{"wg0", peer_controller, traffic_shaper};

    const auto result = executor.execute({
        .type = domain::CommandType::BlockPeer,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    });

    EXPECT_EQ(result.status, application::CommandExecutionStatus::Executed);
}
#endif
