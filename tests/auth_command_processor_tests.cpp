#include "wg_radius/application/auth_command_processor.hpp"

#include "test_harness.hpp"

using namespace wg_radius;

namespace {

template <typename T>
concept HasEndpoint = requires(T value) {
    value.endpoint;
};

template <typename T>
concept HasAllowedIps = requires(T value) {
    value.allowed_ips;
};

template <typename T>
concept HasNasIdentifier = requires(T value) {
    value.nas_identifier;
};

template <typename T>
concept HasNasIpAddress = requires(T value) {
    value.nas_ip_address;
};

template <typename T>
concept HasCallingStationId = requires(T value) {
    value.calling_station_id;
};

template <typename T>
concept HasUserName = requires(T value) {
    value.user_name;
};

class FakeRadiusClient final : public radius::RadiusClient {
public:
    radius::AuthorizationResponse next_response{
        .decision = radius::AuthorizationDecision::Error,
        .policy = std::nullopt,
    };
    radius::AuthorizationRequest last_request{
        .interface_name = {},
        .peer_public_key = {},
    };
    int authorize_calls{0};

    radius::AuthorizationResponse authorize(const radius::AuthorizationRequest& request) override {
        last_request = request;
        ++authorize_calls;
        return next_response;
    }
};

}  // namespace

TEST_CASE(auth_processor_ignores_non_auth_commands) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    FakeRadiusClient radius_client;
    application::AuthCommandProcessor processor{"wg0", manager, radius_client};

    const auto result = processor.process({
        .type = domain::CommandType::RemovePeer,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    });

    EXPECT_EQ(result.status, application::AuthProcessingStatus::Ignored);
    EXPECT_TRUE(result.follow_up_commands.empty());
    EXPECT_EQ(radius_client.authorize_calls, 0);
}

TEST_CASE(auth_processor_accept_turns_access_request_into_policy_and_accounting_commands) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    FakeRadiusClient radius_client;
    radius_client.next_response = {
        .decision = radius::AuthorizationDecision::Accept,
        .policy = domain::SessionPolicy{
            .ingress_bps = 10'000,
            .egress_bps = 20'000,
            .session_timeout = std::chrono::seconds{3600},
        },
    };
    application::AuthCommandProcessor processor{"wg0", manager, radius_client};

    EXPECT_EQ(manager.on_peer_observed("peer-a").size(), 1U);

    const auto result = processor.process({
        .type = domain::CommandType::SendAccessRequest,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    });

    EXPECT_EQ(result.status, application::AuthProcessingStatus::Processed);
    EXPECT_EQ(radius_client.authorize_calls, 1);
    EXPECT_EQ(radius_client.last_request.interface_name, "wg0");
    EXPECT_EQ(radius_client.last_request.peer_public_key, "peer-a");
    EXPECT_EQ(result.follow_up_commands.size(), 2U);
    EXPECT_EQ(result.follow_up_commands.at(0).type, domain::CommandType::ApplySessionPolicy);
    EXPECT_EQ(result.follow_up_commands.at(1).type, domain::CommandType::StartAccounting);
    EXPECT_TRUE(result.follow_up_commands.at(0).accounting_session_id.has_value());
}

TEST_CASE(auth_processor_reject_turns_access_request_into_remove_peer) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    FakeRadiusClient radius_client;
    radius_client.next_response = {
        .decision = radius::AuthorizationDecision::Reject,
        .policy = std::nullopt,
    };
    application::AuthCommandProcessor processor{"wg0", manager, radius_client};

    EXPECT_EQ(manager.on_peer_observed("peer-a").size(), 1U);

    const auto result = processor.process({
        .type = domain::CommandType::SendAccessRequest,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    });

    EXPECT_EQ(result.status, application::AuthProcessingStatus::Processed);
    EXPECT_EQ(result.follow_up_commands.size(), 1U);
    EXPECT_EQ(result.follow_up_commands.front().type, domain::CommandType::RemovePeer);
}

TEST_CASE(auth_processor_reports_failure_on_radius_error) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    FakeRadiusClient radius_client;
    radius_client.next_response = {
        .decision = radius::AuthorizationDecision::Error,
        .policy = std::nullopt,
    };
    application::AuthCommandProcessor processor{"wg0", manager, radius_client};

    EXPECT_EQ(manager.on_peer_observed("peer-a").size(), 1U);

    const auto result = processor.process({
        .type = domain::CommandType::SendAccessRequest,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    });

    EXPECT_EQ(result.status, application::AuthProcessingStatus::Failed);
    EXPECT_TRUE(result.follow_up_commands.empty());
}

TEST_CASE(auth_processor_reports_failure_on_accept_without_policy) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    FakeRadiusClient radius_client;
    radius_client.next_response = {
        .decision = radius::AuthorizationDecision::Accept,
        .policy = std::nullopt,
    };
    application::AuthCommandProcessor processor{"wg0", manager, radius_client};

    EXPECT_EQ(manager.on_peer_observed("peer-a").size(), 1U);

    const auto result = processor.process({
        .type = domain::CommandType::SendAccessRequest,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    });

    EXPECT_EQ(result.status, application::AuthProcessingStatus::Failed);
    EXPECT_TRUE(result.follow_up_commands.empty());
}

// TODO(stage-1/radius-request-model): re-enable when AuthorizationRequest models
// the full WG/RADIUS context required by the spec.
#if 0
TEST_CASE(radius_authorization_request_must_model_wireguard_context_attributes_required_by_spec) {
    EXPECT_TRUE(HasEndpoint<radius::AuthorizationRequest>);
    EXPECT_TRUE(HasAllowedIps<radius::AuthorizationRequest>);
    EXPECT_TRUE(HasNasIdentifier<radius::AuthorizationRequest>);
    EXPECT_TRUE(HasNasIpAddress<radius::AuthorizationRequest>);
}

TEST_CASE(radius_authorization_request_must_model_calling_station_and_user_name_mapping_required_by_spec) {
    EXPECT_TRUE(HasCallingStationId<radius::AuthorizationRequest>);
    EXPECT_TRUE(HasUserName<radius::AuthorizationRequest>);
}
#endif
