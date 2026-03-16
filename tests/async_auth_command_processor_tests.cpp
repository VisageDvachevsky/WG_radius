#include "wg_radius/application/async_auth_command_processor.hpp"

#include "test_harness.hpp"

#include <chrono>
#include <thread>

using namespace wg_radius;

namespace {

const radius::RadiusProfile kRadiusProfile{
    .auth_server = {"127.0.0.1", 1812},
    .accounting_server = {"127.0.0.1", 1813},
    .shared_secret = "secret",
    .timeout = std::chrono::seconds{5},
    .retries = 3,
    .nas_identifier = "wg-test",
    .nas_ip_address = std::nullopt,
};

class FakeRadiusClient final : public radius::RadiusClient {
public:
    radius::AuthorizationResponse next_response{
        .decision = radius::AuthorizationDecision::Accept,
        .policy = domain::SessionPolicy{
            .ingress_bps = 1000,
            .egress_bps = 2000,
            .session_timeout = std::chrono::seconds{60},
        },
    };

    radius::AuthorizationResponse authorize(const radius::AuthorizationRequest& request) override {
        (void)request;
        return next_response;
    }

    bool account(const radius::AccountingRequest& request) override {
        (void)request;
        return true;
    }
};

}  // namespace

TEST_CASE(async_auth_processor_processes_access_request_in_background) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    FakeRadiusClient radius_client;
    application::AuthCommandProcessor processor{"wg0", kRadiusProfile, manager, radius_client};
    application::AsyncAuthCommandProcessor async_processor{processor};

    EXPECT_EQ(
        manager.on_peer_observed(
            "peer-a",
            {.endpoint = std::nullopt, .allowed_ips = {"10.0.0.2/32"}})
            .size(),
        1U);
    async_processor.submit({
        .type = domain::CommandType::SendAccessRequest,
        .peer_public_key = "peer-a",
        .accounting_session_id = std::nullopt,
        .policy = std::nullopt,
    });

    std::optional<application::AuthProcessingResult> result;
    for (int attempt = 0; attempt < 50 && !result.has_value(); ++attempt) {
        result = async_processor.try_pop_result();
        if (!result.has_value()) {
            std::this_thread::sleep_for(std::chrono::milliseconds{10});
        }
    }

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result->status, application::AuthProcessingStatus::Processed);
    EXPECT_EQ(result->follow_up_commands.size(), 2U);
    EXPECT_EQ(result->follow_up_commands.at(0).type, domain::CommandType::ApplySessionPolicy);
    EXPECT_EQ(result->follow_up_commands.at(1).type, domain::CommandType::StartAccounting);
}
