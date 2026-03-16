#include "wg_radius/domain/session_manager.hpp"

#include "test_harness.hpp"

#include <chrono>

using namespace std::chrono_literals;
using namespace wg_radius::domain;

namespace {

AuthorizationContext test_context() {
    return {.endpoint = std::string{"198.51.100.10:12345"}, .allowed_ips = {"10.0.0.2/32"}};
}

}  // namespace

TEST_CASE(session_manager_requests_auth_on_peer_appearance_mode) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    const auto commands = manager.on_peer_observed("peer-a", test_context());

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::SendAccessRequest);
    EXPECT_EQ(commands.front().peer_public_key, "peer-a");
    EXPECT_TRUE(commands.front().authorization_context.has_value());
    EXPECT_EQ(commands.front().authorization_context->endpoint, std::optional<std::string>{"198.51.100.10:12345"});
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::AuthPending);
}

TEST_CASE(session_manager_requests_auth_on_first_handshake_mode) {
    SessionManager manager{AuthorizationTrigger::OnFirstHandshake, RejectMode::RemovePeer};

    EXPECT_TRUE(manager.on_peer_observed("peer-a", test_context()).empty());

    const auto commands = manager.on_handshake_observed("peer-a", test_context());

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::SendAccessRequest);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::AuthPending);
}

TEST_CASE(session_manager_ignores_handshake_for_unknown_peer) {
    SessionManager manager{AuthorizationTrigger::OnFirstHandshake, RejectMode::RemovePeer};

    EXPECT_TRUE(manager.on_handshake_observed("peer-a", test_context()).empty());
    EXPECT_TRUE(manager.find_session("peer-a") == nullptr);
}

TEST_CASE(session_manager_emits_policy_and_accounting_commands_on_access_accept) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};
    SessionPolicy policy{
        .ingress_bps = 50'000,
        .egress_bps = 80'000,
        .session_timeout = 2h,
    };

    EXPECT_EQ(manager.on_peer_observed("peer-a", test_context()).size(), 1U);

    const auto commands = manager.on_access_accept("peer-a", policy);

    EXPECT_EQ(commands.size(), 2U);
    EXPECT_EQ(commands.at(0).type, CommandType::ApplySessionPolicy);
    EXPECT_EQ(commands.at(1).type, CommandType::StartAccounting);
    EXPECT_TRUE(commands.at(0).accounting_session_id.has_value());
    EXPECT_TRUE(commands.at(1).accounting_session_id.has_value());
    EXPECT_EQ(commands.at(0).accounting_session_id, commands.at(1).accounting_session_id);
    EXPECT_TRUE(commands.at(0).policy.has_value());
    EXPECT_EQ(commands.at(0).policy->ingress_bps, policy.ingress_bps);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::AccountingStartPending);
    EXPECT_EQ(manager.find_session("peer-a")->accounting_session_id(), commands.at(0).accounting_session_id);
}

TEST_CASE(session_manager_emits_remove_peer_on_reject_in_remove_mode) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_observed("peer-a", test_context()).size(), 1U);

    const auto commands = manager.on_access_reject("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::RemovePeer);
    EXPECT_TRUE(manager.find_session("peer-a") != nullptr);
}

TEST_CASE(session_manager_blocks_peer_via_two_phase_confirmation) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::BlockPeer};

    EXPECT_EQ(manager.on_peer_observed("peer-a", test_context()).size(), 1U);

    const auto commands = manager.on_access_reject("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::BlockPeer);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::BlockingPending);
    EXPECT_TRUE(manager.on_peer_blocked("peer-a").empty());
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::Blocked);
}

TEST_CASE(session_manager_stops_accounting_when_active_peer_is_removed_and_keeps_session_until_confirmation) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_observed("peer-a", test_context()).size(), 1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", SessionPolicy{}).size(), 2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());

    const auto commands = manager.on_peer_removed("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::StopAccounting);
    EXPECT_TRUE(commands.front().accounting_session_id.has_value());
    EXPECT_TRUE(manager.find_session("peer-a") != nullptr);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::AccountingStopPending);
    EXPECT_TRUE(manager.on_accounting_stopped("peer-a").empty());
    EXPECT_TRUE(manager.find_session("peer-a") == nullptr);
}

TEST_CASE(session_manager_ignores_duplicate_handshake_after_auth_started) {
    SessionManager manager{AuthorizationTrigger::OnFirstHandshake, RejectMode::RemovePeer};

    EXPECT_TRUE(manager.on_peer_observed("peer-a", test_context()).empty());
    EXPECT_EQ(manager.on_handshake_observed("peer-a", test_context()).size(), 1U);

    const auto commands = manager.on_handshake_observed("peer-a", test_context());

    EXPECT_TRUE(commands.empty());
}

TEST_CASE(session_manager_ignores_duplicate_peer_observation) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_observed("peer-a", test_context()).size(), 1U);

    const auto commands = manager.on_peer_observed("peer-a", test_context());

    EXPECT_TRUE(commands.empty());
}

TEST_CASE(session_manager_ignores_access_accept_for_unknown_peer) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    const auto commands = manager.on_access_accept("peer-a", SessionPolicy{});

    EXPECT_TRUE(commands.empty());
}

TEST_CASE(session_manager_ignores_access_reject_for_unknown_peer) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    const auto commands = manager.on_access_reject("peer-a");

    EXPECT_TRUE(commands.empty());
}

TEST_CASE(session_manager_does_not_stop_accounting_for_pending_peer_removal) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_observed("peer-a", test_context()).size(), 1U);

    const auto commands = manager.on_peer_removed("peer-a");

    EXPECT_TRUE(commands.empty());
    EXPECT_TRUE(manager.find_session("peer-a") == nullptr);
}

TEST_CASE(session_manager_peer_removal_is_idempotent) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_observed("peer-a", test_context()).size(), 1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", SessionPolicy{}).size(), 2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());
    EXPECT_EQ(manager.on_peer_removed("peer-a").size(), 1U);
    EXPECT_TRUE(manager.on_accounting_stopped("peer-a").empty());

    const auto commands = manager.on_peer_removed("peer-a");

    EXPECT_TRUE(commands.empty());
}
