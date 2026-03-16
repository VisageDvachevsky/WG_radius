#include "wg_radius/domain/session_manager.hpp"

#include "test_harness.hpp"

#include <chrono>

using namespace std::chrono_literals;
using namespace wg_radius::domain;

TEST_CASE(session_manager_requests_auth_on_peer_appearance_mode) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    const auto commands = manager.on_peer_discovered("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::SendAccessRequest);
    EXPECT_EQ(commands.front().peer_public_key, "peer-a");
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::PendingAuth);
}

TEST_CASE(session_manager_requests_auth_on_first_handshake_mode) {
    SessionManager manager{AuthorizationTrigger::OnFirstHandshake, RejectMode::RemovePeer};

    EXPECT_TRUE(manager.on_peer_discovered("peer-a").empty());

    const auto commands = manager.on_first_handshake("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::SendAccessRequest);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::PendingAuth);
}

TEST_CASE(session_manager_allows_handshake_as_primary_event) {
    SessionManager manager{AuthorizationTrigger::OnFirstHandshake, RejectMode::RemovePeer};

    const auto commands = manager.on_first_handshake("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::SendAccessRequest);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::PendingAuth);
}

TEST_CASE(session_manager_starts_accounting_on_access_accept) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};
    SessionPolicy policy{
        .ingress_bps = 50'000,
        .egress_bps = 80'000,
        .session_timeout = 2h,
    };

    EXPECT_EQ(manager.on_peer_discovered("peer-a").size(), 1U);

    const auto commands = manager.on_access_accept("peer-a", policy);

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::StartAccounting);
    EXPECT_TRUE(commands.front().policy.has_value());
    EXPECT_EQ(commands.front().policy->ingress_bps, policy.ingress_bps);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::Authorized);
    EXPECT_EQ(manager.find_session("peer-a")->accounting_state(), AccountingState::NotStarted);
}

TEST_CASE(session_manager_removes_peer_on_reject_in_remove_mode) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_discovered("peer-a").size(), 1U);

    const auto commands = manager.on_access_reject("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::RemovePeer);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::Terminated);
}

TEST_CASE(session_manager_blocks_peer_on_reject_in_block_mode) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::BlockPeer};

    EXPECT_EQ(manager.on_peer_discovered("peer-a").size(), 1U);

    const auto commands = manager.on_access_reject("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::BlockPeer);
    EXPECT_EQ(manager.find_session("peer-a")->state(), SessionState::Blocked);
}

TEST_CASE(session_manager_stops_accounting_when_authorized_peer_is_removed) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_discovered("peer-a").size(), 1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", SessionPolicy{}).size(), 1U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());

    const auto commands = manager.on_peer_removed("peer-a");

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, CommandType::StopAccounting);
    EXPECT_TRUE(manager.find_session("peer-a") == nullptr);
}

TEST_CASE(session_manager_ignores_duplicate_handshake_after_auth_started) {
    SessionManager manager{AuthorizationTrigger::OnFirstHandshake, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_first_handshake("peer-a").size(), 1U);

    const auto commands = manager.on_first_handshake("peer-a");

    EXPECT_TRUE(commands.empty());
}

TEST_CASE(session_manager_ignores_duplicate_peer_discovery) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_discovered("peer-a").size(), 1U);

    const auto commands = manager.on_peer_discovered("peer-a");

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

    EXPECT_EQ(manager.on_peer_discovered("peer-a").size(), 1U);

    const auto commands = manager.on_peer_removed("peer-a");

    EXPECT_TRUE(commands.empty());
    EXPECT_TRUE(manager.find_session("peer-a") == nullptr);
}

TEST_CASE(session_manager_peer_removal_is_idempotent) {
    SessionManager manager{AuthorizationTrigger::OnPeerAppearance, RejectMode::RemovePeer};

    EXPECT_EQ(manager.on_peer_discovered("peer-a").size(), 1U);
    EXPECT_EQ(manager.on_access_accept("peer-a", SessionPolicy{}).size(), 1U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());
    EXPECT_EQ(manager.on_peer_removed("peer-a").size(), 1U);

    const auto commands = manager.on_peer_removed("peer-a");

    EXPECT_TRUE(commands.empty());
}
