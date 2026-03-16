#include "wg_radius/domain/peer_session.hpp"

#include "test_harness.hpp"

#include <chrono>

using namespace std::chrono_literals;
using namespace wg_radius::domain;

TEST_CASE(peer_appearance_mode_requests_authorization_immediately) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_EQ(session.state(), SessionState::Discovered);
    EXPECT_TRUE(session.on_peer_discovered());
    EXPECT_EQ(session.state(), SessionState::PendingAuth);
    EXPECT_EQ(session.accounting_state(), AccountingState::NotStarted);
}

TEST_CASE(first_handshake_mode_waits_until_handshake) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnFirstHandshake};

    EXPECT_FALSE(session.on_peer_discovered());
    EXPECT_EQ(session.state(), SessionState::Discovered);
    EXPECT_TRUE(session.on_first_handshake());
    EXPECT_TRUE(session.first_handshake_seen());
    EXPECT_EQ(session.state(), SessionState::PendingAuth);
}

TEST_CASE(access_accept_authorizes_session_and_starts_accounting) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};
    SessionPolicy policy{
        .ingress_bps = 10'000,
        .egress_bps = 20'000,
        .session_timeout = 1h,
    };

    EXPECT_TRUE(session.on_peer_discovered());
    EXPECT_TRUE(session.accept(policy));
    EXPECT_EQ(session.state(), SessionState::Authorized);
    EXPECT_EQ(session.accounting_state(), AccountingState::NotStarted);
    EXPECT_TRUE(session.applied_policy().has_value());
    EXPECT_EQ(session.applied_policy()->ingress_bps, policy.ingress_bps);
    EXPECT_EQ(session.applied_policy()->egress_bps, policy.egress_bps);
    EXPECT_EQ(session.applied_policy()->session_timeout, policy.session_timeout);
}

TEST_CASE(accounting_starts_only_after_explicit_confirmation) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_TRUE(session.on_peer_discovered());
    EXPECT_TRUE(session.accept(SessionPolicy{}));
    EXPECT_EQ(session.accounting_state(), AccountingState::NotStarted);
    EXPECT_TRUE(session.mark_accounting_started());
    EXPECT_EQ(session.accounting_state(), AccountingState::Started);
}

TEST_CASE(access_reject_can_block_peer) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_TRUE(session.on_peer_discovered());
    EXPECT_TRUE(session.reject(RejectMode::BlockPeer));
    EXPECT_EQ(session.state(), SessionState::Blocked);
    EXPECT_EQ(session.accounting_state(), AccountingState::NotStarted);
}

TEST_CASE(access_reject_can_terminate_peer) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_TRUE(session.on_peer_discovered());
    EXPECT_TRUE(session.reject(RejectMode::RemovePeer));
    EXPECT_EQ(session.state(), SessionState::Terminated);
    EXPECT_EQ(session.accounting_state(), AccountingState::NotStarted);
}

TEST_CASE(termination_stops_accounting_for_authorized_session) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_TRUE(session.on_peer_discovered());
    EXPECT_TRUE(session.accept(SessionPolicy{}));
    EXPECT_TRUE(session.mark_accounting_started());
    EXPECT_TRUE(session.terminate());
    EXPECT_EQ(session.state(), SessionState::Terminated);
    EXPECT_EQ(session.accounting_state(), AccountingState::Stopped);
}
