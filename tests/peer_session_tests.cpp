#include "wg_radius/domain/peer_session.hpp"

#include "test_harness.hpp"

#include <chrono>

using namespace std::chrono_literals;
using namespace wg_radius::domain;

TEST_CASE(peer_appearance_mode_requests_authorization_immediately) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_EQ(session.state(), SessionState::Discovered);
    EXPECT_TRUE(session.on_peer_observed());
    EXPECT_EQ(session.state(), SessionState::AuthPending);
}

TEST_CASE(first_handshake_mode_waits_until_handshake) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnFirstHandshake};

    EXPECT_FALSE(session.on_peer_observed());
    EXPECT_EQ(session.state(), SessionState::Discovered);
    EXPECT_TRUE(session.on_handshake_observed());
    EXPECT_TRUE(session.first_handshake_seen());
    EXPECT_EQ(session.state(), SessionState::AuthPending);
}

TEST_CASE(access_accept_moves_session_to_accounting_start_pending) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};
    SessionPolicy policy{
        .ingress_bps = 10'000,
        .egress_bps = 20'000,
        .session_timeout = 1h,
    };

    EXPECT_TRUE(session.on_peer_observed());
    EXPECT_TRUE(session.accept(policy, "sess-1"));
    EXPECT_EQ(session.state(), SessionState::AccountingStartPending);
    EXPECT_TRUE(session.accounting_session_id().has_value());
    EXPECT_EQ(*session.accounting_session_id(), "sess-1");
    EXPECT_TRUE(session.applied_policy().has_value());
    EXPECT_EQ(session.applied_policy()->ingress_bps, policy.ingress_bps);
    EXPECT_EQ(session.applied_policy()->egress_bps, policy.egress_bps);
    EXPECT_EQ(session.applied_policy()->session_timeout, policy.session_timeout);
}

TEST_CASE(accounting_starts_only_after_explicit_confirmation) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_TRUE(session.on_peer_observed());
    EXPECT_TRUE(session.accept(SessionPolicy{}, "sess-1"));
    EXPECT_EQ(session.state(), SessionState::AccountingStartPending);
    EXPECT_TRUE(session.mark_accounting_started());
    EXPECT_EQ(session.state(), SessionState::Active);
}

TEST_CASE(reject_can_move_session_into_blocking_pending) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_TRUE(session.on_peer_observed());
    EXPECT_TRUE(session.begin_block());
    EXPECT_EQ(session.state(), SessionState::BlockingPending);
    EXPECT_TRUE(session.mark_blocked());
    EXPECT_EQ(session.state(), SessionState::Blocked);
}

TEST_CASE(reject_can_move_session_back_to_discovered_before_peer_removal_confirmation) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_TRUE(session.on_peer_observed());
    EXPECT_TRUE(session.begin_removal());
    EXPECT_EQ(session.state(), SessionState::Discovered);
}

TEST_CASE(accounting_stop_is_two_phase) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    EXPECT_TRUE(session.on_peer_observed());
    EXPECT_TRUE(session.accept(SessionPolicy{}, "sess-1"));
    EXPECT_TRUE(session.mark_accounting_started());
    EXPECT_TRUE(session.begin_accounting_stop());
    EXPECT_EQ(session.state(), SessionState::AccountingStopPending);
    EXPECT_TRUE(session.mark_accounting_stopped());
}

TEST_CASE(handshake_observed_does_not_create_auth_for_blocked_session) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnFirstHandshake};

    EXPECT_TRUE(session.on_peer_observed() == false);
    EXPECT_TRUE(session.on_handshake_observed());
    EXPECT_TRUE(session.begin_block());
    EXPECT_TRUE(session.mark_blocked());
    EXPECT_FALSE(session.on_handshake_observed());
}

TEST_CASE(peer_present_returns_true_again_after_re_observation) {
    PeerSession session{"peer-public-key", AuthorizationTrigger::OnPeerAppearance};

    session.observe_peer_removed();
    EXPECT_FALSE(session.peer_present());
    EXPECT_TRUE(session.on_peer_observed());
    EXPECT_TRUE(session.peer_present());
}
