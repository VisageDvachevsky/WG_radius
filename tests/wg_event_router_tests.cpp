#include "wg_radius/application/wg_event_router.hpp"

#include "test_harness.hpp"

using namespace wg_radius;

TEST_CASE(router_turns_peer_observed_into_access_request_in_peer_appearance_mode) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};

    const auto commands = router.handle({
        .type = wireguard::EventType::PeerObserved,
        .peer_public_key = "peer-a",
    });

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, domain::CommandType::SendAccessRequest);
    EXPECT_EQ(commands.front().peer_public_key, "peer-a");
}

TEST_CASE(router_turns_handshake_observed_into_access_request_in_handshake_mode) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnFirstHandshake,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};

    EXPECT_TRUE(router.handle({
        .type = wireguard::EventType::PeerObserved,
        .peer_public_key = "peer-a",
    }).empty());
    const auto commands = router.handle({
        .type = wireguard::EventType::HandshakeObserved,
        .peer_public_key = "peer-a",
    });

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, domain::CommandType::SendAccessRequest);
    EXPECT_EQ(commands.front().peer_public_key, "peer-a");
}

TEST_CASE(router_ignores_handshake_updates_for_already_known_peer) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};

    EXPECT_EQ(
        router.handle({
            .type = wireguard::EventType::PeerObserved,
            .peer_public_key = "peer-a",
        }).size(),
        1U);

    const auto commands = router.handle({
        .type = wireguard::EventType::HandshakeObserved,
        .peer_public_key = "peer-a",
    });

    EXPECT_TRUE(commands.empty());
}

TEST_CASE(router_turns_peer_removed_into_stop_accounting_for_active_session) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};

    EXPECT_EQ(
        router.handle({
            .type = wireguard::EventType::PeerObserved,
            .peer_public_key = "peer-a",
        }).size(),
        1U);
    EXPECT_EQ(
        manager.on_access_accept("peer-a", domain::SessionPolicy{}).size(),
        2U);
    EXPECT_TRUE(manager.on_accounting_started("peer-a").empty());

    const auto commands = router.handle({
        .type = wireguard::EventType::PeerRemoved,
        .peer_public_key = "peer-a",
    });

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, domain::CommandType::StopAccounting);
    EXPECT_EQ(commands.front().peer_public_key, "peer-a");
}

TEST_CASE(router_ignores_traffic_only_updates) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnPeerAppearance,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};

    const auto commands = router.handle({
        .type = wireguard::EventType::TrafficUpdated,
        .peer_public_key = "peer-a",
    });

    EXPECT_TRUE(commands.empty());
}

TEST_CASE(router_seed_reconciles_existing_handshaken_peer_into_access_request) {
    domain::SessionManager manager{
        domain::AuthorizationTrigger::OnFirstHandshake,
        domain::RejectMode::RemovePeer};
    application::WgEventRouter router{manager};

    const auto commands = router.seed({
        .interface_name = "wg0",
        .peers =
            {{
                "peer-a",
                {
                    .public_key = "peer-a",
                    .endpoint = std::string{"198.51.100.10:12345"},
                    .allowed_ips = {"10.0.0.2/32"},
                    .latest_handshake_epoch_sec = 1710000000,
                    .transfer_rx_bytes = 10,
                    .transfer_tx_bytes = 20,
                },
            }},
    });

    EXPECT_EQ(commands.size(), 1U);
    EXPECT_EQ(commands.front().type, domain::CommandType::SendAccessRequest);
    EXPECT_EQ(commands.front().peer_public_key, "peer-a");
}
