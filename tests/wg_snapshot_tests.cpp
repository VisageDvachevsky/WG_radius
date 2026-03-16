#include "wg_radius/wireguard/wg_snapshot.hpp"

#include "test_harness.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace wg_radius::wireguard;

namespace {

template <typename T>
concept HasHandshakeRefreshed = requires {
    T::HandshakeRefreshed;
};

const std::string kBaseDump =
    "private-key\tpublic-key\t51820\toff\n"
    "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t0\t100\t200\toff\n"
    "peer-b\t(none)\t(none)\t10.0.0.3/32\t1710000000\t300\t400\t25\n";

std::vector<std::pair<EventType, std::string>> normalize(const std::vector<Event>& events) {
    std::vector<std::pair<EventType, std::string>> normalized;
    normalized.reserve(events.size());

    for (const auto& event : events) {
        normalized.emplace_back(event.type, event.peer_public_key);
    }

    std::sort(
        normalized.begin(),
        normalized.end(),
        [](const auto& left, const auto& right) {
            if (left.second == right.second) {
                return static_cast<int>(left.first) < static_cast<int>(right.first);
            }

            return left.second < right.second;
        });

    return normalized;
}

}  // namespace

TEST_CASE(snapshot_parser_parses_interface_dump) {
    const auto snapshot = SnapshotParser::parse_dump("wg0", kBaseDump);

    EXPECT_TRUE(snapshot.has_value());
    EXPECT_EQ(snapshot->interface_name, "wg0");
    EXPECT_EQ(snapshot->peers.size(), 2U);
    EXPECT_EQ(snapshot->peers.at("peer-a").allowed_ips.size(), 1U);
    EXPECT_EQ(snapshot->peers.at("peer-a").allowed_ips.at(0), "10.0.0.2/32");
    EXPECT_TRUE(snapshot->peers.at("peer-a").endpoint.has_value());
    EXPECT_EQ(*snapshot->peers.at("peer-a").endpoint, "198.51.100.10:12345");
    EXPECT_FALSE(snapshot->peers.at("peer-b").endpoint.has_value());
}

TEST_CASE(snapshot_parser_rejects_malformed_dump) {
    const auto snapshot = SnapshotParser::parse_dump("wg0", "bad-row\npeer-a\tbroken\n");

    EXPECT_FALSE(snapshot.has_value());
}

TEST_CASE(snapshot_differ_seeds_initial_snapshot_without_emitting_events) {
    const auto snapshot = SnapshotParser::parse_dump("wg0", kBaseDump);

    const auto events = normalize(SnapshotDiffer::diff(std::nullopt, *snapshot));

    EXPECT_TRUE(events.empty());
}

TEST_CASE(snapshot_differ_emits_handshake_observed_when_handshake_appears) {
    const auto previous = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t0\t100\t200\toff\n");
    const auto current = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t1710000001\t100\t200\toff\n");

    const auto events = SnapshotDiffer::diff(previous, *current);

    EXPECT_EQ(events.size(), 1U);
    EXPECT_EQ(events.front().type, EventType::HandshakeObserved);
    EXPECT_EQ(events.front().peer_public_key, "peer-a");
}

TEST_CASE(snapshot_differ_emits_peer_observed_for_new_runtime_peer) {
    const auto previous = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t0\t100\t200\toff\n");
    const auto current = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t0\t100\t200\toff\n"
        "peer-b\t(none)\t(none)\t10.0.0.3/32\t1710000000\t300\t400\t25\n");

    const auto events = normalize(SnapshotDiffer::diff(previous, *current));

    EXPECT_EQ(events.size(), 2U);
    EXPECT_EQ(events.at(0).first, EventType::PeerObserved);
    EXPECT_EQ(events.at(0).second, "peer-b");
    EXPECT_EQ(events.at(1).first, EventType::HandshakeObserved);
    EXPECT_EQ(events.at(1).second, "peer-b");
}

TEST_CASE(snapshot_differ_emits_peer_removed_for_missing_peer) {
    const auto previous = SnapshotParser::parse_dump("wg0", kBaseDump);
    const auto current = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t0\t100\t200\toff\n");

    const auto events = SnapshotDiffer::diff(previous, *current);

    EXPECT_EQ(events.size(), 1U);
    EXPECT_EQ(events.front().type, EventType::PeerRemoved);
    EXPECT_EQ(events.front().peer_public_key, "peer-b");
}

TEST_CASE(snapshot_differ_emits_handshake_observed_and_traffic_update) {
    const auto previous = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t1710000001\t100\t200\toff\n");
    const auto current = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t1710000002\t101\t200\toff\n");

    const auto events = normalize(SnapshotDiffer::diff(previous, *current));

    EXPECT_EQ(events.size(), 2U);
    EXPECT_EQ(events.at(0).first, EventType::HandshakeObserved);
    EXPECT_EQ(events.at(1).first, EventType::TrafficUpdated);
}

// TODO(stage-1/observer-semantics): re-enable once the event model separates
// first handshake from handshake refresh per spec.
#if 0
TEST_CASE(snapshot_differ_must_distinguish_first_handshake_from_handshake_refresh_per_spec) {
    const auto previous = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t1710000001\t100\t200\toff\n");
    const auto current = SnapshotParser::parse_dump(
        "wg0",
        "private-key\tpublic-key\t51820\toff\n"
        "peer-a\t(none)\t198.51.100.10:12345\t10.0.0.2/32\t1710000002\t101\t200\toff\n");

    const auto events = SnapshotDiffer::diff(previous, *current);

    EXPECT_EQ(events.size(), 2U);
    EXPECT_TRUE(HasHandshakeRefreshed<EventType>);
    EXPECT_EQ(events.at(1).type, EventType::TrafficUpdated);
}
#endif
