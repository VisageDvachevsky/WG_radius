#include "wg_radius/shaping/tc_traffic_shaper.hpp"

#include "test_harness.hpp"

#include <chrono>
#include <string>
#include <vector>

using namespace wg_radius;

namespace {

std::string join(const std::vector<std::string>& argv) {
    std::string result;
    for (std::size_t index = 0; index < argv.size(); ++index) {
        if (index != 0) {
            result += ' ';
        }
        result += argv[index];
    }
    return result;
}

class FakeTcCommandRunner final : public shaping::TcCommandRunner {
public:
    int fail_call{-1};
    int calls{0};
    std::vector<std::string> commands;

    bool run(const std::vector<std::string>& argv) override {
        ++calls;
        commands.push_back(join(argv));
        return fail_call < 0 || calls != fail_call;
    }
};

constexpr auto kPeerClassId = "1:8757";
constexpr auto kPeerPref = "36347";

}  // namespace

TEST_CASE(tc_traffic_shaper_applies_bidirectional_policy_for_allowed_ip) {
    FakeTcCommandRunner runner;
    shaping::TcTrafficShaper shaper{runner};

    EXPECT_TRUE(shaper.apply_policy(
        "wg0",
        "peer-a",
        {"10.0.0.2/32"},
        {.ingress_bps = 10'000, .egress_bps = 20'000, .session_timeout = std::nullopt}));

    EXPECT_EQ(runner.commands.size(), 9U);
    EXPECT_TRUE(runner.commands.at(0).find("tc qdisc replace dev wg0 root handle 1: htb default 1") != std::string::npos);
    EXPECT_TRUE(runner.commands.at(1).find("tc class replace dev wg0 parent 1: classid 1:1 htb") != std::string::npos);
    EXPECT_TRUE(runner.commands.at(2).find("tc qdisc replace dev wg0 clsact") != std::string::npos);
    EXPECT_TRUE(runner.commands.at(3).find(std::string{"tc filter delete dev wg0 parent ffff: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(4).find(std::string{"tc filter delete dev wg0 parent 1: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(5).find(std::string{"tc class delete dev wg0 classid "} + kPeerClassId) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(6).find(std::string{"tc class replace dev wg0 parent 1:1 classid "} + kPeerClassId + " htb rate 20000bit") != std::string::npos);
    EXPECT_TRUE(runner.commands.at(7).find(std::string{"tc filter add dev wg0 parent 1: protocol ip pref "} + kPeerPref + " flower dst_ip 10.0.0.2/32 classid " + kPeerClassId) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(8).find(std::string{"tc filter add dev wg0 parent ffff: protocol ip pref "} + kPeerPref + " flower src_ip 10.0.0.2/32 action police rate 10000bit") != std::string::npos);
}

TEST_CASE(tc_traffic_shaper_removes_existing_peer_policy) {
    FakeTcCommandRunner runner;
    shaping::TcTrafficShaper shaper{runner};

    EXPECT_TRUE(shaper.apply_policy(
        "wg0",
        "peer-a",
        {"10.0.0.2/32"},
        {.ingress_bps = 10'000, .egress_bps = 20'000, .session_timeout = std::nullopt}));
    runner.commands.clear();

    EXPECT_TRUE(shaper.remove_policy("wg0", "peer-a"));

    EXPECT_EQ(runner.commands.size(), 3U);
    EXPECT_TRUE(runner.commands.at(0).find(std::string{"tc filter delete dev wg0 parent ffff: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(1).find(std::string{"tc filter delete dev wg0 parent 1: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(2).find(std::string{"tc class delete dev wg0 classid "} + kPeerClassId) != std::string::npos);
}

TEST_CASE(tc_traffic_shaper_remove_policy_cleans_deterministic_handles_without_in_memory_state) {
    FakeTcCommandRunner runner;
    shaping::TcTrafficShaper shaper{runner};

    EXPECT_TRUE(shaper.remove_policy("wg0", "peer-a"));

    EXPECT_EQ(runner.commands.size(), 3U);
    EXPECT_TRUE(runner.commands.at(0).find(std::string{"tc filter delete dev wg0 parent ffff: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(1).find(std::string{"tc filter delete dev wg0 parent 1: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(2).find(std::string{"tc class delete dev wg0 classid "} + kPeerClassId) != std::string::npos);
}

TEST_CASE(tc_traffic_shaper_policy_without_rates_turns_into_cleanup_only) {
    FakeTcCommandRunner runner;
    shaping::TcTrafficShaper shaper{runner};

    EXPECT_TRUE(shaper.apply_policy(
        "wg0",
        "peer-a",
        {"10.0.0.2/32"},
        {.ingress_bps = std::nullopt, .egress_bps = std::nullopt, .session_timeout = std::chrono::seconds{60}}));

    EXPECT_EQ(runner.commands.size(), 3U);
    EXPECT_TRUE(runner.commands.at(0).find(std::string{"tc filter delete dev wg0 parent ffff: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(1).find(std::string{"tc filter delete dev wg0 parent 1: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(2).find(std::string{"tc class delete dev wg0 classid "} + kPeerClassId) != std::string::npos);
}

TEST_CASE(tc_traffic_shaper_rolls_back_to_previous_policy_when_update_fails) {
    FakeTcCommandRunner runner;
    shaping::TcTrafficShaper shaper{runner};

    EXPECT_TRUE(shaper.apply_policy(
        "wg0",
        "peer-a",
        {"10.0.0.2/32"},
        {.ingress_bps = 10'000, .egress_bps = 20'000, .session_timeout = std::nullopt}));
    runner.commands.clear();
    runner.calls = 0;
    runner.fail_call = 5;

    EXPECT_FALSE(shaper.apply_policy(
        "wg0",
        "peer-a",
        {"10.0.0.3/32"},
        {.ingress_bps = 30'000, .egress_bps = 40'000, .session_timeout = std::nullopt}));

    EXPECT_TRUE(runner.commands.at(0).find(std::string{"tc filter delete dev wg0 parent ffff: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(1).find(std::string{"tc filter delete dev wg0 parent 1: pref "} + kPeerPref) != std::string::npos);
    EXPECT_TRUE(runner.commands.at(2).find(std::string{"tc class delete dev wg0 classid "} + kPeerClassId) != std::string::npos);
    EXPECT_TRUE(runner.commands.back().find(std::string{"tc filter add dev wg0 parent ffff: protocol ip pref "} + kPeerPref + " flower src_ip 10.0.0.2/32 action police rate 10000bit") != std::string::npos);
}
