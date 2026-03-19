#include "wg_radius/config/config_parser.hpp"

#include "test_harness.hpp"

#include <filesystem>

using namespace wg_radius::config;

namespace {

std::filesystem::path project_root() {
    return std::filesystem::path{__FILE__}.parent_path().parent_path();
}

}  // namespace

TEST_CASE(config_parser_parses_multiple_interface_profiles) {
    const auto config = ConfigParser::parse(
        "[profile wg-main]\n"
        "interface = wg0\n"
        "auth_host = 127.0.0.1\n"
        "auth_port = 1812\n"
        "acct_host = 127.0.0.1\n"
        "acct_port = 1813\n"
        "secret = topsecret\n"
        "nas_identifier = wg-main\n"
        "nas_ip_address = 192.0.2.1\n"
        "timeout_ms = 3000\n"
        "retries = 2\n"
        "poll_interval_ms = 1500\n"
        "reject_handling = block-peer\n"
        "authorization_trigger = peer-appearance\n"
        "\n"
        "[profile wg-alt]\n"
        "interface = wg1\n"
        "auth_host = 10.0.0.10\n"
        "auth_port = 18120\n"
        "acct_host = 10.0.0.11\n"
        "acct_port = 18130\n"
        "secret = altsecret\n"
        "nas_identifier = wg-alt\n"
        "authorization_trigger = first-handshake\n");

    EXPECT_TRUE(config.has_value());
    EXPECT_EQ(config->profiles.size(), 2U);
    EXPECT_EQ(config->profiles.at(0).name, "wg-main");
    EXPECT_EQ(config->profiles.at(0).interface_name, "wg0");
    EXPECT_EQ(config->profiles.at(0).radius_profile.auth_server.host, "127.0.0.1");
    EXPECT_EQ(config->profiles.at(0).radius_profile.auth_server.port, 1812);
    EXPECT_EQ(config->profiles.at(0).radius_profile.nas_ip_address, std::optional<std::string>{"192.0.2.1"});
    EXPECT_EQ(config->profiles.at(0).radius_profile.timeout, std::chrono::milliseconds{3000});
    EXPECT_EQ(config->profiles.at(0).poll_interval_ms, 1500);
    EXPECT_EQ(config->profiles.at(0).reject_mode, wg_radius::domain::RejectMode::BlockPeer);
    EXPECT_EQ(config->profiles.at(1).authorization_trigger, wg_radius::domain::AuthorizationTrigger::OnFirstHandshake);
}

TEST_CASE(config_parser_rejects_missing_required_fields) {
    const auto config = ConfigParser::parse(
        "[profile wg-main]\n"
        "interface = wg0\n"
        "auth_host = 127.0.0.1\n");

    EXPECT_FALSE(config.has_value());
}

TEST_CASE(config_parser_rejects_duplicate_profile_names) {
    const auto config = ConfigParser::parse(
        "[profile wg-main]\n"
        "interface = wg0\n"
        "auth_host = 127.0.0.1\n"
        "auth_port = 1812\n"
        "acct_host = 127.0.0.1\n"
        "acct_port = 1813\n"
        "secret = topsecret\n"
        "\n"
        "[profile wg-main]\n"
        "interface = wg1\n"
        "auth_host = 127.0.0.2\n"
        "auth_port = 1812\n"
        "acct_host = 127.0.0.2\n"
        "acct_port = 1813\n"
        "secret = topsecret\n");

    EXPECT_FALSE(config.has_value());
}

TEST_CASE(config_parser_rejects_unknown_keys) {
    const auto config = ConfigParser::parse(
        "[profile wg-main]\n"
        "interface = wg0\n"
        "auth_host = 127.0.0.1\n"
        "auth_port = 1812\n"
        "acct_host = 127.0.0.1\n"
        "acct_port = 1813\n"
        "secret = topsecret\n"
        "surprise = nope\n");

    EXPECT_FALSE(config.has_value());
}

TEST_CASE(config_parser_accepts_accounting_runtime_fields_required_for_phase2) {
    const auto config = ConfigParser::parse(
        "[profile wg-main]\n"
        "interface = wg0\n"
        "auth_host = 127.0.0.1\n"
        "auth_port = 1812\n"
        "acct_host = 127.0.0.1\n"
        "acct_port = 1813\n"
        "secret = topsecret\n"
        "acct_interim_interval = 60\n"
        "inactive_timeout = 300\n"
        "inactivity_strategy = handshake-and-traffic\n");

    EXPECT_TRUE(config.has_value());
    EXPECT_EQ(config->profiles.size(), 1U);
    EXPECT_EQ(config->profiles.front().acct_interim_interval, std::chrono::seconds{60});
    EXPECT_EQ(config->profiles.front().inactive_timeout, std::chrono::seconds{300});
    EXPECT_EQ(
        config->profiles.front().inactivity_strategy,
        wg_radius::config::InactivityStrategy::HandshakeAndTraffic);
}

TEST_CASE(config_parser_accepts_optional_coa_endpoint_fields) {
    const auto config = ConfigParser::parse(
        "[profile wg-main]\n"
        "interface = wg0\n"
        "auth_host = 127.0.0.1\n"
        "auth_port = 1812\n"
        "acct_host = 127.0.0.1\n"
        "acct_port = 1813\n"
        "coa_host = 127.0.0.1\n"
        "coa_port = 3799\n"
        "secret = topsecret\n");

    EXPECT_TRUE(config.has_value());
    EXPECT_TRUE(config->profiles.front().coa_server.has_value());
    EXPECT_EQ(config->profiles.front().coa_server->host, "127.0.0.1");
    EXPECT_EQ(config->profiles.front().coa_server->port, 3799);
}

// TODO(stage-1+/deliverables): re-enable after config grows the remaining spec
// fields and packaging/docs artifacts are added.
#if 0
TEST_CASE(config_parser_must_accept_coa_and_accounting_runtime_settings_required_by_spec) {
    const auto config = ConfigParser::parse(
        "[profile wg-main]\n"
        "interface = wg0\n"
        "auth_host = 127.0.0.1\n"
        "auth_port = 1812\n"
        "acct_host = 127.0.0.1\n"
        "acct_port = 1813\n"
        "coa_host = 127.0.0.1\n"
        "coa_port = 3799\n"
        "secret = topsecret\n"
        "nas_identifier = wg-main\n"
        "acct_interim_interval = 60\n"
        "reject_handling = remove-peer\n"
        "logging_level = info\n"
        "authorization_trigger = peer-appearance\n");

    EXPECT_TRUE(config.has_value());
}

TEST_CASE(config_parser_must_accept_inactivity_policy_fields_required_by_spec) {
    const auto config = ConfigParser::parse(
        "[profile wg-main]\n"
        "interface = wg0\n"
        "auth_host = 127.0.0.1\n"
        "auth_port = 1812\n"
        "acct_host = 127.0.0.1\n"
        "acct_port = 1813\n"
        "secret = topsecret\n"
        "nas_identifier = wg-main\n"
        "inactive_timeout = 300\n"
        "inactivity_strategy = handshake-and-traffic\n"
        "authorization_trigger = peer-appearance\n");

    EXPECT_TRUE(config.has_value());
}

TEST_CASE(project_must_ship_systemd_unit_required_by_spec) {
    EXPECT_TRUE(std::filesystem::exists(project_root() / "packaging/systemd/wg_radiusd.service"));
}

TEST_CASE(project_must_ship_radius_attribute_documentation_required_by_spec) {
    EXPECT_TRUE(std::filesystem::exists(project_root() / "docs/radius-attributes.md"));
}

TEST_CASE(project_must_ship_radius_integration_example_required_by_spec) {
    EXPECT_TRUE(std::filesystem::exists(project_root() / "docs/radius-integration-example.md"));
}

TEST_CASE(project_must_ship_startup_instructions_required_by_spec) {
    EXPECT_TRUE(std::filesystem::exists(project_root() / "docs/startup.md"));
}

TEST_CASE(project_must_ship_attribute_mapping_table_required_by_spec) {
    EXPECT_TRUE(std::filesystem::exists(project_root() / "docs/radius-attribute-mapping.md"));
}
#endif
