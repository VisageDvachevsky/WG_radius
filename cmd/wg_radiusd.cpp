#include "wg_radius/application/async_auth_command_processor.hpp"
#include "wg_radius/application/auth_command_processor.hpp"
#include "wg_radius/application/command_executor.hpp"
#include "wg_radius/application/profile_runtime.hpp"
#include "wg_radius/application/wg_event_router.hpp"
#include "wg_radius/application/wg_polling_coordinator.hpp"
#include "wg_radius/config/config_parser.hpp"
#include "wg_radius/domain/session_manager.hpp"
#include "wg_radius/radius/radcli_radius_client.hpp"
#include "wg_radius/shaping/noop_traffic_shaper.hpp"
#include "wg_radius/wireguard/netlink_peer_controller.hpp"
#include "wg_radius/wireguard/netlink_wireguard_client.hpp"

#include <chrono>
#include <fstream>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace {

int print_usage() {
    std::cerr << "usage: wg_radiusd <config-file> [--once]\n";
    return 2;
}

struct RuntimeContext {
    wg_radius::domain::SessionManager session_manager;
    wg_radius::wireguard::NetlinkWireGuardClient wireguard_client;
    wg_radius::wireguard::NetlinkPeerController peer_controller;
    wg_radius::shaping::NoopTrafficShaper traffic_shaper;
    wg_radius::radius::RadcliRadiusClient radius_client;
    wg_radius::application::WgEventRouter event_router;
    wg_radius::application::WgPollingCoordinator polling_coordinator;
    wg_radius::application::AuthCommandProcessor auth_processor;
    wg_radius::application::AsyncAuthCommandProcessor async_auth_processor;
    wg_radius::application::CommandExecutor command_executor;
    wg_radius::application::ProfileRuntime runtime;

    explicit RuntimeContext(const wg_radius::config::InterfaceProfile& profile)
        : session_manager(profile.authorization_trigger, profile.reject_mode),
          wireguard_client(),
          peer_controller(),
          traffic_shaper(),
          radius_client(profile.radius_profile),
          event_router(session_manager),
          polling_coordinator(profile.interface_name, wireguard_client, event_router),
          auth_processor(profile.interface_name, profile.radius_profile, session_manager, radius_client),
          async_auth_processor(auth_processor),
          command_executor(profile.interface_name, radius_client, peer_controller, traffic_shaper),
          runtime(polling_coordinator, async_auth_processor, session_manager, command_executor) {}
};

}  // namespace

int main(int argc, char** argv) {
    if (argc != 2 && argc != 3) {
        return print_usage();
    }

    const bool run_once = argc == 3 && std::string{argv[2]} == "--once";
    if (argc == 3 && !run_once) {
        return print_usage();
    }

    std::ifstream input(argv[1]);
    if (!input) {
        std::cerr << "failed to open config file: " << argv[1] << '\n';
        return 1;
    }

    std::stringstream buffer;
    buffer << input.rdbuf();

    const auto config = wg_radius::config::ConfigParser::parse(buffer.str());
    if (!config.has_value()) {
        std::cerr << "failed to parse config\n";
        return 1;
    }

    std::vector<std::unique_ptr<RuntimeContext>> runtimes;
    runtimes.reserve(config->profiles.size());
    for (const auto& profile : config->profiles) {
        runtimes.push_back(std::make_unique<RuntimeContext>(profile));
        std::cout << "profile " << profile.name << " interface=" << profile.interface_name
                  << " auth=" << profile.radius_profile.auth_server.host << ':'
                  << profile.radius_profile.auth_server.port
                  << " poll_interval_ms=" << profile.poll_interval_ms << '\n';
    }

    do {
        for (std::size_t index = 0; index < config->profiles.size(); ++index) {
            const auto& profile = config->profiles[index];
            auto result = runtimes[index]->runtime.step();
            std::cout << "profile " << profile.name
                      << " poll_status=" << static_cast<int>(result.poll_status)
                      << " auth_submitted=" << result.auth_commands_submitted
                      << " auth_results=" << result.auth_results_processed
                      << " executed=" << result.executed_commands.size() << '\n';
        }

        if (!run_once) {
            std::this_thread::sleep_for(std::chrono::milliseconds{250});
        }
    } while (!run_once);

    return 0;
}
