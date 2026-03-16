#include "wg_radius/application/command_executor.hpp"
#include "wg_radius/shaping/noop_traffic_shaper.hpp"
#include "wg_radius/wireguard/netlink_peer_controller.hpp"
#include "wg_radius/wireguard/netlink_wireguard_client.hpp"

#include <iostream>
#include <string>

namespace {

int print_usage() {
    std::cerr << "usage:\n";
    std::cerr << "  wg_native_smoke snapshot <iface>\n";
    std::cerr << "  wg_native_smoke remove-peer <iface> <peer-pubkey>\n";
    std::cerr << "  wg_native_smoke exec-remove-peer <iface> <peer-pubkey>\n";
    return 2;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 3) {
        return print_usage();
    }

    const std::string command = argv[1];
    const std::string interface_name = argv[2];

    if (command == "snapshot") {
        wg_radius::wireguard::NetlinkWireGuardClient client;
        const auto snapshot = client.fetch_interface_snapshot(interface_name);
        if (!snapshot.has_value()) {
            std::cerr << "failed to read snapshot for interface " << interface_name << '\n';
            return 1;
        }

        std::cout << "interface: " << snapshot->interface_name << '\n';
        std::cout << "peers: " << snapshot->peers.size() << '\n';
        for (const auto& [public_key, peer] : snapshot->peers) {
            std::cout << "- peer: " << public_key << '\n';
            std::cout << "  endpoint: " << (peer.endpoint.has_value() ? *peer.endpoint : "<none>") << '\n';
            std::cout << "  handshake: " << peer.latest_handshake_epoch_sec << '\n';
            std::cout << "  rx: " << peer.transfer_rx_bytes << '\n';
            std::cout << "  tx: " << peer.transfer_tx_bytes << '\n';
            std::cout << "  allowed_ips:";
            if (peer.allowed_ips.empty()) {
                std::cout << " <none>";
            } else {
                for (const auto& allowed_ip : peer.allowed_ips) {
                    std::cout << ' ' << allowed_ip;
                }
            }
            std::cout << '\n';
        }
        return 0;
    }

    if (command == "remove-peer") {
        if (argc != 4) {
            return print_usage();
        }

        wg_radius::wireguard::NetlinkPeerController controller;
        const bool ok = controller.remove_peer(interface_name, argv[3]);
        if (!ok) {
            std::cerr << "failed to remove peer from interface " << interface_name << '\n';
            return 1;
        }

        std::cout << "peer removed\n";
        return 0;
    }

    if (command == "exec-remove-peer") {
        if (argc != 4) {
            return print_usage();
        }

        wg_radius::wireguard::NetlinkPeerController controller;
        wg_radius::shaping::NoopTrafficShaper traffic_shaper;
        wg_radius::application::CommandExecutor executor{
            interface_name,
            controller,
            traffic_shaper,
        };
        const auto result = executor.execute({
            .type = wg_radius::domain::CommandType::RemovePeer,
            .peer_public_key = argv[3],
            .accounting_session_id = std::nullopt,
            .policy = std::nullopt,
        });
        if (result.status != wg_radius::application::CommandExecutionStatus::Executed) {
            std::cerr << "command executor failed to remove peer from interface " << interface_name
                      << '\n';
            return 1;
        }

        std::cout << "peer removed via executor\n";
        return 0;
    }

    return print_usage();
}
