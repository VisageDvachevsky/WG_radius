#include "wg_radius/coa/request_source.hpp"

#include "test_harness.hpp"

#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstdint>
#include <thread>

using namespace wg_radius;

namespace {

std::uint16_t test_port() {
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    return static_cast<std::uint16_t>(40000 + (ticks % 20000));
}

}  // namespace

TEST_CASE(udp_coa_request_source_parses_disconnect_datagram_with_matching_secret) {
    const auto port = test_port();
    coa::UdpRequestSource source{
        radius::RadiusEndpoint{.host = "127.0.0.1", .port = port},
        "secret"};

    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_TRUE(fd >= 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    EXPECT_TRUE(inet_pton(AF_INET, "127.0.0.1", &address.sin_addr) == 1);

    const char payload[] = "disconnect secret peer-a";
    EXPECT_TRUE(
        sendto(fd, payload, sizeof(payload) - 1, 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >=
        0);
    close(fd);

    for (int attempt = 0; attempt < 20; ++attempt) {
        const auto request = source.try_pop_request();
        if (request.has_value()) {
            EXPECT_EQ(request->type, coa::RequestType::Disconnect);
            EXPECT_EQ(request->peer_public_key, "peer-a");
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    EXPECT_TRUE(false);
}
