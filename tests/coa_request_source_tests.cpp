#include "wg_radius/coa/request_source.hpp"

#include "test_harness.hpp"

#include <openssl/hmac.h>
#include <openssl/md5.h>

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

std::vector<std::uint8_t> encode_attr(std::uint8_t type, const std::string& value) {
    std::vector<std::uint8_t> attr;
    attr.push_back(type);
    attr.push_back(static_cast<std::uint8_t>(value.size() + 2));
    attr.insert(attr.end(), value.begin(), value.end());
    return attr;
}

std::vector<std::uint8_t> encode_uint32_attr(std::uint8_t type, std::uint32_t value) {
    std::vector<std::uint8_t> attr;
    attr.push_back(type);
    attr.push_back(6);
    attr.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    attr.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    attr.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    attr.push_back(static_cast<std::uint8_t>(value & 0xff));
    return attr;
}

std::vector<std::uint8_t> encode_vendor_uint32_attr(std::uint32_t vendor, std::uint8_t vendor_type, std::uint32_t value) {
    std::vector<std::uint8_t> attr;
    attr.push_back(26);
    attr.push_back(12);
    attr.push_back(static_cast<std::uint8_t>((vendor >> 24) & 0xff));
    attr.push_back(static_cast<std::uint8_t>((vendor >> 16) & 0xff));
    attr.push_back(static_cast<std::uint8_t>((vendor >> 8) & 0xff));
    attr.push_back(static_cast<std::uint8_t>(vendor & 0xff));
    attr.push_back(vendor_type);
    attr.push_back(6);
    attr.push_back(static_cast<std::uint8_t>((value >> 24) & 0xff));
    attr.push_back(static_cast<std::uint8_t>((value >> 16) & 0xff));
    attr.push_back(static_cast<std::uint8_t>((value >> 8) & 0xff));
    attr.push_back(static_cast<std::uint8_t>(value & 0xff));
    return attr;
}

std::vector<std::uint8_t> build_radius_packet(
    std::uint8_t code,
    std::uint8_t identifier,
    const std::string& secret,
    const std::vector<std::vector<std::uint8_t>>& attrs) {
    std::vector<std::uint8_t> packet(20, 0);
    packet[0] = code;
    packet[1] = identifier;
    packet[2] = 0;
    packet[3] = 0;
    for (const auto& attr : attrs) {
        packet.insert(packet.end(), attr.begin(), attr.end());
    }

    const auto length = static_cast<std::uint16_t>(packet.size() + 18);
    packet[2] = static_cast<std::uint8_t>((length >> 8) & 0xff);
    packet[3] = static_cast<std::uint8_t>(length & 0xff);
    const auto message_auth_offset = packet.size();
    packet.push_back(80);
    packet.push_back(18);
    packet.insert(packet.end(), 16, 0);

    std::vector<std::uint8_t> auth_input = packet;
    std::fill(auth_input.begin() + 4, auth_input.begin() + 20, 0);
    auth_input.insert(auth_input.end(), secret.begin(), secret.end());

    unsigned char request_authenticator[MD5_DIGEST_LENGTH];
    MD5(auth_input.data(), auth_input.size(), request_authenticator);
    for (int i = 0; i < MD5_DIGEST_LENGTH; ++i) {
        packet[4 + i] = request_authenticator[i];
    }

    std::vector<std::uint8_t> hmac_input = packet;
    for (int i = 0; i < 16; ++i) {
        hmac_input[message_auth_offset + 2 + i] = 0;
    }

    unsigned int hmac_length = 0;
    unsigned char* hmac =
        HMAC(EVP_md5(), secret.data(), static_cast<int>(secret.size()), hmac_input.data(), hmac_input.size(), nullptr, &hmac_length);
    EXPECT_TRUE(hmac != nullptr);
    EXPECT_EQ(hmac_length, 16U);

    for (int i = 0; i < 16; ++i) {
        packet[message_auth_offset + 2 + i] = hmac[i];
    }

    return packet;
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

TEST_CASE(udp_coa_request_source_parses_coa_datagram_with_policy_updates) {
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

    const char payload[] = "coa secret peer-a ingress_bps=1234 egress_bps=5678 session_timeout=90";
    EXPECT_TRUE(
        sendto(fd, payload, sizeof(payload) - 1, 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >=
        0);
    close(fd);

    for (int attempt = 0; attempt < 20; ++attempt) {
        const auto request = source.try_pop_request();
        if (request.has_value()) {
            EXPECT_EQ(request->type, coa::RequestType::Coa);
            EXPECT_EQ(request->peer_public_key, "peer-a");
            EXPECT_TRUE(request->policy.has_value());
            EXPECT_EQ(request->policy->ingress_bps, std::optional<std::uint64_t>{1234});
            EXPECT_EQ(request->policy->egress_bps, std::optional<std::uint64_t>{5678});
            EXPECT_EQ(
                request->policy->session_timeout,
                std::optional<std::chrono::seconds>{std::chrono::seconds{90}});
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    EXPECT_TRUE(false);
}

TEST_CASE(udp_coa_request_source_rejects_coa_datagram_without_valid_policy_attributes) {
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

    const char payload[] = "coa secret peer-a broken_attribute";
    EXPECT_TRUE(
        sendto(fd, payload, sizeof(payload) - 1, 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >=
        0);
    close(fd);

    for (int attempt = 0; attempt < 20; ++attempt) {
        EXPECT_TRUE(!source.try_pop_request().has_value());
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}

TEST_CASE(udp_coa_request_source_rejects_disconnect_datagram_with_unexpected_trailing_tokens) {
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

    const char payload[] = "disconnect secret peer-a unexpected";
    EXPECT_TRUE(
        sendto(fd, payload, sizeof(payload) - 1, 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >=
        0);
    close(fd);

    for (int attempt = 0; attempt < 20; ++attempt) {
        EXPECT_TRUE(!source.try_pop_request().has_value());
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}

TEST_CASE(udp_coa_request_source_parses_radius_disconnect_request_with_message_authenticator) {
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

    const auto packet = build_radius_packet(40, 7, "secret", {encode_attr(1, "peer-radius-disc")});
    EXPECT_TRUE(
        sendto(fd, packet.data(), packet.size(), 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >=
        0);
    close(fd);

    for (int attempt = 0; attempt < 20; ++attempt) {
        const auto request = source.try_pop_request();
        if (request.has_value()) {
            EXPECT_EQ(request->type, coa::RequestType::Disconnect);
            EXPECT_EQ(request->peer_public_key, "peer-radius-disc");
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    EXPECT_TRUE(false);
}

TEST_CASE(udp_coa_request_source_parses_radius_coa_request_with_policy_updates) {
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

    const auto packet = build_radius_packet(
        43,
        9,
        "secret",
        {
            encode_attr(1, "peer-radius-coa"),
            encode_uint32_attr(27, 120),
            encode_vendor_uint32_attr(10055, 1, 3456),
            encode_vendor_uint32_attr(10055, 2, 7890),
        });
    EXPECT_TRUE(
        sendto(fd, packet.data(), packet.size(), 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >=
        0);
    close(fd);

    for (int attempt = 0; attempt < 20; ++attempt) {
        const auto request = source.try_pop_request();
        if (request.has_value()) {
            EXPECT_EQ(request->type, coa::RequestType::Coa);
            EXPECT_EQ(request->peer_public_key, "peer-radius-coa");
            EXPECT_TRUE(request->policy.has_value());
            EXPECT_EQ(request->policy->ingress_bps, std::optional<std::uint64_t>{7890});
            EXPECT_EQ(request->policy->egress_bps, std::optional<std::uint64_t>{3456});
            EXPECT_EQ(
                request->policy->session_timeout,
                std::optional<std::chrono::seconds>{std::chrono::seconds{120}});
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    EXPECT_TRUE(false);
}

TEST_CASE(udp_coa_request_source_rejects_radius_request_from_unexpected_sender) {
    const auto port = test_port();
    coa::UdpRequestSource source{
        radius::RadiusEndpoint{.host = "127.0.0.2", .port = port},
        "secret"};

    const int fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_TRUE(fd >= 0);

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    EXPECT_TRUE(inet_pton(AF_INET, "127.0.0.2", &address.sin_addr) == 1);

    const auto packet = build_radius_packet(40, 11, "secret", {encode_attr(1, "peer-radius-disc")});
    EXPECT_TRUE(
        sendto(fd, packet.data(), packet.size(), 0, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) >=
        0);
    close(fd);

    for (int attempt = 0; attempt < 20; ++attempt) {
        EXPECT_TRUE(!source.try_pop_request().has_value());
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
}
