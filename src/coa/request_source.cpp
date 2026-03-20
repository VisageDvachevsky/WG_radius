#include "wg_radius/coa/request_source.hpp"

#include <openssl/hmac.h>

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace wg_radius::coa {

namespace {

constexpr std::uint8_t kDisconnectRequestCode = 40;
constexpr std::uint8_t kCoaRequestCode = 43;
constexpr std::uint8_t kUserNameAttr = 1;
constexpr std::uint8_t kSessionTimeoutAttr = 27;
constexpr std::uint8_t kCallingStationIdAttr = 31;
constexpr std::uint8_t kVendorSpecificAttr = 26;
constexpr std::uint8_t kMessageAuthenticatorAttr = 80;
constexpr std::uint32_t kRoaringPenguinVendorId = 10055;
constexpr std::uint8_t kRpUpstreamSpeedLimitAttr = 1;
constexpr std::uint8_t kRpDownstreamSpeedLimitAttr = 2;

std::optional<std::uint64_t> parse_u64(const std::string& value) {
    std::uint64_t parsed = 0;
    const auto [ptr, ec] = std::from_chars(value.data(), value.data() + value.size(), parsed);
    if (ec != std::errc{} || ptr != value.data() + value.size()) {
        return std::nullopt;
    }
    return parsed;
}

std::uint16_t read_u16(const std::uint8_t* bytes) {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(bytes[0]) << 8) | bytes[1]);
}

std::uint32_t read_u32(const std::uint8_t* bytes) {
    return (static_cast<std::uint32_t>(bytes[0]) << 24) | (static_cast<std::uint32_t>(bytes[1]) << 16) |
        (static_cast<std::uint32_t>(bytes[2]) << 8) | static_cast<std::uint32_t>(bytes[3]);
}

bool verify_message_authenticator(
    std::vector<std::uint8_t> packet,
    const std::string& secret,
    std::size_t attribute_offset) {
    if (attribute_offset + 18 > packet.size()) {
        return false;
    }

    std::array<std::uint8_t, 16> message_authenticator{};
    std::memcpy(message_authenticator.data(), packet.data() + attribute_offset + 2, message_authenticator.size());
    std::fill(
        packet.begin() + static_cast<std::ptrdiff_t>(attribute_offset + 2),
        packet.begin() + static_cast<std::ptrdiff_t>(attribute_offset + 18),
        0);

    unsigned int hmac_length = 0;
    unsigned char* digest =
        HMAC(EVP_md5(), secret.data(), static_cast<int>(secret.size()), packet.data(), packet.size(), nullptr, &hmac_length);
    return digest != nullptr && hmac_length == message_authenticator.size() &&
        std::memcmp(digest, message_authenticator.data(), message_authenticator.size()) == 0;
}

std::optional<Request> parse_radius_request(
    const std::vector<std::uint8_t>& packet,
    const std::string& shared_secret) {
    if (packet.size() < 20) {
        return std::nullopt;
    }

    const auto code = packet[0];
    if (code != kDisconnectRequestCode && code != kCoaRequestCode) {
        return std::nullopt;
    }

    const auto packet_length = read_u16(packet.data() + 2);
    if (packet_length != packet.size()) {
        return std::nullopt;
    }

    std::optional<std::size_t> message_authenticator_offset;
    std::optional<std::string> user_name;
    std::optional<std::string> calling_station_id;
    domain::SessionPolicy policy;
    bool has_policy_update = false;

    std::size_t offset = 20;
    while (offset < packet.size()) {
        if (offset + 2 > packet.size()) {
            return std::nullopt;
        }

        const auto type = packet[offset];
        const auto attr_length = packet[offset + 1];
        if (attr_length < 2 || offset + attr_length > packet.size()) {
            return std::nullopt;
        }

        const auto* value = packet.data() + offset + 2;
        const auto value_length = static_cast<std::size_t>(attr_length - 2);

        switch (type) {
            case kUserNameAttr:
                user_name = std::string{reinterpret_cast<const char*>(value), value_length};
                break;
            case kCallingStationIdAttr:
                calling_station_id = std::string{reinterpret_cast<const char*>(value), value_length};
                break;
            case kSessionTimeoutAttr:
                if (value_length != 4) {
                    return std::nullopt;
                }
                policy.session_timeout = std::chrono::seconds{read_u32(value)};
                has_policy_update = true;
                break;
            case kVendorSpecificAttr:
                if (value_length < 6) {
                    return std::nullopt;
                }
                if (read_u32(value) == kRoaringPenguinVendorId) {
                    const auto vendor_type = value[4];
                    const auto vendor_length = value[5];
                    if (vendor_length != 6 || value_length != 10) {
                        return std::nullopt;
                    }
                    const auto vendor_value = read_u32(value + 6);
                    if (vendor_type == kRpUpstreamSpeedLimitAttr) {
                        policy.egress_bps = vendor_value;
                        has_policy_update = true;
                    } else if (vendor_type == kRpDownstreamSpeedLimitAttr) {
                        policy.ingress_bps = vendor_value;
                        has_policy_update = true;
                    }
                }
                break;
            case kMessageAuthenticatorAttr:
                if (value_length != 16 || message_authenticator_offset.has_value()) {
                    return std::nullopt;
                }
                message_authenticator_offset = offset;
                break;
            default:
                break;
        }

        offset += attr_length;
    }

    if (!message_authenticator_offset.has_value() ||
        !verify_message_authenticator(packet, shared_secret, *message_authenticator_offset)) {
        return std::nullopt;
    }

    const auto peer_public_key = user_name.has_value() ? *user_name : calling_station_id.value_or(std::string{});
    if (peer_public_key.empty()) {
        return std::nullopt;
    }

    if (code == kDisconnectRequestCode) {
        return Request{
            .type = RequestType::Disconnect,
            .peer_public_key = peer_public_key,
            .policy = std::nullopt,
        };
    }

    if (!has_policy_update) {
        return std::nullopt;
    }

    return Request{
        .type = RequestType::Coa,
        .peer_public_key = peer_public_key,
        .policy = std::move(policy),
    };
}

std::optional<Request> parse_request(const std::string& payload, const std::string& shared_secret) {
    std::stringstream stream(payload);
    std::string verb;
    std::string secret;
    std::string peer_public_key;
    stream >> verb >> secret >> peer_public_key;

    if (secret != shared_secret || peer_public_key.empty()) {
        return std::nullopt;
    }

    if (verb == "disconnect") {
        std::string trailing;
        if (stream >> trailing) {
            return std::nullopt;
        }
        return Request{
            .type = RequestType::Disconnect,
            .peer_public_key = peer_public_key,
            .policy = std::nullopt,
        };
    }

    if (verb != "coa") {
        return std::nullopt;
    }

    domain::SessionPolicy policy;
    bool any_attribute = false;
    std::string attribute;
    while (stream >> attribute) {
        const auto separator = attribute.find('=');
        if (separator == std::string::npos || separator == 0 || separator == attribute.size() - 1) {
            return std::nullopt;
        }

        const auto key = attribute.substr(0, separator);
        const auto value = attribute.substr(separator + 1);

        if (key == "ingress_bps") {
            const auto parsed = parse_u64(value);
            if (!parsed.has_value()) {
                return std::nullopt;
            }
            policy.ingress_bps = *parsed;
            any_attribute = true;
            continue;
        }

        if (key == "egress_bps") {
            const auto parsed = parse_u64(value);
            if (!parsed.has_value()) {
                return std::nullopt;
            }
            policy.egress_bps = *parsed;
            any_attribute = true;
            continue;
        }

        if (key == "session_timeout") {
            const auto parsed = parse_u64(value);
            if (!parsed.has_value()) {
                return std::nullopt;
            }
            policy.session_timeout = std::chrono::seconds{*parsed};
            any_attribute = true;
            continue;
        }

        return std::nullopt;
    }

    if (!any_attribute) {
        return std::nullopt;
    }

    return Request{
        .type = RequestType::Coa,
        .peer_public_key = peer_public_key,
        .policy = std::move(policy),
    };
}

}  // namespace

std::optional<Request> NoopRequestSource::try_pop_request() {
    return std::nullopt;
}

UdpRequestSource::UdpRequestSource(
    std::optional<radius::RadiusEndpoint> endpoint,
    std::string shared_secret)
    : shared_secret_(std::move(shared_secret)) {
    if (!endpoint.has_value()) {
        return;
    }

    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (fd_ < 0) {
        return;
    }

    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(endpoint->port);
    if (inet_pton(AF_INET, endpoint->host.c_str(), &address.sin_addr) != 1) {
        close(fd_);
        fd_ = -1;
        return;
    }
    allowed_sender_ipv4_host_order_ = ntohl(address.sin_addr.s_addr);

    const int enabled = 1;
    setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
    setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled));

    if (bind(fd_, reinterpret_cast<const sockaddr*>(&address), sizeof(address)) != 0) {
        close(fd_);
        fd_ = -1;
        return;
    }
}

UdpRequestSource::~UdpRequestSource() {
    if (fd_ >= 0) {
        close(fd_);
    }
}

std::optional<Request> UdpRequestSource::try_pop_request() {
    if (fd_ < 0) {
        return std::nullopt;
    }

    std::array<char, 2048> buffer{};
    sockaddr_in sender{};
    socklen_t sender_length = sizeof(sender);
    const auto received =
        recvfrom(fd_, buffer.data(), buffer.size() - 1, MSG_DONTWAIT, reinterpret_cast<sockaddr*>(&sender), &sender_length);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::nullopt;
        }
        return std::nullopt;
    }
    if (received == 0) {
        return std::nullopt;
    }

    if (!allowed_sender_ipv4_host_order_.has_value() || sender.sin_family != AF_INET ||
        ntohl(sender.sin_addr.s_addr) != *allowed_sender_ipv4_host_order_) {
        return std::nullopt;
    }

    buffer[static_cast<std::size_t>(received)] = '\0';
    const auto bytes = std::vector<std::uint8_t>{
        reinterpret_cast<const std::uint8_t*>(buffer.data()),
        reinterpret_cast<const std::uint8_t*>(buffer.data()) + received};

    if (const auto request = parse_radius_request(bytes, shared_secret_); request.has_value()) {
        return request;
    }

    return parse_request(std::string{buffer.data(), static_cast<std::size_t>(received)}, shared_secret_);
}

}  // namespace wg_radius::coa
