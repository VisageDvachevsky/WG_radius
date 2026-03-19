#include "wg_radius/coa/request_source.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <optional>
#include <sstream>
#include <string>

namespace wg_radius::coa {

namespace {

std::optional<Request> parse_request(const std::string& payload, const std::string& shared_secret) {
    std::stringstream stream(payload);
    std::string verb;
    std::string secret;
    std::string peer_public_key;
    stream >> verb >> secret >> peer_public_key;

    if (verb != "disconnect" || secret != shared_secret || peer_public_key.empty()) {
        return std::nullopt;
    }

    return Request{.type = RequestType::Disconnect, .peer_public_key = peer_public_key};
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
    const auto received =
        recv(fd_, buffer.data(), buffer.size() - 1, MSG_DONTWAIT);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return std::nullopt;
        }
        return std::nullopt;
    }
    if (received == 0) {
        return std::nullopt;
    }

    buffer[static_cast<std::size_t>(received)] = '\0';
    return parse_request(std::string{buffer.data()}, shared_secret_);
}

}  // namespace wg_radius::coa
