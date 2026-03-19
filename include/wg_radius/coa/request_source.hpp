#pragma once

#include "wg_radius/radius/radius_profile.hpp"

#include <optional>
#include <string>

namespace wg_radius::coa {

enum class RequestType {
    Disconnect,
};

struct Request {
    RequestType type;
    std::string peer_public_key;
};

class RequestSource {
public:
    virtual ~RequestSource() = default;

    [[nodiscard]] virtual std::optional<Request> try_pop_request() = 0;
};

class NoopRequestSource final : public RequestSource {
public:
    [[nodiscard]] std::optional<Request> try_pop_request() override;
};

class UdpRequestSource final : public RequestSource {
public:
    UdpRequestSource(
        std::optional<radius::RadiusEndpoint> endpoint,
        std::string shared_secret);
    ~UdpRequestSource();

    UdpRequestSource(const UdpRequestSource&) = delete;
    UdpRequestSource& operator=(const UdpRequestSource&) = delete;

    [[nodiscard]] std::optional<Request> try_pop_request() override;

private:
    int fd_{-1};
    std::string shared_secret_;
};

}  // namespace wg_radius::coa
