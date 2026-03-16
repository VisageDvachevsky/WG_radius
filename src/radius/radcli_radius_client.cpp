#include "wg_radius/radius/radcli_radius_client.hpp"

#include <radcli/radcli.h>

#include <array>
#include <charconv>
#include <optional>
#include <string>

namespace wg_radius::radius {

namespace {

constexpr char kDictionary[] =
    "ATTRIBUTE User-Name 1 string\n"
    "ATTRIBUTE NAS-IP-Address 4 ipaddr\n"
    "ATTRIBUTE Service-Type 6 integer\n"
    "ATTRIBUTE Framed-IP-Address 8 ipaddr\n"
    "ATTRIBUTE Session-Timeout 27 integer\n"
    "ATTRIBUTE Calling-Station-Id 31 string\n"
    "ATTRIBUTE NAS-Identifier 32 string\n"
    "ATTRIBUTE Acct-Interim-Interval 85 integer\n"
    "ATTRIBUTE Idle-Timeout 28 integer\n"
    "VENDOR Roaring-Penguin 10055\n"
    "ATTRIBUTE RP-Upstream-Speed-Limit 1 integer Roaring-Penguin\n"
    "ATTRIBUTE RP-Downstream-Speed-Limit 2 integer Roaring-Penguin\n";

std::string make_server_string(const RadiusEndpoint& endpoint, const std::string& secret) {
    return endpoint.host + ":" + std::to_string(endpoint.port) + ":" + secret;
}

std::optional<std::uint32_t> get_uint32_attr(VALUE_PAIR* received, int attrid, int vendor = 0) {
    VALUE_PAIR* pair = rc_avpair_get(received, attrid, vendor);
    if (pair == nullptr) {
        return std::nullopt;
    }

    std::uint32_t value = 0;
    if (rc_avpair_get_uint32(pair, &value) != 0) {
        return std::nullopt;
    }

    return value;
}

AuthorizationResponse map_response(int result, VALUE_PAIR* received) {
    switch (result) {
        case OK_RC: {
            domain::SessionPolicy policy;
            if (const auto timeout = get_uint32_attr(received, PW_SESSION_TIMEOUT); timeout.has_value()) {
                policy.session_timeout = std::chrono::seconds{*timeout};
            }
            if (const auto ingress = get_uint32_attr(received, 2, VENDOR_ROARING_PENGUIN); ingress.has_value()) {
                policy.ingress_bps = *ingress;
            }
            if (const auto egress = get_uint32_attr(received, 1, VENDOR_ROARING_PENGUIN); egress.has_value()) {
                policy.egress_bps = *egress;
            }
            return {.decision = AuthorizationDecision::Accept, .policy = policy};
        }
        case REJECT_RC:
            return {.decision = AuthorizationDecision::Reject, .policy = std::nullopt};
        case ERROR_RC:
        case TIMEOUT_RC:
        case BADRESP_RC:
        default:
            return {.decision = AuthorizationDecision::Error, .policy = std::nullopt};
    }
}

}  // namespace

RadcliRadiusClient::RadcliRadiusClient(RadiusProfile profile) : profile_(std::move(profile)) {}

AuthorizationResponse RadcliRadiusClient::authorize(const AuthorizationRequest& request) {
    rc_handle* handle = rc_new();
    if (handle == nullptr) {
        return {.decision = AuthorizationDecision::Error, .policy = std::nullopt};
    }

    VALUE_PAIR* send = nullptr;
    VALUE_PAIR* received = nullptr;
    std::array<char, 4096> message{};

    auto cleanup = [&]() {
        if (send != nullptr) {
            rc_avpair_free(send);
        }
        if (received != nullptr) {
            rc_avpair_free(received);
        }
        rc_destroy(handle);
    };

    if (rc_config_init(handle) == nullptr ||
        rc_add_config(
            handle,
            "authserver",
            make_server_string(profile_.auth_server, profile_.shared_secret).c_str(),
            "wg-radius",
            0) != 0 ||
        rc_add_config(
            handle,
            "acctserver",
            make_server_string(profile_.accounting_server, profile_.shared_secret).c_str(),
            "wg-radius",
            0) != 0 ||
        rc_add_config(handle, "dictionary", "/dev/null", "wg-radius", 0) != 0 ||
        rc_read_dictionary_from_buffer(handle, kDictionary, sizeof(kDictionary) - 1) != 0 ||
        rc_apply_config(handle) != 0) {
        cleanup();
        return {.decision = AuthorizationDecision::Error, .policy = std::nullopt};
    }

    const auto timeout_seconds =
        std::max<std::int64_t>(1, std::chrono::duration_cast<std::chrono::seconds>(profile_.timeout).count());
    const auto timeout_string = std::to_string(timeout_seconds);
    const auto retries_string = std::to_string(profile_.retries);
    if (rc_add_config(handle, "radius_timeout", timeout_string.c_str(), "wg-radius", 0) != 0 ||
        rc_add_config(handle, "radius_retries", retries_string.c_str(), "wg-radius", 0) != 0) {
        cleanup();
        return {.decision = AuthorizationDecision::Error, .policy = std::nullopt};
    }

    if (rc_avpair_add(handle, &send, PW_USER_NAME, request.peer_public_key.c_str(), -1, 0) == nullptr ||
        rc_avpair_add(handle, &send, PW_CALLING_STATION_ID, request.peer_public_key.c_str(), -1, 0) ==
            nullptr ||
        rc_avpair_add(handle, &send, PW_NAS_IDENTIFIER, profile_.nas_identifier.c_str(), -1, 0) ==
            nullptr) {
        cleanup();
        return {.decision = AuthorizationDecision::Error, .policy = std::nullopt};
    }

    const auto result = rc_auth(handle, 0, send, &received, message.data());
    const auto response = map_response(result, received);
    cleanup();
    return response;
}

}  // namespace wg_radius::radius
