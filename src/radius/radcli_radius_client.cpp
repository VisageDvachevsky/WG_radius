#include "wg_radius/radius/radcli_radius_client.hpp"

#include <radcli/radcli.h>

#include <array>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <arpa/inet.h>
#include <iostream>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <unistd.h>

namespace wg_radius::radius {

namespace {

constexpr char kDictionary[] =
    "ATTRIBUTE User-Name 1 string\n"
    "ATTRIBUTE User-Password 2 string\n"
    "ATTRIBUTE NAS-IP-Address 4 ipaddr\n"
    "ATTRIBUTE NAS-Port 5 integer\n"
    "ATTRIBUTE Service-Type 6 integer\n"
    "ATTRIBUTE Framed-IP-Address 8 ipaddr\n"
    "ATTRIBUTE Reply-Message 18 string\n"
    "ATTRIBUTE Session-Timeout 27 integer\n"
    "ATTRIBUTE Calling-Station-Id 31 string\n"
    "ATTRIBUTE NAS-Identifier 32 string\n"
    "ATTRIBUTE Proxy-State 33 string\n"
    "ATTRIBUTE Acct-Status-Type 40 integer\n"
    "ATTRIBUTE Acct-Delay-Time 41 integer\n"
    "ATTRIBUTE Acct-Input-Octets 42 integer\n"
    "ATTRIBUTE Acct-Output-Octets 43 integer\n"
    "ATTRIBUTE Acct-Session-Id 44 string\n"
    "ATTRIBUTE Acct-Session-Time 46 integer\n"
    "ATTRIBUTE Acct-Terminate-Cause 49 integer\n"
    "ATTRIBUTE Connect-Info 77 string\n"
    "ATTRIBUTE Acct-Interim-Interval 85 integer\n"
    "ATTRIBUTE Idle-Timeout 28 integer\n"
    "ATTRIBUTE Message-Authenticator 80 string\n"
    "VENDOR Roaring-Penguin 10055\n"
    "ATTRIBUTE RP-Upstream-Speed-Limit 1 integer Roaring-Penguin\n"
    "ATTRIBUTE RP-Downstream-Speed-Limit 2 integer Roaring-Penguin\n";

std::string make_server_string(const RadiusEndpoint& endpoint) {
    return endpoint.host + ":" + std::to_string(endpoint.port);
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

std::optional<std::uint32_t> parse_ipv4_host_order(const std::string& value) {
    in_addr address{};
    if (inet_pton(AF_INET, value.c_str(), &address) != 1) {
        return std::nullopt;
    }

    return ntohl(address.s_addr);
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

const char* stop_reason_string(domain::AccountingStopReason reason) {
    switch (reason) {
        case domain::AccountingStopReason::PeerRemoved:
            return "peer-removed";
        case domain::AccountingStopReason::InactivityHandshake:
            return "inactive-handshake";
        case domain::AccountingStopReason::InactivityTraffic:
            return "inactive-traffic";
        case domain::AccountingStopReason::InactivityHandshakeAndTraffic:
            return "inactive-handshake-and-traffic";
        case domain::AccountingStopReason::DisconnectRequest:
            return "disconnect-request";
    }

    return "unknown";
}

std::optional<std::uint32_t> stop_reason_code(domain::AccountingStopReason reason) {
    switch (reason) {
        case domain::AccountingStopReason::PeerRemoved:
            return 10;  // NAS-Request
        case domain::AccountingStopReason::InactivityHandshake:
        case domain::AccountingStopReason::InactivityTraffic:
        case domain::AccountingStopReason::InactivityHandshakeAndTraffic:
            return 4;  // Idle-Timeout
        case domain::AccountingStopReason::DisconnectRequest:
            return 6;  // Admin-Reset
    }

    return std::nullopt;
}

}  // namespace

RadcliRadiusClient::RadcliRadiusClient(RadiusProfile profile) : profile_(std::move(profile)) {
    initialized_ = initialize_handle();
}

RadcliRadiusClient::~RadcliRadiusClient() {
    cleanup_servers_file();
}

void RadcliRadiusClient::HandleDeleter::operator()(rc_conf* handle) const noexcept {
    if (handle != nullptr) {
        rc_destroy(handle);
    }
}

bool RadcliRadiusClient::initialize_handle() {
    handle_.reset(rc_new());
    if (!handle_) {
        return false;
    }

    if (!create_servers_file()) {
        return false;
    }

    const char* bind_address = nullptr;
    const char* nas_ip = nullptr;
    if (profile_.nas_ip_address.has_value() && !profile_.nas_ip_address->empty()) {
        bind_address = profile_.nas_ip_address->c_str();
        nas_ip = profile_.nas_ip_address->c_str();
    }

    if (rc_config_init(handle_.get()) == nullptr ||
        rc_add_config(
            handle_.get(),
            "authserver",
            make_server_string(profile_.auth_server).c_str(),
            "wg-radius",
            0) != 0 ||
        rc_add_config(
            handle_.get(),
            "acctserver",
            make_server_string(profile_.accounting_server).c_str(),
            "wg-radius",
            0) != 0 ||
        rc_add_config(handle_.get(), "servers", servers_file_path_.c_str(), "wg-radius", 0) != 0 ||
        (nas_ip != nullptr &&
         rc_add_config(handle_.get(), "nas-ip", nas_ip, "wg-radius", 0) != 0) ||
        (bind_address != nullptr &&
         rc_add_config(handle_.get(), "bindaddr", bind_address, "wg-radius", 0) != 0) ||
        rc_add_config(handle_.get(), "dictionary", "/dev/null", "wg-radius", 0) != 0 ||
        rc_read_dictionary_from_buffer(handle_.get(), kDictionary, sizeof(kDictionary) - 1) != 0) {
        handle_.reset();
        return false;
    }

    const auto timeout_seconds =
        std::max<std::int64_t>(1, std::chrono::duration_cast<std::chrono::seconds>(profile_.timeout).count());
    const auto timeout_string = std::to_string(timeout_seconds);
    const auto retries_string = std::to_string(profile_.retries);
    if (rc_add_config(handle_.get(), "radius_timeout", timeout_string.c_str(), "wg-radius", 0) != 0 ||
        rc_add_config(handle_.get(), "radius_retries", retries_string.c_str(), "wg-radius", 0) != 0 ||
        rc_apply_config(handle_.get()) != 0) {
        handle_.reset();
        return false;
    }

    return true;
}

bool RadcliRadiusClient::create_servers_file() {
    std::array<char, 64> path_template{};
    std::snprintf(path_template.data(), path_template.size(), "/tmp/wg-radius-radcli-XXXXXX");

    const int fd = mkstemp(path_template.data());
    if (fd == -1) {
        return false;
    }

    servers_file_path_ = path_template.data();
    std::set<std::string> hosts{profile_.auth_server.host, profile_.accounting_server.host};
    std::string contents;
    for (const auto& host : hosts) {
        contents.append(host);
        contents.push_back('\t');
        contents.append(profile_.shared_secret);
        contents.push_back('\n');
    }

    const ssize_t written = write(fd, contents.data(), contents.size());
    close(fd);
    if (written != static_cast<ssize_t>(contents.size())) {
        cleanup_servers_file();
        return false;
    }

    return true;
}

void RadcliRadiusClient::cleanup_servers_file() noexcept {
    if (!servers_file_path_.empty()) {
        std::remove(servers_file_path_.c_str());
        servers_file_path_.clear();
    }
}

AuthorizationResponse RadcliRadiusClient::authorize(const AuthorizationRequest& request) {
    std::lock_guard lock(mutex_);
    if (!initialized_ || handle_ == nullptr) {
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
    };

    if (rc_avpair_add(handle_.get(), &send, PW_USER_NAME, request.user_name.c_str(), -1, 0) == nullptr ||
        rc_avpair_add(handle_.get(), &send, PW_CALLING_STATION_ID, request.calling_station_id.c_str(), -1, 0) ==
            nullptr ||
        rc_avpair_add(handle_.get(), &send, PW_NAS_IDENTIFIER, request.nas_identifier.c_str(), -1, 0) ==
            nullptr) {
        cleanup();
        return {.decision = AuthorizationDecision::Error, .policy = std::nullopt};
    }

    if (!request.allowed_ips.empty()) {
        const auto& first_allowed_ip = request.allowed_ips.front();
        const auto slash = first_allowed_ip.find('/');
        const auto framed_ip = first_allowed_ip.substr(0, slash);
        const auto framed_ip_value = parse_ipv4_host_order(framed_ip);
        if (framed_ip_value.has_value() &&
            rc_avpair_add(handle_.get(), &send, PW_FRAMED_IP_ADDRESS, &*framed_ip_value, 0, 0) ==
                nullptr) {
            cleanup();
            return {.decision = AuthorizationDecision::Error, .policy = std::nullopt};
        }
    }

    const auto result = rc_aaa(handle_.get(), 0, send, &received, message.data(), 0, PW_ACCESS_REQUEST);
    if (result != OK_RC && result != REJECT_RC) {
        std::cerr << "radcli authorize failed interface=" << request.interface_name
                  << " user=" << request.user_name << " result=" << result
                  << " message=" << message.data() << '\n';
    }
    const auto response = map_response(result, received);
    cleanup();
    return response;
}

bool RadcliRadiusClient::account(const AccountingRequest& request) {
    std::lock_guard lock(mutex_);
    if (!initialized_ || handle_ == nullptr) {
        return false;
    }

    VALUE_PAIR* send = nullptr;
    auto cleanup = [&]() {
        if (send != nullptr) {
            rc_avpair_free(send);
        }
    };

    const std::uint32_t status_type =
        request.event_type == AccountingEventType::Start
        ? PW_STATUS_START
        : request.event_type == AccountingEventType::InterimUpdate
        ? PW_STATUS_ALIVE
        : PW_STATUS_STOP;

    if (rc_avpair_add(handle_.get(), &send, PW_USER_NAME, request.peer_public_key.c_str(), -1, 0) ==
            nullptr ||
        rc_avpair_add(handle_.get(), &send, PW_CALLING_STATION_ID, request.peer_public_key.c_str(), -1, 0) ==
            nullptr ||
        rc_avpair_add(handle_.get(), &send, PW_NAS_IDENTIFIER, profile_.nas_identifier.c_str(), -1, 0) ==
            nullptr ||
        rc_avpair_add(handle_.get(), &send, PW_ACCT_SESSION_ID, request.accounting_session_id.c_str(), -1, 0) ==
            nullptr ||
        rc_avpair_add(handle_.get(), &send, PW_ACCT_STATUS_TYPE, &status_type, sizeof(status_type), 0) ==
            nullptr) {
        cleanup();
        return false;
    }

    if (request.endpoint.has_value() || request.stop_reason.has_value()) {
        std::string connect_info;
        if (request.endpoint.has_value()) {
            connect_info = std::string{"wg-endpoint="} + *request.endpoint;
        }
        if (request.stop_reason.has_value()) {
            if (!connect_info.empty()) {
                connect_info.append(";");
            }
            connect_info.append("wg-stop-reason=");
            connect_info.append(stop_reason_string(*request.stop_reason));
        }
        if (rc_avpair_add(handle_.get(), &send, 77, connect_info.c_str(), -1, 0) == nullptr) {
            cleanup();
            return false;
        }
    }

    if (request.framed_ip_address.has_value()) {
        const auto framed_ip_value = parse_ipv4_host_order(*request.framed_ip_address);
        if (framed_ip_value.has_value() &&
            rc_avpair_add(handle_.get(), &send, PW_FRAMED_IP_ADDRESS, &*framed_ip_value, 0, 0) == nullptr) {
            cleanup();
            return false;
        }
    }

    const auto rx_octets = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(request.transfer_rx_bytes, std::numeric_limits<std::uint32_t>::max()));
    const auto tx_octets = static_cast<std::uint32_t>(
        std::min<std::uint64_t>(request.transfer_tx_bytes, std::numeric_limits<std::uint32_t>::max()));
    if (rc_avpair_add(handle_.get(), &send, PW_ACCT_INPUT_OCTETS, &rx_octets, sizeof(rx_octets), 0) == nullptr ||
        rc_avpair_add(handle_.get(), &send, PW_ACCT_OUTPUT_OCTETS, &tx_octets, sizeof(tx_octets), 0) == nullptr) {
        cleanup();
        return false;
    }

    if (request.session_duration.has_value()) {
        const auto session_time = static_cast<std::uint32_t>(std::max<std::int64_t>(
            0,
            request.session_duration->count()));
        if (rc_avpair_add(handle_.get(), &send, PW_ACCT_SESSION_TIME, &session_time, sizeof(session_time), 0) ==
            nullptr) {
            cleanup();
            return false;
        }
    }

    if (request.stop_reason.has_value()) {
        const auto terminate_cause = stop_reason_code(*request.stop_reason);
        if (terminate_cause.has_value() &&
            rc_avpair_add(
                handle_.get(),
                &send,
                PW_ACCT_TERMINATE_CAUSE,
                &*terminate_cause,
                sizeof(*terminate_cause),
                0) == nullptr) {
            cleanup();
            return false;
        }
    }

    const auto result = rc_acct(handle_.get(), 0, send);
    if (result != OK_RC) {
        std::cerr << "radcli accounting failed interface=" << request.interface_name
                  << " user=" << request.peer_public_key << " result=" << result << '\n';
    }
    cleanup();
    return result == OK_RC;
}

}  // namespace wg_radius::radius
