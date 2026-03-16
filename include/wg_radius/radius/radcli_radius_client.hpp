#pragma once

#include "wg_radius/radius/radius_client.hpp"
#include "wg_radius/radius/radius_profile.hpp"

#include <memory>
#include <mutex>

struct rc_conf;

namespace wg_radius::radius {

class RadcliRadiusClient final : public RadiusClient {
public:
    explicit RadcliRadiusClient(RadiusProfile profile);
    ~RadcliRadiusClient() override;

    RadcliRadiusClient(const RadcliRadiusClient&) = delete;
    RadcliRadiusClient& operator=(const RadcliRadiusClient&) = delete;

    [[nodiscard]] AuthorizationResponse authorize(
        const AuthorizationRequest& request) override;
    [[nodiscard]] bool account(const AccountingRequest& request) override;

private:
    struct HandleDeleter {
        void operator()(rc_conf* handle) const noexcept;
    };

    [[nodiscard]] bool initialize_handle();

    RadiusProfile profile_;
    std::unique_ptr<rc_conf, HandleDeleter> handle_;
    bool initialized_{false};
    std::mutex mutex_;
};

}  // namespace wg_radius::radius
