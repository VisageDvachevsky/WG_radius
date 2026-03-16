#pragma once

#include "wg_radius/radius/radius_client.hpp"
#include "wg_radius/radius/radius_profile.hpp"

namespace wg_radius::radius {

class RadcliRadiusClient final : public RadiusClient {
public:
    explicit RadcliRadiusClient(RadiusProfile profile);

    [[nodiscard]] AuthorizationResponse authorize(
        const AuthorizationRequest& request) override;

private:
    RadiusProfile profile_;
};

}  // namespace wg_radius::radius
