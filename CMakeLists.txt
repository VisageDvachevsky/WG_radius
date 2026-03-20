cmake_minimum_required(VERSION 3.31)

project(wg_radius VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBNL REQUIRED IMPORTED_TARGET libnl-3.0 libnl-genl-3.0)
pkg_check_modules(RADCLI REQUIRED IMPORTED_TARGET radcli)

enable_testing()

option(WG_RADIUS_ENABLE_INTEGRATION_TESTS "Enable opt-in integration tests that require sudo and real WireGuard" OFF)

add_library(
    wg_radius_domain
    src/config/config_parser.cpp
    src/domain/peer_session.cpp
    src/domain/session_manager.cpp
    src/application/async_auth_command_processor.cpp
    src/application/auth_command_processor.cpp
    src/application/profile_runtime.cpp
    src/application/command_executor.cpp
    src/coa/request_source.cpp
    src/radius/radcli_radius_client.cpp
    src/application/wg_polling_coordinator.cpp
    src/application/wg_event_router.cpp
    src/shaping/noop_traffic_shaper.cpp
    src/wireguard/netlink_peer_controller.cpp
    src/wireguard/netlink_wireguard_client.cpp
    src/wireguard/wg_snapshot.cpp
)

target_include_directories(
    wg_radius_domain
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

add_executable(
    wg_radius_domain_tests
    tests/test_main.cpp
    tests/async_auth_command_processor_tests.cpp
    tests/auth_command_processor_tests.cpp
    tests/coa_request_source_tests.cpp
    tests/command_executor_tests.cpp
    tests/config_parser_tests.cpp
    tests/peer_session_tests.cpp
    tests/phase1_smoke_tests.cpp
    tests/profile_runtime_tests.cpp
    tests/session_manager_tests.cpp
    tests/wg_event_router_tests.cpp
    tests/wg_polling_coordinator_tests.cpp
    tests/wg_snapshot_tests.cpp
)

target_link_libraries(
    wg_radius_domain
    PRIVATE
        PkgConfig::LIBNL
        PkgConfig::RADCLI
)

target_link_libraries(
    wg_radius_domain_tests
    PRIVATE
        wg_radius_domain
)

add_test(NAME wg_radius_domain_tests COMMAND wg_radius_domain_tests)

add_executable(
    wg_radiusd
    cmd/wg_radiusd.cpp
)

target_link_libraries(
    wg_radiusd
    PRIVATE
        wg_radius_domain
)

add_executable(
    wg_native_smoke
    cmd/wg_native_smoke.cpp
)

target_link_libraries(
    wg_native_smoke
    PRIVATE
        wg_radius_domain
)

if(WG_RADIUS_ENABLE_INTEGRATION_TESTS)
    add_test(
        NAME wg_radius_phase1_integration
        COMMAND
            ${CMAKE_SOURCE_DIR}/tests/integration/phase1_real_wg_smoke.sh
            ${CMAKE_BINARY_DIR}/wg_native_smoke
            ${CMAKE_BINARY_DIR}/wg_radiusd
            ${CMAKE_SOURCE_DIR}
    )
    set_tests_properties(
        wg_radius_phase1_integration
        PROPERTIES
            LABELS "integration;wireguard;phase1"
            SKIP_RETURN_CODE 77
    )

    add_test(
        NAME wg_radius_phase1_radius_integration
        COMMAND
            ${CMAKE_SOURCE_DIR}/tests/integration/phase1_real_radius_flow.sh
            ${CMAKE_BINARY_DIR}/wg_radiusd
            ${CMAKE_SOURCE_DIR}
    )
    set_tests_properties(
        wg_radius_phase1_radius_integration
        PROPERTIES
            LABELS "integration;wireguard;radius;phase1"
            SKIP_RETURN_CODE 77
    )

    add_test(
        NAME wg_radius_phase2_radius_accounting_integration
        COMMAND
            ${CMAKE_SOURCE_DIR}/tests/integration/phase2_real_radius_accounting.sh
            ${CMAKE_BINARY_DIR}/wg_radiusd
            ${CMAKE_SOURCE_DIR}
    )
    set_tests_properties(
        wg_radius_phase2_radius_accounting_integration
        PROPERTIES
            LABELS "integration;wireguard;radius;phase2"
            SKIP_RETURN_CODE 77
    )

    add_test(
        NAME wg_radius_global_smoke_integration
        COMMAND
            ${CMAKE_SOURCE_DIR}/tests/integration/global_real_smoke.sh
            ${CMAKE_BINARY_DIR}/wg_radiusd
            ${CMAKE_SOURCE_DIR}
    )
    set_tests_properties(
        wg_radius_global_smoke_integration
        PROPERTIES
            LABELS "integration;wireguard;radius;phase2;global"
            SKIP_RETURN_CODE 77
    )
endif()
