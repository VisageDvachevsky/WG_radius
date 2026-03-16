cmake_minimum_required(VERSION 3.31)

project(wg_radius VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()

add_library(
    wg_radius_domain
    src/domain/peer_session.cpp
    src/domain/session_manager.cpp
)

target_include_directories(
    wg_radius_domain
    PUBLIC
        ${PROJECT_SOURCE_DIR}/include
)

add_executable(
    wg_radius_domain_tests
    tests/test_main.cpp
    tests/peer_session_tests.cpp
    tests/session_manager_tests.cpp
)

target_link_libraries(
    wg_radius_domain_tests
    PRIVATE
        wg_radius_domain
)

add_test(NAME wg_radius_domain_tests COMMAND wg_radius_domain_tests)
