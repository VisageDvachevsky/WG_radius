#include <iostream>
#include "test_harness.hpp"

int main() {
    int failed = 0;

    for (const auto& test_case : test::registry()) {
        try {
            test_case.function();
            std::cout << "[PASS] " << test_case.name << '\n';
        } catch (const test::Failure& failure) {
            ++failed;
            std::cerr << "[FAIL] " << test_case.name << ": " << failure.message << '\n';
        } catch (const std::exception& ex) {
            ++failed;
            std::cerr << "[FAIL] " << test_case.name << ": unexpected exception: " << ex.what()
                      << '\n';
        } catch (...) {
            ++failed;
            std::cerr << "[FAIL] " << test_case.name << ": unknown exception\n";
        }
    }

    return failed == 0 ? 0 : 1;
}
