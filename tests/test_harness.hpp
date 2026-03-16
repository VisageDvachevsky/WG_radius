#pragma once

#include <exception>
#include <functional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace test {

struct Failure {
    std::string message;
};

using TestFunction = std::function<void()>;

struct TestCase {
    std::string name;
    TestFunction function;
};

inline std::vector<TestCase>& registry() {
    static std::vector<TestCase> tests;
    return tests;
}

class Registrar {
public:
    Registrar(std::string name, TestFunction function) {
        registry().push_back(TestCase{std::move(name), std::move(function)});
    }
};

[[noreturn]] inline void fail(const char* expr, const char* file, int line) {
    std::ostringstream stream;
    stream << file << ":" << line << ": expectation failed: " << expr;
    throw Failure{stream.str()};
}

template <typename Left, typename Right>
void expect_equal(
    const Left& left,
    const Right& right,
    const char* left_expr,
    const char* right_expr,
    const char* file,
    int line) {
    if (!(left == right)) {
        std::ostringstream stream;
        stream << file << ":" << line << ": expected " << left_expr << " == " << right_expr;
        throw Failure{stream.str()};
    }
}

}  // namespace test

#define TEST_CASE(name)                                      \
    static void name();                                      \
    static ::test::Registrar name##_registrar{#name, name};  \
    static void name()

#define EXPECT_TRUE(expr) \
    do {                  \
        if (!(expr)) {    \
            ::test::fail(#expr, __FILE__, __LINE__); \
        }                 \
    } while (false)

#define EXPECT_FALSE(expr) EXPECT_TRUE(!(expr))

#define EXPECT_EQ(left, right) \
    ::test::expect_equal((left), (right), #left, #right, __FILE__, __LINE__)
