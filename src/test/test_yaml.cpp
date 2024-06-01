// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include <catch2/catch_all.hpp>

#include "ebpf_verifier.hpp"
#include "ebpf_yaml.hpp"

// TODO: move out of this framework

#define YAML_CASE(path) \
    TEST_CASE("YAML suite: " path, "[yaml]") { \
        foreach_suite(path, [&](TestCase test_case){ \
            if (test_case.partition_keys.size() == 1 && test_case.partition_keys[0] == "none") { \
                test_case.partition_keys.clear(); \
            } \
            std::optional<Failure> failure = run_yaml_test_case(test_case); \
            if (failure) { \
                std::cout << "test case: " << test_case.name << "\n"; \
                print_failure(*failure, std::cout); \
            } \
            REQUIRE(!failure); \
        }); \
    }

#define YAML_CASE_WITH_PARTITION(path, partition) \
    TEST_CASE("YAML suite: " path " with partition " partition, "[yaml]") { \
        foreach_suite(path, [&](TestCase test_case){ \
            if (test_case.partition_keys.size() == 1 && test_case.partition_keys[0] == "none") { \
                /* Skip test cases that are not partitioned */ \
                return; \
            } \
            test_case.partition_keys = {partition}; \
            std::optional<Failure> failure = run_yaml_test_case(test_case); \
            if (failure) { \
                std::cout << "test case: " << test_case.name << "\n"; \
                print_failure(*failure, std::cout); \
            } \
            REQUIRE(!failure); \
        }); \
    }


YAML_CASE("test-data/add.yaml")
YAML_CASE("test-data/assign.yaml")
YAML_CASE("test-data/atomic.yaml")
YAML_CASE("test-data/bitop.yaml")
YAML_CASE("test-data/call.yaml")
YAML_CASE("test-data/callx.yaml")
YAML_CASE("test-data/udivmod.yaml")
YAML_CASE("test-data/sdivmod.yaml")
YAML_CASE("test-data/full64.yaml")
YAML_CASE("test-data/jump.yaml")
YAML_CASE("test-data/loop.yaml")
YAML_CASE("test-data/movsx.yaml")
YAML_CASE("test-data/packet.yaml")
YAML_CASE("test-data/parse.yaml")
YAML_CASE("test-data/sext.yaml")
YAML_CASE("test-data/shift.yaml")
YAML_CASE("test-data/stack.yaml")
YAML_CASE("test-data/subtract.yaml")
YAML_CASE("test-data/unop.yaml")
YAML_CASE("test-data/unsigned.yaml")

YAML_CASE_WITH_PARTITION("test-data/add.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/assign.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/atomic.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/bitop.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/call.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/callx.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/udivmod.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/sdivmod.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/full64.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/jump.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/loop.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/movsx.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/packet.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/parse.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/sext.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/shift.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/stack.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/subtract.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/unop.yaml", "packet_size");
YAML_CASE_WITH_PARTITION("test-data/unsigned.yaml", "packet_size");
