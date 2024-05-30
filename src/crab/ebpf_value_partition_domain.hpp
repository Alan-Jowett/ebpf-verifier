// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>
#include <vector>
#include <variant>

#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
#include "string_constraints.hpp"

#include "crab/ebpf_domain.hpp"

namespace crab {

class ebpf_value_partition_domain_t {
public:
    ebpf_value_partition_domain_t();
    ebpf_value_partition_domain_t(crab::domains::NumAbsDomain inv, crab::domains::array_domain_t stack);
    ebpf_value_partition_domain_t(ebpf_domain_t ebpf_domain);

    // Generic abstract domain operations
    static ebpf_value_partition_domain_t top();
    static ebpf_value_partition_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    [[nodiscard]] bool is_bottom() const;
    [[nodiscard]] bool is_top() const;
    bool operator<=(const ebpf_value_partition_domain_t& other);
    bool operator==(const ebpf_value_partition_domain_t& other) const;
    void operator|=(ebpf_value_partition_domain_t&& other);
    void operator|=(const ebpf_value_partition_domain_t& other);
    ebpf_value_partition_domain_t operator|(ebpf_value_partition_domain_t&& other) const;
    ebpf_value_partition_domain_t operator|(const ebpf_value_partition_domain_t& other) const&;
    ebpf_value_partition_domain_t operator|(const ebpf_value_partition_domain_t& other) &&;
    ebpf_value_partition_domain_t operator&(const ebpf_value_partition_domain_t& other) const;
    ebpf_value_partition_domain_t widen(const ebpf_value_partition_domain_t& other, bool to_constants);
    ebpf_value_partition_domain_t widening_thresholds(const ebpf_value_partition_domain_t& other, const crab::iterators::thresholds_t& ts);
    ebpf_value_partition_domain_t narrow(const ebpf_value_partition_domain_t& other);

    typedef bool check_require_func_t(NumAbsDomain&, const linear_constraint_t&, std::string);
    void set_require_check(std::function<check_require_func_t> f);
    bound_t get_loop_count_upper_bound();
    static ebpf_value_partition_domain_t setup_entry(bool init_r1);

    static ebpf_value_partition_domain_t from_constraints(const std::set<std::string>& constraints, bool setup_constraints);
    string_invariant to_set();

    // abstract transformers

    template <typename statement_t>
    void operator()(const statement_t& stmt) {
        for (auto & partition : partitions) {
            partition(stmt);
        }
    }

    void initialize_loop_counter(label_t label);
    static ebpf_value_partition_domain_t calculate_constant_limits();

    friend std::ostream& operator<<(std::ostream& o, const ebpf_value_partition_domain_t& dom);

    void merge_all_partitions();

private:
    static ebpf_value_partition_domain_t join(const ebpf_value_partition_domain_t& lhs, const ebpf_value_partition_domain_t& rhs);

  std::vector<ebpf_domain_t> partitions;
};

} // namespace crab
