// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#pragma once

// This file is eBPF-specific, not derived from CRAB.

#include <functional>
#include <optional>
#include <variant>
#include <vector>

#include "crab/array_domain.hpp"
#include "crab/split_dbm.hpp"
#include "crab/variable.hpp"
#include "string_constraints.hpp"

#include "crab/ebpf_domain.hpp"

namespace crab {

/**
 * @brief This class represents a set of ebpf_domain_t instances, where each instance has a distinct partition based on
 * the packet_size variable. Operations are broadcasted to all partitions. Functions that generate new instances (e.g.,
 * widening) are implemented by applying the function to each partition, potentially merging them if they are have
 * different partitions.
 */
class ebpf_value_partition_domain_t {
  public:
    ebpf_value_partition_domain_t();
    ebpf_value_partition_domain_t(crab::domains::NumAbsDomain inv, crab::domains::array_domain_t stack);
    ebpf_value_partition_domain_t(ebpf_domain_t ebpf_domain);
    ebpf_value_partition_domain_t(std::vector<ebpf_domain_t>&& partitions);

    // Generic abstract domain operations
    static ebpf_value_partition_domain_t top();
    static ebpf_value_partition_domain_t bottom();
    void set_to_top();
    void set_to_bottom();
    [[nodiscard]]
    bool is_bottom() const;
    [[nodiscard]]
    bool is_top() const;
    bool operator<=(const ebpf_value_partition_domain_t& other) const;
    bool operator==(const ebpf_value_partition_domain_t& other) const;
    void operator|=(ebpf_value_partition_domain_t&& other);
    void operator|=(const ebpf_value_partition_domain_t& other);
    ebpf_value_partition_domain_t operator|(ebpf_value_partition_domain_t&& other) const;
    ebpf_value_partition_domain_t operator|(const ebpf_value_partition_domain_t& other) const&;
    ebpf_value_partition_domain_t operator|(const ebpf_value_partition_domain_t& other) const&&;
    ebpf_value_partition_domain_t operator&(const ebpf_value_partition_domain_t& other) const;
    ebpf_value_partition_domain_t widen(const ebpf_value_partition_domain_t& other, bool to_constants) const;
    ebpf_value_partition_domain_t widening_thresholds(const ebpf_value_partition_domain_t& other,
                                                      const crab::iterators::thresholds_t& ts)  const;
    ebpf_value_partition_domain_t narrow(const ebpf_value_partition_domain_t& other) const;

    typedef bool check_require_func_t(NumAbsDomain&, const linear_constraint_t&, std::string);
    void set_require_check(std::function<check_require_func_t> f);
    bound_t get_loop_count_upper_bound();
    static ebpf_value_partition_domain_t setup_entry(bool init_r1);

    static ebpf_value_partition_domain_t from_constraints(const std::set<std::string>& constraints,
                                                          bool setup_constraints);
    string_invariant to_set();

    // abstract transformers

    /**
     * @brief Forward the given statement to all partitions.
     *
     * @tparam statement_t The type of the statement.
     * @param[in] stmt The statement to forward.
     */
    template <typename statement_t>
    void operator()(const statement_t& stmt) {
        for (auto& partition : partitions) {
            partition(stmt);
        }
        // Should we drop bottom partitions here?
    }

    void initialize_loop_counter(label_t label);
    static ebpf_value_partition_domain_t calculate_constant_limits();

    friend std::ostream& operator<<(std::ostream& o, const ebpf_value_partition_domain_t& dom);

  private:
    void merge_all_partitions();

    /**
     * @brief Given two value partition domains, form a new domain that contains a set of partitions that is the union
     * of the partitions in the two input domains. Partitions are merged if they have the same packet_size variable.
     *
     * @param[in] lhs Left-hand side of the join operation.
     * @param[in] rhs Right-hand side of the join operation.
     * @return Combined domain.
     */
    static ebpf_value_partition_domain_t join(const ebpf_value_partition_domain_t& lhs,
                                              const ebpf_value_partition_domain_t& rhs);

    /**
     * @brief Check if the two value partition domains have the same partitions based on the packet_size variable.
     *
     * @param[in] other The other value partition domain to compare with.
     * @return true There are the same number of partitions and they have the same packet_size variable.
     * @return false The two domains have different partitions.
     */
    bool has_same_partitions(const ebpf_value_partition_domain_t& other) const;

    /**
     * @brief Given to value partition domains, apply the given function to each partition in both domains. If the
     * domains have different partitions, merge them first.
     *
     * @param[in] other Other value partition domain.
     * @param[in] f Function to apply to each partition.
     */
    void merge_or_apply_to_all_partitions(const ebpf_value_partition_domain_t& other,
                                          std::function<void(const ebpf_domain_t&, const ebpf_domain_t&)> f) const;

    std::vector<ebpf_domain_t> partitions;
};

} // namespace crab
