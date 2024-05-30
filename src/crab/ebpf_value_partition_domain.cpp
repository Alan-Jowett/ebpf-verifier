// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT

// This file is eBPF-specific, not derived from CRAB.

#include <bitset>
#include <optional>
#include <utility>
#include <vector>

#include "boost/endian/conversion.hpp"
#include "boost/range/algorithm/set_algorithm.hpp"

#include "crab/array_domain.hpp"
#include "crab/ebpf_value_partition_domain.hpp"

#include "asm_ostream.hpp"
#include "asm_unmarshal.hpp"
#include "config.hpp"
#include "dsl_syntax.hpp"
#include "platform.hpp"
#include "string_constraints.hpp"

namespace crab {

ebpf_value_partition_domain_t::ebpf_value_partition_domain_t() : partitions(1) {}
ebpf_value_partition_domain_t::ebpf_value_partition_domain_t(crab::domains::NumAbsDomain inv,
                                                             crab::domains::array_domain_t stack)
    : partitions{{std::move(inv), stack}} {}

ebpf_value_partition_domain_t::ebpf_value_partition_domain_t(ebpf_domain_t ebpf_domain)
    : partitions(1, std::move(ebpf_domain)) {}

ebpf_value_partition_domain_t::ebpf_value_partition_domain_t(std::vector<ebpf_domain_t>&& partitions)
    : partitions(std::move(partitions)) {}

// Generic abstract domain operations
ebpf_value_partition_domain_t ebpf_value_partition_domain_t::top() {
    ebpf_value_partition_domain_t abs;
    abs.set_to_top();
    return abs;
}
ebpf_value_partition_domain_t ebpf_value_partition_domain_t::bottom() {
    ebpf_value_partition_domain_t abs;
    abs.set_to_bottom();
    return abs;
}
void ebpf_value_partition_domain_t::set_to_top() {
    partitions.resize(1);
    partitions[0].set_to_top();
}
void ebpf_value_partition_domain_t::set_to_bottom() {
    partitions.resize(1);
    partitions[0].set_to_bottom();
}
[[nodiscard]]
bool ebpf_value_partition_domain_t::is_bottom() const {
    return std::all_of(partitions.begin(), partitions.end(),
                       [](const auto& partition) { return partition.is_bottom(); });
}
[[nodiscard]]
bool ebpf_value_partition_domain_t::is_top() const {
    return std::all_of(partitions.begin(), partitions.end(), [](const auto& partition) { return partition.is_top(); });
}
bool ebpf_value_partition_domain_t::operator<=(const ebpf_value_partition_domain_t& other) const {

    bool return_value = true;
    merge_or_apply_to_all_partitions(
        other, [&return_value](const ebpf_domain_t& lhs, const ebpf_domain_t& rhs) { return_value &= lhs <= rhs; });

    return return_value;
}
bool ebpf_value_partition_domain_t::operator==(const ebpf_value_partition_domain_t& other) const {
    bool return_value = true;
    merge_or_apply_to_all_partitions(
        other, [&return_value](const ebpf_domain_t& lhs, const ebpf_domain_t& rhs) { return_value &= lhs == rhs; });

    return return_value;
}

ebpf_value_partition_domain_t ebpf_value_partition_domain_t::join(const ebpf_value_partition_domain_t& lhs,
                                                                  const ebpf_value_partition_domain_t& rhs) {
    std::vector<ebpf_domain_t> partitions;

    // Check if any partitions have a value for the packet size.
    bool has_packet_size = false;
    for (const auto& partition : lhs.partitions) {
        if (!partition.is_bottom() && !partition.m_inv[variable_t::packet_size()].is_bottom() &&
            !partition.m_inv[variable_t::packet_size()].is_top()) {
            auto interval = partition.m_inv[variable_t::packet_size()];
            has_packet_size = true;
            break;
        }
    }

    for (const auto& partition : rhs.partitions) {
        if (!partition.is_bottom() && !partition.m_inv[variable_t::packet_size()].is_bottom() &&
            !partition.m_inv[variable_t::packet_size()].is_top()) {
            auto interval = partition.m_inv[variable_t::packet_size()];
            has_packet_size = true;
            break;
        }
    }

    // If no partitions have a value for the packet size, just merge all partitions.
    if (!has_packet_size) {
        ebpf_domain_t res_domain;
        res_domain.set_to_bottom();
        for (const auto& lhs_partition : lhs.partitions) {
            res_domain |= lhs_partition;
        }
        for (const auto& rhs_partition : rhs.partitions) {
            res_domain |= rhs_partition;
        }
        partitions.push_back(res_domain);

        ebpf_value_partition_domain_t res;
        res.partitions = std::move(partitions);
        return res;
    }

    // Copy all non-bottom partitions from the left-hand side.
    for (const auto& lhs_partition : lhs.partitions) {
        if (!lhs_partition.is_bottom()) {
            partitions.push_back(lhs_partition);
        }
    }

    // Copy all non-bottom partitions from the right-hand side.
    for (const auto& rhs_partition : rhs.partitions) {
        if (!rhs_partition.is_bottom()) {
            partitions.push_back(rhs_partition);
        }
    }

    // Sort the partitions by the packet size interval.
    std::sort(partitions.begin(), partitions.end(), [](const auto& lhs, const auto& rhs) {
        auto lhs_interval = lhs.m_inv[variable_t::packet_size()];
        auto rhs_interval = rhs.m_inv[variable_t::packet_size()];

        if (lhs_interval.is_bottom()) {
            return false;
        }
        if (rhs_interval.is_bottom()) {
            return true;
        }

        if (lhs_interval.lb() < rhs_interval.lb()) {
            return true;
        } else if (lhs_interval.lb() > rhs_interval.lb()) {
            return false;
        } else {
            return lhs_interval.ub() < rhs_interval.ub();
        }
    });

    // Merge partitions that have the same packet size interval.
    for (size_t i = 0; i < partitions.size(); i++) {
        for (size_t j = i + 1; j < partitions.size(); j++) {
            if (partitions[i].m_inv[variable_t::packet_size()] == partitions[j].m_inv[variable_t::packet_size()]) {
                partitions[i] |= partitions[j];
                partitions.erase(partitions.begin() + j);
                j--;
            } else {
                break;
            }
        }
    }

    ebpf_value_partition_domain_t res;

    res.partitions = std::move(partitions);

    return res;
}

void ebpf_value_partition_domain_t::operator|=(ebpf_value_partition_domain_t&& other) {
    *this = join(*this, std::move(other));
}

void ebpf_value_partition_domain_t::operator|=(const ebpf_value_partition_domain_t& other) {
    *this = join(*this, other);
}

ebpf_value_partition_domain_t ebpf_value_partition_domain_t::operator|(ebpf_value_partition_domain_t&& other) const {
    return join(*this, std::move(other));
}

ebpf_value_partition_domain_t
ebpf_value_partition_domain_t::operator|(const ebpf_value_partition_domain_t& other) const& {
    return join(*this, other);
}

ebpf_value_partition_domain_t ebpf_value_partition_domain_t::operator|(const ebpf_value_partition_domain_t& other) && {
    return std::move(join(*this, other));
}

ebpf_value_partition_domain_t
ebpf_value_partition_domain_t::operator&(const ebpf_value_partition_domain_t& other) const {
    std::vector<ebpf_domain_t> partitions;

    merge_or_apply_to_all_partitions(
        other, [&partitions](const ebpf_domain_t& lhs, const ebpf_domain_t& rhs) { partitions.push_back(lhs & rhs); });

    return std::move(partitions);
}
ebpf_value_partition_domain_t ebpf_value_partition_domain_t::widen(const ebpf_value_partition_domain_t& other,
                                                                   bool to_constants) {
    std::vector<ebpf_domain_t> partitions;
    merge_or_apply_to_all_partitions(other,
                                     [&partitions, to_constants](const ebpf_domain_t& lhs, const ebpf_domain_t& rhs) {
                                         partitions.push_back(lhs.widen(rhs, to_constants));
                                     });

    return std::move(partitions);
}
ebpf_value_partition_domain_t ebpf_value_partition_domain_t::narrow(const ebpf_value_partition_domain_t& other) {
    std::vector<ebpf_domain_t> partitions;
    merge_or_apply_to_all_partitions(other, [&partitions](const ebpf_domain_t& lhs, const ebpf_domain_t& rhs) {
        partitions.push_back(lhs.narrow(rhs));
    });

    return std::move(partitions);
}

void ebpf_value_partition_domain_t::set_require_check(std::function<check_require_func_t> f) {
    merge_all_partitions();
    for (auto& partition : partitions) {
        partition.set_require_check(f);
    }
}
bound_t ebpf_value_partition_domain_t::get_loop_count_upper_bound() {
    merge_all_partitions();
    bound_t ub{number_t{0}};
    for (auto& partition : partitions) {
        ub = std::max(ub, partition.get_loop_count_upper_bound());
    }
    return ub;
}

ebpf_value_partition_domain_t ebpf_value_partition_domain_t::setup_entry(bool init_r1) {
    ebpf_value_partition_domain_t abs;
    abs.partitions[0] = ebpf_domain_t::setup_entry(init_r1);
    return abs;
}

ebpf_value_partition_domain_t ebpf_value_partition_domain_t::from_constraints(const std::set<std::string>& constraints,
                                                                              bool setup_constraints) {
    ebpf_value_partition_domain_t abs;
    abs.partitions[0] = ebpf_domain_t::from_constraints(constraints, setup_constraints);
    return abs;
}

string_invariant ebpf_value_partition_domain_t::to_set() {
    ebpf_value_partition_domain_t tmp = *this;
    tmp.merge_all_partitions();
    return tmp.partitions[0].to_set();
}

void ebpf_value_partition_domain_t::initialize_loop_counter(label_t label) {
    merge_all_partitions();

    for (auto& partition : partitions) {
        partition.initialize_loop_counter(label);
    }
}

ebpf_value_partition_domain_t ebpf_value_partition_domain_t::calculate_constant_limits() {
    ebpf_value_partition_domain_t abs;
    abs.partitions[0] = ebpf_domain_t::calculate_constant_limits();
    return abs;
}

std::ostream& operator<<(std::ostream& o, const ebpf_value_partition_domain_t& dom) {
    ebpf_value_partition_domain_t tmp = dom;
    tmp.merge_all_partitions();
    o << tmp.partitions[0];
    return o;
}

void ebpf_value_partition_domain_t::merge_all_partitions() {
    if (partitions.size() == 0) {
        set_to_bottom();
    } else if (partitions.size() == 1) {
        // Nothing to do.
    } else {
        // Merge all partitions into the first one.
        for (size_t i = 1; i < partitions.size(); i++) {
            partitions[0] |= partitions[i];
        }
        partitions.resize(1);
    }
}

bool ebpf_value_partition_domain_t::has_same_partitions(const ebpf_value_partition_domain_t& other) const {
    if (partitions.size() != other.partitions.size()) {
        return false;
    }

    for (size_t i = 0; i < partitions.size(); i++) {
        if (partitions[i].m_inv[variable_t::packet_size()] != other.partitions[i].m_inv[variable_t::packet_size()]) {
            return false;
        }
    }

    return true;
}

void ebpf_value_partition_domain_t::merge_or_apply_to_all_partitions(
    const ebpf_value_partition_domain_t& other,
    std::function<void(const ebpf_domain_t&, const ebpf_domain_t&)> f) const {
    if (!has_same_partitions(other)) {
        ebpf_value_partition_domain_t lhs = *this;
        ebpf_value_partition_domain_t rhs = other;
        lhs.merge_all_partitions();
        rhs.merge_all_partitions();

        f(lhs.partitions[0], rhs.partitions[0]);
    } else {
        for (size_t i = 0; i < partitions.size(); i++) {
            f(partitions[i], other.partitions[i]);
        }
    }
}

} // namespace crab
