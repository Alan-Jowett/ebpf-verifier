// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <map>
#include <tuple>

#include "config.hpp"
#include "crab/cfg.hpp"
#include "crab/ebpf_domain.hpp"

namespace crab {

template <typename domain_t>
using invariant_table_t = std::map<label_t, domain_t>;

template <typename domain_t = ebpf_domain_t>
std::pair<invariant_table_t<domain_t>, invariant_table_t<domain_t>> run_forward_analyzer(cfg_t& cfg,
                                                                                         domain_t entry_inv);

} // namespace crab
