// Copyright (c) Prevail Verifier contributors.
// SPDX-License-Identifier: MIT
#include "config.hpp"

const ebpf_verifier_options_t ebpf_verifier_default_options = {
    .check_termination = false,
    .assume_assertions = false,
    .print_invariants = false,
    .print_failures = false,
    .simplify = true,
    .mock_map_fds = true,
    .strict = false,
    .print_line_info = false,
    .allow_division_by_zero = true,
    .setup_constraints = true,
    .big_endian = false,
    .store_pre_invariants = false, // Enable this to permit usage of the ebpf_check_constraints_at_label and ebpf_get_invariants_at_label functions.
};
