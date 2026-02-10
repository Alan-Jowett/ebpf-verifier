# LLM Context Document for Prevail eBPF Verifier

This document provides the context needed for an LLM to accurately diagnose eBPF verification failures when given a Prevail log output.

## 1. Overview

**Prevail** is a static verifier for eBPF programs that uses **abstract interpretation** to prove memory safety, type safety, and (optionally) termination without executing the code. Unlike the Linux kernel verifier that simulates execution, Prevail computes **invariants**—logical statements that hold at every program point regardless of input values.

### What Prevail Verifies

1. **Memory safety**: All reads/writes stay within valid memory regions (stack, packet, context, shared/map memory)
2. **Type safety**: Registers contain the expected types (numbers, pointers to specific regions)
3. **Pointer arithmetic**: Only numbers can be added to pointers; only compatible pointers can be subtracted
4. **Division safety**: Divisors are never zero (unless explicitly allowed)
5. **Helper function contracts**: Arguments match the expected types and bounds
6. **Termination** (optional): Loops have bounded iteration counts

### How Verification Works

1. **Parse** the eBPF program into a control-flow graph (CFG)
2. **Initialize** abstract state at entry (context pointer in r1, stack pointer in r10)
3. **Iterate** to a fixpoint using widening/narrowing to handle loops
4. **Check assertions** at each program point (memory access, type constraints, etc.)
5. **Report errors** when an assertion cannot be proven to hold

---

## 2. Understanding Verification Logs

Prevail logs show the abstract state at each program point. Here's how to interpret them.

### 2.1 Log Structure

A typical verbose log shows:

```
Pre-invariant:[
    <state variables>]
   <pc>:<instruction>
   ...
Expected post-invariant: [<state variables>]
```

- **Pre-invariant**: The abstract state *before* executing the instruction(s)
- **pc**: Program counter (instruction number within the section)
- **instruction**: The eBPF instruction in human-readable form
- **Post-invariant**: The abstract state *after* executing the instruction(s)

### 2.2 Register State Format

Each register has multiple abstract properties:

| Property | Meaning |
|----------|---------|
| `r<N>.type` | Type: `number`, `ctx`, `stack`, `packet`, `shared`, `map_fd`, or `map_programs` |
| `r<N>.svalue` | Signed value or interval `[min, max]` |
| `r<N>.uvalue` | Unsigned value or interval `[min, max]` |
| `r<N>.ctx_offset` | Offset within context struct (if type=ctx) |
| `r<N>.stack_offset` | Offset within stack (if type=stack) |
| `r<N>.packet_offset` | Offset within packet (if type=packet) |
| `r<N>.shared_offset` | Offset within shared memory (if type=shared) |
| `r<N>.shared_region_size` | Size of the shared region (for bounds checking) |
| `r<N>.stack_numeric_size` | Number of contiguous numeric bytes at stack location |
| `r<N>.map_fd` | Map file descriptor value (if type=map_fd) |

**Interval notation**: `[min, max]` means the value is constrained to that range. `[4098, 2147418112]` is a typical pointer address range.

**Relational constraints**: Entries like `r2.packet_offset=packet_size` indicate relationships between variables.

### 2.3 Stack State Format

Stack memory is tracked separately:

| Property | Meaning |
|----------|---------|
| `s[N...M].type` | Type of bytes N through M |
| `s[N...M].svalue` | Signed value stored at those bytes |
| `s[N...M].uvalue` | Unsigned value stored at those bytes |
| `s[N].ctx_offset` | If a pointer is stored, its ctx_offset |
| `s[N].packet_offset` | If a pointer is stored, its packet_offset |

Stack offsets are from the *base* of the stack frame (0-511 for main program).

### 2.4 Global State Variables

| Variable | Meaning |
|----------|---------|
| `meta_offset` | Offset of packet metadata (negative = before data pointer) |
| `packet_size` | Packet size constraint |
| `pc[N]` | Loop counter for basic block N (used in termination checking) |

### 2.5 Error Message Format

Errors follow this pattern:

```
<pc>: <reason> (<assertion>)
```

Where:
- **pc**: The program counter (or `pc:target` for conditional jumps)
- **reason**: Human-readable explanation of the failure
- **assertion**: The formal assertion that failed

**Example errors**:

```
0: Invalid type (r3.type in {number, ctx, stack, packet, shared})
1: Upper bound must be at most packet_size (valid_access(r1.offset, width=8) for write)
0 (counter): Loop counter is too large (pc[0] < 100000)
```

---

## 3. Glossary of Log Terms

### Types

| Term | Description |
|------|-------------|
| `number` | A scalar integer (not a pointer) |
| `ctx` | Pointer to program context structure (e.g., `xdp_md`, `sk_buff`) |
| `stack` | Pointer to stack memory (512 bytes per stack frame) |
| `packet` | Pointer to packet data |
| `shared` | Pointer to shared memory (e.g., map values) |
| `map_fd` | Map file descriptor (not directly dereferenceable) |
| `map_programs` | Program array map FD |

### Type Groups

| Group | Members |
|-------|---------|
| `pointer` | ctx, stack, packet, shared |
| `singleton_ptr` | Pointers to unique memory regions (ctx, stack, packet, map_fd) |
| `mem` | ctx, stack, packet, shared (memory that can be read/written) |
| `mem_or_num` | number, ctx, stack, packet, shared |
| `ptr_or_num` | All types except uninitialized |

### Common Assertions

| Assertion | What It Checks |
|-----------|----------------|
| `valid_access(reg.offset, width=N) for read/write` | Memory access is within bounds |
| `r<N>.type in {types}` | Register has one of the listed types |
| `r<N>.type == number` | Register is a number (not a pointer) |
| `r<N> != 0` | Register is non-zero (for division) |
| `pc[N] < 100000` | Loop counter is within limit |
| `within(reg:key_size(map))` | Map key access is valid |

### Access Bounds Messages

| Message | Meaning |
|---------|---------|
| `Lower bound must be at least 0` | Offset is negative when it shouldn't be |
| `Upper bound must be at most X` | Access extends past end of region |
| `Lower bound must be at least meta_offset` | Packet access before metadata start |
| `Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE` | Stack underflow |
| `Stack content is not numeric` | Reading non-numeric data from stack |
| `Possible null access` | Pointer might be NULL |

---

## 4. Common Failure Patterns

### 4.1 Uninitialized Register Use

**Symptom**: `Invalid type (r<N>.type in {number, ctx, stack, packet, shared})`

**Cause**: Using a register before it has been assigned a value.

**Example**:
```
Pre-invariant:[r0.type=number, r0.svalue=1]
   0: r0 += r3
Error: 0: Invalid type (r3.type in {number, ctx, stack, packet, shared})
```

**Fix**: Initialize the register before use, or ensure it's passed as a parameter.

---

### 4.2 Unbounded Packet Access

**Symptom**: `Upper bound must be at most packet_size (valid_access(r<N>.offset, width=W) for read/write)`

**Cause**: Reading/writing packet data without first checking the bounds.

**Example**:
```
Pre-invariant:[packet_size=[0, 65534], r1.type=packet, r1.packet_offset=0]
   0: r4 = *(u64 *)(r1 + 0)
Error: 0: Upper bound must be at most packet_size
```

**Fix**: Add a bounds check before the access:
```c
if (data + sizeof(__u64) > data_end) return XDP_DROP;
```

---

### 4.3 Stack Out-of-Bounds Access

**Symptom**: `Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE`

**Cause**: Accessing stack memory beyond the allocated frame.

**Example**:
```
Pre-invariant:[r10.type=stack, r10.stack_offset=1024]
   0: *(u8 *)(r10 - 513) = 0
Error: 0: Lower bound must be at least r10.stack_offset - EBPF_SUBPROGRAM_STACK_SIZE
```

**Fix**: Keep stack accesses within -512 to -1 of r10, or reduce local variable size.

---

### 4.4 Null Pointer After Map Lookup

**Symptom**: `Possible null access (valid_access(...) for read/write)`

**Cause**: Using a map lookup result without checking for NULL.

**Example**:
```c
value = bpf_map_lookup_elem(&my_map, &key);
*value = 42;  // Error: value might be NULL
```

**Fix**: Check the return value:
```c
value = bpf_map_lookup_elem(&my_map, &key);
if (value) {
    *value = 42;
}
```

---

### 4.5 Type Mismatch (Number as Pointer)

**Symptom**: `Only pointers can be dereferenced (valid_access(...))`

**Cause**: Trying to dereference a register that contains a number instead of a pointer.

**Example**:
```
Pre-invariant:[r1.type=number, r1.svalue=42]
   0: r2 = *(u64 *)(r1 + 0)
Error: 0: Only pointers can be dereferenced
```

**Fix**: Ensure the register contains a valid pointer type before dereferencing.

---

### 4.6 Pointer Arithmetic with Non-Number

**Symptom**: `Only numbers can be added to pointers`

**Cause**: Adding a pointer to another pointer, or adding an uninitialized value to a pointer.

**Fix**: Ensure the addend is a number (scalar), not a pointer or uninitialized register.

---

### 4.7 Infinite Loop / Termination Failure

**Symptom**: `Loop counter is too large (pc[N] < 100000)`

**Cause**: The verifier cannot prove the loop terminates within the iteration limit.

**Example**:
```
Pre-invariant:[]
   0: r0 = 0
   1: if r0 < 1 goto <start>
Error: 0 (counter): Loop counter is too large (pc[0] < 100000)
```

**Causes**:
- No increment to the loop variable
- Infinite loop by design (always branches back)
- Bound check uses wrong comparison (e.g., `!=` instead of `<`)

**Fix**: Ensure loop has a clear termination condition with a bounded counter.

---

### 4.8 Division by Zero

**Symptom**: `Possible division by zero (r<N> != 0)`

**Cause**: The divisor register might be zero.

**Fix**: Add an explicit check before division:
```c
if (divisor != 0) {
    result = dividend / divisor;
}
```

---

### 4.9 Map Key/Value Size Mismatch

**Symptom**: `Illegal map update with a non-numerical value` or `Map key size is not singleton`

**Cause**: The pointer passed to map helper doesn't point to enough numeric bytes, or the key/value size doesn't match the map definition.

**Fix**: Ensure the stack buffer used for key/value is properly sized and initialized with numeric data.

---

### 4.10 Context Field Bounds Violation

**Symptom**: `Upper bound must be at most <size>` for context access

**Cause**: Reading past the end of the context structure.

**Example**: XDP context is 20 bytes, accessing at offset 24 fails.

**Fix**: Only access defined fields within the context structure.

---

## 5. LLM Reasoning Protocol

When diagnosing a Prevail verification failure:

### Step 1: Identify the Error

Look for lines matching the pattern `<pc>: <message> (<assertion>)`. Note:
- The program counter (pc) where the error occurs
- The assertion type (e.g., `valid_access`, `type in {...}`, etc.)
- The specific constraint that failed

### Step 2: Locate the Context

Find the pre-invariant just before the failing instruction. This shows the abstract state at that point.

### Step 3: Trace the Register/Variable

For the register(s) mentioned in the error:
1. Check its type in the pre-invariant
2. Check its value/offset constraints
3. Look for missing constraints (e.g., no `packet_size` bound)

### Step 4: Identify Missing Constraints

Common missing constraints:
- **For packet access**: `packet_size >= access_end` relationship is missing
- **For shared access**: `r<N>.svalue > 0` (null check) is missing
- **For stack access**: `stack_numeric_size` is too small
- **For loops**: No counter increment or wrong comparison

### Step 5: Trace Backwards

If the pre-invariant seems correct, trace backwards to find where:
- A required constraint was lost (widening in loops)
- A branch condition wasn't captured
- An initialization was skipped

### Step 6: Formulate the Fix

Typical fixes:
- **Add bounds check** before memory access
- **Add null check** after map lookup
- **Initialize registers** before use
- **Add loop bound** for termination
- **Cast/narrow types** appropriately

### Red Flags to Watch For

| Pattern | Likely Issue |
|---------|--------------|
| `r<N>.type` missing from invariant | Uninitialized register |
| `packet_size=[0, X]` without offset constraint | Missing bounds check |
| `pc[N]=[1, +oo]` | Possible infinite loop |
| `shared_region_size` not constrained | Map value size unknown |
| Type is `number` but being dereferenced | Wrong register or missing assignment |

---

## 6. Extracting Additional Information

When analyzing failures, you may need more context. Here's how to request it:

### Verbose Output

Run with `-v` flag for verbose output showing invariants at each step:
```bash
./bin/run_yaml test-data/<file>.yaml "<test name>" -v
```

### Full Program Listing

Request the full disassembly to see surrounding instructions:
```bash
./bin/check <elf-file> <section> --print-disasm
```

### Specific Invariant

Ask the user to share:
1. The complete pre-invariant at the failing instruction
2. The 3-5 instructions leading up to the failure
3. Any branch conditions in the path

### Map/Context Definitions

For map-related errors, request:
- Map type (array, hash, etc.)
- Key size and value size
- Context structure definition

---

## 7. Version Information

- **Prevail Version**: Check with `./bin/check --version`
- **Document Version**: 1.0
- **Last Updated**: 2024

---

## Appendix A: Quick Reference

### Register Conventions

| Register | Convention |
|----------|------------|
| r0 | Return value from helpers; final program return |
| r1-r5 | Function arguments (caller-saved) |
| r6-r9 | Callee-saved |
| r10 | Read-only stack frame pointer |

### Stack Layout

- Main program: offsets 0-511 (accessed as r10-1 through r10-512)
- Subprograms: additional 512 bytes per call depth
- Total: up to 8KB (16 frames × 512 bytes)

### Common Helper Patterns

```c
// Map lookup - always check for NULL
void *value = bpf_map_lookup_elem(&map, &key);
if (!value) return 0;

// Packet access - always check bounds
if (data + sizeof(struct hdr) > data_end) return XDP_DROP;

// Division - always check divisor
if (divisor == 0) return 0;
result = dividend / divisor;
```

---

## Appendix C: Worked Diagnosis Example

**Scenario**: Unbounded packet read fails verification.

### The Error

```
0: Upper bound must be at most packet_size (valid_access(r1.offset, width=8) for read)
```

### The Log

```
Pre-invariant:[
    meta_offset=0,
    packet_size=[0, 65534],
    r1.packet_offset=0, r1.type=packet, r1.svalue=[4098, 2147418112]]
   0: r4 = *(u64 *)(r1 + 0)
```

### Diagnosis

1. **Error location**: PC 0, reading 8 bytes from `r1`
2. **Pre-invariant shows**: `r1.packet_offset=0`, `packet_size=[0, 65534]`
3. **The problem**: Access requires `0 + 8 <= packet_size`, but `packet_size` could be 0
4. **Missing constraint**: No bounds check establishes `packet_size >= 8`

### Fix

Add bounds check before access:
```c
if (data + 8 > data_end) return XDP_DROP;
// Now packet_size >= 8 is established
value = *(u64 *)data;
```
