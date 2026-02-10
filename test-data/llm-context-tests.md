# LLM Context Document Test Cases

This file contains test cases for validating that `docs/llm-context.md` enables accurate diagnosis of verification failures.

## How to Test

In a GitHub Copilot CLI session:
```
Using docs/llm-context.md, run ./bin/check <sample> <section> -v and diagnose the failure.
```

The LLM should:
1. Identify the correct failure pattern from the document
2. Explain the root cause by reading the pre-invariant
3. Suggest the correct fix

## Test Cases

### Test 1: Null Pointer After Map Lookup
```bash
./bin/check ebpf-samples/build/nullmapref.o test -v
```
**Expected error**: `Possible null access (valid_access(r0.offset, width=4) for write)`
**Pattern**: 4.4 - Null Pointer After Map Lookup
**Key invariant**: `r0.svalue=[0, 2147418112]` - lower bound of 0 means NULL is possible
**Fix**: Add null check after `bpf_map_lookup_elem`

---

### Test 2: Unbounded Packet Access
```bash
./bin/check ebpf-samples/build/packet_overflow.o xdp -v
```
**Expected error**: `Upper bound must be at most packet_size (valid_access(r2.offset, width=4) for read)`
**Pattern**: 4.2 - Unbounded Packet Access
**Key invariant**: `packet_size=0` - no bounds check established minimum packet size
**Fix**: Add `if (data + N > data_end)` check before access

---

### Test 3: Uninitialized Stack Memory
```bash
./bin/check ebpf-samples/build/ringbuf_uninit.o .text -v
```
**Expected error**: `Stack content is not numeric (valid_access(r2.offset, width=r3) for read)`
**Pattern**: 4.1 - Uninitialized Register Use (stack variant)
**Key invariant**: `Stack: Numbers -> {}` - no stack bytes marked as numeric
**Fix**: Initialize stack buffer before passing to helper

---

### Test 4: Pointer Exposure to Map
```bash
./bin/check ebpf-samples/build/exposeptr.o .text -v
```
**Expected error**: `Illegal map update with a non-numerical value [4088-4096) (within(r3:value_size(r1)))`
**Pattern**: 4.9 - Map Key/Value Size Mismatch (non-numeric variant)
**Key invariant**: `s[4088...4095].type=ctx` - context pointer stored on stack, passed as map value
**Fix**: Store numeric data only in maps (security: prevents kernel address leaks)

---

### Test 5: Nonzero Context Offset
```bash
./bin/check ebpf-samples/build/ctxoffset.o sockops -v
```
**Expected error**: `Nonzero context offset (r1.ctx_offset == 0)`
**Pattern**: 4.10 - Context Field Bounds Violation
**Key invariant**: `r1.ctx_offset=8` - context pointer was modified before helper call
**Fix**: Pass original unmodified context pointer to helpers

---

### Test 6: Map Value Overrun
```bash
./bin/check ebpf-samples/build/mapvalue-overrun.o .text -v
```
**Expected error**: `Upper bound must be at most r1.shared_region_size (valid_access(r1.offset, width=8) for read)`
**Pattern**: Similar to 4.2 but for shared memory
**Key invariant**: `r1.shared_region_size=4` - map value is 4 bytes, but reading 8
**Fix**: Match read width to map value size, or increase map value size

---

## Results Summary

All 6 test cases validated successfully with GitHub Copilot CLI on 2026-02-10.
