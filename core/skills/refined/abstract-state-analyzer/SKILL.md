---
name: abstract-state-analyzer
description: Performs abstract interpretation over source code to infer possible program states, variable ranges, and data properties without executing the program. Reports potential runtime errors including out-of-bounds accesses, null dereferences, type inconsistencies, division by zero, and integer overflows. Use when analyzing code for potential runtime errors, performing static analysis, checking safety properties, or verifying program behavior without execution.
---

# Abstract State Analyzer

## Overview

This skill performs abstract interpretation to statically analyze source code and infer possible program states, variable ranges, and data properties. It identifies potential runtime errors without executing the program.

## Analysis Workflow

### Step 1: Parse and Understand Code Structure

Analyze the code to identify:
- Functions and their control flow
- Variable declarations and types
- Loops and conditionals
- Array/buffer operations
- Pointer/reference operations
- Function calls and parameter passing
- Relevant callers, callees, callbacks, and asynchronous work that affect these operations
- Shared state, lock boundaries, and resource acquisition or release when they affect safety
- Where externally supplied lengths, counts, indices, and configuration values originate and where they are consumed

### Step 2: Select Abstract Domains

Choose appropriate abstract domains based on the analysis goals:

**Interval Domain**: Track numeric variable ranges
- Example: `x ∈ [0, 100]` means x is between 0 and 100
- Good for: Array bounds checking, overflow detection

**Sign Domain**: Track whether values are positive, negative, or zero
- Values: {+, -, 0, ⊤}
- Good for: Division by zero, sign-dependent operations

**Null Domain**: Track whether pointers/references can be null
- Values: {null, not-null, maybe-null, ⊤}
- Good for: Null dereference detection

**Type Domain**: Track possible types of variables
- Good for: Type consistency checking, dynamic language analysis

**Combination**: Use multiple domains together for more precise analysis

### Step 3: Initialize Abstract States

Set initial abstract values for:
- Function parameters (based on preconditions or ⊤ for unknown)
- Global variables
- Constants and literals

Record which preconditions are established by code and which are assumptions. Treat unknown values, pointer nullability, object lifetime, and synchronization state as unknown unless the code or a stated contract proves otherwise. Add ownership or lock state to the abstract state when it is relevant to the property being checked.

Example:
```python
def process(arr, index):
    # Initial state:
    # arr: not-null only if guaranteed by a stated precondition; otherwise maybe-null
    # index: ⊤ (unknown integer)
```

### Step 4: Perform Forward Analysis

Propagate abstract states through the program:

**Assignment**: Update abstract value
```python
x = 5
# x: [5, 5]

y = x + 3
# y: [8, 8]
```

**Conditionals**: Split into branches
```python
if x > 10:
    # Branch 1: x ∈ [11, ∞]
else:
    # Branch 2: x ∈ [-∞, 10]
```

**Loops**: Iterate until fixpoint
```python
i = 0
while i < n:
    # Iteration 1: i ∈ [0, 0]
    # Iteration 2: i ∈ [0, 1]
    # ...
    # Fixpoint: i ∈ [0, n-1]
    i += 1
```

**Join Points**: Merge states from multiple paths
```python
if condition:
    x = 5  # x: [5, 5]
else:
    x = 10  # x: [10, 10]
# After join: x ∈ [5, 10]
```

Include early returns, errors, retries, and cleanup branches in the path analysis. Inspect relevant helper and caller behavior when it can change a value's range, transfer ownership, invalidate a pointer, release a lock, sleep, or affect whether an operation succeeded. A check on one path or at one call site does not establish an invariant on other paths.

**Ownership and Concurrency**: Track state across calls and lifecycle boundaries
- Pair each allocation, reference, registration, lock, and initialized resource with its transfer or release on every success, failure, retry, and teardown path.
- Check cleanup order: callbacks and workers must be quiesced before releasing state they can access; a reference drop may run destruction, and a container reference does not necessarily keep each contained object alive.
- For asynchronous operations, trace whether work can still use a submitted buffer or object after a timeout or error return, and follow completion and caller cleanup before treating that return as proof the resource can be released.
- Trace borrowed pointers across helper calls that can resize, linearize, replace, or otherwise relocate backing storage. Reacquire them after such calls when needed.
- For shared state, trace each reader, writer, callback, and teardown path across lock boundaries. Verify the required lock protects the full access, check acquisition order and re-entry, and revalidate state after an unlock/relock gap.
- Check publication and initialization order against concurrent callbacks or teardown. A reference protects allocation lifetime but does not by itself make multi-step publication atomic.
- Check a callee's execution-context and locking requirements at each relevant call site, including calls that may sleep, wait, cancel work, or invoke callbacks.

### Step 5: Detect Potential Errors

Check for violations at each operation:

**Array Bounds**:
```python
arr[index]
# Check: index ∈ [0, len(arr)-1]?
# If index: ⊤ → Potential out-of-bounds
# If index: [0, 5] and len(arr) = 10 → Safe
```

**Null Dereference**:
```python
ptr.field
# Check: ptr is not-null?
# If ptr: maybe-null → Potential null dereference
```

**Division by Zero**:
```python
x / y
# Check: 0 ∉ y?
# If y: [1, 10] → Safe
# If y: [-5, 5] → Potential division by zero
```

**Integer Overflow**:
```python
x = a * b
# Check: a * b within type bounds?
# If a: [1000, 2000], b: [1000, 2000] → Potential overflow for int32
```

**Type Inconsistency**:
```python
result = func(arg)
# Check: arg type matches parameter type?
```

Also check these properties when relevant to the code and analysis goal:

- **Exact bounds and lengths**: At every read and write, compare the index or offset plus access length with the actual source or destination capacity. Trace untrusted, returned, nested, and mutable lengths to the access they control; a source-length check does not prove destination space, and an earlier snapshot may be stale after shared state changes.
- **Pointer use**: Verify that a null or validity check dominates every dereference on every reachable branch, including error handling, logging, and cleanup before a return. Check pointer lifetime and ownership separately from nullability.
- **Initialization and outputs**: Follow each initialization path and helper output through its first use. Verify every relevant branch initializes the full value or callback table that later consumers expect, including configured dispatch paths; check readiness before exposing cached or reused data, and ensure failure is propagated rather than leaving unusable state behind.
- **Resource lifecycle**: Confirm each acquired resource is released or transferred exactly once on every terminal path, in an order that preserves dependencies. Include partial initialization, retries, resize failures, callbacks, and normal removal.
- **Concurrency and progress**: Check races, lock ordering, re-entrant acquisition, waits under locks, stale checks across lock gaps, and whether retry or skip paths can loop or stall. Inspect shared-state synchronization even when the initial review focus is bounds or data flow.
- **Failure behavior**: Follow error values, sentinels, and encoded error pointers through shared cleanup and callers. Check reachable assertion, panic, or fatal-diagnostic paths when inputs or ordinary failures can violate their assumptions.

### Step 6: Report Findings

For each potential error, report:

1. **Location**: File, line number, function
2. **Error Type and CWE**: Identify the mechanism, such as an out-of-bounds read/write or null dereference. For memory-safety or security findings, include the specific CWE identifier and name when supported by the evidence; distinguish nearby categories rather than using only a generic bounds label.
3. **Abstract State**: Variable values at the error point
4. **Severity**: Definite error vs. potential error
5. **Explanation**: Why the error might occur
6. **Suggestion**: How to fix (add check, change bounds, etc.)

Before reporting, confirm that the path is reachable under the stated assumptions and that the evidence supports the claimed cause. Anchor the location to the exact statement or construct that creates the unsafe condition or that a repair would change; verify it against the source listing. A later dereference may show the consequence, while the root cause may be an earlier missing check, state publication, synchronization, or cleanup step. Do not substitute a nearby plausible issue for the path being explained. For lifetime and concurrency findings, identify the exact operation or ordering that creates the unsafe transition (for example, losing ownership, invalidating a borrowed pointer, or crossing an unprotected synchronization gap). Cite that root-cause construct; use later accesses to explain impact, not as a substitute for the repair location. State uncertainty as potential rather than definite when the available contracts or paths do not prove certainty.

## Complete Example

```python
def find_max(arr, n):
    if n <= 0:
        return None

    max_val = arr[0]
    i = 1
    while i < n:
        if arr[i] > max_val:
            max_val = arr[i]
        i += 1
    return max_val
```

**Analysis:**

**Initial State:**
- arr: not-null (assumed)
- n: ⊤ (unknown integer)

**Line 2: `if n <= 0`**
- Branch 1 (n ≤ 0): n ∈ [-∞, 0]
- Branch 2 (n > 0): n ∈ [1, ∞]

**Line 3: `return None`** (Branch 1)
- Safe return

**Line 5: `max_val = arr[0]`** (Branch 2)
- Access: arr[0]
- Check: 0 < len(arr)?
- **POTENTIAL ERROR**: arr length unknown, might be empty
- State: max_val = arr[0], n ∈ [1, ∞]

**Line 6: `i = 1`**
- State: i = [1, 1]

**Line 7: `while i < n`**
- Loop invariant: i ∈ [1, n]
- Fixpoint: i ∈ [1, n-1] inside loop

**Line 8: `if arr[i] > max_val`**
- Access: arr[i] where i ∈ [1, n-1]
- Check: i < len(arr)?
- **POTENTIAL ERROR**: If n > len(arr), out-of-bounds access
- State: max_val updated if arr[i] > max_val

**Line 10: `i += 1`**
- State: i ∈ [2, n]

**Report:**

```
POTENTIAL ERRORS FOUND:

1. Out-of-Bounds Access
   Location: line 5, arr[0]
   State: n ∈ [1, ∞], arr length unknown
   Severity: Potential
   Explanation: Array 'arr' might be empty when n > 0
   Suggestion: Add check: if len(arr) == 0 or add precondition

2. Out-of-Bounds Access
   Location: line 8, arr[i]
   State: i ∈ [1, n-1], arr length unknown
   Severity: Potential
   Explanation: If n > len(arr), accessing beyond array bounds
   Suggestion: Add precondition: n <= len(arr) or check i < len(arr)
```

## Language-Specific Considerations

### C/C++
- Track pointer arithmetic carefully
- Consider undefined behavior (signed overflow, null dereference)
- Analyze memory allocation/deallocation
- Check buffer sizes for string operations

### Python
- Dynamic typing requires type domain
- List/dict operations need bounds checking
- None values require null domain
- Consider duck typing and attribute access

### Java
- Null pointer exceptions
- Array bounds (ArrayIndexOutOfBoundsException)
- Integer overflow (silent wraparound)
- Type casting (ClassCastException)

### JavaScript
- Undefined and null values
- Type coercion issues
- Array bounds (returns undefined, not error)
- Property access on null/undefined

## Handling Complexity

### Widening for Loops
When loops don't converge quickly, apply widening:
```python
# Instead of: [0, 0] → [0, 1] → [0, 2] → ...
# Widen to: [0, ∞]
```

### Function Summaries
For called functions, use summaries instead of full analysis:
```python
def helper(x):
    # Verified summary under the applicable type and overflow assumptions:
    # returns x + 1, no errors
    return x + 1

# Use summary instead of analyzing helper body
```

### Path Sensitivity
For complex conditionals, track path conditions:
```python
if x > 0 and x < 10:
    # x ∈ [1, 9] (path-sensitive)
    # vs x ∈ [-∞, ∞] (path-insensitive)
```

## References

For detailed information on abstract interpretation techniques and domains:
- **references/abstract_domains.md**: Detailed abstract domain definitions and operations
- **references/analysis_patterns.md**: Common analysis patterns for different error types
- **references/language_specifics.md**: Language-specific analysis considerations
