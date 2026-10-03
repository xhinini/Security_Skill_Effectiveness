---
name: audit-design-weaknesses
description: 'Audit C headers and source files for design-phase security weaknesses mapped to CWE-701 categories and CERT-C design rules (CWE-1154; note CWE-734 is the legacy 2008 edition)'
argument-hint: '[path or interface name]'
---

# Audit Design Weaknesses

Use this skill to audit C public API headers and related source for weaknesses whose root
cause is a design decision rather than an implementation error.  Reference framework:
CWE-701 ("Weaknesses Introduced During Design"), CWE-1400 comprehensive categorization,
and CERT-C design rules via CWE-1154 (current view; CWE-734 is the retired 2008 edition).

## Input Checklist

- Target path or interface under `include/` or `src/`.
- Whether the change adds, removes, or modifies a public function signature.
- Whether the change touches resource allocation, error-return paths, or sensitive data flows.
- Whether concurrency or shared state is involved.

## Steps

### 1 — Map the API surface

Enumerate every public function in the target header.  For each function record:
- Parameter types, sizes, and documented preconditions (or absence thereof).
- Return type and all documented failure values.
- Ownership of any pointer parameters or return values.

### 2 — Check resource lifetime contracts (CWE-664)

- Does every allocating function document whether the caller or library owns the result?
- Is the paired deallocation function named in the declaration comment?
- Is behavior on allocation failure (NULL return, error code, or abort) documented?

### 3 — Check trust boundary placement (CWE-693 / CWE-345)

- Is each parameter classified as trusted (internal) or untrusted (caller-supplied)?
- Does the interface document which validation is the caller's responsibility vs. the library's?
- Are size parameters bounded by documented invariants (e.g., key length == `crypto_box_PUBLICKEYBYTES`)?

### 4 — Check error-return consistency (CERT-C ERR-series, CWE-701)

- Does every fallible function return a type that can represent all failure modes?
- Are `void`-returning functions guaranteed to be infallible by design?
- Is the return-value convention (0 = success, negative = error) consistent across the entire public API?

### 5 — Check access control and exposure (CWE-284)

- Does the public API expose internal state that callers should not need to read or modify?
- Can any combination of valid API calls produce an undefined or privilege-escalating state?

### 6 — Check sensitive data handling design (CWE-226 / CWE-693)

- Are sensitive parameters (key material, plaintext) isolated from non-sensitive parameters
  at the function signature level?
- Is the zeroing contract documented — which party is responsible for wiping sensitive buffers?

### 7 — Check for implicit concurrency hazards (CWE-362)

- Does any function use or modify shared static state without documenting thread-safety?
- Is the intended threading model (not thread-safe / thread-safe / re-entrant) stated in the
  header comment for the module?

### 8 — Cross-reference CERT-C design rules (CWE-1154)

For each finding from steps 2–7, note the applicable CERT-C rule:
- DCL: undeclared preconditions or hidden static state coupling.
- ERR: fallible functions returning `void` or an insufficient error type.
- MEM: unspecified allocation ownership or missing deallocation pairing.
- EXP: buffer-size parameters without documented valid ranges.

## Example Output

```text
Severity: HIGH
Class: Resource Lifetime (CWE-664)
File: include/salt.h (line 23)
Finding: salt_encrypt() returns a heap-allocated buffer with no documented ownership contract.
CERT-C: MEM35-C
Fix: Add declaration comment stating caller must free the buffer; document NULL on failure.

Severity: MEDIUM
Class: Protection Mechanism Failure (CWE-693)
File: include/salt.h (line 41)
Finding: Public key parameter has no length argument; callers must know crypto_box_PUBLICKEYBYTES
         implicitly — this is a trust-boundary enforcement gap.
Fix: Add key_len parameter or use a typed key struct to make the invariant part of the interface.

Severity: LOW
Class: Error Propagation (CWE-701 / ERR-series)
File: src/cli/internal.h (line 75)
Finding: parse_args() returns void; callers cannot detect parse failures without inspecting
         global state, creating an implicit coupling.
Fix: Change return type to int; document 0 = success, negative = parse error.
```

## Output

Report findings in descending severity order (CRITICAL, HIGH, MEDIUM, LOW).
Each finding must include: severity, CWE class, file and line, a one-sentence description,
the applicable CERT-C rule (if any), and a concrete fix recommendation.
