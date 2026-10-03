---
name: security-review
description: "Security-focused code review with attack surface mapping and risk classification. Use when reviewing PRs for security, auditing code changes, or analyzing potential vulnerabilities. Triggers on: 'security review', 'use security mode', 'audit this', 'check for vulnerabilities', 'is this secure', 'attack surface', 'threat model', 'security check'. Read-only mode - identifies issues but doesn't fix them."
context: fork
allowed-tools: [Read, Grep, Glob, LSP]
---

# Security Review

Systematic security analysis of code changes.

## Core Approach

> "Assume the user is the attacker. Find where trust is misplaced."

Follow changed data and state from entry points to the operation that consumes them. Check the actual caller, helper, and cleanup contracts; a nearby guard, comment, or successful return does not prove a later access is safe.

## Risk Classification

| Risk Level | Triggers                                                         |
| ---------- | ---------------------------------------------------------------- |
| **HIGH**   | Auth, crypto, external calls, value transfer, validation removal |
| **MEDIUM** | Business logic, state changes, new public APIs                   |
| **LOW**    | Comments, tests, UI, logging                                     |

Raise or lower the level based on reachable impact and affected data or users. Include availability, integrity, and lifecycle failures as well as confidentiality issues.

## Attack Surface Mapping

For each change, identify:

1. **User inputs** - request params, headers, body, URL components
2. **Database queries** - any SQL/ORM operations
3. **Auth/authz checks** - where permissions are verified
4. **External calls** - APIs, services, file system
5. **Cryptographic operations** - hashing, encryption, tokens
6. **Shared state and lifetimes** - callbacks, workers, timers, interrupts, published objects, and resources acquired or released

## Security Checklist

### Input Validation

- [ ] All user input validated before use
- [ ] Validation happens at trust boundary (not just client)
- [ ] Type coercion handled safely
- [ ] Size/length limits enforced
- [ ] For each read, write, copy, or index, the check covers the exact pointer or destination, current offset, remaining length, and actual capacity at that operation
- [ ] Nested headers, declared lengths, offsets, and multi-slot items are bounded by their containing buffer before advancing or dereferencing
- [ ] Zero, sentinel, overflow, and boundary values are handled according to the API's semantics

### Authentication/Authorization

- [ ] Auth checks present on all protected paths
- [ ] No privilege escalation paths
- [ ] Session handling is secure
- [ ] Token expiration enforced
- [ ] Trace each writable interface and each instantiation or dispatch path; validation or authorization on one path does not cover a separate path

### Data Exposure

- [ ] No secrets in logs or responses
- [ ] Sensitive data filtered from error messages
- [ ] PII handling follows policy
- [ ] Debug endpoints disabled in production
- [ ] Every returned, cached, or serialized buffer is fully initialized across the span consumers can observe

### Injection Prevention

- [ ] Parameterized queries for SQL
- [ ] Output encoding for XSS
- [ ] Command injection prevented
- [ ] Path traversal blocked

### Cryptography

- [ ] No custom crypto implementations
- [ ] Strong algorithms used (no MD5/SHA1 for security)
- [ ] Secrets not hardcoded
- [ ] Key rotation possible

### Lifetime, Cleanup, and Concurrency

- [ ] Trace every acquired allocation, reference, mapping, lock, registration, and child resource through success, every error exit, retry, and teardown; confirm it is released or ownership is explicitly transferred
- [ ] Compare partial-initialization unwinds and normal teardown; include removal/unbind and callbacks that may still use the resource
- [ ] For asynchronous work, bounded waits, DMA, callbacks, or queued work, verify the work has completed or been cancelled before freeing or reusing referenced state
- [ ] For every pointer kept across an unlock, callback, iterator step, or buffer mutation, prove that the pointee remains alive and the pointer remains valid until its next use; a reference to an owner does not necessarily retain a nested object
- [ ] Check initialization before publication or activation, and trace every publication/index and its corresponding removal on partial failure
- [ ] Identify exactly which fields each lock protects; trace all callers, lock ordering, callback/re-entry behavior, interrupt context, and synchronous cancellation for deadlocks or races
- [ ] Where a check and use are separated by an unlock or helper that can block, allocate, or retry, verify the state and bounds again under the protection used for the action
- [ ] For RCU or other deferred readers, establish that readers have quiesced before reclaiming memory

### Contracts, Failure Paths, and Reachability

- [ ] Enumerate helper return values and failure classes; verify callers handle all errors and do not consume outputs that are undefined on any success path
- [ ] Check null guards in execution order, including expressions before the guard and all fall-through, fallback, logging, and error branches after it
- [ ] Check whether pointer-based cleanup is valid after partial allocation or resize failure, and whether a helper consumes or frees inputs on error before retry
- [ ] Verify API nullability, allocator boundary semantics, execution-context requirements, and configuration-specific paths at the call site
- [ ] Trace attacker-controlled or runtime-controlled values to warnings, assertions, panics, and other fatal invariants; confirm unsupported states fail safely

## Blast Radius Analysis

For HIGH risk changes:

1. Count direct callers
2. Trace transitive dependencies
3. Identify failure modes
4. Check rollback feasibility
5. Assess data exposure scope
6. Trace lifecycle and synchronization boundaries that can affect those callers or resources

## Red Flags (Stop and Escalate)

- 🔴 Removed validation without replacement
- 🔴 Access control modifiers weakened
- 🔴 External calls added without error handling
- 🔴 Crypto operations changed
- 🔴 Auth bypass paths introduced
- 🔴 Secrets in source code
- 🔴 `eval()` or dynamic code execution
- 🔴 Disabled security controls (even "temporarily")
- 🔴 A reachable error, assertion, or warning path can leave stale shared state, use freed or invalid memory, or terminate processing

## Common Vulnerability Patterns

| Pattern                      | Look For                                      |
| ---------------------------- | --------------------------------------------- |
| **IDOR**                     | User-controlled IDs without ownership check   |
| **Mass Assignment**          | Binding request body directly to models       |
| **SSRF**                     | User-controlled URLs in server requests       |
| **Path Traversal**           | User input in file paths without sanitization |
| **Race Condition**           | Check-then-use without locking                |
| **Insecure Deserialization** | Deserializing untrusted data                  |

## Finding Quality

- Anchor each finding to the root-cause statement and show the path from reachable input or state to the unsafe operation.
- Verify the relevant contract, bounds, ownership, or synchronization at that operation. Do not treat a plausible nearby issue as evidence for a different defect.
- State the concrete impact and affected conditions; distinguish confirmed defects from concerns that need more evidence.
- Continue past the first plausible issue and inspect related failure, fallback, and teardown paths before finalizing the review.

## Output Format

For each finding:

```markdown
**File**: `path/to/file.py:42`
**Risk**: HIGH | MEDIUM | LOW
**Category**: [Input Validation | Auth | Data Exposure | Injection | Crypto]
**Issue**: [Brief description of what's wrong]
**Evidence**: [Specific code or pattern that demonstrates the issue]
**Recommendation**: [What should be done - without implementing it]
```

## Review Summary Template

```markdown
## Security Review Summary

**Scope**: [Files/changes reviewed]
**Risk Level**: [Overall: HIGH/MEDIUM/LOW]

### Attack Surface

- Inputs: [list]
- External calls: [list]
- Auth points: [list]

### Findings

| #   | Risk | Category | File:Line  | Issue                    |
| --- | ---- | -------- | ---------- | ------------------------ |
| 1   | HIGH | Auth     | file.py:42 | Missing permission check |

### Recommendations

1. [Priority-ordered list of fixes]

### Not Reviewed

[Areas that need separate review or were out of scope]
```

## What NOT to Do

- ❌ Fix the issues (identify only)
- ❌ Assume "internal only" means safe
- ❌ Skip test files (they often reveal behavior)
- ❌ Trust comments that say "safe" or "validated elsewhere"
- ❌ Ignore configuration files
- ❌ Treat an error return, lock, reference count, or successful lookup as proof of completion, ownership, or lifetime without tracing its contract and callers

## The Security Reviewer's Creed

> "I'm not here to approve—I'm here to find what's missed."

Trust nothing. Verify everything. Document clearly.
