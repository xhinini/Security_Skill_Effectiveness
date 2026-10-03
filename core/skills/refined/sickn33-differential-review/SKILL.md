---
name: differential-review
description: "Security-focused code review for PRs, commits, and diffs."
risk: critical
source: community
---

# Differential Security Review

Security-focused code review for PRs, commits, and diffs.

## When to Use
- You need a security-focused review of a PR, commit range, or diff rather than a general code review.
- The changes touch auth, crypto, external calls, value transfer, permissions, or other high-risk logic.
- You need findings backed by code evidence, attack scenarios, and an explicit report artifact.

## Core Principles

1. **Risk-First**: Focus on auth, crypto, value transfer, external calls
2. **Evidence-Based**: Every finding backed by code, relevant history when available, line numbers, and an attack scenario
3. **Adaptive**: Scale to codebase size (SMALL/MEDIUM/LARGE)
4. **Honest**: Explicitly state coverage limits, confidence, and uncertainty about change attribution
5. **Output-Driven**: Always generate the comprehensive markdown report file using the established report format
6. **Root-Cause Focused**: Validate that the finding, function, and cited statement describe the same defect; keep separate issues separate

---

## Rationalizations (Do Not Skip)

| Rationalization | Why It's Wrong | Required Action |
|-----------------|----------------|-----------------|
| "Small PR, quick review" | A critical flaw can hinge on a tiny change | Classify by RISK, not size |
| "I know this codebase" | Familiarity breeds blind spots | Build explicit baseline context |
| "Git history takes too long" | History reveals regressions | Never skip Phase 1 |
| "Blast radius is obvious" | You'll miss transitive callers | Calculate quantitatively |
| "No tests = not my problem" | Missing tests = elevated risk rating | Flag in report, elevate severity |
| "Just a refactor, no security impact" | Refactors break invariants | Analyze as HIGH until proven LOW |
| "I'll explain verbally" | No artifact = findings lost | Always write report |
| "The first plausible issue explains it" | Nearby defects can have different causes and fixes | Check the evidence against the actual root-cause construct; continue the relevant review paths |
| "No baseline means no security finding" | Current code can expose a reachable flaw even when introduction timing is unknown | Assess the source-level risk and qualify regression attribution separately |

---

## Quick Reference

### Codebase Size Strategy

| Codebase Size | Strategy | Approach |
|---------------|----------|----------|
| SMALL (<20 files) | DEEP | Read all deps, full git blame |
| MEDIUM (20-200) | FOCUSED | 1-hop deps, priority files |
| LARGE (200+) | SURGICAL | Critical paths only |

### Risk Level Triggers

| Risk Level | Triggers |
|------------|----------|
| HIGH | Auth, crypto, external calls, value transfer, validation removal |
| MEDIUM | Business logic, state changes, new public APIs |
| LOW | Comments, tests, UI, logging |

---

## Workflow Overview

```
Pre-Analysis → Phase 0: Triage → Phase 1: Code Analysis → Phase 2: Test Coverage
    ↓              ↓                    ↓                        ↓
Phase 3: Blast Radius → Phase 4: Deep Context → Phase 5: Adversarial → Phase 6: Report
```

Use a small coverage map for the changed security-relevant files and paths. Revisit it before closing the review so a large file or subsystem is not represented only by the first path examined. Prioritize by risk, but record skipped or lightly reviewed areas as coverage limits.

---

## Decision Tree

**Starting a review?**

```
├─ Need detailed phase-by-phase methodology?
│  └─ Read: methodology.md
│     (Pre-Analysis + Phases 0-4: triage, code analysis, test coverage, blast radius)
│
├─ Analyzing HIGH RISK change?
│  └─ Read: adversarial.md
│     (Phase 5: Attacker modeling, exploit scenarios, exploitability rating)
│
├─ Writing the final report?
│  └─ Read: reporting.md
│     (Phase 6: Report structure, templates, formatting guidelines)
│
├─ Looking for specific vulnerability patterns?
│  └─ Read: patterns.md
│     (Regressions, reentrancy, access control, overflow, etc.)
│
└─ Quick triage only?
   └─ Use Quick Reference above, skip detailed docs
```

---

## Cross-Cutting Verification Checks

Apply the checks relevant to the code under review; they are prompts for tracing behavior, not assumptions that every category contains a defect.

- **Trace values and helper contracts to their use.** Follow each relevant input, return value, pointer, length, index, state flag, and output through validation, callers, branches, and cleanup. Check the exact predicate and API contract, including nullable inputs, every failure return, and errors reported through side effects. Confirm callers catch the full failure class before using dependent state. Check pointers before their first dereference, including in fallback, logging, diagnostic, assertion, and macro paths. Enumerate output-parameter guarantees and verify outputs before reads; for count- or sentinel-based values, follow zero, empty, and boundary cases through allocation semantics, arithmetic, and consumers. If a failed call can consume an argument, verify retries receive valid state. For untrusted selectors and keys, compare accepted ranges and uniqueness assumptions with each actual destination and insertion contract. Trace warnings and assertions to determine whether malformed input or routine failures can reach a fatal sink, including denial-of-service outcomes from user-controlled values. For exposed output, compare the declared span with bytes actually initialized on every branch.
- **Check complete memory spans and content validity.** For every read, write, copy, index, pointer formation, or parser cursor advance, trace the tainted value to the first operation that can cross a source or destination boundary. At parser call sites, carry the pointer with the exact bytes remaining, reduce that span after each consumed prefix, and check every branch's fixed-field reads and length-derived offsets before dereferencing, calculating a pull, advancing, or copying. For each affected handler, identify the guard that is supposed to protect the first access; follow decoded lengths and offsets through dispatch and any later skip. Inventory fixed-field and length-derived reads across relevant handlers and files; do not let checking one receive branch stand in for the others. Validate embedded lengths against their enclosing input. For every length-driven copy, prove the count fits both the bytes remaining in the source and the destination capacity, including counts returned by a peer; a request-side limit does not constrain a response-side length, and expected-trusted input does not replace a bounds proof. For copies into fixed buffers, calculate the full destination span after adding generated prefixes or headers, and check both the copy and resulting output length against capacity. Recalculate bounds after cursor changes, nested lengths, and every width-driven index increment before the next store; a loop-entry check does not cover later accesses within a variable-width record. Distinguish parser-internal bounds failures from request or copy-boundary failures, identify the first invalid access and the boundary it crosses, and select the weakness class that matches that violated boundary. Check zero-size and boundary values, sentinel arithmetic, and attacker-controlled selectors. Track pointers together with their lengths, and reacquire or copy cached pointers after operations that can relocate backing storage. When exposing output or recycled memory, compare the span declared to consumers with the bytes actually initialized on every runtime branch.
- **Trace ownership from acquisition through every exit.** For allocations, references, registrations, mappings, locks, and other resources, enumerate each successful acquisition and follow every later success, failure, retry, partial-initialization, rollback, unregister, and teardown path, including disposal before publication or registration. On each exit, verify that the exact resources acquired on that path are released through the matching API and that ownership is returned or transferred as required; a shared cleanup label or matching function name is not proof that it releases them. Pair specialized acquisition APIs with their actual release operations and check whether destroying a parent also releases subordinate resources. Track pointer state at each cleanup operation, including error-valued or partially initialized pointers, and account for nested resources, secondary indexes, and every way an object remains reachable after removal from a primary queue. Name the exact resource whose release is missing and distinguish a memory leak from other unreleased-resource classes. Free only after asynchronous users are quiesced. Check release order explicitly: dropping an owning reference may run final destruction immediately, so any later access needs an independent lifetime guarantee. Before replacing or resizing an owned allocation, check the allocator's failure contract and retain the old allocation as the valid owned value until the replacement succeeds; trace failure cleanup and retry paths for lost references, leaks, or stale pointers, and compare related growth paths for consistent ownership handling. Recreate arguments a failed callee may have consumed before retrying.
- **Trace lifetimes, synchronization, and execution context.** Pair every shared-state read with the lock or other synchronization protecting that exact invariant, and inspect all readers, writers, publication, deletion, and reclamation under relevant interleavings. Revalidate state after crossing into the lock that protects an operation. A lock may not pin a raw pointer after unlock, a reference to a related object may not protect it, and balanced references do not prove multi-index publication is atomic. If publication releases a lock between index updates, trace teardown interleavings at every step: a temporary reference preserves memory but not publication eligibility, so serialize the updates with teardown or revalidate liveness before each publication. Follow callbacks, IRQs, workers, timers, and queued work through handoff, cancellation, unregister, and teardown; assume activation may permit immediate execution, compare it with initialization of every field and reference they can touch, and enumerate caller operations after enqueue against concurrent teardown. For pointers retained for later use, trace the producer, every storage and retrieval operation, all consumers, and every cleanup path; identify which operation ends the lifetime and what synchronization or ownership should prevent a later dereference. Classify the finding by its concrete violated lifetime or synchronization condition and consequence, not by a broad nearby race or memory-corruption description. For synchronous cancellation or teardown waits, trace caller-held locks against every lock needed by the callback or worker before it can complete; waiting while holding one of those locks can deadlock. Follow stop, completion, and worker exit before using a cached task or object pointer. Carry inherited lock state through helpers and callbacks; check every operation through unlock, including potentially sleeping allocation and user-memory access, lock ordering, interrupt re-entry, and whether waits, callbacks, final releases, or nested helpers can reacquire a held lock. Distinguish the unsafe access from the operation or missing invariant that permits it.
- **Verify initialization and state transitions end to end.** Check each construction mode and configuration entry against required fields and callback assumptions. Trace fields from their actual producer or constructor through publication to their first consumer, confirming the required initialization occurs on every path. Match storage and retrieval APIs and object types; initializing a private allocation does not initialize a separately supplied object. For aggregate initialization, check evaluation order when an expression reads from the object being initialized. Follow successful setup and each helper error through caller guards, dependent uses, rollback, and teardown. Verify runtime discovery, rollback, or partial setup updates every later probe, iteration, and teardown guard. For writable runtime parameters, trace every permitted update to every consumer and check that the setter enforces the consumer's range and synchronization requirements; initialization-time validation does not constrain later writes. When the bad state originates in file-scope configuration or initialization, identify that producer as the causal location rather than citing only a downstream consumer. Assess source reachability separately from whether history establishes when the defect was introduced.
- **Validate recovery and side-effect scope.** Follow error codes into callers and shared cleanup labels, checking that cleanup is valid for each state and that recovery, reset, wake, cache, or persistence operations apply to the resource and transaction that actually failed. Trace fallback branches from the initial data or state mutation through transaction start and metadata finalization, and follow queued side effects through execution, rollback, and object reuse. Check error values against every producer before treating them as proof of state or passing them to ordinary release functions.

For each candidate, trace the claimed cause through the relevant input or state, caller and helper contracts, execution context, ordering, and violated invariant. Identify the exact unsafe operation and enclosing function; cite the statement that causes or fails to prevent the defect, not a nearby symptom or independent issue. If the cause is in file-scope configuration or initialization, cite that producer even when a downstream function exposes the effect. For bounds flaws, map each affected path to its causal statement: cite the unchecked field access in each affected handler when the guard is missing there; when a derived span is wrong, cite the statement that establishes its pointer offset or remaining length and use the later access as supporting evidence. Include affected files and branches rather than treating one example as complete coverage. Identify the first invalid access and the source or destination boundary crossed. For lifetime and concurrency flaws, distinguish the unsafe access from the operation or missing ownership, reclamation, or synchronization invariant that permits it; classify by the violated invariant and concrete consequence rather than a broad symptom label. Select the narrowest applicable weakness class (CWE) and check that its definition matches the root cause. Explain a concrete reachable path and impact, including fatal diagnostic or assertion sinks when relevant. Keep code-level confidence separate from confidence that the reviewed change introduced the flaw; when a baseline is unavailable, limit attribution but still assess reachable flaws in supplied source. Before closing, verify each finding's function, cited statement, and weakness class all describe the same root cause, then continue through other relevant paths in the coverage map.

---

## Quality Checklist

Before delivering:

- [ ] All changed files analyzed; relevant paths and any intentionally limited coverage recorded
- [ ] Git blame/history checked for removed or changed security code when available
- [ ] Blast radius calculated for HIGH risk
- [ ] Relevant error, parser, initialization, cleanup, ownership, and asynchronous paths traced to completion, including fixed-field reads across handlers and files, derived pointer offsets and remaining spans, source and destination spans for copies, cached pointers across relocating operations, failed allocation replacements, failure returns, interrupted exits, release ordering, and objects reachable through multiple indexes
- [ ] Every successful acquisition matched to the right release and ownership transfer on every later error and cleanup path; buffer growth preserves the old owned allocation if replacement fails
- [ ] Lifecycle state traced from its actual producer or constructor through matching storage and retrieval APIs, publication, every consumer, and cleanup; findings cite the root-cause construct and separately establish reachability
- [ ] Candidate findings checked against their root-cause construct; bounds classes match the first invalid access and crossed boundary; lifetime and concurrency classes match the violated invariant and concrete consequence; CWE definitions, functions, and citations describe the same defect; unrelated issues kept separate
- [ ] Helper outputs, retry arguments, and nullable failure paths verified; diagnostic and assertion paths checked for fatal outcomes; configuration or initialization causes cited at their producer
- [ ] Review continued across the relevant coverage map after identifying a candidate finding
- [ ] Attack scenarios are concrete (not generic)
- [ ] Each finding names the enclosing function, applicable CWE, and causal line(s): unchecked accesses for missing per-handler guards, or the span-derivation statement for an incorrect pointer/length pair
- [ ] Regression attribution and confidence reflect available history and evidence
- [ ] Report file generated in the established format
- [ ] User notified with summary

---

## Integration

**audit-context-building skill:**
- Pre-Analysis: Build baseline context
- Phase 4: Deep context on HIGH RISK changes

**issue-writer skill:**
- Transform findings into formal audit reports
- Command: `issue-writer --input DIFFERENTIAL_REVIEW_REPORT.md --format audit-report`

---

## Example Usage

### Quick Triage (Small PR)
```
Input: 5 file PR, 2 HIGH RISK files
Strategy: Use Quick Reference
1. Classify risk level per file (2 HIGH, 3 LOW)
2. Focus on 2 HIGH files only
3. Git blame removed code
4. Generate minimal report
Time: ~30 minutes
```

### Standard Review (Medium Codebase)
```
Input: 80 files, 12 HIGH RISK changes
Strategy: FOCUSED (see methodology.md)
1. Full workflow on HIGH RISK files
2. Surface scan on MEDIUM
3. Skip LOW risk files
4. Complete report with all sections
Time: ~3-4 hours
```

### Deep Audit (Large, Critical Change)
```
Input: 450 files, auth system rewrite
Strategy: SURGICAL + audit-context-building
1. Baseline context with audit-context-building
2. Deep analysis on auth changes only
3. Blast radius analysis
4. Adversarial modeling
5. Comprehensive report
Time: ~6-8 hours
```

---

## When NOT to Use This Skill

- **Greenfield code** (no baseline to compare)
- **Documentation-only changes** (no security impact)
- **Formatting/linting** (cosmetic changes)
- **User explicitly requests quick summary only** (they accept risk)

For these cases, use standard code review instead.

---

## Red Flags (Stop and Investigate)

**Immediate escalation triggers:**
- Removed code from security-advisory or fix commits
- Access control modifiers removed (onlyOwner, internal → external)
- Validation removed without replacement
- External calls added without checks
- High blast radius (50+ callers) + HIGH risk change

These patterns require adversarial analysis even in quick triage.

---

## Tips for Best Results

**Do:**
- Start with git blame for removed code
- Calculate blast radius early to prioritize
- Generate concrete attack scenarios
- Reference specific line numbers and commits
- Be honest about coverage limitations
- Always generate the output file
- Trace the exact failing path, cleanup ordering, and object lifetime for relevant findings
- Continue the coverage map after finding an issue; one finding does not establish that other paths are safe

**Don't:**
- Skip git history analysis when history is available
- Make generic findings without evidence
- Claim full analysis when time-limited
- Forget to check test coverage
- Miss high blast radius changes
- Substitute a plausible neighboring issue for the defect being evaluated
- Output report only to chat (file required)

---

## Supporting Documentation

- **methodology.md** - Detailed phase-by-phase workflow (Phases 0-4)
- **adversarial.md** - Attacker modeling and exploit scenarios (Phase 5)
- **reporting.md** - Report structure and formatting (Phase 6)
- **patterns.md** - Common vulnerability patterns reference

---

**For first-time users:** Start with methodology.md to understand the complete workflow.

**For experienced users:** Use this page's Quick Reference and Decision Tree to navigate directly to needed content.

## Limitations
- Use this skill only when the task clearly matches the scope described above.
- Do not treat the output as a substitute for environment-specific validation, testing, or expert review.
- Stop and ask for clarification if required inputs, permissions, safety boundaries, or success criteria are missing.
