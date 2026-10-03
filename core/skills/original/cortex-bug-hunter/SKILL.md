---
name: bug-hunter
description: Expert procedure for auditing the Nox engine for subtle logic bugs, security vulnerabilities, and standard violations. Use this when performing deep logic forensics or when a new subtle vector is identified.
license: MIT
metadata:
  version: "1.0.0"
  specialization: logical-audit
---

# Bug Hunter Skill

This skill turns an AI agent into a "Bug Hunting Expert" specialized in the Nox stack (TypeScript, Bytecode, VM).

## Core Audit Protocols

### 1. Precedence & Parsing
- **Logic:** Check `Parser.ts` for operator precedence errors. Ensure `logicalOr` calls `logicalAnd`, which calls `comparison`, etc.
- **Edge Cases:** Look for missing unary operators (e.g., `-`, `!`) or incorrect greedy matching in assignments.

### 2. Scope & Memory Management
- **Leakage:** Verify every control flow block (`if`, `while`) correctly pushes and pops its own scope.
- **Collisions:** Check if local variables can overwrite globals or arguments without proper relative addressing.
- **Frames:** Ensure `Opcode.CALL` and `Opcode.RET` perfectly balance the `basePointer` and `memoryStackPointer`.

### 3. VM Security (DoS & Data)
- **Unbounded Loops:** Check for opcodes that can cause infinite loops or recursion without depth limits.
- **Buffer Safety:** Ensure every `readOperand()` call has a corresponding bounds check against the bytecode length.
- **Typed Access:** Verify zero usage of `as any`. Use strict type guards for arithmetic on the `stack`.

## Workflow
1. **Research:** Read the relevant source files thoroughly.
2. **Reproduce:** Create a minimal `.nx` script or vitest case that demonstrates the bug.
3. **Analyze:** Identify the root cause in the Lexer/Parser/Compiler/VM pipeline.
4. **Fix:** Apply a surgical fix that maintains engine performance and purity.
5. **Verify:** Run the reproduction script and all existing tests.

## Tools of the Trade
- `grep -r "as any" .`
- `npx vitest packages/runtime/tests/safety.test.ts`
- `npm test`
