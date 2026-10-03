# Threat-Model Checklist

Walk this for every changed file in the diff. For each item, mark ✅ / ⚠️ / N/A with a one-line reason. Don't skip categories silently — saying "N/A: no crypto in this change" is a real review artifact.

---

## 1. Trust boundaries

A trust boundary is anywhere data flows from a less-trusted source to a more-trusted one.

- [ ] External → application (HTTP request, websocket message, file upload, IPC, env var, CLI arg)
- [ ] Untrusted user → privileged operation (admin endpoint, billing op, account modification)
- [ ] Tenant A → tenant B (multi-tenant data isolation)
- [ ] Network → in-process (deserialization, RPC, parsing)
- [ ] Third-party API → your code (you don't control the response shape)

For each boundary: what data crosses, what validation is applied at the boundary, what assumptions does code beyond the boundary make?

## 2. Input validation

- [ ] Every external input has a typed schema (Pydantic, Zod, struct tags, etc.)
- [ ] Length limits on strings, arrays, and uploads
- [ ] Content validation (allowlist > denylist) on enums, IDs, file types, MIME types
- [ ] Numeric bounds (no negative quantities, no `Int.MAX`)
- [ ] Unicode normalization where identity comparison matters (homograph attacks)
- [ ] No "stringly typed" parameters that get later parsed unsafely

### File uploads (apply when the diff adds or touches an upload path)

File uploads are their own attack surface, not a generic input check. Walk these explicitly:

- [ ] **Size cap** enforced at the HTTP layer (not just at the storage layer where the body has already been read)
- [ ] **Count cap** on multipart fields and on the upload endpoint per session
- [ ] **MIME-type allowlist** (not denylist). `image/png`, `image/jpeg` allowed; everything else rejected. `text/*` is rarely a good idea on an upload endpoint.
- [ ] **Content sniff** matches the claimed MIME. Reject if `python-magic` / `file(1)` disagrees with the `Content-Type` header.
- [ ] **Extension normalisation**. Strip path components, normalise Unicode, lowercase, and don't trust the client name as the storage name (use a UUID + a server-side mapping).
- [ ] **Storage path** computed from a server-side ID; never derived from the client name. Saved outside the web root or behind an auth-gated handler, not a static file route.
- [ ] **Zip-slip / archive traversal** on every archive (`.zip`, `.tar`, `.tar.gz`, `.7z`, `.rar`): validate that each entry's resolved path is inside the extraction root.
- [ ] **Archive bombs**: cap decompressed size + entry count before extraction commits to disk.
- [ ] **Polyglot files**: a real JPEG with PHP / JS appended is still a JPEG to most sniffers. If the file will be served back, set `Content-Disposition: attachment` or serve from a sandbox origin.
- [ ] **Image / media processing CVEs**: ImageMagick, libvips, sharp, Pillow, ffmpeg have a long CVE history. Run versions through `composite_risk` and treat unreachable findings as still worth patching (reachability changes the moment user-uploaded content flows in).
- [ ] **Virus / malware scan hook** if the file will be downloaded by other users (ClamAV is the boring default; many cloud providers offer scanned-bucket variants).
- [ ] **Resource cap** on transcoding / thumbnailing pipelines (CPU, memory, time). An "image" that decodes to a 1 GB bitmap is a DoS.

## 3. Injection sinks

Search the diff for these sinks and confirm each one is fed only safe inputs:

- [ ] **SQL** — parameterized queries only, no string concatenation, no `f"... {var}"` in raw SQL, no ORM raw modes without binding
- [ ] **Command / shell** — `subprocess` with list args + `shell=False`, no `os.system`, no `eval`, no `shell=True` with user input
- [ ] **OS path** — no path constructed from user input passed to `open`/`os.remove`/etc. without realpath + allowlist check
- [ ] **Template / SSTI** — Jinja `autoescape` on, no `| safe` on user input, no user-controlled template *strings* (not just template variables). Classic payloads worth grepping for and explicitly rejecting: `{{config}}`, `{{''.__class__.__mro__}}`, `{{request.application.__globals__}}` (Jinja), `<%= system(...) %>` (ERB), `{{_self.env.registerUndefinedFilterCallback(...)}}` (Twig), `{{constructor.constructor('...')()}}` (Handlebars / Angular). Jinja `SandboxedEnvironment` is not a hard sandbox; never feed it untrusted templates.
- [ ] **HTML** — output encoded for context (HTML body vs attribute vs JS vs CSS vs URL)
- [ ] **HTTP headers** — no `\r\n` injection from user input into Set-Cookie / Location
- [ ] **Log** — no `\n` injection allowing fake log lines
- [ ] **NoSQL** — no object-shaped query payloads accepted from JSON (`{"$gt": ""}` bypasses)
- [ ] **LDAP / XPath / XML** — appropriate escaping for the target language
- [ ] **Regex** — no user-supplied patterns (ReDoS); patterns reviewed for catastrophic backtracking

## 4. AuthN / AuthZ

- [ ] Every new endpoint / handler / RPC method has an explicit auth check
- [ ] Auth check happens **before** any side effect or expensive operation
- [ ] Object-level permissions enforced (the resource belongs to the requesting user) — this is IDOR territory
- [ ] No "security through obscurity" — UUIDs are not authorization
- [ ] Role/permission checks use a centralized helper, not ad-hoc string compares
- [ ] Session handling: rotation on privilege change, invalidation on logout, secure cookie flags
- [ ] No JWT `alg: none`; signing key not user-controllable; expiry enforced
- [ ] No timing-unsafe credential comparison (`==` on tokens / hashes)
- [ ] MFA / step-up auth required for sensitive actions where applicable

### Auth-specific attack patterns

- [ ] **Credential stuffing / brute force** — login + password-reset + MFA-challenge endpoints have rate limiting *per identifier* (not just per IP). Backoff increases on failure. Lockout has an admin-bypass path.
- [ ] **Password reset poisoning** — reset link is built from a server-known canonical URL, never from `Host` / `X-Forwarded-Host`. Token has a short TTL, is single-use, and is invalidated on use *and* on password change *and* on session-token rotation.
- [ ] **MFA bypass via response manipulation** — `/verify-otp` returns `{ "ok": true, "token": "..." }` only after server-side validation; the client cannot promote itself to authenticated by editing the response. Step-up flows can't be skipped by going straight to the post-step-up URL.
- [ ] **OAuth / OIDC callback hijacking** — `redirect_uri` validated against an exact-match allowlist (no wildcard subdomains, no prefix match); `state` and `nonce` checked; PKCE used for public clients; no implicit flow for new code.
- [ ] **Account enumeration** — login and password-reset return identical responses + timing for "user exists with wrong password" vs "user doesn't exist." Same for "email already registered" on signup (use a delayed-confirmation flow instead).
- [ ] **Session fixation** — session ID rotates on login and on privilege change; pre-auth session cookies are not reused post-auth.

## 5. Secrets and credentials

- [ ] No hardcoded API keys, tokens, passwords, private keys, connection strings
- [ ] Secrets not logged (including in error messages, request dumps, telemetry)
- [ ] Secrets not embedded in URLs (visible in proxy logs, browser history, Referer)
- [ ] `.env` / `secrets.yaml` not committed
- [ ] Test fixtures don't contain real credentials
- [ ] Secret rotation supported (no assumption of immutable secret)

## 6. Cryptography

- [ ] Algorithms: AES-GCM or ChaCha20-Poly1305 (not ECB, not raw CBC without MAC)
- [ ] Hashes: SHA-256+ for integrity; bcrypt / argon2 / scrypt for passwords (never MD5/SHA-1/plain-SHA-256 for passwords)
- [ ] HMAC for integrity, not raw hash
- [ ] Key length: RSA ≥2048, ECC P-256+, AES ≥128
- [ ] IV / nonce: random per encryption, never reused with the same key
- [ ] No custom crypto. None. Always a red flag.
- [ ] Constant-time comparison for MACs and tokens
- [ ] TLS verification not disabled (`verify=False`, `rejectUnauthorized: false`, `InsecureSkipVerify: true`)
- [ ] Random: cryptographic RNG (`secrets`, `crypto.randomBytes`) for security purposes, never `random` / `Math.random` / `rand()`

## 7. Deserialization

- [ ] No `pickle.load` / `cPickle.load` on untrusted data — EVER
- [ ] No `yaml.load` without `Loader=SafeLoader` (or use `yaml.safe_load`)
- [ ] No Java `ObjectInputStream` / PHP `unserialize` / .NET `BinaryFormatter` on untrusted data
- [ ] JSON parsers configured to reject duplicate keys if order matters
- [ ] XML parsers configured against XXE (`resolve_entities=False`, `defusedxml` for Python)
- [ ] No `eval`, `exec`, `Function()`, dynamic `require` on user input

## 8. SSRF / file inclusion

- [ ] URL fetches: hostname allowlist, no `localhost` / `127.0.0.1` / `169.254.169.254` / `::1` / private RFC 1918 ranges
- [ ] Redirects followed only within the allowlist
- [ ] DNS rebinding considered (resolve once, connect to resolved IP)
- [ ] File paths: realpath + prefix check against a base directory
- [ ] No user-controlled scheme (`file://`, `gopher://`, `dict://`)

### Common SSRF vectors to grep for explicitly

Most SSRF in 2026 is not "user submitted an http:// to a fetch endpoint." It's hidden in features that *coincidentally* make outbound HTTP. Walk the diff for these:

- [ ] **PDF generators** that render user-supplied HTML (wkhtmltopdf, headless Chromium, Puppeteer, WeasyPrint) — `<iframe src="http://169.254.169.254/...">` fetches cloud metadata server-side
- [ ] **Webhook callbacks** where the user supplies the URL (Slack-style integrations, payment-provider notifications)
- [ ] **OAuth callback URLs** — see category 4; also a classic SSRF disguised as auth flow
- [ ] **Image fetchers in markdown / chat renderers** — auto-fetching `<img src>` to inline or cache means user-supplied URL → server-side request
- [ ] **OEmbed / link unfurlers** — Slack/Discord/Mattermost-style URL previewing
- [ ] **RSS / Atom / sitemap processors**
- [ ] **Avatar / profile-image proxies** that fetch and cache an external URL
- [ ] **SVG / XML processors** — XXE is the classic, but `<image href="...">` inside SVG also fetches
- [ ] **Server-side prefetch / SSR / "click for preview"** features
- [ ] **External webhooks for "test connection"** in integration setup UIs

## 9. Race conditions / TOCTOU / replay

- [ ] No check-then-act on file existence/permissions (use atomic operations)
- [ ] Database operations use transactions + appropriate isolation, or row-level locking
- [ ] No "check balance, then debit" without lock — use atomic decrement / compare-and-set
- [ ] Idempotency keys for retryable mutations
- [ ] **Replay protection for signed-message endpoints**: signed messages with
  timestamps (Stripe webhooks, JWTs, signed cookies, OAuth requests) must
  reject stale messages — the timestamp/nonce must be *checked*, not just
  parsed. A captured-valid signed message replayed indefinitely is a signature
  failure even though the signature is technically valid.
- [ ] No assumption that an auth check still holds N milliseconds later

## 10. Error handling

- [ ] Stack traces not returned to users in production
- [ ] Exceptions not silently swallowed (`except: pass`, empty catch blocks)
- [ ] No fail-open: if auth check throws, request fails closed
- [ ] Sensitive info (paths, query fragments, internal hosts) not in error messages
- [ ] Errors logged at appropriate level (not as warnings if they break the request)

## 11. Logging and PII

- [ ] No passwords, tokens, session IDs, API keys, full card numbers, SSNs in logs
- [ ] PII logged only with a defined retention + minimization policy
- [ ] Log injection prevented (newline stripping or structured logging)
- [ ] Logs not world-readable / not in the web root
- [ ] Audit log for security-sensitive events (login, permission change, data export)

## 12. Dependencies

(Most of this is covered by OSV-Scanner / the MCP server. Manual checks:)

- [ ] No typosquats — package name matches what the user actually wanted
- [ ] No abandoned packages (last release >2y, no maintainer response)
- [ ] No packages where the maintainer changed recently and suspiciously
- [ ] Pinned versions or lockfile committed
- [ ] License compatible with the project
- [ ] No transitive dep brings in a known-vulnerable version (`osv-scanner` covers this)

## 13. Supply chain

- [ ] No `postinstall` / `preinstall` scripts in new npm deps without scrutiny
- [ ] No dynamic code download at install/build time (`curl | sh`, fetching tarballs from arbitrary URLs)
- [ ] Build scripts don't read secrets and write to network
- [ ] No `eval(fetch(...))` patterns
- [ ] Container base images pinned by digest, not just tag
- [ ] CI uses pinned action versions (not `@main`)

## 14. Concurrency

- [ ] Shared mutable state protected by lock / channel / actor
- [ ] No "check if cache has it, then set" without atomic operations
- [ ] Goroutines / async tasks don't leak (timeout / cancellation propagation)
- [ ] Database connections / file handles closed in finally / `with` / `defer`

## 15. Resource exhaustion (DoS)

- [ ] Request body size limits enforced
- [ ] Upload size and count limits enforced
- [ ] Regex patterns reviewed for catastrophic backtracking (ReDoS) — especially on user input
- [ ] Unbounded loops / recursion guarded by depth/iteration limits
- [ ] Pagination on list endpoints (no "return all rows")
- [ ] Rate limiting on expensive operations
- [ ] Memory caps on parsers (JSON depth, XML entity expansion, decompression bombs)

## 16. Web-app cross-cutting concerns

Things that aren't injection sinks but bite web apps constantly. Skip if the project has no HTTP surface.

- [ ] **CSRF** — state-changing requests require a CSRF token or use SameSite=Lax/Strict cookies, double-submit, or a custom header check. If the framework provides a CSRF middleware (Django, Rails, Express csurf), it's enabled and not bypassed on the route.
- [ ] **CORS** — `Access-Control-Allow-Origin` is not `*` when credentials are sent; not a regex that reflects arbitrary origins; not a fixed string that's actually attacker-controlled (e.g. via `Origin` reflection)
- [ ] **Open redirect** — every redirect target (login flow, OAuth callback, `?next=`) is validated against an allowlist of paths or hostnames before issuing the 30x
- [ ] **Security headers** — at minimum: `Content-Security-Policy` (real, not `unsafe-inline` everywhere), `Strict-Transport-Security`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy` reducing unused features
- [ ] **Cookie flags** — `Secure`, `HttpOnly`, `SameSite=Lax` or `Strict` on session / auth cookies; no auth tokens in non-`HttpOnly` cookies or `localStorage`
- [ ] **Cache poisoning / web cache deception** — cache key includes everything that affects the response (Vary headers correct); no user-specific data behind a CDN with a public cache key; no `.css`/`.js` extension tricks that bypass auth checks
- [ ] **Host header injection** — `Host` / `X-Forwarded-Host` not trusted for absolute URL construction (password reset links, etc.)
- [ ] **Clickjacking** — `Content-Security-Policy: frame-ancestors` or `X-Frame-Options: DENY` on sensitive pages

## 17. Protocol-specific (GraphQL, WebSocket, gRPC, webhooks)

- [ ] **GraphQL — introspection** disabled in production
- [ ] **GraphQL — query depth limit** enforced (no deeply nested recursive queries)
- [ ] **GraphQL — query complexity limit** enforced (no `users { posts { author { posts { ... } } } }` cost-bombs)
- [ ] **GraphQL — batching** rate limited (no 10,000-op batched payload to brute-force a password)
- [ ] **GraphQL — error messages** don't leak field-level info ("user not found" vs "wrong password")
- [ ] **WebSocket — origin** validated on the upgrade handshake
- [ ] **WebSocket — auth** enforced at connect time, not per-message after the fact
- [ ] **WebSocket — message size + rate** limits enforced
- [ ] **gRPC — auth** interceptor enforced before any handler
- [ ] **gRPC — reflection** disabled in production
- [ ] **Webhooks — signature verified** *before* parsing the body (HMAC, Stripe-Signature, GitHub `X-Hub-Signature-256`)
- [ ] **Webhooks — replay protection** via timestamp window + nonce

## 18. Authorization matrix walkthrough

For every new endpoint, handler, RPC, GraphQL mutation, or background job in the diff, write one line in this format:

```
<route or handler>:  caller=<anon|auth|role:X|admin>  side_effect=<...>  lesser_role_result=<403|403-with-info-leak|allowed-but-shouldn't|allowed-and-OK>
```

Then ask, for each row:

- [ ] Is the auth check **before** the side effect, not after?
- [ ] Is the resource ownership check there, not just "is the user logged in"? (IDOR territory)
- [ ] Would an anonymous caller get a useful error message that leaks the resource's existence? (IDOR-with-info-leak)
- [ ] Is `lesser_role_result` what you actually want, or are you relying on UI hiding the button?
- [ ] If this is a write, is it idempotent or transactional under retry / replay?
- [ ] **Multi-tenant**: does every tenant-scoped query include `tenant_id` (or equivalent) in the `WHERE`/`filter` clause? Cross-tenant data leaks happen when this is enforced in middleware "everywhere" but missed on one new query.

IDOR lives in the gap between what the app accepts and what it should allow. Scanners do not catch IDOR. Walk this table or you will miss it.

### OWASP API Security Top 10 (2023) mapping

When the change touches an HTTP API surface, walk this list explicitly. Most map to checks already above; the goal is to make sure the API mental model isn't different from the general web one.

- [ ] **API1 BOLA — Broken Object-Level Auth** — covered by the IDOR / object-ownership row above. Confirm per-object, not per-endpoint.
- [ ] **API2 Broken Authentication** — covered by category 4 + "Auth-specific attack patterns." Confirm token rotation, MFA, and identifier-keyed rate limits.
- [ ] **API3 BOPLA — Broken Object Property-Level Auth** — mass assignment (also category 19). Server filters which fields can be set via `PATCH` / `PUT`, regardless of what the framework auto-binds. Property-level read filtering on responses (don't return `password_hash`, `internal_role`, audit timestamps a user shouldn't see).
- [ ] **API4 Unrestricted Resource Consumption** — covered by category 15. Per-endpoint rate limits + per-user / per-IP caps + bounded pagination + memory caps on parsing.
- [ ] **API5 BFLA — Broken Function-Level Auth** — admin endpoints aren't authorised by "the UI doesn't expose this." Confirm role check on every admin / privileged / internal route, not just on the discovery endpoint.
- [ ] **API6 Unrestricted Access to Sensitive Business Flows** — referral abuse, gift-card redemption, account creation, password reset. Velocity limits, CAPTCHAs or proof-of-work where the action is monetisable, anomaly detection (also category 19).
- [ ] **API7 SSRF** — covered by category 8 + the "common SSRF vectors" sub-list. Webhook / callback URL endpoints especially.
- [ ] **API8 Security Misconfiguration** — DEBUG off, error responses don't leak stack traces, default credentials not present, CORS not `*` with credentials, security headers set (category 16), cloud bucket / object-store policies tightened.
- [ ] **API9 Improper Inventory Management** — every documented endpoint has auth + rate-limit + monitoring; no shadow / deprecated / non-prod APIs reachable from the public hostname. New endpoints added to the OpenAPI spec (negative space, category 21).
- [ ] **API10 Unsafe Consumption of APIs** — third-party API responses are validated like user input (especially when concatenated into queries, paths, or HTML). Outbound `verify=True`. Treat the *response* as untrusted even if the *destination* is trusted.

## 19. Business logic

Pure app-layer flaws that no scanner finds. For each new flow that involves money, identity, permissions, or state transitions, ask:

- [ ] **Payment / billing** — can a user complete checkout while skipping a step that's supposed to charge them? Can a coupon be applied twice? Can a refund exceed the original charge? Can a negative quantity reverse a charge?
- [ ] **Workflow step skipping** — does the server enforce step order, or only the client? Can `POST /step3` succeed without `POST /step2` having happened?
- [ ] **Race-on-balance** — can two concurrent withdrawals each see "balance is sufficient" before either commits? (Atomic decrement / row lock / CAS required.)
- [ ] **Referral / coupon abuse** — can one user create N accounts to farm referral bonuses? Is the abuse-detection check after the bonus is paid?
- [ ] **Replay of signed messages** — is the timestamp / nonce on JWTs, webhooks, signed cookies, OAuth callbacks actually *checked*, not just parsed?
- [ ] **State machine bypass** — can an order go from `cancelled` back to `paid`? Can a banned user re-register with the same email?
- [ ] **Mass assignment** — does a `PATCH /users/me` allow setting `is_admin: true` because the framework auto-binds all body keys?

## 20. LLM / AI agent / MCP security

Mirrors the OWASP LLM Top 10 (2025). Apply when the change touches an LLM call, prompt template, RAG / vector store, tool / function-calling surface, or MCP server.

- [ ] **Direct prompt injection** — user input concatenated into a system prompt without delimiting or input filtering; injection attempts in the test corpus
- [ ] **Indirect prompt injection** — content from retrieved documents, scraped web pages, file uploads, or third-party APIs flowed into the prompt; assumed-trusted
- [ ] **Insecure output handling** — LLM output passed to `eval` / `exec` / shell / SQL / HTML without sanitization. Treat LLM output as untrusted user input.
- [ ] **Excessive functionality** — the agent has tools it doesn't need for this task (e.g. shell access for a Q&A agent)
- [ ] **Excessive permissions** — tools run with credentials broader than the user's (e.g. agent DB user with `DROP TABLE` for a read-only task)
- [ ] **Excessive autonomy** — no human-in-the-loop confirmation for irreversible / high-blast-radius actions (delete, transfer, publish, send-email)
- [ ] **System prompt leakage** — sensitive context (keys, internal URLs, real user data) embedded in the system prompt where a clever user can elicit it
- [ ] **RAG / vector poisoning** — write path to the vector store / knowledge base is authenticated and audited; no anonymous ingestion of documents the agent will trust
- [ ] **Unbounded consumption** — agent loop / tool-calling loop has a hop limit, a cost cap, and a hard timeout; no recursive self-invocation without bounds
- [ ] **Output filter not the only defense** — output filters are nice but assume the prompt boundary will fail; defense in depth via permissioning and review

### MCP-specific (if the change touches an MCP server or client)

- [ ] **Input validation on every tool argument** — types, length caps, regex on identifier-shaped fields. 43% of 2026 MCP CVEs are shell / exec injection through tool args.
- [ ] **No shell construction from tool args** — no `os.system(f"... {arg}")`, no `subprocess(shell=True, ...)` with user-controlled input
- [ ] **No SSRF in fetch / browse tools** — outbound URL allowlist or block-list of internal ranges (`127.0.0.0/8`, `169.254.169.254`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `::1`)
- [ ] **Auth on connect** — if the MCP server speaks HTTP/SSE rather than stdio, it has auth on the transport, not "trust the network"
- [ ] **No secrets in tool descriptions or responses** — the LLM will paraphrase / leak them
- [ ] **Response size caps** — a runaway upstream response can exhaust the model's context window

## 21. The "negative space" check

The diff is what changed. Often the bug is what *didn't* change. For each significant addition, ask:

- [ ] **New route / endpoint / handler** — was it added to the auth middleware allow-list / required-auth list? To the rate-limit decorator's set? To the audit log? To the OpenAPI spec?
- [ ] **New model field that looks like PII** (email, phone, SSN-shape, address, free-text containing names) — was the log scrubber updated? The telemetry redaction list? The data export filter? The CSV-export header allowlist?
- [ ] **New file upload path** — is the MIME / extension allowlist updated to actually allow what this needs, and *only* what this needs? Size cap? Virus-scan hook?
- [ ] **Removed or weakened a security control** — CSP relaxed? Regex broadened? Middleware dropped? JWT `exp` window widened? CORS allowlist expanded? `verify=False` introduced? Look at deletions in the diff, not just additions.
- [ ] **New external dependency** — covered by Step 3 of the workflow, but also: does it bring transitive deps that change the risk surface? (Native modules, postinstall scripts, network-during-build.)
- [ ] **New cron / scheduled / background job** — does it run as the same identity as a request handler, or with elevated creds? Is the auth check skipped because "it's an internal job"?
- [ ] **New configuration flag** — does the default value match what the rest of the codebase assumes? Is there a path where it can be flipped via env var without an audit trail?

## 22. AI-generated code red flags

Research suggests AI-generated code carries ~2.74x more vulnerabilities than human-written code on average. If the diff looks AI-generated, do an extra pass on the items below.

Tell-tale shapes:

- Verbose / restating-the-obvious comments above every line
- Over-broad `try / except Exception` that swallows everything
- Defensive `if x is not None` chains where the type already guarantees it
- Duplicate helpers with similar names in different files
- Pristine 0-1-many handling for cases that never happen, missing handling for cases that do
- Long parameter lists with `Optional[...]` everywhere and no real defaults

Extra checks for AI-shaped code:

- [ ] Inputs treated as the *type the model imagined*, not the type they actually are at the boundary (e.g. `int(request.args["id"])` with no error handling)
- [ ] Error paths that *log* but don't *fail* — silently continue with a half-built object
- [ ] Authorization checks that pattern-match what a tutorial would write but miss the project's centralized helper
- [ ] String-built SQL / commands / paths that "look like" the safe pattern but aren't (e.g. `f"... ?"` placeholders followed by `% (var,)` substitution)
- [ ] New helper functions whose name and behavior duplicate an existing helper. AI loves to re-invent.
- [ ] Tests that exercise the happy path only, with no adversarial inputs

### "Looks done but isn't" patterns

These are the failure mode where the code reads correct, type-checks, and even runs, but doesn't actually do the security-relevant work it claims to. Worst case in a security review: the model and a human reviewer both nod past them.

- [ ] **Validators that don't validate** — `def validate_x(payload): return True`, or a function whose body is `pass` / `...` / a single `return value` with no inspection
- [ ] **Sanitisers that don't sanitise** — `def sanitize(s): return s.strip()` named as if it's HTML-escaping, or a regex `re.sub` that misses the case it claims to remove
- [ ] **Tests that test nothing** — `assert True`, `assert result is not None` where the real contract is much stronger, `assert response.status_code == 200` with no body / shape check, mocks set up for calls that never happen
- [ ] **Dead-code branches** — `if False:`, `if 1 == 2:`, unreachable `else` after exhaustive returns, error handlers for exceptions that the wrapped code can no longer raise
- [ ] **Half-refactored identifiers** — function renamed in declaration but called by old name elsewhere (works because the old name still exists from an undeleted shim); enum value renamed in one switch arm but not another
- [ ] **TODO / FIXME / XXX / HACK in production paths** — especially adjacent to auth, validation, crypto, or anywhere a comment like "// trust this for now"
- [ ] **Commented-out code blocks** — usually the model trying two approaches and not deciding; reviewer should ask which one is supposed to be live
- [ ] **Inconsistent error handling between sibling endpoints** — `/api/v1/orders` does `try/except/abort(400)` on bad input, `/api/v1/orders/{id}` two lines later returns the raw exception. AI-drift signal.
- [ ] **Logging that pretends to be auditing** — `log.info("user %s did %s", user_id, action)` is not an audit log; an audit log persists, is tamper-evident, and is queried on incidents. If the code claims to "audit" but only emits to stdout, that's a fake control.
- [ ] **Feature flags / kill-switches that don't kill** — flag is checked, but the code path below the check still hits the same downstream code; or the flag is read once at import time and never refreshed
- [ ] **Retry loops with no backoff and no upper bound** — `while True: try ... except: continue` is not retry logic, it's a busy loop disguised as resilience

## 23. Memory safety and unsafe-language constructs

Most language-level "this could be a CVE" bugs in 2026 still come from a handful of patterns: panics in long-running services, raw `unsafe` blocks in Rust, classic UB in C/C++, and dropped error handling in Go. Walk this when the diff includes the relevant language.

### Rust

- [ ] **`unsafe` blocks** carry a `// SAFETY:` comment explaining the invariant the author is upholding. No `// SAFETY: this should be fine` or no comment at all.
- [ ] **`.unwrap()` / `.expect()`** appear only in `#[cfg(test)]` paths, examples, or `main`/`fn run() -> Result` style binaries where the program ending is the intended behaviour. Library code returns `Result` / `Option` and lets the caller decide.
- [ ] **`panic!()` / `todo!()` / `unimplemented!()`** are not on a code path reachable from a request handler. `todo!()` left in is a stronger smell than a TODO comment because it crashes when hit.
- [ ] **Integer overflow** — release builds wrap (don't panic). Use `checked_*` / `saturating_*` / `wrapping_*` explicitly on arithmetic over untrusted inputs.
- [ ] **`Box<dyn Error>` / `anyhow::Error` returns** preserve `source` chains; no `.to_string()` early that loses the underlying context.
- [ ] **`mem::transmute` / pointer casts** are flagged and justified in line. These are the things `cargo-geiger` will count.
- [ ] **Async cancellation**: futures hold no critical sections across `.await` points that must run to completion. No locks held across `.await`. Cancellation-safe by construction.

### C / C++

- [ ] **Buffer operations** use bounded variants: `strncpy_s` / `snprintf` (not `strcpy` / `sprintf` / `gets`); std::string / std::span where the project allows.
- [ ] **No format-string vulnerabilities** — never `printf(user_input)`; always `printf("%s", user_input)`.
- [ ] **No use-after-free** — clear ownership; smart pointers where the project uses them; manual `free` paired with `nullptr` assignment.
- [ ] **No double-free** — destructors / `free` paths don't run twice on the same pointer through control-flow exits.
- [ ] **Integer overflow on size arithmetic** — `size_t` overflow in `malloc(n * m)` where `n` and `m` are externally influenced; use saturating multiplication or explicit bounds.
- [ ] **Uninitialized memory** — every stack allocation is initialized before any branch reads from it; valgrind / MSan / UBSan in test runs.
- [ ] **Concurrency on POSIX**: signal handlers do not call non-async-signal-safe functions; shared state across threads has appropriate synchronisation.

### Go

- [ ] **Errors checked at every call site** — `_, err := f(); if err != nil { return err }` not `_, _ := f()`. The Go vet tool catches some of these; gosec catches more; the model should flag any `err` shadowed or ignored.
- [ ] **Nil pointer dereferences** — type assertions use the two-value form (`v, ok := x.(T)`) before dereferencing; map reads on possibly-nil maps are checked.
- [ ] **`context.Context` propagated** through every call chain that involves I/O, with a deadline / cancel; no `context.Background()` in a request handler.
- [ ] **Goroutine leaks** — every spawned goroutine has a clear termination path (context cancel, channel close, or a bounded loop). `go func() { for { ... } }()` with no exit is a leak.
- [ ] **Slice aliasing** — `append` on a slice passed in by the caller can mutate the caller's view if cap > len; if you don't intend that, copy first.
- [ ] **`defer` in loops** — defers don't run until the surrounding function returns, so `for { defer file.Close() }` leaks until the function exits.
- [ ] **`time.After` in `select`** is not garbage-collected until it fires; use `time.NewTimer` + explicit `Stop()` in long-running loops.

### How to run the scanners

- **Rust**: `cargo-geiger` (count of `unsafe`), `cargo clippy --all-targets -- -W clippy::unwrap_used -W clippy::expect_used -W clippy::panic -W clippy::indexing_slicing`
- **C / C++**: `flawfinder`, `cppcheck --enable=warning,performance,portability`, `clang-tidy --checks=clang-analyzer-security.*,clang-analyzer-core.*,bugprone-*`
- **Go**: `gosec`, `go vet`, `staticcheck`, plus `go test -race ./...` as a runtime check
- **General**: `compiler` warnings with `-Werror` / `RUSTFLAGS=-Dwarnings` in CI

## 24. Context-specific surfaces (when relevant)

Skip whichever sub-block doesn't apply to the project. These are deep enough that they deserve walking, but narrow enough that most reviews only touch one (or none).

### Mobile (iOS / Android)

- [ ] **Certificate pinning** on every TLS connection to your own backend (or the framework's built-in mechanism). Pin SPKI hashes, not full certs, so rotation doesn't brick the app. Plan for pin-failure recovery so a misissued cert isn't a brick.
- [ ] **Deep-link / universal-link validation** — `intent:` / `myapp://` / Universal Links / App Links. Sender / origin checked; URL parameters validated; no opening WebViews to attacker-supplied URLs without a same-origin check.
- [ ] **Exported components (Android)**: every `<activity>` / `<service>` / `<receiver>` / `<provider>` with `android:exported="true"` has a permission check or is genuinely intended to be public. `<provider>` with `exported=true` and no `permission` is a classic data-leak.
- [ ] **iOS URL schemes** registered for `LSApplicationQueriesSchemes` validated; no unconstrained `openURL:` to user-supplied schemes.
- [ ] **Keychain / Keystore usage** — credentials in Keychain (iOS) / Keystore (Android) with appropriate access flags (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, `setUserAuthenticationRequired`), not in `UserDefaults` / `SharedPreferences`.
- [ ] **Jailbreak / root detection** is best-effort; assume any client check can be bypassed. Never rely on it for authorization decisions.
- [ ] **Backup exclusion** — secrets and sensitive caches excluded from iCloud / Google Drive backups.
- [ ] **WebView hardening** — `setJavaScriptEnabled(true)` only when needed; `setAllowFileAccess(false)`, `setAllowContentAccess(false)`, `setAllowUniversalAccessFromFileURLs(false)` on Android; iOS `WKWebView` not `UIWebView`; same-origin checks on `shouldOverrideUrlLoading`.
- [ ] **Inter-process communication**: bound services with explicit auth; intents with `setPackage(...)` to a specific recipient when sending sensitive payloads.

### Cloud IAM (when Terraform / CloudFormation / Pulumi is in the diff)

`checkov` catches most of this; the items below are the ones a senior reviewer still grep-spot-checks.

- [ ] **No `Action: "*"` paired with `Resource: "*"`** — even in `Deny` statements (denial chains have hit production). Use specific action prefixes.
- [ ] **Public S3 / GCS / Azure Blob** — `BlockPublicAcls`, `BlockPublicPolicy`, `IgnorePublicAcls`, `RestrictPublicBuckets` all `true` unless the bucket is *intentionally* public (and then it's a static-website bucket only, not a data bucket).
- [ ] **OIDC trust-policy wildcards** — `repo:*/*` in a GitHub Actions OIDC `sub` condition is the workflow-injection-via-third-party-PR pattern. Pin to `repo:org/repo:ref:refs/heads/main` or similar.
- [ ] **AssumeRole chains** — role A can assume role B can assume role C; ensure no privilege escalation along the chain (B should not be able to assume something A can't).
- [ ] **KMS key policies** — root account `*` actions only when intentional; key administrators distinct from key users; deletion protection on customer-managed keys.
- [ ] **Secrets Manager / Parameter Store IAM** — read access scoped per-secret, not `secretsmanager:GetSecretValue` + `Resource: "*"`.
- [ ] **VPC security groups** — no `0.0.0.0/0` on management ports (22, 3389, 5432, 6379, 27017, 9200, ...).
- [ ] **CloudTrail / Cloud Audit Logs** — enabled in every region, log-file validation on, log destination locked down, alerts on configuration changes to the trail itself.
- [ ] **GuardDuty / Security Command Center / Defender for Cloud** — enabled in every account / project / subscription, findings routed to incident queue not just an inbox.
- [ ] **Service Control Policies (AWS Org) / Org Policies (GCP)** — deny destructive actions (delete CloudTrail, disable Config, ...) at the org level, not just the account level.
- [ ] **Cross-account roles** — `ExternalId` required for third-party trust; principal pinned to specific account/role, not `*`.

---

## Bonus: project-specific patterns

Add patterns specific to your codebase here. Examples:

- "All money calculations use `Decimal`, never `float`."
- "Webhook handlers verify the HMAC signature before parsing the body."
- "Background jobs validate the user_id parameter against the calling session."
