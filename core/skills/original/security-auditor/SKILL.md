---
name: security-auditor
description: Automated security scanning for code, configurations, dependencies, and infrastructure. Detects vulnerabilities (OWASP Top 10, CWE, CVEs), misconfigurations, secrets exposure, and provides remediation guidance with severity prioritization.
version: 2.0.0
author: Hermes Skills Team
license: MIT
platforms: [macos, linux, windows]
metadata:
  hermes:
    tags: [security, vulnerability-scanning, owasp, cve, devsecops, compliance]
    category: security
    related_skills: [code-review-pro, github-integration, utility-toolkit]
    config:
      - key: scan_depth
        description: "Scanning thoroughness (quick/standard/comprehensive)"
        default: "comprehensive"
        prompt: "How thorough should the security scan be?"
      - key: compliance_frameworks
        description: "Compliance standards to check against"
        default: "[owasp-top10, soc2, gdpr, pci-dss]"
        prompt: "Which compliance frameworks to validate?"
---

# Security Auditor Skill

Comprehensive security analysis engine that transforms your codebase into a hardened fortress by identifying vulnerabilities before attackers do.

## When to Use

Trigger this skill for any security-related task:
- **Pre-deployment Scan**: "Security audit before we ship this"
- **Vulnerability Assessment**: "Find all security issues in this codebase"
- **Dependency Check**: "Are my dependencies safe? Any known CVEs?"
- **Secrets Detection**: "Did anyone commit passwords or API keys?"
- **Configuration Review**: "Is this server/config secure?"
- **Compliance Check**: "Does this meet OWASP/SOC2/GDPR requirements?"
- **Incident Response**: "We had a breach, find how it happened"

## Quick Reference

| Scan Type | Command | Coverage |
|----------|---------|----------|
| Full Audit | `/security audit [path]` | Everything below |
| Code Vulnerabilities | `/security code-scan` | OWASP Top 10, CWE |
| Secrets Detection | `/security secrets` | Keys, tokens, passwords |
| Dependency Scan | `/security deps` | Known CVEs in libraries |
| Config Review | `/security configs` | Hardening, misconfigurations |
| Compliance | `/security compliance [framework]` | Standards alignment |

## Procedure

### Phase 1: Reconnaissance (2-3 minutes)

1. **Map the Attack Surface**
   ```
   Identify all entry points and assets:
   
   🎯 Attack Vectors to Map:
   - Web endpoints (API routes, controllers, views)
   - Authentication mechanisms (login, OAuth, sessions)
   - Database interactions (queries, ORMs, raw SQL)
   - File operations (uploads, downloads, temp files)
   - External integrations (API calls, webhooks)
   - User input acceptance (forms, headers, params)
   - Background jobs (cron, queues, workers)
   - Infrastructure (containers, cloud configs, CI/CD)
   
   📦 Assets to Inventory:
   - Source code files (.py/.js/.go/.rs/.java etc.)
   - Configuration files (.env, .yaml, .json, .conf)
   - Dependency manifests (requirements.txt, package.json, go.mod)
   - Infrastructure as Code (Dockerfile, Terraform, K8s manifests)
   - Build/deploy scripts (CI pipelines, Makefiles)
   ```

2. **Classify Sensitivity**
   
   ```
   Data Classification:
   🔴 HIGHLY SENSITIVE:
   - PII (names, emails, SSN, phone numbers)
   - Credentials (passwords, API keys, tokens)
   - Financial data (credit cards, bank accounts)
   - Health information (HIPAA if applicable)
   
   🟡 MEDIUM SENSITIVITY:
   - Business logic/algorithms
   - Internal system details
   - User preferences/settings
   - Analytics data
   
   🟢 LOW SENSITIVITY:
   - Public content
   - Cached/aggregated data
   - Open source components
   ```

### Phase 2: Vulnerability Scanning (5-10 minutes)

3. **Application Layer Scanning (OWASP Top 10 Focus)**
   
   ```markdown
   ## 🔍 OWASP Top 10 (2021) Checklist
   
   ### A01:2021 – Broken Access Control
   - [ ] Horizontal privilege escalation (accessing other users' data)?
   - [ ] Vertical privilege escalation (regular user → admin)?
   - [ ] IDOR (Insecure Direct Object References)? Can I manipulate IDs?
   - [ ] Bypassing access control via URL manipulation / parameter tampering?
   - [ ] CORS misconfiguration allowing unauthorized domains?
   - [ ] Missing authentication on sensitive endpoints?
   
   **Test Method:**
   1. Try accessing /admin, /api/admin, /dashboard without auth
   2. Change user_id parameter from own ID to another user's
   3. Modify HTTP method (POST → GET on state-changing endpoints)
   4. Add ?admin=true or role=admin parameters
   
   ---
   
   ### A02:2021 – Cryptographic Failures
   - [ ] Using outdated/hashed algorithms (MD5, SHA1 for passwords)?
   - [ ] Weak cipher suites (TLS 1.0, 1.1, null ciphers)?
   - [ ] Hardcoded encryption keys in source code?
   - [ ] Improper key management (keys in env vars, committed to git)?
   - [ ] Missing encryption for sensitive data at rest?
   - [ ] Using insecure random number generators?
   - [ ] IV/nonce reuse in cryptographic operations?
   
   **Check Locations:**
   - Search for: `md5(`, `sha1(`, `encrypt(`, `password`
   - Check TLS configurations (nginx/apache/app settings)
   - Review crypto library usage patterns
   
   ---
   
   ### A03:2021 – Injection
   #### SQL Injection:
   - [ ] String concatenation in queries?
   - [ ] Raw query builders without sanitization?
   - [ ] ORM raw() or execute() with user input?
   - [ ] Stored procedures with dynamic SQL inside?
   
   **Pattern to Find:**
   ```python
   # ❌ Dangerous
   f"SELECT * FROM users WHERE id = {user_id}"
   "SELECT * FROM users WHERE name = '" + name + "'"
   cursor.execute("UPDATE users SET x = %s" % (user_input,))
   
   # ✅ Safe
   cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
   session.query(User).filter(User.id == user_id).first()
   ```
   
   #### NoSQL Injection:
   - [ ] MongoDB $where, $regex with user input?
   - [ ] Elasticsearch query_string with unsanitized input?
   
   #### Command Injection:
   - [ ] os.system(), subprocess.call(shell=True) with user input?
   - [ ] exec(), eval() on user-provided strings?
   - [ ] Template engines (Jinja2, ERB) with user-controlled templates?
   
   #### LDAP/XPath/Header Injection:
   - [ ] LDAP filters constructed from input?
   - [ ] XPath queries with concatenation?
   - [ ] HTTP headers set from user input without validation?
   
   ---
   
   ### A04:2021 – Insecure Design
   - [ ] Business logic flaws (can I bypass limits, get free stuff)?
   - [ ] Race conditions (TOCTOU - time of check to time of use)?
   - [ ] Missing rate limiting on sensitive operations?
   - [ ] Trusting client-side validation only?
   - [ ] Insecure workflow (multi-step process can be skipped)?
   - [ ] Default credentials still active?
   - [ ] Debug/prod mode not properly separated?
   
   ---
   
   ### A05:2021 – Security Misconfiguration
   - [ ] Default accounts/passwords enabled?
   - [ ] Error messages revealing stack traces/details?
   - [ ] Directory listing enabled?
   - [ ] Unnecessary features/services running?
   - [ ] Outdated software versions?
   - [ ] Permissions too loose (777, world-writable)?
   - [ ] Cloud metadata endpoints accessible (169.254.169.254)?
   - [ ] Admin interfaces exposed to internet?
   - [ ] CORS set to * (wildcard)?
   - [ ] Missing security headers (CSP, X-Frame-Options, HSTS)?
   
   **Quick Checks:**
   - Visit /.git/, /.env, /server-status, /actuator
   - Check response headers for security headers
   - Look for debug=True, DEBUG=1 in configs
   - Test robots.txt for disallowed paths that exist
   
   ---
   
   ### A06:2021 – Vulnerable & Outdated Components
   - [ ] Dependencies with known CVEs? (Run dependency scanner)
   - [ ] Using EOL (End of Life) frameworks/versions?
   - [ ] Unmaintained libraries in dependency tree?
   - [ ] Components missing security patches?
   
   **Action Required:**
   - Run: `npm audit`, `pip-audit`, `snyk test`, `dependabot`
   - Check: GitHub Advisory Database, Snyk, Depfu alerts
   
   ---
   
   ### A07:2021 – Identification & Authentication Failures
   - [ ] Weak password policy (allows "password", "123456")?
   - [ ] Brute force protection absent (no rate limiting, CAPTCHA)?
   - [ ] Session fixation possible?
   - [ ] Session timeout too long or non-existent?
   - [ ] Cookies missing Secure/HttpOnly/SameSite flags?
   - [ ] Multi-factor authentication unavailable for sensitive ops?
   - [ ] Password reset flows vulnerable (token prediction, host header injection)?
   - [ ] User enumeration possible (different error messages for existing vs non-existing users)?
   
   ---
   
   ### A08:2021 – Software & Data Integrity Failures
   - [ ] Deserialization of untrusted data?
   - [ ] Unsigned/unsigned firmware/software updates?
   - [ ] CI/CD pipeline compromised (injection into build process)?
   - [ ] Integrity checks missing on critical data (hash verification)?
   
   ---
   
   ### A09:2021 – Security Logging & Monitoring Failures
   - [ ] Login failures not logged?
   - [ ] Admin actions not audited?
   - [ ] Logs don't contain enough context (who, what, when, from where)?
   - [ ] Log injection possible (user input in logs without sanitization)?
   - [ ] No alerting on suspicious activity patterns?
   - [ ] Logs stored insecurely (world-readable)?
   - [ ] Log retention policy undefined/too short/too long?
   
   ---
   
   ### A10:2021 – Server-Side Request Forgery (SSRF)
   - [ ] User-supplied URLs fetched server-side?
   - [ ] URL whitelist/scheme restrictions absent?
   - [ ] Internal network accessible via SSRF (cloud metadata, internal APIs)?
   - [ ] Redirects based on user input without validation?
   - [ ] Webhooks receiving unvalidated URLs?
   
   **SSRF Test Cases:**
   - Try: url=http://169.254.169.254/latest/meta-data/
   - Try: url=file:///etc/passwd
   - Try: url=http://internal-service:8080/admin
   ```

4. **Secrets & Credential Exposure Scan**
   
   ```markdown
   ## 🔑 Secrets Detection Patterns
   
   ### High-Confidence Patterns (Almost Certainly Credentials):
   
   **API Keys & Tokens:**
   - `sk_live_` / `sk_test_` → Stripe keys
   - `ghp_` / `github_pat_` → GitHub tokens
   - `AKIA` + 16 char base64 → AWS keys
   - `AIza` → Google API keys
   - `xoxb-` / `xoxp-` → Slack tokens
   - `-----BEGIN.*PRIVATE KEY-----` → Private keys
   - `client_secret` = `"..."` → OAuth secrets
   
   **Passwords:**
   - `password` = `"..."` (explicit assignment)
   - `passwd` = `"..."`
   - `pwd` = `"..."`
   - `DB_PASSWORD` / `DATABASE_URL` with value
   
   **Connection Strings:**
   - `mongodb://user:pass@host`
   - `postgres://user:pass@`
   - `mysql://root:`
   - `redis://:` (with password in URL)
   
   **Scan These Locations:**
   - ✅ Environment files (.env, .env.local, .env.production)
   - ✅ Config files (settings.py, app.config, application.yml)
   - ✅ Docker compose files (docker-compose.yml)
   - ✅ CI/CD configs (.github/workflows/*.yml, Jenkinsfile)
   - ✅ Documentation (README.md with "replace this" examples)
   - ✅ Git history (git log -p for added secrets)
   - ✅ Comments (# TODO: remove password before commit)
   
   **Tools to Use:**
   - `git-secrets` (pre-commit hook)
   - `truffleHog` (scan git history)
   - `detect-secrets` (Yelp's tool)
   - `gitleaks` (comprehensive secret scanner)
   ```

5. **Infrastructure & Configuration Security**
   
   ```markdown
   ## ☸️ Container & Cloud Security
   
   ### Docker/Kubernetes:
   - [ ] Containers running as root? (USER directive missing)
   - [ ] Sensitive mounts (/var/run/docker.sock)?
   - [ ] Resource limits unset (memory/CPU DoS risk)?
   - [ ] Image using `latest` tag (unreproducible)?
   - [ ] Secrets in environment variables vs Kubernetes secrets?
   - [ ] Network policies defined? (default allow-all?)
   - [ ] Pod Security Standards enforced?
   - [ ] RBAC overly permissive (cluster-admin bound to service account)?
   
   ### Cloud-Specific (AWS/GCP/Azure):
   - [ ] S3 buckets public? (Block Public Access disabled?)
   - [ ] IAM policies least-privilege? (Not using * wildcard?)
   - [ ] Encryption at rest enabled for storage services?
   - [ ] Logging/monitoring configured?
   - [ ] VPC/security groups properly restricted?
   - [ ] Metadata endpoint locked down (IMDSv2 required)?
   - [ ] Unencrypted EBS volumes?
   
   ### CI/CD Pipeline Security:
   - [ ] Pipelines injecting secrets safely (not in logs)?
   - [ ] Third-party actions/repos pinned to SHA (not just tag)?
   - [ ] Artifact signing/verification?
   - [ ] Production deployments require approval?
   - [ ] Separate deploy keys per environment?
   - [ ] Branch protection rules enforced on main/master?
   ```

### Phase 3: Risk Assessment & Prioritization (2-3 minutes)

6. **Calculate Risk Scores**
   
   For each finding, compute:
   
   ```
   Risk Score = Likelihood × Impact × Reachability
   
   Where:
   
   LIKELIHOOD (1-5):
   1 = Very unlikely (requires multiple coincidences)
   2 = Unlikely (specific conditions needed)
   3 = Possible (common mistake pattern)
   4 = Likely (easy to exploit, common attack)
   5 = Almost Certain (trivially exploitable)
   
   IMPACT (1-5):
   1 = Minimal (information disclosure, inconvenience)
   2 = Low (single user affected, minor data)
   3 = Moderate (many users, sensitive data)
   4 = High (system compromise, major data breach)
   5 = Critical (complete takeover, massive breach, regulatory fines)
   
   REACHABILITY (0.5-1.5 multiplier):
   0.5 = Requires internal access / physical proximity
   0.75 = Requires authenticated user
   1.0 = Internet-facing, no auth needed
   1.5 = Actively exposed (listed in search engines, linked publicly)
   
   SEVERITY CLASSIFICATION:
   🔴 CRITICAL (Score ≥ 15): Fix immediately, block deployment
   🟠 HIGH (10-14): Fix within 24-48 hours
   🟡 MEDIUM (5-9): Fix within 1-2 sprints
   🟢 LOW (1-4): Fix when convenient, backlog it
   ℹ️ INFO (0): Best practice suggestion, no immediate action
   ```

7. **Generate Remediation Roadmap**
   
   ```markdown
   ## 🛡️ Remediation Plan
   
   ### Immediate Actions (Next 24 Hours)
   
   | Issue | Severity | Effort | Owner | Status |
   |-------|----------|--------|-------|--------|
   | SQL Injection in auth module | 🔴 Critical | 2h | @security-team | TODO |
   | Exposed .env file in repo | 🔴 Critical | 30m | @devops | TODO |
   | Missing auth on /api/admin | 🟠 High | 1h | @backend | TODO |
   
   ### Short-Term (This Sprint)
   - [ ] Implement parameterized queries across codebase
   - [ ] Add rate limiting to login endpoint
   - [ ] Enable CSP headers
   - [ ] Rotate all exposed credentials
   - [ ] Set up secrets scanning in CI pipeline
   
   ### Medium-Term (Next Month)
   - [ ] Security training for development team
   - [ ] Penetration testing engagement
   - [ ] Implement WAF rules for common attacks
   - [ ] Set up dependency vulnerability automation
   - [ ] Create security playbook for incident response
   
   ### Long-Term (Ongoing)
   - [ ] Quarterly security audits
   - [ ] Bug bounty program consideration
   - [ ] SOC2 / ISO 27001 certification path
   - [ ] Threat modeling for new features
   - [ ] Security champions program in engineering
   ```

### Phase 4: Report Generation (2-3 minutes)

8. **Produce Executive Summary**
   
   ```markdown
   # 🔒 Security Audit Report
   
   **Project:** [Name]  
   **Date:** [timestamp]  
   **Auditor:** Hermes Security Auditor v2.0  
   **Scope:** [N] files scanned, [N] lines of code
   
   ---
   
   ## 📊 Executive Summary
   
   **Overall Security Posture:** 🔴 Poor / 🟡 Fair / 🟢 Good / 💚 Excellent
   
   **Critical Findings:** [N] (must fix immediately)  
   **High Severity:** [N] (fix this week)  
   **Medium Severity:** [N] (fix this month)  
   **Low Severity:** [N] (backlog)
   
   **Top Risks:**
   1. [Risk 1] - Potential impact: [description]
   2. [Risk 2] - Potential impact: [description]
   3. [Risk 3] - Potential impact: [description]
   
   **Estimated Remediation Effort:** [X] developer-days
   
   **Compliance Status:**
   - OWASP Top 10: [X]/10 categories addressed
   - GDPR: [Compliant/Partial Gaps/Major Issues]
   - SOC2: [Compliant/Partial Gaps/Major Issues]
   
   ---
   
   ## 🚨 Critical Findings (Fix Immediately)
   
   [Detailed findings table with location, description, PoC, fix]
   
   ---
   
   ## Detailed Findings
   
   [Full report organized by category/severity with code examples]
   
   ---
   
   ## ✅ Positive Security Observations
   
   What you're doing well:
   - [Good practice 1]
   - [Good practice 2]
   
   ---
   
   ## 📈 Trend Analysis (if historical data available)
   
   [Compare with previous scans: improving/regressing/stable]
   
   ---
   
   ## 🎯 Recommendations Priority Matrix
   
   | Recommendation | Impact | Effort | Quick Win? |
   |---------------|--------|--------|------------|
   | [Rec 1] | High | Low | ✅ Yes |
   | [Rec 2] | High | High | ❌ No |
   ```

## Output Templates

### Template A: Finding Report (Individual Issue)
```markdown
## 🔴 [ID]: [Vulnerability Name]

**Location:** `[file_path]:L[line_number]`  
**Category:** Injection / Crypto / Access Control / etc.  
**OWASP:** A03:2021 (Injection)  
**CWE:** CWE-89 (SQL Injection)  
**Severity:** 🔴 Critical (Score: 20/25)  

### Description  
[Clear explanation of the vulnerability]

### Proof of Concept  
```bash
# Demonstrate the issue (safe example)
curl -X POST https://target/api/login \
  -d '{"username": "admin'--", "password": "anything"}'
# Result: Authenticated as admin without valid password
```

### Affected Code  
```python
# Vulnerable line(s)
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # L42
    return db.execute(query).fetchone()
```

### Remediation  
```python
# Fixed version
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = %s"
    return db.execute(query, (user_id,)).fetchone()  # Parameterized!
```

### Verification  
- [ ] Apply fix
- [ ] Re-run scan to confirm resolved
- [ ] Add test case preventing regression
- [ ] Check for similar patterns elsewhere

**References:**  
- OWASP: https://owasp.org/www-project-web-security-testing/  
- CWE: https://cwe.mitre.org/data/definitions/89.html  
- Example Breach: [Real-world incident if applicable]
```

### Template CISO Dashboard (for executives)
```markdown
## 📊 Security Dashboard (Executive Briefing)

**Date Range:** [start] to [end]  
**Scan Coverage:** [X]% of codebase  

---

### Risk Exposure Overview  
```
Total Findings: [N]
├── 🔴 Critical: [N]  ([%]%)
├── 🟠 High:     [N]  ([%]%)
├── 🟡 Medium:  [N]  ([%]%)
└── 🟢 Low:     [N]  ([%]%)
```

### Top 5 Risks Requiring Attention  
1. ⚠️ [Risk name] - Business impact: $[estimated cost if exploited]
2. ⚠️ [Risk name] - Regulatory implication: [GDPR fine up to €20M?]
3. ...

### Remediation Progress  
- **This Week Fixed:** [N] issues  
- **Remaining Critical:** [N]  
- **Mean Time to Fix:** [X] days (target: < 7 days for critical)  

### Compliance Scorecard  
| Framework | Status | Gap Count |
|-----------|--------|-----------|
| OWASP Top 10 | 🟢 Pass / 🟡 Partial / 🔴 Fail | [N] |
| SOC2 TSC | ... | ... |
| GDPR Art. 32 | ... | ... |

### Budget Impact Estimate  
- **Immediate fixes needed:** $[X] (effort)  
- **Potential breach cost avoided:** $[Y] (based on industry averages)  
- **ROI on security investment:** [Z]%
```

## Integration Notes

**Works synergistically with:**
- **Code Review Pro**: Deep-dive into specific vulnerabilities found
- **GitHub Integration**: Auto-scan PRs, block merge on critical issues
- **Utility Toolkit**: Run automated scanners (bandit, semgrep, safety)
- **Capability Evolver**: Learn project's security patterns over time

**Automated Integration:**
```
Developer pushes code
    ↓
CI Pipeline triggers
    ↓
Security Auditor scans:
  ├── Dependencies (vulnerabilities)
  ├── Secrets detection (credentials)
  ├── Static analysis (SAST patterns)
  └── Config review (hardening)
    ↓
Results:
  ├── Critical → Block merge, alert security team
  ├── High → Comment on PR, require acknowledgment
  ├── Medium/Low → Track in backlog, address in sprint
    ↓
Dashboard updated, metrics collected
```

## Pitfalls & Best Practices

### ❌ Common Auditor Mistakes:

**False Positives Overload**
- Problem: Too many low-priority findings dilute important ones
- Solution: Tune scanner rules, focus on high-confidence issues first

**Context Blindness**
- Problem: Flagging patterns without understanding business justification
- Solution: Always ask "is this actually exploitable in our context?"

**Fear-Mongering**
- Problem: Presenting risks in terrifying way without balanced perspective
- Solution: Provide likelihood estimates, show real-world exploitation difficulty

**Scanner Reliance Only**
- Problem: Only running automated tools, no manual thinking
- Solution: Tools find ~70% of issues; human creativity finds the rest

**Neglecting Defense in Depth**
- Problem: Focusing on single fix rather than layered approach
- Solution: Recommend defense layers (WAF + input validation + output encoding)

### ✅ Best Practices:

**Risk-Based Prioritization**
- Not all vulnerabilities are equal; focus on what matters most
- Consider: exploitability, asset value, threat actor capability

**Constructive Reporting**
- Don't just say "this is broken"; explain why and exactly how to fix
- Provide code examples, links to documentation, step-by-step guides

**Continuous Scanning**
- One-time scan is a snapshot; threats evolve daily
- Integrate into CI/CD pipeline for continuous protection

**Collaborative Approach**
- Work with developers, not against them
- Explain trade-offs (sometimes risk is accepted deliberately)
- Celebrate security wins, not just criticize failures

## Verification Checklist

Before finalizing any security assessment:
- [ ] Scan completed on latest code (not stale branch)
- [ ] All high/critical findings have clear remediation steps
- [ ] False positives documented and filtered
- [ ] Risk scores calculated consistently
- [ ] Report reviewed for accuracy (no hallucinated vulns)
- [ ] Remediation suggestions tested (won't break existing functionality)
- [ ] Compliance mappings accurate to actual standard requirements
- [ ] Executive summary actionable (not just scary)
- [ ] Follow-up plan defined (when to re-scan)

---

*Enterprise-grade security auditing powered by Hermes AI, aligned with OWASP ASVS v4.0 standards*
