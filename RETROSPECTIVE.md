# Project Retrospective

## Overall: 7.5/10 — a strong senior-level portfolio project; not yet production-enterprise

The architecture instincts here are genuinely good. What separates it from "enterprise" is
operational maturity (delivery guarantees, observability, secrets) and a few missing core auth
features — not code quality.

## Scorecard

| Dimension | Score | Notes |
|---|---|---|
| Code structure & design | 9/10 | Clean package-by-feature, correct access modifiers, records, DTO separation |
| Domain/security modeling | 9/10 | `public_id` UUIDv7 vs internal PK, token hashing done right, pre-account-hijacking defense |
| Persistence & migrations | 8/10 | Liquibase, FKs, indexes, unique constraints all present and correct |
| Testing | 8/10 | Testcontainers integration + unit + slice tests; good coverage |
| Distributed systems / messaging | 5/10 | `AFTER_COMMIT` is right, but it's a dual-write with no outbox/retry/DLQ — messages can be lost |
| Observability | 2/10 | No actuator, no metrics, no tracing, no structured logging |
| Secrets & config | 3/10 | **Private signing key committed to the repo** |
| Auth feature completeness | 5/10 | No refresh/logout, no password reset, no rate limiting, no MFA, no roles |

## What's genuinely strong

- **`IdentityProvisioningService.claim()`** — the unverified-account pre-hijacking mitigation
  (discard local password, require provider-verified email to elevate trust) is real
  enterprise-grade security thinking, well-documented.
- **`public_id` (UUIDv7) as the external identifier** while keeping a `bigint` sequence PK
  internally — exactly right, and the JWT subject uses it.
- **Token hashing** (`EmailVerificationTokenService`): SHA-256 for high-entropy tokens with the
  doc comment explaining why *not* bcrypt — correct and shows you understand the distinction.
- **RS256 asymmetric signing**, stateless sessions, ordered filter chains, RFC 7807
  `ProblemDetail` errors, Liquibase with proper constraints.

## Gaps to close, prioritized

### P0 — do these before calling it production-ready

1. **Get the private key out of source control.** `src/main/resources/keys/private.pem` is
   committed. Externalize to env/mounted secret/vault, rotate it, and `git rm` it from history.
   This is the single biggest red flag.
2. **Kafka dual-write can silently lose email-verification messages.**
   `EmailVerificationEventPublisher` fires after commit and only logs on failure — if the broker
   is down, the user never gets verified. The enterprise fix is a **transactional outbox**
   (persist the event in the same DB tx, relay to Kafka with retry + DLQ). This is the most
   impactful distributed-systems upgrade.
3. **No rate limiting / brute-force protection** on `/api/v1/auth` (login), `/register`, or
   `/verify`. Add bucket4j or gateway-level throttling + account lockout.

### P1 — needed for a real auth product

4. **No refresh tokens, logout, or revocation.** `TokenService` issues a fixed 1-hour access
   token and that's it. Add refresh-token rotation + a revocation/denylist (or short access +
   refresh).
5. **No password-reset flow.** Core feature for any auth service; you already have the
   token-issue/hash infrastructure to reuse.
6. **No observability.** Add `spring-boot-starter-actuator` + Micrometer (health,
   readiness/liveness, metrics), tracing, and structured JSON logging. Also scrub PII — you're
   logging usernames/emails (`"User registered with username..."`).
7. **Hardcoded config in `TokenService`** — issuer `https://cakeslayer.dev` and `3600` expiry
   should be `@ConfigurationProperties`, like you already do nicely for
   `EmailVerificationTokenProperties`.

### P2 — polish / consistency

8. **Inconsistent login response contract.** Local login returns `{accessToken, username}`
   (`AuthResponse`); `OAuth2LoginSuccessHandler` returns `{token}`. Unify the shape.
9. **`email_verified` is nullable + boxed `Boolean`**, forcing defensive `Boolean.TRUE.equals(...)`.
   Make the column `NOT NULL DEFAULT false` and the field a primitive `boolean`.
10. **No optimistic locking (`@Version`)** on `User` — the `claim()` path mutates a user that
    concurrent flows could touch.
11. **Informal log messages** ("User verified successfully!:)") — fine for a hobby project, not
    for enterprise log hygiene.
12. **No roles/authorities in the JWT** — authorization is binary (authenticated or not). If RBAC
    is in scope, add a roles claim; if not, that's a legitimate scope decision.

## Verdict

As a **learning/portfolio project**, this is well above average — the security modeling in
particular is something many professional codebases get wrong. To call it "enterprise," the
decisive moves are: **outbox for reliable messaging, secrets out of the repo, rate limiting,
refresh/revocation, and observability.** Those five change it from "demonstrates the right ideas"
to "I'd trust this with real users."
