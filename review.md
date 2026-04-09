# Code Review: PR #29388 — LDAP Filter Injection Fix (SCYLLADB-1309)

## Local/Remote Status

Local branch `ldap_escape_user` matches PR #29388 at `a047f737a3`.

## Summary

This change fixes LDAP filter injection (SCYLLADB-1309) in `ldap_role_manager::get_url()` by adding two-layer encoding (RFC 4515 filter escaping + URL percent-encoding) and startup validation that restricts `{USER}` to the filter component of LDAP URL templates. The fix is well-designed, correctly implemented, and accompanied by strong test coverage (9 new tests) and a documentation update. **(0 blockers, 2 warnings, 5 notes.)**

---

## Warnings

### W1. [Performance] `escape_filter_value` / `percent_encode_for_url` build `std::string` then copy to `sstring`

**`auth/ldap_role_manager.cc:47`**

Both encoding functions build a `std::string` intermediate, then return `sstring(escaped)` — creating a redundant copy.

> `escape_filter_value()` (line 60) and `percent_encode_for_url()` (line 91) both construct a `std::string`, populate it, then copy it into an `sstring` on return. This runs on every `query_granted` call (the per-authentication path). Building directly into `sstring` or using `std::move()` into an `sstring` constructor (if available) would avoid the copy. The practical impact is negligible since LDAP network I/O dominates this path, but it's a minor inefficiency in security-critical code that could be trivially fixed.

### W2. [Style] PR description contains duplicate `Fixes: SCYLLADB-1309`

**PR description**

The `Fixes: SCYLLADB-1309` trailer appears twice in the PR body — once after the technical summary and once after the compatibility note.

> Remove one of the two instances to keep the PR description clean. This doesn't affect automation (GitHub parses both), but it looks like an editing artifact.

---

## Notes

### N1. [Architecture] `validate_query_template()` throws synchronously from future-returning `start()`

**`auth/ldap_role_manager.cc:192`**

`start()` returns `future<>` but `validate_query_template()` throws synchronously rather than returning a failed future.

> This diverges from the idiomatic Seastar pattern. In practice, all current callers handle this correctly: `auth/service.cc` uses `co_await` (which wraps the expression in try-catch), and the test uses `BOOST_REQUIRE_EXCEPTION`. The existing `parse_url` call just below uses `make_exception_future` for its error path, making this a minor inconsistency within the same function.

### N2. [Style] Two validation error messages are nearly identical

**`auth/ldap_role_manager.cc:456`**

The error messages for "sentinel not found in filter" vs "sentinel found in filter AND another component" are almost indistinguishable.

> Lines 456-460 and 464-468 produce very similar "LDAP URL template places `{USER}` outside the filter component" messages for two different failure modes. A user seeing the error cannot tell which problem occurred. Consider making the second message mention that `{USER}` appears in multiple components.

### N3. [Tests] No direct coverage of backslash and NUL byte escaping

**`test/ldap/role_manager_test.cc`**

`escape_filter_value()` has `\` → `\5c` and `\0` → `\00` code paths that are exercised only by code inspection, not by any test.

> These share the same trivial switch-case pattern as the tested characters (`*`, `(`, `)`), and the integration tests prove the two-layer encoding pipeline works end-to-end, so this is a completeness observation rather than a coverage gap. The functions are in an anonymous namespace, so direct unit testing would require refactoring.

### N4. [Style] Minor typo in PR description: "severeness" → "severity"

**PR description**

The backport line reads "Due to severeness" — should be "Due to severity" or "Due to the severity of this issue."

### N5. [Documentation] Documentation update is well-aligned with code changes

**`docs/operating-scylla/security/ldap-authorization.rst`**

The `.. note::` block correctly documents the automatic escaping behavior, the `{USER}` filter-only restriction, and the startup rejection of invalid templates. No missing documentation identified.

---

## Commit Discipline

### C1. Test commit missing formal task reference footer

**Severity: WARNING**

The test commit `ecc3bcabd4` mentions SCYLLADB-1309 parenthetically in the body but lacks a formal `Refs SCYLLADB-1309` footer.

> Per project conventions, every commit should have a `Refs SCYLLADB-<number>` or `Fixes SCYLLADB-<number>` footer line. The issue number appears in the body text ("(SCYLLADB-1309)") but not as a structured trailer. Add `Refs SCYLLADB-1309` at the end of this commit message.

### C2. Fix commit bundles multiple concerns (acceptable)

**Severity: NOTE**

Commit `a047f737a3` includes the security fix, startup validation, `parse_url` signature change, additional tests, and documentation update.

> The `parse_url` signature change and the doc update could be separate commits. However, for a security fix where self-containedness and bisectability matter, keeping it as one commit is reasonable. The test-first ordering (commit 1 demonstrates the bug, commit 2 fixes it) is well executed.
