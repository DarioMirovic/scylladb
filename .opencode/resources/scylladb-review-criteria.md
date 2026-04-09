# ScyllaDB Review Criteria

Reference material for review subagents. Each subagent reads only the sections relevant to its focus area.

## A.1 Performance (Critical for ScyllaDB)

This is a database engine. Performance is not optional.

**Hot path analysis:**
- Is the modified code on a hot path (request processing, read/write path, compaction, memtable flush, CQL parsing/execution, connection handling)? If so, apply heightened scrutiny.
- Does it introduce unnecessary complexity or indirection that could slow things down?

**Seastar futures and coroutines:**
- If a function always returns a ready future (the common/fast path is synchronous), does it use `make_ready_future<>()` and avoid `co_await` / continuation overhead? Unnecessary coroutine frames or continuation scheduling on the reactor's task queue is a real cost.
- If it IS a coroutine on a hot path, be very careful about:
  - **Exception throwing**: exceptions in coroutines are expensive. Watch for two categories:
    - **Expected exceptions** (part of normal logic flow — e.g., wrong protocol version during connection storm, validation failures that happen regularly): prime candidates for refactoring to avoid the throw. Patterns like `result_with_exception<T>` or returning error codes/`std::optional`/`std::expected` can yield significant improvements.
    - **Unexpected exceptions** (truly exceptional conditions — e.g., a buffer verification that is almost never wrong): throwing is acceptable here.
  - **Coroutine exception avoidance pattern**: when a coroutine receives a `future<T>` from elsewhere, watch for calling `.get()` on a potentially failed future (which throws). Instead, check `.failed()` first and return the exception via `coroutine::exception` without throwing.
  - **Exception wrapping overhead**: watch for `futurize_invoke` and similar wrappers that add exception handling layers on hot paths.
- Are continuations (`.then()`, `.finally()`, `.handle_exception()`) used where a simpler coroutine or direct return would suffice? Conversely, are coroutines used where a simple continuation chain would be clearer?
- Is there a `co_await coroutine::maybe_yield()` or `need_preempt()` check in computational loops? Loops without preemption checks will stall the reactor.

**Memory allocation:**
- Dynamic memory allocation on a hot path? Can it be avoided with stack allocation, pre-allocated buffers, `small_vector`, or `chunked_vector`?
- `chunked_vector` is preferred over `std::vector` for large or growing collections.
- Watch for hidden allocations: lambda captures by value of large objects, `std::function` (type-erased, allocates), unnecessary copies.

**Smart pointer hierarchy:**
- `std::shared_ptr` — avoid on hot paths; heavyweight (thread-safe refcount).
- `seastar::shared_ptr` — lighter, use when shared ownership is needed.
- `seastar::lw_shared_ptr` — lightest; preferred within a single shard.
- `seastar::foreign_ptr` — for cross-shard ownership transfer.
- Flag `std::shared_ptr` where `lw_shared_ptr` would suffice. Flag missing `foreign_ptr` for cross-shard transfers.

**Continuation lifetime safety:**
- **Never capture references or pointers to local variables in continuations.** The enclosing scope's locals may be destroyed by the time the continuation runs.
- Must **move** or **copy** into the lambda capture.
- Common anti-pattern: `auto& ref = local_var; return do_something().then([&ref] { use(ref); });` — `ref` dangles.
- This does NOT apply to coroutines (frame keeps locals alive). It DOES apply to `.then()` / continuation chains, even inside a coroutine body.

**Other:**
- Quadratic (or worse) behavior on user-controlled inputs.
- N+1 patterns or unbounded iteration.
- Unnecessary `std::move()` on trivially-copyable types, or missing `std::move()` where it matters.

## A.2 Concurrency and Seastar Architecture

- **Shard-per-core**: any shared mutable state between shards? Cross-shard access must go through `smp::submit_to()` or `foreign_ptr`.
- Does new concurrent code have bounded concurrency?
- If a component does background work, does it have a `stop()` or `close()` method to drain?
- Are scheduling groups respected?
- **Backpressure asymmetry**: bounded request queue with unbounded response accumulation creates memory pressure. Check if backpressure propagates in both directions.

## A.3 Comments (C++ code comments)

**Be very strict about comment quality. Prevent LLM-style over-commenting.**

- Flag unnecessary comments that just restate the code. `// increment counter` above `++counter` is noise.
- Flag overly verbose comments. A 10-line comment explaining a 3-line function is usually wrong.
- Detailed explanation is fine for genuinely complex logic.
- For public API doc comments: check if other functions at the same API layer have them. Match the existing convention.

## A.4 Commit Discipline

**Format** — each commit message must follow:
```
<module>: <optional_submodule_or_file>: <short imperative description>

<body: motivation, what changed, why>

Refs SCYLLADB-<number>
```

- The module is typically a directory name: `cql3`, `sstables`, `raft`, `test`, `docs`, etc.
- Avoid generic titles like "sstables: fix the bug" — be specific.
- Try to limit lines to 72 chars width.
- Body must be self-contained — no references to out-of-band discussions.
- Each commit must have a **motivation**. The inverse patch test: if "make X not do Y" sounds equally valid, the motivation is missing.
- **Current behavior description**: good commit messages describe what happens now and why it's problematic, then explain the new approach. Gentle nudge if missing, not rigid enforcement.

**Task references:**
- Every commit should have `Refs SCYLLADB-<number>` or `Fixes SCYLLADB-<number>`.
- At least one commit should use `Fixes` if the PR resolves the issue.
- Flag missing task references unless the user explicitly skips this check.

**Commit organization:**
- Each commit should be self-contained and do one thing.
- Each commit should individually compile and be correct.
- Watch for regression test ordered before fix, or method used before the commit that introduces it.
- **Formatting/indentation changes should be in separate commits** (for non-Python files). If a commit touches existing code and needs to reindent or reformat it, the formatting change should be a separate commit from the functional change. This makes the functional diff reviewable without formatting noise. Do NOT suggest squashing formatting commits into their parent — separate formatting commits are the project convention.

## A.5 Security

- User input (CQL query, REST API, Alternator request) validated and sanitized?
- Buffer overflow: out-of-bounds access, unchecked buffer sizes, `memcpy`/`memmove` with incorrect lengths.
- Use-after-free, dangling references, double-free.
- Unsafe casts, especially `reinterpret_cast` or C-style casts.
- Use judgement — don't flag obviously safe patterns.

## A.6 Documentation

- Does any commit change documented functionality? Does `docs/` need updating?
- Is there something genuinely new that should be documented?
- Does old documentation need removal?

## A.7 Architecture and Code Quality

- Is this the **optimal solution**, or just "a solution"?
- Does the code follow existing ScyllaDB patterns? Is there an existing abstraction it should use?
- Are names descriptive? (Industry-standard abbreviations like `cql`, `sstable`, `rpc` are fine.)
- Templates vs type erasure: prefer type erasure in non-performance-sensitive code. Template parameters should be constrained by C++ concepts.
- Avoid singletons that create initialization-order confusion.

**Invariant checking** (three tiers):
- **assert**: critical to system stability — broken = data corruption.
- **throw**: needed by specific features — system can shut down cleanly.
- **log**: operations that can be silently ignored.

## A.8 PR-Level Checks (when a GitHub PR is provided)

**Unresolved review comments:**
- For each unresolved comment, report: who, what file/line, whether **addressed** / **partially addressed** / **not addressed**, and a brief explanation.
- If the user asks for suggested responses, provide them.

**PR description / cover letter:**
- Clear and well-motivated?
- Has `Fixes SCYLLADB-<number>` or `Refs SCYLLADB-<number>`? If any commit has `Fixes`, the PR should too.
- Backport explanation?
- **Version notes**: check for version history on multi-push PRs.

**JIRA issue relevance:**
- Do the changes actually relate to the referenced issue? Only flag if genuinely suspicious.

## A.8b Testing

**Coverage analysis:**
- What test cases does the change need? Are existing tests sufficient? Do existing tests need updating?
- Bug fix → regression test that fails before the fix and passes after?
- New generic code → test all aspects, not just the ones used by this patchset?
- **Representative coverage, not exhaustive enumeration**: test each unique code path, not every input value that shares the same path. Use judgement.

**Test location appropriateness:**
- `test/boost` — C++ unit tests, single-node, fast.
- `test/cqlpy` — Python-based CQL tests, single-node.
- `test/cluster` — multi-node cluster tests, heavier.
- **Use the lightest framework that adequately tests the functionality.**

**Test migration patterns:**
- **External scylla-dtest → `test/cluster/dtest`**: copy unchanged + disable → refactor → enable. Flag if modified and enabled in the same commit as the copy.
- **`test/cluster/dtest` → `test/cluster`**: similar staged approach. No commit should leave the test in neither suite.

## A.9 Code Style (Seastar/ScyllaDB conventions)

- 4-space indent, no tabs, 160-column limit.
- `snake_case` for everything.
- Private members prefixed with `_`.
- Braces on all scoped blocks, even single-line `if`.
- Opening brace on same line as statement.
- Namespace bodies not indented.
- `#include <seastar/...>` with angle brackets; `#include "..."` with relative paths for Scylla.
- `noexcept` on move constructors, move assignment, and simple accessors.
- Generic lambdas (`auto` params) discouraged where the type is known.
- `std::move()` used correctly.

## A.10 Before You Flag Something

**Be certain.** This is a sophisticated C++23 codebase. Before calling something a bug:

- Only review the changes — do not review pre-existing code that wasn't modified.
- Don't flag something as a bug if you're unsure. Investigate first: read the full file, check callers, check the type hierarchy.
- Don't invent hypothetical problems. If an edge case matters, describe the realistic scenario.
- Don't be a zealot about style. Verify the code actually violates the convention.
- Pointer dereferencing that is clearly safe in context does not need flagging.
- Use the Explore agent to find how existing code handles similar patterns before claiming something doesn't fit.
