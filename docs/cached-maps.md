# Cached maps and controlled fork

Use `MapsCache::capture()` while the host holds a stability window over the
relevant images and page permissions. `import_text(data, length)` accepts a full
maps snapshot saved by the host. Both own the parsed mapping data. The host
asserts that imported addresses belong to this process or its controlled parent
and still describe the relevant mappings. Parsing checks structure and bounds.
Input and materialized mapping/page data each have a 64 MiB logical limit and at most
1,048,576 mapping records are accepted.

Pass the cache explicitly to `hook_batch_cached`, `hook_imports_cached`, or
`hook_function_imports_cached`. Named variants bind the system path, and
`hook_batch_nonnull_named_cached` requires nonzero originals. These entry points
accept optional slot reports and operation diagnostics. `unhook_cached` and
`query_cached` use the same cache. A batch of one covers a single import.
System-image operations retain linker identity/path validation. Custom images
retain their unique instance-token and stable-mapping requirements.

`HookSession` and `FunctionHookSession` expose `install_cached` and
`unhook_cached`. RuleSet exposes cached refresh, loader notifications, image
release, rule removal and unhook, including report overloads. Refresh validates
retained bindings with the supplied cache. Every cached operation uses zero
maps reads, including failures. Missing coverage is an error.

## Permission lifetime

Serialize access to a cache, including capture, import, invalidation, moves and
destruction. Keep relevant mappings stable through their last cached access.
Coordinate other permission writers with this library. A page with a live
cache binding accepts the same cache for further operations. Different caches
can operate on disjoint pages. Live operations still read maps and update the
associated bookkeeping. A conflicting observation invalidates the cached page.

The registry retains cache state for live bindings. C cache destruction fails
while those bindings exist. C++ destruction releases the wrapper and performs
no implicit unhook. Retain the wrapper through cached recovery.

Capture and import explicitly replace the snapshot. Failure preserves the
previous snapshot. Active pages must remain covered. Clean pages adopt the new
baseline. Outstanding permission-restoration targets survive replacement,
and pages with restoration obligations outside this cache are marked unusable
until those obligations are resolved and the cache is explicitly refreshed.
Conflicting protections reject replacement. Before an external permission
or mapping change, call `invalidate()` and complete recovery using a fresh
snapshot or the live APIs. Abandonment with page residue and image invalidation
invalidate the affected cached pages.

An incomplete cached transaction retains its handle and permission obligations.
Retry with `unhook_cached`. The implementation repairs unknown residual
protections before accessing slots, after all page validation and allocations.
A slot already holding its original value still requires page restoration.
Cached recovery confirms residual targets with successful `mprotect`, including
when a refreshed snapshot reports the target protection.
Third-party slot values produce conflicts and remain untouched.

## Controlled fork

The host first drains all library calls, callbacks and object access. Call
`prepare_fork()` to initialize the registry, page size and C object store and
check that recovery is complete. Keep this quiet window until the appropriate
completion call. Library locks are released before fork.

After fork, the parent calls `after_fork_parent()`, including when fork fails.
The child completes its host allocator, loader and C++ runtime coordination,
then calls `after_fork_child()` before invoking the library. This is a host
integration contract for controlled Android/runtime call sites. The general
restriction on calls after a multithreaded fork before exec still applies
outside this protocol. [Linux fork contract](https://man7.org/linux/man-pages/man2/fork.2.html)

The child inherits existing handles and C object tokens, with independent
process-local ownership. It can restore a parent's clean installed hook with
`unhook_cached`. A plain installed handle can first bind to a cache during
restoration. An untracked indeterminate handle requires live recovery first.
The host coordinates each library copy separately. Repeated preparation,
incorrect completion calls and unacknowledged PID changes are rejected before
library locking. Inline result access and object destruction remain subject to
the host's quiet-window contract.

## C hosts

Probe `YUKIPLT_C_FEATURE_CACHED_MAPS` and
`YUKIPLT_C_FEATURE_CONTROLLED_FORK`. Create a `yukiplt_c_maps_cache`, capture or
import its snapshot, then pass its token to the cached batch, diagnosed function,
query, diagnosed unhook, session or rule entry points. Destroy it after all
bindings have been consumed. The three fork protocol functions have matching
`yukiplt_c_` entry points. Existing diagnostic layouts and ABI version 1 apply.
The diagnosed batch variants accept optional operation diagnostics. The nonnull
named batch accepts name-only `YUKIPLT_C_SELECTOR` requests and rejects additional
version, hidden-bit, dependency or relocation-index filters.
