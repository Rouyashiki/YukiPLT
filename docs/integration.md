# Integrate the APIs

Include `<yukiplt.hpp>` for the complete C++ API or `<yukiplt.h>` for
the complete C ABI. Keep the selected images loaded while inspecting,
installing and restoring them.

## Select an image and import

Use `find_images()` with an explicit path, basename, load bias or main-image
selector. `find_image_containing()` finds an image by a LOAD address. Discovery
does not pin mappings or guarantee visibility into every linker namespace.
Prefer the `*_named` entry points when installing into a discovered system
image: they verify the exact saved path as well as bias and program headers.

`inspect_imports()` and `inspect_versioned_imports()` return owning metadata
without reading GOT values or changing memory. An `ImportSelector` combines a
symbol name with any, unversioned or exact version matching. Optional hidden-bit,
declared-dependency and relocation-index filters all apply together. A declared
dependency does not identify the actual provider. Multiple distinct matching
slots are ambiguous; repeated relocation records for one slot are malformed.

The name/version APIs handle `JUMP_SLOT` only. For function imports use
`inspect_function_imports()` and `hook_function_import(s)()` with explicit source
and type masks. Portable source constants are `kSourceNativeDynamic` and
`kSourceNativeAndroidPacked`; REL and RELA constants remain distinct.
Eligible `GLOB_DAT` imports must be undefined `STT_FUNC`, have effective addend
zero and a nonzero current slot. A zero `JUMP_SLOT` is allowed. An ineligible
matched import rejects the entire request before modification.

## Install and retain recovery state

Finish binding imports before installation. Custom loaders must complete all
relocations; NOW flags alone do not prove readiness. Use an exact replacement
function signature and calling convention, including ARM/Thumb address bits.
Do not install into the image containing the executing copy of YukiPLT.

Store original addresses in stable, aligned memory through recovery and
caller-established quiescence. Non-null outputs must be
distinct and cannot alias target slots or existing owners. Use
`OriginalSlot<FunctionPointer>` for typed storage, or `load_original()` /
`yukiplt_c_load_original()` for raw outputs. These helpers perform an acquire
fence before the acquire load; an acquire load alone is insufficient on ARM.
Never clear or reuse a published original slot. Its value can be another
framework's replacement, and a failed installation can still publish it.

Check the error and retain every live handle, including `Indeterminate`
results. Read [recovery rules](lifecycle.md) before disposing of handles.
A one-image batch accepts 1–64 requests. It validates every request first,
then commits with CAS and reverses earlier writes on conflict. Other threads
can observe intermediate slots; the batch is not a global atomic switch.

## Plans, sessions and candidate selection

`build_hook_plan()` / `build_function_hook_plan()` copy metadata without
freezing GOT values or extending mapping lifetime. Prepare a session, then
install it and inspect each image result. Groups execute independently;
failure in one image does not roll back other images. Unhook attempts all
groups in reverse order and retains failed groups for retry.

Function requests can require an expected current slot value. Candidate
expansion supports exact, prefix, suffix and substring matching, followed by
an optional host callback over owned snapshots outside library/linker locks.
Convert chosen candidates into an explicit plan before installation.

## C callers

Initialize each structure's `struct_size` to its documented size, probe new
features with `yukiplt_c_has_feature()`, and provide buffers required by the
individual query. Handle tokens have unique ownership: do not copy them to
create another owner or pass them to another library copy. No STL objects or
exceptions cross the C boundary. See [ABI compatibility](abi.md).
