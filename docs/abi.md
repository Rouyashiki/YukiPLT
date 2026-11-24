# ABI compatibility

YukiPLT is unreleased. Rebuild all C++ callers with matching public headers,
compiler, NDK and standard-library configuration. Private members affect
by-value object storage; mixing layouts can overwrite caller memory.

On RISC-V64, inspection returns `UnsupportedFormat` if a readable ELF header's
floating-point ABI or reduced-register flag (`EF_RISCV_RVE`) differs from the
library's. Android riscv64 uses LP64D with the full integer register set. For a
custom image supplied through program headers alone, the loader must verify the
calling convention.

The current `HookPlan`, `FunctionHookPlan`, `HookSession`,
`FunctionHookSession` and `RuleSet` layouts are frozen. New capabilities use
new types or entry points. Do not mix STL iterator/debug modes, and do not
infer compatibility from equal `sizeof` alone.

C ABI version 1, existing numeric values and existing C structures remain
unchanged. Use `yukiplt_c_has_feature()` to detect additions, including
architecture-specific relocation support such as `YUKIPLT_C_FEATURE_REL_IMPORTS`
(feature 6) and `YUKIPLT_C_FEATURE_GLOB_DAT_IMPORTS` (feature 22, false on
`riscv64`). Probe `YUKIPLT_C_FEATURE_RISCV64_FUNCTION_ADDRESSES` (feature 23)
before requesting the opt-in `R_RISCV_64` type. The probe returns zero on the
other ABIs and on older RISC-V64 libraries. On the four original ABIs, older
libraries that report feature 1 already support function `GLOB_DAT`. Clients can use the
[combined probe](integration.md#select-an-image-and-import). `struct_size`
validates a frozen layout; it does not permit fields to be appended in place.
The legacy recovery diagnostic is frozen even though it has no size field.
`OperationDiagnostic`'s version is an output identifier, not an extension slot.

Compile replacement code using `OriginalSlot::load()`, `load_original()` or
`yukiplt_c_load_original()` so original reads include the required fence.
Path-bound APIs do not remove the caller's lifecycle responsibility for a
same-path, same-address reload.

Shared artifacts bind internal API calls to their own implementations. For a
manually embedded static copy, define `YUKIPLT_STATIC` in every library and
caller translation unit, compile implementation sources with hidden visibility
(`-fvisibility=hidden -fvisibility-inlines-hidden`), and localize archives at the
host DSO link (`-Wl,--exclude-libs,ALL` or a restrictive version script). Export
only your wrapper API. The macro alone does not hide archive implementation
symbols or keep the host alive.

The documented `ANDROID_STL=c++_shared` build depends on the matching NDK's
`libc++_shared.so`, even for C-only callers. The `c++_static` shared variant is for C ABI boundaries. For static embedding,
select the runtime at the final host link. Do not mix incompatible C++ runtime
instances, artifacts or callers.

Use `<yukiplt.h>` for C and `<yukiplt.hpp>` for C++. The former
`yukiplt/` include paths have been removed; update source includes when
rebuilding. Header consolidation preserves existing layouts, numeric values
and exported signatures.

## Reading targets from C plans and sessions

A client that supports older shared libraries should first call
`yukiplt_c_has_feature(YUKIPLT_C_FEATURE_BULK_TARGETS)` (feature 21). If the
probe succeeds, use `dlsym` on the loaded YukiPLT library to resolve
`yukiplt_c_plan_targets_copy` or `yukiplt_c_session_targets_copy`. Call through
the function pointer if the lookup succeeds. A strong reference to either symbol can
cause the loader to reject the client before the probe runs.

If the feature or the required symbol is absent, read targets in index order.
For plans (feature 12), use `yukiplt_c_plan_size` and `yukiplt_c_plan_target`.
For sessions (feature 13), use the target count from `yukiplt_c_session_size`
and read each row with `yukiplt_c_session_target`.

For a bulk read, pass null buffers and zero capacities to obtain the record
count and total text bytes. Supply both buffers on the second call.
Records follow the original target order. String offsets refer to the start of
the returned text buffer. If either buffer is too small, the call returns
`YUKIPLT_C_OUT_OF_BOUNDS` and writes only the required sizes. Session records
include the original address and the installation and restoration reports.
Serialize reads with other operations on the same session.

### 兼容旧库的目标读取

先调用 `yukiplt_c_has_feature(YUKIPLT_C_FEATURE_BULK_TARGETS)`（feature 21）。探测成功后，在已加载的 YukiPLT 库上用 `dlsym` 解析所需的 `yukiplt_c_plan_targets_copy` 或 `yukiplt_c_session_targets_copy`。解析成功后再通过函数指针调用。直接强引用这些可选符号，可能导致宿主在执行探测前就因旧库缺少符号而加载失败。

如果缺少该 feature 或所需符号，可按下标逐项读取。计划（feature 12）用 `yukiplt_c_plan_size` 取目标数，再调用 `yukiplt_c_plan_target`。会话（feature 13）用 `yukiplt_c_session_size` 取目标数，再调用 `yukiplt_c_session_target`。整个读取过程应与同一会话的其他操作串行。

## Batch import selection

Feature 20, `YUKIPLT_C_FEATURE_BATCH_SELECT`, selects 1–64 imports from one image during a single inspection. Use `yukiplt_c_select_imports` with version selectors or `yukiplt_c_select_function_imports` with function selectors. Their `_named` counterparts bind a system image to the exact discovered path. The corresponding C++ calls are `find_imports`, `find_function_imports`, `find_imports_named` and `find_function_imports_named`.

Function selectors in one call must share their source mask. Each selector must identify one eligible slot. Repeated selectors produce independent rows in request order. Copy and destroy a successful C result with the existing import-snapshot APIs. On failure the call publishes no rows. An optional `failed_index` receives the first failing request index, or `SIZE_MAX` for success, an image error, a scan-wide budget error or allocation failure. Copies of selected text share the operation's materialization budget.

After validating the call arguments, the batch APIs inspect the full image before matching selectors. Image errors therefore take precedence over selector errors, even for one request. The first function selector supplies the source mask needed to decode the image. An invalid or unsupported mask fails at index zero before inspection. The C entry points validate selector representations as they convert them and resolve the valid preceding requests before reporting a malformed selector. The shared byte budget includes the request index when the batch builds one.

A binary that supports older shared libraries can probe feature 20 and then resolve the optional symbols with `dlsym`. With the image held stable, a caller can collect ordinary single-selector results into private storage and publish only after all requests succeed.

Error precedence can change in that fallback. For a custom image without `PT_DYNAMIC` and a first version selector whose `symbol` is null, `yukiplt_c_select_imports` returns `YUKIPLT_C_INVALID_IMAGE` with `failed_index == SIZE_MAX`. At index zero, `yukiplt_c_select_import` checks the selector before inspecting the image and returns `YUKIPLT_C_NULL_POINTER`.

Single-selector calls have separate budgets. When selectors match the same import, the native batch charges each copy of the import's text against one shared 64 MiB materialization budget. It can return `OutOfBounds` even when every single call succeeds. Set a limit on the total bytes staged for records and text, and reject a result before retaining it if it would exceed that limit. If the caller requires native batch error precedence, `failed_index`, or exact budget behavior, report batch selection as unavailable when feature 20 is absent.

A batch reports the skipped relocation count once for the scanned sources. The older single-selector C calls report zero, so a fallback that needs the count must obtain it from a full versioned or function snapshot using the same sources. If exact path binding is required, use a path-bound interface supported by the installed library or report that the operation is unavailable.

### 中文接入说明

通过 `yukiplt_c_has_feature(YUKIPLT_C_FEATURE_BATCH_SELECT)` 探测后，可在一次映像检查中按顺序查找 1–64 项。函数选择器共用同一来源掩码，`_named` 入口在检查时核对完整系统路径。每项都须唯一匹配，重复选择器分别产生拥有型条目。成功后使用既有快照接口查询容量、复制并销毁结果。

批量入口先校验调用参数，再完成整幅映像的检查，然后按序匹配选择器。即使只有一项，映像错误也优先于匹配错误。第一项函数选择器的来源掩码决定解码范围，掩码无效或 ABI 不支持时会在检查映像前返回下标 0。C 接口转换选择器时验证结构和枚举，若遇到无法转换的项，先解析它之前的合法请求，再报告该项错误。构建请求索引时，其大小计入共享字节预算。

请求错误返回首个失败下标。成功、映像错误、整次扫描预算不足或分配失败时下标为 `SIZE_MAX`。失败不会发布部分快照。若需兼容旧共享库，可在探测后才用 `dlsym` 解析新符号。调用方若能在整批期间保持映像稳定，可暂存逐项普通查找的结果，全部成功后再发布。

逐项降级可能改变错误优先级。例如，自定义映像缺少 `PT_DYNAMIC` 且首个版本选择器的 `symbol` 为空指针时，`yukiplt_c_select_imports` 返回 `YUKIPLT_C_INVALID_IMAGE`，`failed_index` 为 `SIZE_MAX`。逐项调用 `yukiplt_c_select_import` 会先检查选择器，在第 0 项返回 `YUKIPLT_C_NULL_POINTER`。

逐项调用各自计算预算。原生批量查询重复选择同一导入时，每份结果的文本副本都计入整批共享的 64 MiB 物化预算。即使逐项查询全部成功，原生批量查询也可能因超限返回 `OutOfBounds`。降级时应在暂存每项结果前检查记录和文本的累计大小，超出调用方设定的上限即停止。若要求与原生批量查询相同的错误优先级、失败下标或预算失败条件，缺少 feature 20 时应报告批量查询不可用。

批量快照对扫描来源中跳过的重定位只计数一次。旧版 C 单项接口的计数固定为零，降级时若需要该值，应从相同来源的完整版本导入或函数导入快照读取。要求路径绑定时，应选用相应的具名接口，或向上层报告该能力不可用。
