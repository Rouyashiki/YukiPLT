# YukiPLT

A standalone Android Native PLT/GOT hook library, independently implemented
under Apache-2.0. It requires C++17 and Android API 23 or newer (`riscv64`
requires NDK r30 or newer and Android API 37 or newer), with no root, JNI,
Java, daemon or private linker dependency.

| ABI | Support | Minimum API | Native relocations |
| --- | --- | --- | --- |
| `arm64-v8a` | Official, guaranteed | 23 | ELF64 RELA, APS2 RELA |
| `armeabi-v7a` | Official, guaranteed | 23 | ELF32 REL, APS2 REL |
| `x86_64` | Official, environment-dependent | 23 | ELF64 RELA, APS2 RELA |
| `x86` | Official, environment-dependent | 23 | ELF32 REL, APS2 REL |
| `riscv64` | Official, environment-dependent | 37 | ELF64 RELA, APS2 RELA (`JUMP_SLOT`, opt-in `R_RISCV_64` function addresses) |

The `armeabi-v7a` build passed runtime tests on a Samsung Galaxy Note5 (SM-N9200)
running Android 7.0 (API 24), both from `adb shell` and in a regular app.

Each artifact handles only its process's native ABI. Other architectures and
API levels below each ABI's minimum (API 21–22, or API 21–36 on `riscv64`) are
unsupported. Page size is detected at runtime; shared artifacts use 16K LOAD
alignment.

Select images and imports explicitly. YukiPLT provides unique-slot hooks,
version selectors, batch transactions, owning import snapshots, multi-image
sessions, rule registration and synchronous custom-loader notifications.
Function selectors support `GLOB_DAT` on architectures with a distinct
relocation type. On RISC-V64, hosts can explicitly select `R_RISCV_64`
references to imported functions in GOT entries and ordinary data pointers.
APS2 is available through explicit source selection. There is no automatic
loader tracking, inline hook or general hook-chain manager.

- [Build and package](docs/building.md)
- [Integrate the C++ and C APIs](docs/integration.md)
- [Manage lifetime, recovery and loader cooperation](docs/lifecycle.md)
- [Match ABI and runtime dependencies](docs/abi.md)

Read the lifetime contract before installing a hook. Imports must already be
bound, output storage and replacement code must remain alive through recovery,
and every modifying result must be checked. Successful unhook does not prove
that replacement code is no longer executing.

This library is unreleased. Rebuild all C++ callers with matching headers,
toolchain and STL configuration. C ABI v1 retains its fixed layouts and values.

Licensed under [Apache-2.0](LICENSE).
