# Build and package

Use Clang, CMake 3.22 or newer, Ninja and the Android NDK. Select the native ABI
of the process that will load the library. The minimum Android API is 23.

```sh
cmake -S . -B build-android -G Ninja \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-23 \
  -DANDROID_STL=c++_shared -DCMAKE_BUILD_TYPE=Release
cmake --build build-android
cmake --install build-android --prefix package --component production
```

The package contains `lib/libyukiplt.so`, `include/yukiplt.h` (C) and
`include/yukiplt.hpp` (C++), the license and these
integration guides. Deploy the matching NDK's `libc++_shared.so` too, including
when every caller uses the C interface. Android does not supply that runtime.

For an existing CMake project, use `add_subdirectory(path/to/YukiPLT)` and link
your target with `yukiplt`. Configure the parent project with the same NDK,
ABI, API and STL settings. Project warnings apply only to YukiPLT's targets.

Shared artifacts use hidden visibility, an explicit export map, 16K LOAD
alignment and NODELETE. Internal calls bind to the same copy of the library.
Keep the owning loader group alive; NODELETE is not a substitute for the
[lifetime contract](lifecycle.md).

On a 16K device, a 4K-aligned library loaded in page-size compatibility mode
may have an executable GOT mapping. YukiPLT refuses executable, shared or
unreadable slot pages with `PermissionDenied`. Build target libraries with
16K alignment where possible; never bypass this check with writable-executable
permissions. The actual VMA, rather than ELF RELRO flags, decides eligibility.

Native host builds produce a static library for development. Android shared
artifacts are the supported distribution format. HWASan requires arm64-v8a
and API 34 or newer.

Implementation sources are grouped by responsibility: `elf.cpp` validates ELF
metadata and resolves hashes; `imports.cpp` decodes relocations, versions and
explicit candidates; `memory.cpp` owns live maps, page protections and slot
transactions; `registry.cpp` owns claims and recovery state. `yukiplt.cpp`
coordinates public operations and diagnostics, `session.cpp` discovers images
and manages plans/sessions, and `rules.cpp` manages refresh and loader
notifications. The C boundary has separate operation/token, metadata, session
and rule units. Internal helpers stay with these owners.
