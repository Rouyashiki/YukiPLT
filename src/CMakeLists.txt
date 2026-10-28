# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rouyashiki <https://rouyashiki.org>

set(YUKIPLT_SOURCES
    c_api.cpp
    imports.cpp
    elf.cpp
    session.cpp
    memory.cpp
    registry.cpp
    rules.cpp
    yukiplt.cpp
)

if(CMAKE_CROSSCOMPILING)
    add_library(yukiplt SHARED ${YUKIPLT_SOURCES})
    target_link_options(yukiplt PRIVATE -Wl,-z,max-page-size=16384 -Wl,-z,nodelete)
    install(TARGETS yukiplt LIBRARY DESTINATION lib COMPONENT production)
    install(FILES "${PROJECT_SOURCE_DIR}/include/yukiplt.h"
    "${PROJECT_SOURCE_DIR}/include/yukiplt.hpp"
    DESTINATION include COMPONENT production)
    install(FILES "${PROJECT_SOURCE_DIR}/LICENSE" DESTINATION share/licenses/YukiPLT COMPONENT production)
else()
    add_library(yukiplt STATIC ${YUKIPLT_SOURCES})
endif()

target_include_directories(yukiplt PUBLIC "${PROJECT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(yukiplt PRIVATE ${YUKIPLT_COMPILE_OPTIONS})
set_target_properties(yukiplt PROPERTIES POSITION_INDEPENDENT_CODE ON)
