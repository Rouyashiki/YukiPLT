# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rouyashiki <https://rouyashiki.org>

set(YUKIPLT_SOURCES
    c_api.cpp
    imports.cpp
    yukiplt.cpp
    elf.cpp
    session.cpp
    memory.cpp
    registry.cpp
    rules.cpp
)

if(CMAKE_CROSSCOMPILING)
    add_library(yukiplt SHARED ${YUKIPLT_SOURCES})
    target_link_options(yukiplt PRIVATE -Wl,-z,max-page-size=16384 -Wl,-z,nodelete)
    set_target_properties(yukiplt PROPERTIES
        CXX_VISIBILITY_PRESET hidden C_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON
        LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/yukiplt.map")
    target_link_options(yukiplt PRIVATE
        "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/yukiplt.map" -Wl,--exclude-libs,ALL)
    target_link_options(yukiplt PRIVATE -Wl,-Bsymbolic-functions)
    install(TARGETS yukiplt LIBRARY DESTINATION lib COMPONENT production)
    install(FILES "${PROJECT_SOURCE_DIR}/include/yukiplt.h"
    "${PROJECT_SOURCE_DIR}/include/yukiplt.hpp"
    DESTINATION include COMPONENT production)
    install(FILES "${PROJECT_SOURCE_DIR}/LICENSE" DESTINATION share/licenses/YukiPLT COMPONENT production)
else()
    add_library(yukiplt STATIC ${YUKIPLT_SOURCES})
    target_compile_definitions(yukiplt PUBLIC YUKIPLT_STATIC=1)
    set_target_properties(yukiplt PROPERTIES
        CXX_VISIBILITY_PRESET hidden C_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
endif()

target_include_directories(yukiplt PUBLIC "${PROJECT_SOURCE_DIR}/include"
    PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}")
target_compile_options(yukiplt PRIVATE ${YUKIPLT_COMPILE_OPTIONS})
set_target_properties(yukiplt PROPERTIES POSITION_INDEPENDENT_CODE ON)

install(DIRECTORY "${PROJECT_SOURCE_DIR}/docs/" DESTINATION share/doc/YukiPLT
    COMPONENT production FILES_MATCHING PATTERN "*.md")
