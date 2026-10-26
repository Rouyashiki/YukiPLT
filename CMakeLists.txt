# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Rouyashiki <https://rouyashiki.org>

cmake_minimum_required(VERSION 3.22)
project(YukiPLT VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(YUKIPLT_COMPILE_OPTIONS -Wall -Wextra -Wpedantic -Werror)

if(ANDROID)
    set(_yukiplt_abis arm64-v8a)
    if(NOT ANDROID_ABI IN_LIST _yukiplt_abis)
        message(FATAL_ERROR "Unsupported Android ABI: ${ANDROID_ABI}")
    endif()
    if(DEFINED ANDROID_PLATFORM_LEVEL)
        set(_yukiplt_api "${ANDROID_PLATFORM_LEVEL}")
    elseif(DEFINED CMAKE_ANDROID_API)
        set(_yukiplt_api "${CMAKE_ANDROID_API}")
    else()
        set(_yukiplt_api "${CMAKE_SYSTEM_VERSION}")
    endif()
    if(NOT _yukiplt_api MATCHES "^[0-9]+$" OR _yukiplt_api LESS 23)
        message(FATAL_ERROR "YukiPLT requires Android API 23 or newer")
    endif()
    if("hwaddress" IN_LIST ANDROID_SANITIZE AND
       (NOT ANDROID_ABI STREQUAL "arm64-v8a" OR _yukiplt_api LESS 34))
        message(FATAL_ERROR "HWASan requires arm64-v8a and Android API 34 or newer")
    endif()
endif()

add_subdirectory(src)
