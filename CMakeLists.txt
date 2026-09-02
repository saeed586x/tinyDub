cmake_minimum_required(VERSION 3.24)
project(tinyDub VERSION 0.2.1 LANGUAGES CXX)

if(MSVC)
    cmake_policy(SET CMP0091 NEW)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(tinyDub WIN32 src/ui_main.cpp)

target_compile_definitions(tinyDub PRIVATE
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(tinyDub PRIVATE
    user32
    gdi32
    ole32
    oleaut32
    uuid
    avrt
    winhttp
    crypt32
    shell32
)

include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
)
FetchContent_MakeAvailable(nlohmann_json)
target_link_libraries(tinyDub PRIVATE nlohmann_json::nlohmann_json)

if(MSVC)
    target_compile_options(tinyDub PRIVATE
        /W4
        /WX
        /utf-8
        /wd4312
        /permissive-
        /EHsc
        /FI"${CMAKE_CURRENT_SOURCE_DIR}/src/win_compat.h"
    )
endif()

if(WIN32)
    set_target_properties(tinyDub PROPERTIES OUTPUT_NAME "tinyDub")
endif()
