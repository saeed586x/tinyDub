cmake_minimum_required(VERSION 3.24)
project(tinyDub VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_executable(tinyDub WIN32 src/main.cpp)

target_compile_definitions(tinyDub PRIVATE
    UNICODE
    _UNICODE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    WINHTTP_WEB_SOCKET_SUCCESS_CLOSE=WINHTTP_WEB_SOCKET_SUCCESS_CLOSE_STATUS
)

target_link_libraries(tinyDub PRIVATE
    ole32
    oleaut32
    uuid
    avrt
    winhttp
    crypt32
    shlwapi
)

include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.12.0/json.tar.xz
)
FetchContent_MakeAvailable(nlohmann_json)
target_link_libraries(tinyDub PRIVATE nlohmann_json::nlohmann_json)

if(MSVC)
    target_compile_options(tinyDub PRIVATE /W4 /permissive- /EHsc /wd4005 /wd4189 /wd4996)
endif()

if(WIN32)
    set_target_properties(tinyDub PROPERTIES OUTPUT_NAME "tinyDub")
endif()
