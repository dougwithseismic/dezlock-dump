cmake_minimum_required(VERSION 3.20)
project(dezlock-dump VERSION 1.8.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Output to bin/ like the old build.bat
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# MSVC flags matching the original build
if(MSVC)
    add_compile_options(/O2 /MP /MT /EHsc /W3 /DUNICODE /D_UNICODE /D_CRT_SECURE_NO_WARNINGS)
    # Use static runtime (/MT) for all configs
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# --- dezlock-worker (DLL injected into game) ---
add_library(dezlock-worker SHARED
    worker.cpp
    src/schema-manager.cpp
    src/rtti-hierarchy.cpp
    src/log.cpp
    src/global-scanner.cpp
    src/pattern-scanner.cpp
    src/interface-scanner.cpp
    src/string-scanner.cpp
    src/protobuf-scanner.cpp
)
target_include_directories(dezlock-worker PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(dezlock-worker PRIVATE user32 psapi)
if(MSVC)
    target_link_options(dezlock-worker PRIVATE /GUARD:NO)
endif()

# --- Generate version.h from CMake project version ---
configure_file(src/version.h.in ${CMAKE_BINARY_DIR}/generated/version.h)

# --- dezlock-dump (CLI orchestrator exe) ---
add_executable(dezlock-dump
    main.cpp
    src/console.cpp
    src/injector.cpp
    src/cli.cpp
    src/output-generator.cpp
    src/generate-signatures.cpp
    src/import-schema.cpp
    src/analyze-members.cpp
    src/ws-server.cpp
    src/live-bridge.cpp
    src/version-check.cpp
)
target_include_directories(dezlock-dump PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/vendor          # asio.hpp, websocketpp/
    ${CMAKE_BINARY_DIR}/generated       # version.h
)
target_compile_definitions(dezlock-dump PRIVATE
    ASIO_STANDALONE
    _WEBSOCKETPP_CPP11_INTERNAL_
    _WEBSOCKETPP_CPP11_THREAD_
    _WEBSOCKETPP_CPP11_FUNCTIONAL_
    _WEBSOCKETPP_CPP11_SYSTEM_ERROR_
    _WEBSOCKETPP_CPP11_RANDOM_DEVICE_
    _WEBSOCKETPP_CPP11_MEMORY_
    _WEBSOCKETPP_CPP11_TYPE_TRAITS_
)
target_link_libraries(dezlock-dump PRIVATE user32 advapi32 ws2_32 winhttp)

# --- Copy config files and scripts to output directory ---
foreach(cfg patterns.json sdk-cherry-pick.json)
    if(EXISTS ${CMAKE_SOURCE_DIR}/${cfg})
        add_custom_command(TARGET dezlock-dump POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                ${CMAKE_SOURCE_DIR}/${cfg}
                $<TARGET_FILE_DIR:dezlock-dump>/${cfg}
            COMMENT "Copying ${cfg}"
        )
    endif()
endforeach()
