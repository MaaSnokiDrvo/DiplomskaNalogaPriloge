cmake_minimum_required(VERSION 3.18)

if(WIN32 AND (NOT DEFINED CMAKE_TOOLCHAIN_FILE OR CMAKE_TOOLCHAIN_FILE STREQUAL "") AND EXISTS "C:/dev/vcpkg/scripts/buildsystems/vcpkg.cmake")
    set(CMAKE_TOOLCHAIN_FILE "C:/dev/vcpkg/scripts/buildsystems/vcpkg.cmake" CACHE FILEPATH "vcpkg toolchain file")
endif()

project(NetSentinelIDS VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(NETSENTINEL_ENABLE_POSTGRESQL "Build PostgreSQL archiver support through libpq when available" ON)

set(NPCAP_SDK_DIR "C:/dev/npcap-sdk-1.16" CACHE PATH "Path to Npcap SDK on Windows")

find_package(Threads REQUIRED)

if(POLICY CMP0167)
    cmake_policy(SET CMP0167 NEW)
    find_package(Boost CONFIG QUIET COMPONENTS system)
else()
    find_package(Boost 1.70 QUIET COMPONENTS system)
endif()
if(NOT Boost_FOUND)
    message(FATAL_ERROR
        "Boost.System is required by the REST/WebSocket server. "
        "Install Boost development files (Windows/vcpkg: vcpkg install boost-system; "
        "Ubuntu/Debian: apt-get install libboost-system-dev) or set BOOST_ROOT.")
endif()

find_package(nlohmann_json 3.10 CONFIG REQUIRED)

set(NETSENTINEL_POSTGRESQL_AVAILABLE OFF)
if(NETSENTINEL_ENABLE_POSTGRESQL)
    find_package(PostgreSQL QUIET)
    if(PostgreSQL_FOUND)
        set(NETSENTINEL_POSTGRESQL_AVAILABLE ON)
    else()
        message(WARNING
            "PostgreSQL/libpq development files were not found. "
            "The C++ archiver will build, but DB archival will be disabled at runtime. "
            "Windows/vcpkg: vcpkg install libpq.")
    endif()
endif()

if(WIN32)
    find_path(PCAP_INCLUDE_DIR
        NAMES pcap.h
        HINTS "${NPCAP_SDK_DIR}/Include"
    )
    find_library(PCAP_LIBRARY
        NAMES wpcap
        HINTS "${NPCAP_SDK_DIR}/Lib/x64"
    )
    find_library(PACKET_LIBRARY
        NAMES Packet
        HINTS "${NPCAP_SDK_DIR}/Lib/x64"
    )
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY OR NOT PACKET_LIBRARY)
        message(FATAL_ERROR
            "Npcap SDK not found. Install Npcap SDK and configure with "
            "-DNPCAP_SDK_DIR=C:/path/to/npcap-sdk.")
    endif()
else()
    find_path(PCAP_INCLUDE_DIR NAMES pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "libpcap development files not found. Install libpcap-dev/libpcap-devel.")
    endif()
endif()

set(SOURCES
    src/main.cpp
    src/CaptureEngine.cpp
    src/ProtocolParser.cpp
    src/FlowManager.cpp
    src/Analytics.cpp
    src/RestAPIServer.cpp
    src/PostgreSQLArchiver.cpp
)

add_executable(${PROJECT_NAME} ${SOURCES})

target_include_directories(${PROJECT_NAME} PRIVATE
    include
    ${PCAP_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    Threads::Threads
    ${PCAP_LIBRARY}
)

if(TARGET Boost::system)
    target_link_libraries(${PROJECT_NAME} PRIVATE Boost::system)
else()
    target_link_libraries(${PROJECT_NAME} PRIVATE ${Boost_LIBRARIES})
endif()

if(TARGET nlohmann_json::nlohmann_json)
    target_link_libraries(${PROJECT_NAME} PRIVATE nlohmann_json::nlohmann_json)
endif()

if(NETSENTINEL_POSTGRESQL_AVAILABLE)
    target_include_directories(${PROJECT_NAME} PRIVATE ${PostgreSQL_INCLUDE_DIRS})
    if(TARGET PostgreSQL::PostgreSQL)
        target_link_libraries(${PROJECT_NAME} PRIVATE PostgreSQL::PostgreSQL)
    else()
        target_link_libraries(${PROJECT_NAME} PRIVATE ${PostgreSQL_LIBRARIES})
    endif()
    target_compile_definitions(${PROJECT_NAME} PRIVATE HAVE_LIBPQ=1)
endif()

if(WIN32)
    target_compile_definitions(${PROJECT_NAME} PRIVATE
        WPCAP
        HAVE_REMOTE
        NOMINMAX
        _WIN32_WINNT=0x0A00
        _CRT_SECURE_NO_WARNINGS
    )
    target_link_libraries(${PROJECT_NAME} PRIVATE
        ${PACKET_LIBRARY}
        ws2_32
        iphlpapi
    )
endif()

if(MSVC)
    string(REGEX REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")
    target_compile_options(${PROJECT_NAME} PRIVATE /W4 /EHsc /permissive- /bigobj)
else()
    target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic)
endif()

message(STATUS "NetSentinel IDS build configuration")
message(STATUS "  PostgreSQL archiver: ${NETSENTINEL_POSTGRESQL_AVAILABLE}")
message(STATUS "  pcap include: ${PCAP_INCLUDE_DIR}")
message(STATUS "  pcap library: ${PCAP_LIBRARY}")
