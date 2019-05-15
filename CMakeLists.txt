cmake_minimum_required(VERSION 3.5.0)

# Project
project(libvnf)

# Description
set(PROJECT_DESCRIPTION "libvnf is a library to easily build custom scalable high performance Virtual Network Functions (VNFs)")

# Release type
set(CMAKE_BUILD_TYPE Release)

# Project version
set(PROJECT_VERSION_MAJOR 0)
set(PROJECT_VERSION_MINOR 9)
set(PROJECT_VERSION_PATCH 1)
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

# Installation paths
set(LIBRARY_INSTALL_DIR /usr/lib)
set(LIBRARY_INSTALL_DIR2 /usr/local/lib)
set(HEADERS_INSTALL_DIR /usr/include/libvnf)
set(HEADERS_INSTALL_DIR2 /usr/local/include/libvnf)

option(STACK "Stack to be used for libvnf" OFF)
if (${STACK} STREQUAL KERNEL)
    message(STATUS "Using ${STACK} stack for libvnf")
    # Flags
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_FLAGS "-fpermissive -lnuma -lrt -DLIBVNF_STACK=1")

    # Include
    include_directories(include)

    # Sources and Headers
    file(GLOB_RECURSE HEADERS "include/*hpp")
    file(GLOB_RECURSE SOURCES "src/datastore/*cpp" "src/kernel_impl/*cpp")

    # Library
    add_library(vnf-kernel-dynamic SHARED ${SOURCES} ${HEADERS})
    add_library(vnf-kernel-static STATIC ${SOURCES} ${HEADERS})

    # Install
    install(TARGETS vnf-kernel-dynamic vnf-kernel-static DESTINATION ${LIBRARY_INSTALL_DIR})
    install(TARGETS vnf-kernel-dynamic vnf-kernel-static DESTINATION ${LIBRARY_INSTALL_DIR2})
    install(DIRECTORY include/ DESTINATION ${HEADERS_INSTALL_DIR})
    install(DIRECTORY include/ DESTINATION ${HEADERS_INSTALL_DIR2})
elseif (${STACK} STREQUAL KERNEL_BYPASS)
    message(STATUS "Using ${STACK} stack for libvnf")
    # Flags
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_FLAGS "-fpermissive -lnuma -lrt -Wno-write-strings -Wall -DLIBVNF_STACK=2")

    # Include
    include_directories(include)
    include_directories(/home/rahul2514888/trishal/mtcp-p/mtcp/include)
    include_directories(/home/rahul2514888/trishal/mtcp-p/util/include)

    # Sources and Headers
    file(GLOB_RECURSE HEADERS "include/*hpp")
    file(GLOB_RECURSE SOURCES "src/datastore/*cpp" "src/kernel_bypass_impl/*cpp")

    # Library
    add_library(vnf-kernelbypass-dynamic SHARED ${SOURCES} ${HEADERS})
    add_library(vnf-kernelbypass-static STATIC ${SOURCES} ${HEADERS})

    # Install
    install(TARGETS vnf-kernelbypass-dynamic vnf-kernelbypass-static DESTINATION ${LIBRARY_INSTALL_DIR})
    install(TARGETS vnf-kernelbypass-dynamic vnf-kernelbypass-static DESTINATION ${LIBRARY_INSTALL_DIR2})
    install(DIRECTORY include/ DESTINATION ${HEADERS_INSTALL_DIR})
    install(DIRECTORY include/ DESTINATION ${HEADERS_INSTALL_DIR2})
elseif (${STACK} STREQUAL L3VNF)
    message(STATUS "Using ${STACK} stack for libvnf")
    # Flags
    set(CMAKE_CXX_STANDARD 11)
    set(CMAKE_CXX_FLAGS "-fpermissive -lnuma -lrt -Wno-write-strings -Wall -DLIBVNF_STACK=3")

    # Include
    include_directories(include)
    include_directories(/home/sgw/Downloads/MTP/netmap-master/sys/)

    # Sources and Headers
    file(GLOB_RECURSE HEADERS "include/*hpp")
    file(GLOB_RECURSE SOURCES "src/datastore/*cpp" "src/kernel_l3_impl/*cpp")

    # Library
    add_library(vnf-l3-dynamic SHARED ${SOURCES} ${HEADERS})
    add_library(vnf-l3-static STATIC ${SOURCES} ${HEADERS})

    # Install
    install(TARGETS vnf-l3-dynamic vnf-l3-static DESTINATION ${LIBRARY_INSTALL_DIR})
    install(TARGETS vnf-l3-dynamic vnf-l3-static DESTINATION ${LIBRARY_INSTALL_DIR2})
    install(DIRECTORY include/ DESTINATION ${HEADERS_INSTALL_DIR})
    install(DIRECTORY include/ DESTINATION ${HEADERS_INSTALL_DIR2})
else ()
    message(FATAL_ERROR "Choose a stack for libvnf. Usage -DSTACK=KERNEL or -DSTACK=KERNEL_BYPASS or -DSTACK=L3VNF")
endif ()
