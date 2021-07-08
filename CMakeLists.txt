project(SFKJ)
cmake_minimum_required(VERSION 3.13)
cmake_policy(SET CMP0077 NEW)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/cmake")

set(SFKJ_SOURCE_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(SFKJ_BINARY_ROOT "${CMAKE_CURRENT_BINARY_DIR}")

set(Boost_USE_STATIC_LIBS OFF CACHE BOOL "Use shared boost libraries" FORCE)
set(Boost_USE_STATIC_RUNTIME OFF CACHE BOOL "Use shared boost runtime" FORCE)

find_package(Boost COMPONENTS system filesystem REQUIRED)
find_package(Threads REQUIRED)

set(ENABLE_RELIC ON CACHE BOOL "Build relic by default" FORCE)
set(MULTI PTHREAD CACHE STRING "Build relic with multithreading from pthread" FORCE)
set(ARITH easy CACHE STRING "Build relic without gmp" FORCE)
set(WITH "MD;DV;BN;FB;FP;EB;EC;EP" CACHE STRING "Overwrite Relic algorithms in ABY with their superset" FORCE)

find_package(OpenSSL REQUIRED)
if(OPENSSL_FOUND)
    if(APPLE)
        include_directories(/usr/local/Cellar/openssl@1.1/1.1.1h/include)
        list(APPEND LIB_LIST /usr/local/Cellar/openssl@1.1/1.1.1h/lib/libssl.dylib)
        list(APPEND LIB_LIST /usr/local/Cellar/openssl@1.1/1.1.1h/lib/libcrypto.dylib)
        message(STATUS "OpenSSL Version: ${OPENSSL_VERSION} ${OPENSSL_INCLUDE_DIR} ${OPENSSL_LIBRARIES}")
    else()
        include_directories(${OPENSSL_INCLUDE_DIR})
        list(APPEND LIB_LIST ${OPENSSL_LIBRARIES})
        message(STATUS "OpenSSL Version: ${OPENSSL_VERSION} ${OPENSSL_INCLUDE_DIR} ${OPENSSL_LIBRARIES}")
    endif()
endif()

find_package(ABY QUIET)
set(ENCRYPTO_UTILS_BUILD_TESTS OFF CACHE BOOL "Disable tests for the ENCRYPTO utils library" FORCE)
if (ABY_FOUND)
    message(STATUS "Found ABY")
elseif (NOT ABY_FOUND AND NOT TARGET ABY::aby)
    message("ABY was not found: add ABY subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/ABY/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/ABY")
        execute_process(COMMAND git submodule update --init extern/ABY
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/ABY)
endif ()

# relic is already compiled by ENCRYPTO_utils, which is ABY's dependency
set(RLC_LIBRARY "${SFKJ_BINARY_ROOT}/extern/ABY/lib/librelic_s.a")

file(COPY
        "${PROJECT_SOURCE_DIR}/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/"
        "${SFKJ_BINARY_ROOT}/extern/ABY/extern/ENCRYPTO_utils/extern/relic/include/relic_conf.h"
    DESTINATION
        "${PROJECT_BINARY_DIR}/include/relic"
)

find_package(HashingTables QUIET)
if (HashingTables_FOUND)
    message(STATUS "Found HashingTables")
elseif (NOT HashingTables_FOUND AND NOT TARGET HashingTables::hashingtables)
    message("HashingTables was not found: add HashingTables subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/HashingTables/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/HashingTables")
        execute_process(COMMAND git submodule update --init extern/HashingTables
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/HashingTables)
endif ()

# we need to set these compile flags globally to compile compile libOTe and its dependencies
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pthread -maes -msse2 -msse3 -msse4.1 -mpclmul -mavx -mavx2")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-ignored-attributes")

set(ENABLE_SIMPLESTOT ON CACHE BOOL "Enable Simplest OT for Base OTs" FORCE)
find_package(libOTe QUIET)
if (libOTe_FOUND)
    message(STATUS "Found libOTe")
elseif (NOT libOTe_FOUND AND NOT TARGET libOTe::libote)
    message("libOTe was not found: add libOTe subdirectory")
    if (NOT EXISTS "${PROJECT_SOURCE_DIR}/extern/libOTe/CMakeLists.txt")
        find_package(Git REQUIRED)
        message("initialize Git submodule: extern/libOTe")
        execute_process(COMMAND git submodule update --init --recursive extern/libOTe
                WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")
    endif ()
    add_subdirectory(extern/libOTe)
endif ()

add_dependencies(libOTe relic_s)

add_subdirectory(src)
