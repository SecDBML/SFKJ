find_package(PkgConfig REQUIRED)
pkg_search_module(GLIB REQUIRED glib-2.0)

find_package(Boost COMPONENTS program_options REQUIRED)

if (NOT Boost_FOUND)
    message(FATAL_ERROR "Boost library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

find_library(NTL_LIB ntl)
if (NOT NTL_LIB)
    message(FATAL_ERROR "ntl library not found.  Rerun cmake with -DCMAKE_PREFIX_PATH=\"<path to lib1>;<path to lib2>\"")
endif ()

find_library(GMP_LIB gmp)
if(NOT GMP_LIB)
  message(FATAL_ERROR "gmp library not found.")
endif()

find_library(GMPXX_LIB gmpxx)
if(NOT GMP_LIB)
  message(FATAL_ERROR "gmpxx library not found.")
endif()

add_library(SFKJ
        common/psi_analytics.cpp
        common/helpers.cpp
        polynomials/Mersenne.cpp
        polynomials/Poly.cpp
        ots/ots.cpp
        PRNG/PRNG.cpp
        PermNet/PermutationNetwork.cpp
        PermNet/WaksmanPermutation.cpp
        OEP/OEP.cpp
        join/join.cpp
        join/twoserverjoin.cpp
        utils/multicom.cpp
        Purify/PurificationCircuit.cpp
        sort/sort.cpp
        )
        
set_target_properties(SFKJ
        PROPERTIES ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/lib"
        )

target_compile_options(SFKJ
        PRIVATE
        -march=native
        -ffunction-sections -mpclmul -mbmi2 -maes
        -mavx -msse2 -msse3 -msse4.1
        -Wall -Wno-strict-overflow -Wno-ignored-attributes -Wno-parentheses)

target_link_libraries(SFKJ INTERFACE
        ABY::aby
        ENCRYPTO_utils::encrypto_utils
        ${GLIB_LDFLAGS}
        ${NTL_LIB}
        ${GMP_LIB}
        ${GMPXX_LIB}
        HashingTables
        libOTe
        Boost::program_options
        Threads::Threads
        # relic is a transitive dependency of libOTe right now
        # change relic to another library (if needed) if this changes
        relic_s
        )

target_include_directories(SFKJ PUBLIC
        ${SFKJ_SOURCE_ROOT}/src
        ${SFKJ_SOURCE_ROOT}/extern
        ${SFKJ_SOURCE_ROOT}/extern/libOTe/cryptoTools
        ${SFKJ_SOURCE_ROOT}/extern/libOTe
        ${SFKJ_SOURCE_ROOT}/extern/ABY/src
        ${SFKJ_SOURCE_ROOT}/extern/ABY/extern/ENCRYPTO_utils/src
        ${SFKJ_SOURCE_ROOT}/extern/HashingTables
        ${GLIB_INCLUDE_DIRS}
        )

add_executable(demo demo.cpp)
target_link_libraries(demo PUBLIC SFKJ)
set_target_properties(demo
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)

add_executable(puri puridemo.cpp)
target_link_libraries(puri PUBLIC SFKJ)
set_target_properties(puri
    PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
