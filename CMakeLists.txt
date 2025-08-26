# Minimum CMake version required
cmake_minimum_required(VERSION 3.10)

# Extract version number from perf_test.c
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/version.h" PERF_TEST_C_CONTENTS)
string(REGEX MATCH "#define PERF_TEST_APP_VERSION_CI \"([^\"]+)\"" PERF_TEST_APP_VERSION_MATCH "${PERF_TEST_C_CONTENTS}")
if(PERF_TEST_APP_VERSION_MATCH)
    string(REGEX REPLACE ".*#define PERF_TEST_APP_VERSION_CI \"v([^\"]+)\".*" "\\1" PERF_TEST_APP_VERSION "${PERF_TEST_C_CONTENTS}")
    message(STATUS "Extracted version: ${PERF_TEST_APP_VERSION}")
    project(PerfTesApp VERSION ${PERF_TEST_APP_VERSION})
else()
    message(FATAL_ERROR "Could not extract version from perf_test.c")
endif()


# Print the current version each time CMake is run
message(STATUS "Current version: ${PROJECT_VERSION}")

# Set the C standard
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED True)

# Ensure required environment variables are set
if(NOT DEFINED ENV{RDMA_CORE_ROOT})
    message(FATAL_ERROR "Environment variable RDMA_CORE_ROOT is not set.")
endif()

set(RDMA_LIB_HBL_PATH $ENV{RDMA_CORE_ROOT}/build/lib/libhbl.so)
set(RDMA_LIB_IBV_PATH $ENV{RDMA_CORE_ROOT}/build/lib/libibverbshl.so)

# Include header files directory
include_directories($ENV{RDMA_CORE_ROOT}/build/include)
include_directories($ENV{HABANALABS_ROOT}/include/uapi)
include_directories(include
                    /usr/include/habanalabs
                    /usr/include/drm
                    /usr/include/libdrm)


# Collect source files for perf_test
file(GLOB PERF_TEST_SOURCES "*.c")
list(FILTER PERF_TEST_SOURCES EXCLUDE REGEX ".*ibv_dev_port_mapping\\.c$")

# Collect source files for mapping
file(GLOB MAPPING_SOURCES "*.c")
list(FILTER MAPPING_SOURCES EXCLUDE REGEX ".*perf_test\\.c$")

# Add the executable target for perf_test
add_executable(perf_test ${PERF_TEST_SOURCES})
target_link_libraries(perf_test ${RDMA_LIB_HBL_PATH} ${RDMA_LIB_IBV_PATH})

# Add the executable target for mapping
add_executable(mapping ${MAPPING_SOURCES})
target_link_libraries(mapping ${RDMA_LIB_HBL_PATH} ${RDMA_LIB_IBV_PATH})


# Add a custom target to print the version before building any file
add_custom_target(print_version
    COMMAND ${CMAKE_COMMAND} -E echo "Building perf_test version: ${PERF_TEST_APP_VERSION}"
)

# Make sure the print_version target runs before building the executable
add_dependencies(perf_test print_version)

# Enable strict warnings and treat them as errors
add_compile_options(-Wall -Wextra -Werror)
