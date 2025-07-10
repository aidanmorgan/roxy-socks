cmake_minimum_required(VERSION 3.10)
project(roxy-socks-tests)

# Find Python
find_package(Python3 REQUIRED COMPONENTS Interpreter)

# Set paths
set(RUST_SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../src)
set(TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})

# Custom target to build the Rust binary
add_custom_target(build-rust-debug
    COMMAND cargo build
    WORKING_DIRECTORY ${RUST_SRC_DIR}
    COMMENT "Building Rust binary..."
)

# Custom target to run the integration tests
add_custom_target(run-tests
    COMMAND uv pip install -e ${TEST_DIR}[test]
    COMMAND ${CMAKE_COMMAND} -E env RUST_LOG=debug uv run --project ${TEST_DIR} pytest ${TEST_DIR} -v -s --tb=short | tee ${TEST_DIR}/test_output.log
    WORKING_DIRECTORY ${TEST_DIR}
    DEPENDS build-rust-debug
)

# Set run_tests as the default target when building in this directory
set_property(DIRECTORY PROPERTY CMAKE_DEFAULT_TARGET run-tests)
