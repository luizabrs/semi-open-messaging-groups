# Set the minimum version of CMake that can be used
# To find the cmake version run
# $ cmake --version
cmake_minimum_required(VERSION 3.5)

# Set the project name
project (mr_impl)

# Add an executable
add_executable(mr_impl
    src/main.cpp
    src/utilities.cpp
    src/trivial_zkproof.cpp
    src/dlog.cpp
    src/dlog_to_gen.cpp
    src/dleq.cpp
    src/batched_dleq.cpp
    src/shuffle_compatible_dleq.cpp
    src/fiat_shamir.cpp
    src/base_point.cpp
    src/verifiable_exponentiation.cpp
    src/shuffled_sigma_protocol.cpp
    src/random_permutation.cpp
    src/repeated_sigma_protocol.cpp
    src/keccak.cpp
    src/protocol_run.cpp
    src/parties.cpp
)

# link against libsodium
target_link_libraries(mr_impl PRIVATE sodium)

set(CMAKE_CXX_FLAGS_DEBUG_INIT "-Wall -g")
set(CMAKE_CXX_FLAGS_RELEASE_INIT "-Wall")

