# Optional post-quantum interop test. Needs OpenSSL >= 3.5 (ML-KEM/ML-DSA);
# kept as its own project so the main build stays on the distro OpenSSL 3.0.
#   cmake -S pq -B build-pq -DOPENSSL_ROOT_DIR=$HOME/ossl35
cmake_minimum_required(VERSION 3.20)
project(ccb_pq C CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_C_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL 3.5 REQUIRED COMPONENTS Crypto)
find_package(Threads REQUIRED)

add_library(nanokem_mlkem STATIC ../third_party/nanokem/src/mlkem768.c ../third_party/nanokem/src/keccak.c)
target_include_directories(nanokem_mlkem PUBLIC ../third_party/nanokem/include)

add_executable(pq_interop pq_interop.cpp)
target_link_libraries(pq_interop nanokem_mlkem OpenSSL::Crypto Threads::Threads ${CMAKE_DL_LIBS})
