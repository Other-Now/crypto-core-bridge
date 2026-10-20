cmake_minimum_required(VERSION 3.20)
project(crypto_core_bridge CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

option(CCB_SANITIZE "Build with ASan + UBSan" OFF)
option(CCB_HARDEN "Hardened build flags (FORTIFY, PIE, RELRO, stack protector)" ON)
set(CCB_RUST_LIB "" CACHE FILEPATH "Path to libccb.a (the Rust staticlib); enables the cross-language targets")

find_package(OpenSSL 3.0 REQUIRED COMPONENTS Crypto)

add_compile_options(-Wall -Wextra -Wpedantic -Wconversion -Wno-sign-conversion)

if(CCB_HARDEN AND NOT CCB_SANITIZE)
  # _FORTIFY_SOURCE needs optimisation; =3 needs GCC 12+ / glibc 2.34+.
  add_compile_options(-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=3 -fstack-protector-strong
                      -fstack-clash-protection -fcf-protection=full)
  add_link_options(-pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack)
endif()
if(CCB_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-sanitize-recover=undefined -fno-omit-frame-pointer)
  add_link_options(-fsanitize=address,undefined)
endif()

add_library(ccb_cpp STATIC src/primitives.cpp src/software_store.cpp src/pkcs11_store.cpp)
target_include_directories(ccb_cpp PUBLIC include PRIVATE ../third_party/pkcs11)
target_link_libraries(ccb_cpp PUBLIC OpenSSL::Crypto ${CMAKE_DL_LIBS})

enable_testing()

add_executable(test_core tests/test_core.cpp)
target_link_libraries(test_core ccb_cpp)
add_test(NAME test_core COMMAND test_core)

add_executable(zeroize_check tests/zeroize_check.cpp)
target_link_libraries(zeroize_check ccb_cpp)
add_test(NAME zeroize_check COMMAND zeroize_check)

if(CCB_RUST_LIB)
  add_library(ccb_rust STATIC IMPORTED)
  set_target_properties(ccb_rust PROPERTIES IMPORTED_LOCATION ${CCB_RUST_LIB})
  target_include_directories(ccb_rust INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/../include)
  find_package(Threads REQUIRED)
  target_link_libraries(ccb_rust INTERFACE Threads::Threads ${CMAKE_DL_LIBS} m)

  add_executable(xlang tests/xlang.cpp)
  target_link_libraries(xlang ccb_cpp ccb_rust)
  add_test(NAME xlang COMMAND xlang)

  add_executable(bench bench/bench.cpp)
  target_link_libraries(bench ccb_cpp ccb_rust)
endif()
